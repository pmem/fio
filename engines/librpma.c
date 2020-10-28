/*
 * librpma: IO engine that uses PMDK librpma to read and write data
 *
 * Copyright 2020, Intel Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2 as published by the Free Software Foundation..
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "../fio.h"
#include "../hash.h"
#include "../optgroup.h"

#include <libpmem.h>
#include <librpma.h>

#define rpma_td_verror(td, err, func) \
	td_vmsg((td), (err), rpma_err_2str(err), (func))

/* client's and server's common */

/*
 * Limited by the maximum length of the private data
 * for rdma_connect() in case of RDMA_PS_TCP (28 bytes).
 */
#define DESCRIPTORS_MAX_SIZE 23

struct workspace {
	uint32_t size;		/* size of workspace for a single connection */
	uint8_t mr_desc_size;	/* size of mr_desc in descriptors[] */
	/* buffer containing mr_desc */
	char descriptors[DESCRIPTORS_MAX_SIZE];
};

/* client side implementation */

struct client_options {
	/*
	 * FIO considers .off1 == 0 absent so the first meaningful field has to
	 * have padding ahead of it.
	 */
	void *pad;
	char *hostname;
	char *port;
};

static struct fio_option fio_client_options[] = {
	{
		.name	= "hostname",
		.lname	= "rpma_client hostname",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct client_options, hostname),
		.help	= "IP address the server is listening on",
		.def    = "",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA,
	},
	{
		.name	= "port",
		.lname	= "rpma_client port",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct client_options, port),
		.help	= "port the server is listening on",
		.def    = "7204",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA,
	},
	{
		.name	= NULL,
	},
};

struct client_data {
	struct rpma_peer *peer;
	struct rpma_conn *conn;

	/* aligned td->orig_buffer */
	char *orig_buffer_aligned;

	/* ious's base address memory registration (cd->orig_buffer_aligned) */
	struct rpma_mr_local *orig_mr;

	/* a server's memory representation */
	struct rpma_mr_remote *server_mr;

	/* remote workspace description */
	size_t ws_offset;
	size_t ws_size;

	/* in-memory queues */
	struct io_u **io_us_queued;
	int io_u_queued_nr;
	struct io_u **io_us_flight;
	int io_u_flight_nr;
	struct io_u **io_us_completed;
	int io_u_completed_nr;
};

static int client_init(struct thread_data *td)
{
	struct client_options *o = td->eo;
	struct client_data *cd;
	struct ibv_context *dev = NULL;
	struct rpma_conn_cfg *cfg = NULL;
	struct rpma_conn_req *req = NULL;
	struct rpma_peer_cfg *pcfg = NULL;
	enum rpma_conn_event event;
	uint32_t cq_size;
	struct rpma_conn_private_data pdata;
	struct workspace *ws;
	size_t server_mr_size;
	int ret = 1;

	/* configure logging thresholds to see more details */
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD, RPMA_LOG_LEVEL_INFO);
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD_AUX, RPMA_LOG_LEVEL_ERROR);

	/* allocate client's data */
	cd = calloc(1, sizeof(struct client_data));
	if (cd == NULL) {
		td_verror(td, errno, "calloc");
		return 1;
	}

	/* allocate all in-memory queues */
	cd->io_us_queued = calloc(td->o.iodepth, sizeof(struct io_u *));
	if (cd->io_us_queued == NULL) {
		td_verror(td, errno, "calloc");
		goto err_free_cd;
	}

	cd->io_us_flight = calloc(td->o.iodepth, sizeof(struct io_u *));
	if (cd->io_us_flight == NULL) {
		td_verror(td, errno, "calloc");
		goto err_free_io_us_queued;
	}

	cd->io_us_completed = calloc(td->o.iodepth, sizeof(struct io_u *));
	if (cd->io_us_completed == NULL) {
		td_verror(td, errno, "calloc");
		goto err_free_io_us_flight;
	}

	/* obtain an IBV context for a remote IP address */
	ret = rpma_utils_get_ibv_context(o->hostname,
				RPMA_UTIL_IBV_CONTEXT_REMOTE,
				&dev);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_utils_get_ibv_context");
		goto err_free_io_us_completed;
	}

	/* create a connection configuration object */
	ret = rpma_conn_cfg_new(&cfg);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_conn_cfg_new");
		goto err_free_io_us_completed;
	}

	/* the send queue has to be big enough to accommodate all io_u's */
	ret = rpma_conn_cfg_set_sq_size(cfg, td->o.iodepth);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_conn_cfg_set_sq_size");
		goto err_cfg_delete;
	}

	/* cq_size = ceil(td->o.iodepth / td->o.iodepth_batch) */
	cq_size = (td->o.iodepth + td->o.iodepth_batch - 1) / td->o.iodepth_batch;

	/*
	 * The completion queue has to be big enough
	 * to accommodate one completion for each batch.
	 */
	ret = rpma_conn_cfg_set_cq_size(cfg, cq_size);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_conn_cfg_set_cq_size");
		goto err_cfg_delete;
	}

	/* create a new peer object */
	ret = rpma_peer_new(dev, &cd->peer);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_peer_new");
		goto err_cfg_delete;
	}

	/* create a connection request */
	ret = rpma_conn_req_new(cd->peer, o->hostname, o->port, cfg, &req);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_conn_req_new");
		goto err_peer_delete;
	}

	ret = rpma_conn_cfg_delete(&cfg);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_conn_cfg_delete");
		goto err_peer_delete;
	}

	/* connect the connection request and obtain the connection object */
	ret = rpma_conn_req_connect(&req, NULL, &cd->conn);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_conn_req_connect");
		goto err_req_delete;
	}

	/* wait for the connection to establish */
	ret = rpma_conn_next_event(cd->conn, &event);
	if (ret) {
		goto err_conn_delete;
	} else if (event != RPMA_CONN_ESTABLISHED) {
		log_err(
			"rpma_conn_next_event returned an unexptected event: (%s != RPMA_CONN_ESTABLISHED)\n",
			rpma_utils_conn_event_2str(event));
		goto err_conn_delete;
	}

	/* get the connection's private data sent from the server */
	if ((ret = rpma_conn_get_private_data(cd->conn, &pdata)))
		goto err_conn_delete;

	ws = pdata.ptr;

	/* validate the received workspace size */
	if (ws->size < td->o.size) {
		log_err(
			"received workspace size is too small (%u < %llu)\n",
			ws->size, td->o.size);
		goto err_conn_delete;
	}

	/* create the server's memory representation */
	if ((ret = rpma_mr_remote_from_descriptor(&ws->descriptors[0],
			ws->mr_desc_size, &cd->server_mr)))
		goto err_conn_delete;

	/* get the total size of the shared server memory */
	if ((ret = rpma_mr_remote_get_size(cd->server_mr, &server_mr_size))) {
		rpma_td_verror(td, ret, "rpma_mr_remote_get_size");
		goto err_conn_delete;
	}

	/* validate the received workspace size */
	cd->ws_offset = (td->thread_number - 1) * ws->size;
	if (cd->ws_offset > server_mr_size) {
		log_err(
			"the workspace starts beyond the memory region (%zu > %zu)\n",
			cd->ws_offset, server_mr_size);
		goto err_conn_delete;
	} else if (cd->ws_offset + ws->size > server_mr_size) {
		log_err(
			"the workspace ends beyond the memory region (%zu > %zu)\n",
			cd->ws_offset + ws->size, server_mr_size);
		goto err_conn_delete;
	}

	/* configure peer's direct write to pmem support */
	ret = rpma_peer_cfg_new(&pcfg);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_peer_cfg_new");
		goto err_conn_delete;
	}

	ret = rpma_peer_cfg_set_direct_write_to_pmem(pcfg, true);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_peer_cfg_set_direct_write_to_pmem");
		goto peer_cfg_delete;
	}

	ret = rpma_conn_apply_remote_peer_cfg(cd->conn, pcfg);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_conn_apply_remote_peer_cfg");
		goto peer_cfg_delete;
	}

	(void) rpma_peer_cfg_delete(&pcfg);

	cd->ws_size = ws->size;
	td->io_ops_data = cd;

	return 0;

peer_cfg_delete:
	(void) rpma_peer_cfg_delete(&pcfg);

err_conn_delete:
	(void) rpma_conn_disconnect(cd->conn);
	(void) rpma_conn_delete(&cd->conn);

err_req_delete:
	if (req)
		(void) rpma_conn_req_delete(&req);
err_peer_delete:
	(void) rpma_peer_delete(&cd->peer);

err_cfg_delete:
	(void) rpma_conn_cfg_delete(&cfg);

err_free_io_us_completed:
	free(cd->io_us_completed);

err_free_io_us_flight:
	free(cd->io_us_flight);

err_free_io_us_queued:
	free(cd->io_us_queued);

err_free_cd:
	free(cd);

	return ret;
}

static int client_post_init(struct thread_data *td)
{
	struct client_data *cd =  td->io_ops_data;
	size_t io_us_size;
	int ret;

	/*
	 * td->orig_buffer is not aligned. The engine requires aligned io_us
	 * so FIO alignes up the address using the formula below.
	 */
	cd->orig_buffer_aligned = PTR_ALIGN(td->orig_buffer, page_mask) +
			td->o.mem_align;

	/*
	 * td->orig_buffer_size beside the space really consumed by io_us
	 * has paddings which can be omitted for the memory registration.
	 */
	io_us_size = (unsigned long long)td_max_bs(td) *
			(unsigned long long)td->o.iodepth;

	if ((ret = rpma_mr_reg(cd->peer, cd->orig_buffer_aligned, io_us_size,
			RPMA_MR_USAGE_READ_DST | RPMA_MR_USAGE_READ_SRC |
			RPMA_MR_USAGE_WRITE_DST | RPMA_MR_USAGE_WRITE_SRC |
			RPMA_MR_USAGE_FLUSH_TYPE_PERSISTENT,
			&cd->orig_mr)))
		rpma_td_verror(td, ret, "rpma_mr_reg");
	return ret;
}

static void client_cleanup(struct thread_data *td)
{
	struct client_data *cd = td->io_ops_data;
	enum rpma_conn_event ev;
	int ret;

	if (cd == NULL)
		return;

	/* delete the iou's memory registration */
	if ((ret = rpma_mr_dereg(&cd->orig_mr)))
		rpma_td_verror(td, ret, "rpma_mr_dereg");

	/* delete the iou's memory registration */
	if ((ret = rpma_mr_remote_delete(&cd->server_mr)))
		rpma_td_verror(td, ret, "rpma_mr_remote_delete");

	/* initiate disconnection */
	if ((ret = rpma_conn_disconnect(cd->conn)))
		rpma_td_verror(td, ret, "rpma_conn_disconnect");

	/* wait for disconnection to end up */
	if ((ret = rpma_conn_next_event(cd->conn, &ev))) {
		rpma_td_verror(td, ret, "rpma_conn_next_event");
	} else if (ev != RPMA_CONN_CLOSED) {
		log_err(
			"client_cleanup received an unexpected event (%s != RPMA_CONN_CLOSED)\n",
			rpma_utils_conn_event_2str(ev));
	}

	/* delete the connection */
	if ((ret = rpma_conn_delete(&cd->conn)))
		rpma_td_verror(td, ret, "rpma_conn_delete");

	/* delete the peer */
	if ((ret = rpma_peer_delete(&cd->peer)))
		rpma_td_verror(td, ret, "rpma_peer_delete");

	/* free the software queues */
	free(cd->io_us_queued);
	free(cd->io_us_flight);
	free(cd->io_us_completed);

	/* free the client's data */
	free(td->io_ops_data);
}

static int client_get_file_size(struct thread_data *td, struct fio_file *f)
{
	struct client_data *cd = td->io_ops_data;

	f->real_file_size = cd->ws_size;
	fio_file_set_size_known(f);

	return 0;
}

static int client_open_file(struct thread_data *td, struct fio_file *f)
{
	/* NOP */
	return 0;
}

static int client_close_file(struct thread_data *td, struct fio_file *f)
{
	/* NOP */
	return 0;
}

static inline int client_io_read(struct thread_data *td, struct io_u *io_u, int flags)
{
	struct client_data *cd = td->io_ops_data;
	size_t dst_offset = (char *)(io_u->xfer_buf) - cd->orig_buffer_aligned;
	size_t src_offset = cd->ws_offset + io_u->offset;
	int ret = rpma_read(cd->conn,
			cd->orig_mr, dst_offset,
			cd->server_mr, src_offset,
			io_u->xfer_buflen,
			flags,
			(void *)(uintptr_t)io_u->index);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_read");
		return -1;
	}

	return 0;
}

static inline int client_io_write(struct thread_data *td, struct io_u *io_u, int flags)
{
	struct client_data *cd = td->io_ops_data;
	size_t src_offset = (char *)(io_u->xfer_buf) - cd->orig_buffer_aligned;
	size_t dst_offset = io_u->offset;

	int ret = rpma_write(cd->conn,
			cd->server_mr, dst_offset,
			cd->orig_mr, src_offset,
			io_u->xfer_buflen,
			flags,
			(void *)(uintptr_t)io_u->index);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_write");
		return -1;
	}

	return 0;
}

static enum fio_q_status client_queue_sync(struct thread_data *td,
					  struct io_u *io_u)
{
	struct client_data *cd = td->io_ops_data;
	struct rpma_completion cmpl;
	/* io_u->index of completed io_u (cmpl.op_context) */
	unsigned int io_u_index;
	int ret;

	/* execute io_us */
	if (io_u->ddir == DDIR_READ) {
		/* post an RDMA read operation */
		if ((ret = client_io_read(td, io_u, RPMA_F_COMPLETION_ALWAYS)))
			goto err;
	} else if (io_u->ddir == DDIR_WRITE) {
		/* post an RDMA write operation */
		if ((ret = client_io_write(td, io_u, RPMA_F_COMPLETION_ON_ERROR)))
			goto err;
		if ((ret = rpma_flush(cd->conn, cd->server_mr,
				io_u->offset, io_u->xfer_buflen,
				RPMA_FLUSH_TYPE_PERSISTENT, RPMA_F_COMPLETION_ALWAYS,
				(void *)(uintptr_t)io_u->index)))
			goto err;
	} else {
		log_err("unsupported IO mode: %s\n", io_ddir_name(io_u->ddir));
		goto err;
	}

	do {
		/* get a completion */
		ret = rpma_conn_completion_get(cd->conn, &cmpl);
		if (ret != 0 && ret != RPMA_E_NO_COMPLETION) {
			/* an error occurred */
			rpma_td_verror(td, ret, "rpma_conn_completion_get");
			goto err;
		}
	} while (ret != 0);

	memcpy(&io_u_index, &cmpl.op_context, sizeof(unsigned int));
	if (io_u->index != io_u_index) {
		log_err(
			"no matching io_u for received completion found (io_u_index=%u)\n",
			io_u_index);
		goto err;
	}

	/* if io_u has completed with an error */
	if (cmpl.op_status != IBV_WC_SUCCESS)
		io_u->error = cmpl.op_status;

	return FIO_Q_COMPLETED;

err:
	io_u->error = -1;
	return FIO_Q_COMPLETED;
}

static enum fio_q_status client_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	struct client_data *cd = td->io_ops_data;

	if (cd->io_u_queued_nr == (int)td->o.iodepth)
		return FIO_Q_BUSY;

	if (td->o.sync_io)
		return client_queue_sync(td, io_u);

	/* io_u -> queued[] */
	cd->io_us_queued[cd->io_u_queued_nr] = io_u;
	cd->io_u_queued_nr++;

	return FIO_Q_QUEUED;
}

static int client_commit(struct thread_data *td)
{
	struct client_data *cd = td->io_ops_data;
	int flags = RPMA_F_COMPLETION_ON_ERROR;
	struct timespec now;
	bool fill_time;
	int ret;
	int i;

	if (!cd->io_us_queued)
		return -1;

	/* execute all io_us from queued[] */
	for (i = 0; i < cd->io_u_queued_nr; i++) {
		struct io_u *io_u = cd->io_us_queued[i];

		if (i == cd->io_u_queued_nr - 1)
			flags = RPMA_F_COMPLETION_ALWAYS;

		if (io_u->ddir == DDIR_READ) {
			/* post an RDMA read operation */
			if ((ret = client_io_read(td, io_u, flags)))
				return -1;
		} else {
			log_err("unsupported IO mode: %s\n", io_ddir_name(io_u->ddir));
			return -1;
		}
	}

	if ((fill_time = fio_fill_issue_time(td)))
		fio_gettime(&now, NULL);

	/* move executed io_us from queued[] to flight[] */
	for (i = 0; i < cd->io_u_queued_nr; i++) {
		struct io_u *io_u = cd->io_us_queued[i];

		/* FIO does not do this if the engine is asynchronous */
		if (fill_time)
			memcpy(&io_u->issue_time, &now, sizeof(now));

		/* move executed io_us from queued[] to flight[] */
		cd->io_us_flight[cd->io_u_flight_nr] = io_u;
		cd->io_u_flight_nr++;

		/*
		 * FIO says:
		 * If an engine has the commit hook it has to call io_u_queued() itself.
		 */
		io_u_queued(td, io_u);
	}

	/* FIO does not do this if an engine has the commit hook. */
	io_u_mark_submit(td, cd->io_u_queued_nr);
	cd->io_u_queued_nr = 0;

	return 0;
}

/*
 * RETURN VALUE
 * - > 0  - a number of completed io_us
 * -   0  - when no complicitions received
 * - (-1) - when an error occurred
 */
static int client_getevent_process(struct thread_data *td)
{
	struct client_data *cd = td->io_ops_data;
	struct rpma_completion cmpl;
	unsigned int io_us_error = 0;
	/* io_u->index of completed io_u (cmpl.op_context) */
	unsigned int io_u_index;
	/* # of completed io_us */
	int cmpl_num = 0;
	/* helpers */
	struct io_u *io_u;
	int i;
	int ret;

	/* get a completion */
	if ((ret = rpma_conn_completion_get(cd->conn, &cmpl))) {
		/* lack of completion is not an error */
		if (ret == RPMA_E_NO_COMPLETION)
			return 0;

		/* an error occurred */
		rpma_td_verror(td, ret, "rpma_conn_completion_get");
		return -1;
	}

	/* if io_us has completed with an error */
	if (cmpl.op_status != IBV_WC_SUCCESS)
		io_us_error = cmpl.op_status;

	/* look for an io_u being completed */
	memcpy(&io_u_index, &cmpl.op_context, sizeof(unsigned int));
	for (i = 0; i < cd->io_u_flight_nr; ++i) {
		if (cd->io_us_flight[i]->index == io_u_index) {
			cmpl_num = i + 1;
			break;
		}
	}

	/* if no matching io_u has been found */
	if (cmpl_num == 0) {
		log_err(
			"no matching io_u for received completion found (io_u_index=%u)\n",
			io_u_index);
		return -1;
	}

	/* move completed io_us to the completed in-memory queue */
	for (i = 0; i < cmpl_num; ++i) {
		/* get and prepare io_u */
		io_u = cd->io_us_flight[i];
		io_u->error = io_us_error;

		/* append to the queue */
		cd->io_us_completed[cd->io_u_completed_nr] = io_u;
		cd->io_u_completed_nr++;
	}

	/* remove completed io_us from the flight queue */
	for (i = cmpl_num; i < cd->io_u_flight_nr; ++i)
		cd->io_us_flight[i - cmpl_num] = cd->io_us_flight[i];
	cd->io_u_flight_nr -= cmpl_num;

	return cmpl_num;
}

static int client_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, const struct timespec *t)
{
	struct client_data *cd = td->io_ops_data;
	/* total # of completed io_us */
	int cmpl_num_total = 0;
	/* # of completed io_us from a single event */
	int cmpl_num;
	int ret;

	do {
		cmpl_num = client_getevent_process(td);
		if (cmpl_num > 0) {
			/* new completions collected */
			cmpl_num_total += cmpl_num;
		} else if (cmpl_num == 0) {
			if (cmpl_num_total >= min)
				break;

			/* too few completions - wait */
			ret = rpma_conn_completion_wait(cd->conn);
			if (ret == 0 || ret == RPMA_E_NO_COMPLETION)
				continue;

			/* an error occurred */
			rpma_td_verror(td, ret, "rpma_conn_completion_wait");
			return -1;
		} else {
			/* an error occurred */
			return -1;
		}
	} while (cmpl_num_total < max);

	return cmpl_num_total;
}

static struct io_u *client_event(struct thread_data *td, int event)
{
	struct client_data *cd = td->io_ops_data;
	struct io_u *io_u;
	int i;

	/* get the first io_u from the queue */
	io_u = cd->io_us_completed[0];

	/* remove the first io_u from the queue */
	for (i = 1; i < cd->io_u_completed_nr; ++i)
		cd->io_us_completed[i - 1] = cd->io_us_completed[i];
	cd->io_u_completed_nr--;

	dprint_io_u(io_u, "client_event");

	return io_u;
}

static char *client_errdetails(struct io_u *io_u)
{
	/* get the string representation of an error */
	enum ibv_wc_status status = io_u->error;
	const char *status_str = ibv_wc_status_str(status);

	/* allocate and copy the error string representation */
	char *details = malloc(strlen(status_str) + 1);
	strcpy(details, status_str);

	/* FIO frees the returned string when it becomes obsolete */
	return details;
}

FIO_STATIC struct ioengine_ops ioengine_client = {
	.name			= "librpma_client",
	.version		= FIO_IOOPS_VERSION,
	.init			= client_init,
	.post_init		= client_post_init,
	.get_file_size		= client_get_file_size,
	.open_file		= client_open_file,
	.queue			= client_queue,
	.commit			= client_commit,
	.getevents		= client_getevents,
	.event			= client_event,
	.errdetails		= client_errdetails,
	.close_file		= client_close_file,
	.cleanup		= client_cleanup,
	/* XXX flags require consideration */
	.flags			= FIO_DISKLESSIO | FIO_UNIDIR | FIO_PIPEIO,
	.options		= fio_client_options,
	.option_struct_size	= sizeof(struct client_options),
};

/* server side implementation */

struct server_options {
	/*
	 * FIO considers .off1 == 0 absent so the first meaningful field has to
	 * have padding ahead of it.
	 */
	void *pad;
	char *bindname;
	char *port;
	unsigned int num_conns;
};

static struct fio_option fio_server_options[] = {
	{
		.name	= "bindname",
		.lname	= "rpma_server bindname",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct server_options, bindname),
		.help	= "IP address to listen on for incoming connections",
		.def    = "",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA,
	},
	{
		.name	= "port",
		.lname	= "rpma_server port",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct server_options, port),
		.help	= "port to listen on for incoming connections",
		.def    = "7204",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA,
	},
	{
		.name	= "num_conns",
		.lname	= "Number of connections",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct server_options, num_conns),
		.help	= "Number of connections to serve",
		.minval = 1,
		.def	= "1",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA,
	},
	{
		.name	= NULL,
	},
};

struct server_data {
	struct rpma_peer *peer;
	struct rpma_ep *ep;

	/* aligned td->orig_buffer */
	char *orig_buffer_aligned;

	struct workspace ws;
	struct rpma_conn_private_data pdata;
};

static int server_init(struct thread_data *td)
{
	struct server_options *o = td->eo;
	struct server_data *sd;
	struct ibv_context *dev = NULL;
	int ret = 1;

	/* configure logging thresholds to see more details */
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD, RPMA_LOG_LEVEL_INFO);
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD_AUX, RPMA_LOG_LEVEL_ERROR);

	/* allocate server's data */
	sd = calloc(1, sizeof(struct server_data));
	if (sd == NULL) {
		td_verror(td, errno, "calloc");
		return 1;
	}

	/* obtain an IBV context for a remote IP address */
	ret = rpma_utils_get_ibv_context(o->bindname,
				RPMA_UTIL_IBV_CONTEXT_LOCAL,
				&dev);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_utils_get_ibv_context");
		goto err_free_sd;
	}

	/* create a new peer object */
	ret = rpma_peer_new(dev, &sd->peer);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_peer_new");
		goto err_free_sd;
	}

	/* start a listening endpoint at addr:port */
	ret = rpma_ep_listen(sd->peer, o->bindname, o->port, &sd->ep);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_ep_listen");
		goto err_peer_delete;
	}

	td->io_ops_data = sd;

	/*
	 * Each connection needs its own workspace which will be allocated as
	 * io_u. So the number of io_us has to be equal to the number of
	 * connections the server will handle and...
	 */
	td->o.iodepth = o->num_conns;

	/*
	 * ... a single io_u size has to be equal to the assumed workspace size.
	 */
	td->o.max_bs[DDIR_READ] = td->o.size;

	return 0;

err_peer_delete:
	(void) rpma_peer_delete(&sd->peer);

err_free_sd:
	free(sd);

	return ret;
}

static void server_cleanup(struct thread_data *td)
{
	struct server_data *sd =  td->io_ops_data;
	int ret;

	if (sd == NULL)
		return;

	/* shutdown the endpoint */
	if ((ret = rpma_ep_shutdown(&sd->ep)))
		rpma_td_verror(td, ret, "rpma_ep_shutdown");

	/* free the peer */
	if ((ret = rpma_peer_delete(&sd->peer)))
		rpma_td_verror(td, ret, "rpma_peer_delete");
}

static int server_open_file(struct thread_data *td, struct fio_file *f)
{
	struct server_data *sd =  td->io_ops_data;
	struct rpma_mr_local *mr;
	size_t mr_desc_size;
	size_t io_us_size;
	int ret = 1;

	/*
	 * td->orig_buffer is not aligned. The engine requires aligned io_us
	 * so FIO alignes up the address using the formula below.
	 */
	sd->orig_buffer_aligned = PTR_ALIGN(td->orig_buffer, page_mask) +
			td->o.mem_align;

	/*
	 * td->orig_buffer_size beside the space really consumed by io_us
	 * has paddings which can be omitted for the memory registration.
	 */
	io_us_size = (unsigned long long)td_max_bs(td) *
			(unsigned long long)td->o.iodepth;

	ret = rpma_mr_reg(sd->peer, sd->orig_buffer_aligned, io_us_size,
			RPMA_MR_USAGE_READ_DST | RPMA_MR_USAGE_READ_SRC |
			RPMA_MR_USAGE_WRITE_DST | RPMA_MR_USAGE_WRITE_SRC |
			RPMA_MR_USAGE_FLUSH_TYPE_PERSISTENT,
			&mr);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_mr_reg");
		return 1;
	}

	/* get size of the memory region's descriptor */
	ret = rpma_mr_get_descriptor_size(mr, &mr_desc_size);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_mr_get_descriptor_size");
		goto err_mr_dereg;
	}

	/* verify size of the memory region's descriptor */
	if (mr_desc_size > DESCRIPTORS_MAX_SIZE) {
		log_err("size of the memory region's descriptor is too big (max=%i)\n",
			DESCRIPTORS_MAX_SIZE);
		goto err_mr_dereg;
	}

	/* get the memory region's descriptor */
	ret = rpma_mr_get_descriptor(mr, &sd->ws.descriptors[0]);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_mr_get_descriptor");
		goto err_mr_dereg;
	}

	/* prepare a workspace description */
	sd->ws.mr_desc_size = mr_desc_size;
	sd->ws.size = td_max_bs(td);

	/* attach the workspace to private data structure */
	sd->pdata.ptr = &sd->ws;
	sd->pdata.len = sizeof(struct workspace);

	FILE_SET_ENG_DATA(f, mr);

	return 0;

err_mr_dereg:
	(void) rpma_mr_dereg(&mr);

	return ret;
}

static int server_close_file(struct thread_data *td, struct fio_file *f)
{
	struct rpma_mr_local *mr = FILE_ENG_DATA(f);
	int ret;

	if ((ret = rpma_mr_dereg(&mr)))
		rpma_td_verror(td, ret, "rpma_mr_dereg");

	FILE_SET_ENG_DATA(f, NULL);

	return ret;
}

static struct rpma_conn *server_conn_establish(struct thread_data *td)
{
	struct server_data *sd =  td->io_ops_data;
	struct rpma_conn_req *req;
	struct rpma_conn *conn;
	enum rpma_conn_event event = RPMA_CONN_UNDEFINED;
	int ret;

	/* receive an incoming connection request */
	ret = rpma_ep_next_conn_req(sd->ep, NULL, &req);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_ep_next_conn_req");
		return NULL;
	}

	/* accept the connection request and obtain the connection object */
	ret = rpma_conn_req_connect(&req, &sd->pdata, &conn);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_conn_req_connect");
		(void) rpma_conn_req_delete(&req);
		return NULL;
	}

	/* wait for the connection to be established */
	ret = rpma_conn_next_event(conn, &event);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_conn_next_event");
		goto err_conn_delete;
	}
	if (event != RPMA_CONN_ESTABLISHED) {
		log_err(
			"rpma_conn_next_event returned an unexptected event: (%s != RPMA_CONN_ESTABLISHED)\n",
			rpma_utils_conn_event_2str(event));
		goto err_conn_delete;
	}

	return conn;

err_conn_delete:
	(void) rpma_conn_disconnect(conn);
	(void) rpma_conn_delete(&conn);

	return NULL;
}

static void server_conn_shutdown(struct thread_data *td, struct rpma_conn *conn)
{
	enum rpma_conn_event event = RPMA_CONN_UNDEFINED;
	int ret;

	/* wait for the connection to be closed */
	ret = rpma_conn_next_event(conn, &event);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_conn_next_event");
		goto conn_delete;
	}
	if (event != RPMA_CONN_CLOSED) {
		log_err(
			"rpma_conn_next_event returned an unexptected event: (%s != RPMA_CONN_CLOSED)\n",
			rpma_utils_conn_event_2str(event));
	}

conn_delete:
	(void) rpma_conn_disconnect(conn);
	(void) rpma_conn_delete(&conn);
}

static enum fio_q_status server_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	struct server_options *o = td->eo;
	struct rpma_conn **conns;
	int i;

	/* prepare space for connection objects */
	conns = calloc(o->num_conns, sizeof(struct rpma_conn *));
	if (conns == NULL) {
		td->terminate = true;
		return FIO_Q_COMPLETED;
	}

	/* establish all connections */
	for (i = 0; i < o->num_conns; ++i) {
		conns[i] = server_conn_establish(td);
		if (conns[i] == NULL) {
			td->terminate = true;
			break;
		}
	}

	/* close all connections */
	for (i = 0; i < o->num_conns && conns[i] != NULL; ++i) {
		server_conn_shutdown(td, conns[i]);
		conns[i] = NULL;
	}

	/* free space after connection objects */
	free(conns);

	/* if the thread didn't fail the job is done */
	if (!td->terminate)
		td->done = true;

	return FIO_Q_COMPLETED;
}

FIO_STATIC struct ioengine_ops ioengine_server = {
	.name			= "librpma_server",
	.version		= FIO_IOOPS_VERSION,
	.init			= server_init,
	.open_file		= server_open_file,
	.close_file		= server_close_file,
	.queue			= server_queue,
	.cleanup		= server_cleanup,
	/* XXX FIO_DISKLESSIO should be removed when pmem_map_file() will be added */
	.flags			= FIO_SYNCIO | FIO_NOEXTEND | FIO_FAKEIO |
				  FIO_NOSTATS | FIO_DISKLESSIO,
	.options		= fio_server_options,
	.option_struct_size	= sizeof(struct server_options),
};

/* register both engines */

static void fio_init fio_librpma_register(void)
{
	register_ioengine(&ioengine_client);
	register_ioengine(&ioengine_server);
}

static void fio_exit fio_librpma_unregister(void)
{
	unregister_ioengine(&ioengine_client);
	unregister_ioengine(&ioengine_server);
}
