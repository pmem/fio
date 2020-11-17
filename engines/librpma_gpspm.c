/*
 * librpma_gpspm: IO engine that uses PMDK librpma to read and write data,
 *                it is a variant of librpma engine in GPSPM mode
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

/* Generated by the protocol buffer compiler from: librpma_gpspm_flush.proto */
#include "librpma_gpspm_flush.pb-c.h"

#define rpma_td_verror(td, err, func) \
	td_vmsg((td), (err), rpma_err_2str(err), (func))

#define IO_U_BUF_LEN (1024)

/* client's and server's common */

/*
 * Limited by the maximum length of the private data
 * for rdma_connect() in case of RDMA_PS_TCP (56 bytes).
 */
#define DESCRIPTORS_MAX_SIZE 24

/* XXX a private data structure borrowed from RPMA examples */
struct example_common_data {
	uint16_t data_offset;	/* user data offset */
	uint8_t mr_desc_size;	/* size of mr_desc in descriptors[] */
	uint8_t pcfg_desc_size;	/* size of pcfg_desc in descriptors[] */
	/* buffer containing mr_desc and pcfg_desc */
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
		.group	= FIO_OPT_G_LIBRPMA_GPSPM,
	},
	{
		.name	= "port",
		.lname	= "rpma_client port",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct client_options, port),
		.help	= "port the server is listening on",
		.def    = "7204",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA_GPSPM,
	},
	{
		.name	= NULL,
	},
};

struct client_data {
	struct rpma_peer *peer;
	struct rpma_conn *conn;

	/* a server's memory representation */
	struct rpma_mr_remote *server_mr;

	/* aligned td->orig_buffer */
	char *orig_buffer_aligned;

	/* ious's base address memory registration (cd->orig_buffer_aligned) */
	struct rpma_mr_local *orig_mr;

	/* memory for sending and reciving buffered */
	char *io_us_msgs;

	/* resources for messaging buffer */
	struct rpma_mr_local *msg_mr;

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
	enum rpma_conn_event event;
	uint32_t cq_size;
	struct rpma_conn_private_data pdata;
	struct example_common_data *data;
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

	/*
	 * The recv queue has to be big enough
	 * to accommodate one completion for each batch.
	 */
	ret = rpma_conn_cfg_set_rq_size(cfg, cq_size);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_conn_cfg_set_rq_size");
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
		ret = -1;
		log_err(
			"rpma_conn_next_event returned an unexptected event: (%s != RPMA_CONN_ESTABLISHED)\n",
			rpma_utils_conn_event_2str(event));
		goto err_conn_delete;
	}

	/* get the connection's private data sent from the server */
	if ((ret = rpma_conn_get_private_data(cd->conn, &pdata)))
		goto err_conn_delete;

	/* create the server's memory representation */
	data = pdata.ptr;
	if ((ret = rpma_mr_remote_from_descriptor(&data->descriptors[0],
			data->mr_desc_size, &cd->server_mr)))
		goto err_conn_delete;

	td->io_ops_data = cd;

	return 0;

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
	unsigned int io_us_msgs_size;
	int ret;

	/* message buffers registration */
	/* ceil(td->o.iodepth / td->o.iodepth_batch) * IO_U_BUF_LEN */
	io_us_msgs_size = ((td->o.iodepth + td->o.iodepth_batch - 1) / td->o.iodepth_batch) * IO_U_BUF_LEN;

	if ((ret = posix_memalign((void **)&cd->io_us_msgs,
			page_mask, io_us_msgs_size))) {
		td_verror(td, ret, "posix_memalign");
		return ret;
	}

	if ((ret = rpma_mr_reg(cd->peer, cd->io_us_msgs, io_us_msgs_size,
			RPMA_MR_USAGE_SEND | RPMA_MR_USAGE_RECV,
			&cd->msg_mr))) {
		rpma_td_verror(td, ret, "rpma_mr_reg");
		return ret;
	}

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
			RPMA_MR_USAGE_WRITE_DST | RPMA_MR_USAGE_WRITE_SRC,
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

	/* deregister the iou's memory */
	if ((ret = rpma_mr_dereg(&cd->orig_mr)))
		rpma_td_verror(td, ret, "rpma_mr_dereg");

	/* deregister the messaging buffer memory */
	if ((ret = rpma_mr_dereg(&cd->msg_mr)))
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

	/* free message buffers */
	free(cd->io_us_msgs);

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
	int ret;

	f = td->files[0];
	if ((ret = rpma_mr_remote_get_size(cd->server_mr, &f->real_file_size)))
		rpma_td_verror(td, ret, "rpma_mr_remote_get_size");

	fio_file_set_size_known(f);

	return ret;
}

static int client_open_file(struct thread_data *td, struct fio_file *f)
{
	/* XXX */
	return 0;
}

static int client_close_file(struct thread_data *td, struct fio_file *f)
{
	/* XXX */
	return 0;
}

static enum fio_q_status client_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	struct client_data *cd = td->io_ops_data;

	if (cd->io_u_queued_nr == (int)td->o.iodepth)
		return FIO_Q_BUSY;

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
	GPSPMFlushRequest flush_req = GPSPM_FLUSH_REQUEST__INIT;
	size_t flush_req_size = 0;
	size_t max_msg_size;
	size_t send_offset;
	size_t recv_offset;
	void *send_ptr;

	if (!cd->io_us_queued)
		return -1;

	/* execute all io_us from queued[] */
	for (i = 0; i < cd->io_u_queued_nr; i++) {
		struct io_u *io_u = cd->io_us_queued[i];

		max_msg_size = io_u->xfer_buflen / 2;
		send_offset = 0;
		recv_offset = max_msg_size;
		send_ptr = (char *)io_u->xfer_buf + send_offset;

		if (i == cd->io_u_queued_nr - 1)
			flags = RPMA_F_COMPLETION_ALWAYS;

		if (io_u->ddir == DDIR_WRITE) {
			/* post an RDMA write operation */
			size_t dst_offset = (char *)(io_u->xfer_buf) - td->orig_buffer;
			size_t src_offset = io_u->offset;
			ret = rpma_write(cd->conn,
					cd->server_mr, dst_offset,
					cd->orig_mr, src_offset,
					io_u->xfer_buflen,
					flags,
					(void *)(uintptr_t)io_u->index);
			if (ret) {
				rpma_td_verror(td, ret, "rpma_write");
				return -1;
			}

			/* prepare a response buffer */
			ret = rpma_recv(cd->conn,
					cd->msg_mr, recv_offset,
					max_msg_size,
					(void *)(uintptr_t)io_u->index);
			if (ret) {
				rpma_td_verror(td, ret, "rpma_read");
				return -1;
			}
			/* prepare a flush message and pack it to a send buffer */
			flush_req.offset = send_offset;
			flush_req.length = 0;
			flush_req.op_context = io_u->index;
			flush_req_size = gpspm_flush_request__get_packed_size(&flush_req);
			if (flush_req_size > max_msg_size) {
				log_err(
					"Packed flush request size is bigger than available send buffer space (%"
					PRIu64 " > %"PRIu64 "\n", flush_req_size,
					max_msg_size);
				return -1;
			}
			(void) gpspm_flush_request__pack(&flush_req, send_ptr);

			/* send the flush message */
			if ((ret = rpma_send(cd->conn, cd->msg_mr, send_offset, flush_req_size,
				RPMA_F_COMPLETION_ON_ERROR, NULL)))
				rpma_td_verror(td, ret, "rpma_send");
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
	.name			= "librpma_gpspm_client",
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
		.group	= FIO_OPT_G_LIBRPMA_GPSPM,
	},
	{
		.name	= "port",
		.lname	= "rpma_server port",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct server_options, port),
		.help	= "port to listen on for incoming connections",
		.def    = "7204",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA_GPSPM,
	},
	{
		.name	= "num_conns",
		.lname	= "Number of connections",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct server_options, num_conns),
		.help	= "Number of connections to server",
		.minval = 1,
		.def	= "1",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA_GPSPM,
	},
	{
		.name	= NULL,
	},
};

struct server_data {
	struct rpma_peer *peer;

	/* aligned td->orig_buffer */
	char *orig_buffer_aligned;

	/* resources of an incoming connection */
	struct rpma_conn *conn;

	/* memory mapped from a file */
	void *mmap_ptr;
	/* size of the mapped memory from a file */
	size_t mmap_size;
	struct rpma_mr_local *mmap_mr;

	/* resources for messaging buffer from DRAM allocated by fio */
	struct rpma_mr_local *msg_mr;
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

	/* obtain an IBV context for a local IP address */
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

	td->io_ops_data = sd;

	return 0;

err_free_sd:
	free(sd);

	return ret;
}

static int server_post_init(struct thread_data *td)
{
	struct server_data *sd = td->io_ops_data;
	size_t io_us_size;
	size_t io_u_buflen;
	int ret;

	/*
	 * td->orig_buffer is not aligned. The engine requires aligned io_us
	 * so FIO alignes up the address using the formula below.
	 */
	sd->orig_buffer_aligned = PTR_ALIGN(td->orig_buffer, page_mask) +
			td->o.mem_align;

	/*
	 * XXX
	 * Each io_u message buffer contains recv and send messages.
	 * Aligning each of those buffers may potentially give some performance benefits.
	 */
	io_u_buflen = td_max_bs(td);

	/*
	 * td->orig_buffer_size beside the space really consumed by io_us
	 * has paddings which can be omitted for the memory registration.
	 */
	io_us_size = (unsigned long long)io_u_buflen *
			(unsigned long long)td->o.iodepth;

	ret = rpma_mr_reg(sd->peer, sd->orig_buffer_aligned, io_us_size,
			RPMA_MR_USAGE_SEND | RPMA_MR_USAGE_RECV,
			&sd->msg_mr);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_mr_reg");
		return 1;
	}

	return 0;
}

static void server_cleanup(struct thread_data *td)
{
	struct server_data *sd =  td->io_ops_data;
	int ret;

	if (sd == NULL)
		return;

	/* rpma_mr_dereg(messaging buffer from DRAM) */
	if ((ret = rpma_mr_dereg(&sd->msg_mr)))
		rpma_td_verror(td, ret, "rpma_mr_dereg");

	/* free the peer */
	if ((ret = rpma_peer_delete(&sd->peer)))
		rpma_td_verror(td, ret, "rpma_peer_delete");

	free(sd);
}

static int server_open_file(struct thread_data *td, struct fio_file *f)
{
	struct server_data *sd =  td->io_ops_data;
	struct server_options *o = td->eo;
	enum rpma_conn_event conn_event = RPMA_CONN_UNDEFINED;
	struct rpma_conn_private_data pdata;
	struct rpma_mr_local *mmap_mr;
	struct example_common_data data;
	struct rpma_conn_req *conn_req;
	struct rpma_conn *conn;
	struct rpma_ep *ep;
	size_t mr_desc_size;
	size_t mmap_size = 0;
	size_t size_recv_msg;
	void *mmap_ptr;
	int mmap_is_pmem;
	int ret;
	int i;

	if (!f->file_name) {
		log_err("fio: filename is not set\n");
		return 1;
	}

	/* map the file */
	mmap_ptr = pmem_map_file(f->file_name, 0 /* len */, 0 /* flags */,
			0 /* mode */, &mmap_size, &mmap_is_pmem);
	if (mmap_ptr == NULL) {
		log_err("fio: pmem_map_file(%s) failed\n", f->file_name);
		/* pmem_map_file() sets errno on failure */
		td_verror(td, errno, "pmem_map_file");
		return 1;
	}

	if (!mmap_is_pmem)
		log_info("fio: %s is not located in persistent memory\n",
			f->file_name);

	log_info("fio: size of memory mapped from the file %s: %zu\n",
		f->file_name, mmap_size);

	ret = rpma_mr_reg(sd->peer, mmap_ptr, mmap_size,
			RPMA_MR_USAGE_READ_DST | RPMA_MR_USAGE_READ_SRC |
			RPMA_MR_USAGE_WRITE_DST | RPMA_MR_USAGE_WRITE_SRC,
			&mmap_mr);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_mr_reg");
		goto err_pmem_unmap;
	}

	/* get size of the memory region's descriptor */
	ret = rpma_mr_get_descriptor_size(mmap_mr, &mr_desc_size);
	if (ret)
		goto err_mr_dereg;

	/* get the memory region's descriptor */
	if ((ret = rpma_mr_get_descriptor(mmap_mr, &data.descriptors[0])))
		goto err_mr_dereg;

	/* calculate data for the server read */
	data.mr_desc_size = mr_desc_size;
	data.data_offset = 0;
	pdata.ptr = &data;
	pdata.len = sizeof(struct example_common_data);

	/* start a listening endpoint at addr:port */
	ret = rpma_ep_listen(sd->peer, o->bindname, o->port, &ep);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_ep_listen");
		goto err_mr_dereg;
	}

	/* receive an incoming connection request */
	if ((ret = rpma_ep_next_conn_req(ep, NULL, &conn_req)))
		goto err_ep_shutdown;

	/* prepare buffers for a flush requests */
	size_recv_msg = td_max_bs(td) / 2;
	for (i = 0; i < td->o.iodepth; i++)
		if ((ret = rpma_conn_req_recv(conn_req, sd->msg_mr,
				(2 * i + 1) * size_recv_msg,
				size_recv_msg, NULL)))
			goto err_req_delete;

	/* accept the connection request and obtain the connection object */
	if ((ret = rpma_conn_req_connect(&conn_req, &pdata, &conn)))
		goto err_conn_delete;

	/* wait for the connection to be established */
	ret = rpma_conn_next_event(conn, &conn_event);
	if (ret)
		rpma_td_verror(td, ret, "rpma_conn_next_event");
	if (!ret && conn_event != RPMA_CONN_ESTABLISHED) {
		log_err("rpma_conn_next_event returned an unexptected event\n");
		ret = 1;
	}
	if (ret)
		goto err_conn_delete;

	/* end-point is no longer needed */
	(void) rpma_ep_shutdown(&ep);

	sd->mmap_mr = mmap_mr;
	sd->mmap_ptr = mmap_ptr;
	sd->mmap_size = mmap_size;
	sd->conn = conn;

	return 0;

err_conn_delete:
	(void) rpma_conn_delete(&conn);

err_req_delete:
	(void) rpma_conn_req_delete(&conn_req);

err_ep_shutdown:
	(void) rpma_ep_shutdown(&ep);

err_mr_dereg:
	(void) rpma_mr_dereg(&mmap_mr);

err_pmem_unmap:
	(void) pmem_unmap(mmap_ptr, mmap_size);

	return ret;
}

static int server_close_file(struct thread_data *td, struct fio_file *f)
{
	struct server_data *sd =  td->io_ops_data;
	enum rpma_conn_event conn_event = RPMA_CONN_UNDEFINED;
	int ret;
	int rv;

	/* wait for the connection to be closed */
	ret = rpma_conn_next_event(sd->conn, &conn_event);
	if (!ret && conn_event != RPMA_CONN_CLOSED) {
		log_err("rpma_conn_next_event returned an unexptected event\n");
		rv = 1;
	}

	if ((ret = rpma_conn_disconnect(sd->conn))) {
		rpma_td_verror(td, ret, "rpma_conn_disconnect");
		rv |= ret;
	}

	if ((ret = rpma_conn_delete(&sd->conn))) {
		rpma_td_verror(td, ret, "rpma_conn_delete");
		rv |= ret;
	}

	if ((ret = rpma_mr_dereg(&sd->mmap_mr))) {
		rpma_td_verror(td, ret, "rpma_mr_dereg");
		rv |= ret;
	}

	if (pmem_unmap(sd->mmap_ptr, sd->mmap_size)) {
		td_verror(td, errno, "pmem_unmap");
		rv |= errno;
	}

	return rv ? -1 : 0;
}

static enum fio_q_status server_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	struct server_data *sd =  td->io_ops_data;
	struct rpma_completion cmpl;
	GPSPMFlushRequest *flush_req;
	GPSPMFlushResponse flush_resp = GPSPM_FLUSH_RESPONSE__INIT;
	size_t flush_resp_size = 0;
	size_t max_msg_size;
	size_t send_offset;
	size_t recv_offset;
	void *send_ptr;
	void *recv_ptr;
	void *op_ptr;
	int ret;

	/*
	 * XXX
	 * The server handles only one io_us for now (it should handle multiple io_us).
	 * It is a temporary solution, we expect to change it in the future.
	 * A new message can be defined that will be sent when the client is done,
	 * so the server will transition to the cleanup stage.
	 */

	max_msg_size = io_u->xfer_buflen / 2;
	send_offset = 0;
	recv_offset = max_msg_size;
	send_ptr = (char *)io_u->xfer_buf + send_offset;
	recv_ptr = (char *)io_u->xfer_buf + recv_offset;

	/* wait for the completion to be ready */
	if ((ret = rpma_conn_completion_wait(sd->conn)))
		goto err_terminate;
	if ((ret = rpma_conn_completion_get(sd->conn, &cmpl)))
		goto err_terminate;

	/* unpack a flush request from the received buffer */
	flush_req = gpspm_flush_request__unpack(NULL, cmpl.byte_len, recv_ptr);
	if (flush_req == NULL) {
		log_err("cannot unpack the flush request buffer\n");
		goto err_terminate;
	}

	op_ptr = (char *)sd->mmap_ptr + flush_req->offset;
	pmem_persist(op_ptr, flush_req->length);

	/* prepare a flush response and pack it to a send buffer */
	flush_resp.op_context = flush_req->op_context;
	flush_resp_size = gpspm_flush_response__get_packed_size(&flush_resp);
	if (flush_resp_size > max_msg_size) {
		log_err("Size of the packed flush response is bigger than the available space of the send buffer (%"
			PRIu64 " > %zu\n", flush_resp_size, max_msg_size);
		goto err_terminate;
	}

	(void) gpspm_flush_response__pack(&flush_resp, send_ptr);
	gpspm_flush_request__free_unpacked(flush_req, NULL);

	/* send the flush response */
	if ((ret = rpma_send(sd->conn, sd->msg_mr, send_offset, flush_resp_size,
			RPMA_F_COMPLETION_ALWAYS, NULL)))
		goto err_terminate;

	/* wait for the completion to be ready */
	if ((ret = rpma_conn_completion_wait(sd->conn)))
		goto err_terminate;
	if ((ret = rpma_conn_completion_get(sd->conn, &cmpl)))
		goto err_terminate;

	/* validate the completion */
	if (cmpl.op_status != IBV_WC_SUCCESS)
		goto err_terminate;
	if (cmpl.op != RPMA_OP_SEND) {
		log_err("unexpected cmpl.op value (0x%" PRIXPTR " != 0x%" PRIXPTR ")\n",
			(uintptr_t)cmpl.op, (uintptr_t)RPMA_OP_SEND);
		goto err_terminate;
	}

	td->done = true;

	return FIO_Q_COMPLETED;

err_terminate:
	td->terminate = true;

	return FIO_Q_COMPLETED;
}

static int server_invalidate(struct thread_data *td, struct fio_file *file)
{
	/* NOP */
	return 0;
}

FIO_STATIC struct ioengine_ops ioengine_server = {
	.name			= "librpma_gpspm_server",
	.version		= FIO_IOOPS_VERSION,
	.init			= server_init,
	.post_init		= server_post_init,
	.open_file		= server_open_file,
	.close_file		= server_close_file,
	.queue			= server_queue,
	.invalidate		= server_invalidate,
	.cleanup		= server_cleanup,
	.flags			= FIO_SYNCIO | FIO_NOEXTEND | FIO_FAKEIO |
				  FIO_NOSTATS,
	.options		= fio_server_options,
	.option_struct_size	= sizeof(struct server_options),
};

/* register both engines */

static void fio_init fio_librpma_gpspm_register(void)
{
	register_ioengine(&ioengine_client);
	register_ioengine(&ioengine_server);
}

static void fio_exit fio_librpma_gpspm_unregister(void)
{
	unregister_ioengine(&ioengine_client);
	unregister_ioengine(&ioengine_server);
}
