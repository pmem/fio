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

#define MSGS_SIZE (1024)

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
	io_us_msgs_size = 2 * td->o.iodepth/td->o.iodepth_batch * MSGS_SIZE;

	if ((ret = posix_memalign((void **)&cd->io_us_msgs,
			page_mask, io_us_msgs_size))) {
		rpma_td_verror(td, ret, "posix_memalign");
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
	/*
	 * - rpma_mr_dereg
	 * - rpma_conn_disconnect
	 * - free peer
	 */
}

static int client_get_file_size(struct thread_data *td, struct fio_file *f)
{
	/* XXX */
	return 0;
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
	/*
	 * - add io_u to queued[] array
	 */
	return FIO_Q_BUSY;
}

static int client_commit(struct thread_data *td)
{
	/*
	 * - execute all io_us from queued[]
	 * - move executed io_us to flight[]
	 */
	return 0;
}

static int client_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, const struct timespec *t)
{
	/*
	 * - wait for a completion
	 * - move completed io_us to completed[]
	 * - return # of io_us completed with collected completion
	 */
	return 0;
}

static struct io_u *client_event(struct thread_data *td, int event)
{
	/*
	 * - take io_us from completed[] (at the end it should be empty)
	 */
	return 0;
}

static char *client_errdetails(struct io_u *io_u)
{
	/* XXX */
	return 0;
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
	size_t msg_size;
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
	msg_size = td_max_bs(td);

	/*
	 * td->orig_buffer_size beside the space really consumed by io_us
	 * has paddings which can be omitted for the memory registration.
	 */
	io_us_size = (unsigned long long)msg_size *
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
	size_t msg_size;
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
	msg_size = td_max_bs(td);
	for (i = 0; i < td->o.iodepth; i++)
		if ((ret = rpma_conn_req_recv(conn_req, sd->msg_mr,
				i * msg_size, msg_size, NULL)))
			goto err_req_delete;

	/* accept the connection request and obtain the connection object */
	if ((ret = rpma_conn_req_connect(&conn_req, &pdata, &conn)))
		goto err_conn_delete;

	/* wait for the connection to be established */
	ret = rpma_conn_next_event(sd->conn, &conn_event);
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
	int ret1, ret2;
	int ret3 = 0;

	if ((ret1 = rpma_conn_delete(&sd->conn)))
		rpma_td_verror(td, ret1, "rpma_conn_delete");

	if ((ret2 = rpma_mr_dereg(&sd->mmap_mr)))
		rpma_td_verror(td, ret2, "rpma_mr_dereg");

	if (pmem_unmap(sd->mmap_ptr, sd->mmap_size)) {
		td_verror(td, errno, "pmem_unmap");
		ret3 = errno;
	}

	return (ret1 | ret2 | ret3) ? -1 : 0;
}

static enum fio_q_status server_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	/*
	 * - rpma_conn_completion_wait()
	 * - rpma_conn_completion_get()
	 * - pmem_persist(f, NULL);
	 * - rpma_recv() to prepare for next incoming receive
	 * - rpma_send(the response)
	 */
	return FIO_Q_BUSY;
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
