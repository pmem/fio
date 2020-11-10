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

/* client's and server's common */

/*
 * Limited by the maximum length of the private data
 * for rdma_connect() in case of RDMA_PS_TCP (56 bytes).
 */
#define DESCRIPTORS_MAX_SIZE 24

struct common_data {
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
	struct server_options *o = td->eo;
	(void) o; /* XXX delete when o will be used */

	/*
	 * - configure logging thresholds
	 * - allocate client's data
	 * - allocate all in-memory queues
	 * - find ibv_context using o->hostname
	 * - create new peer
	 * - create a connection request (o->hostname, o->port) and connect it
	 * - get memory region from server
	 */
	return 0;
}

static int client_post_init(struct thread_data *td)
{
	/*
	 * - register the buffers for rpma_send()
	 */
	return 0;
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
	struct rpma_ep *ep;

	/* aligned td->orig_buffer */
	char *orig_buffer_aligned;

	/* resources of an incoming connection */
	struct rpma_conn_req *conn_req;
	struct rpma_conn *conn;

	/* memory mapped from a file */
	void *mmap_ptr;
	/* size of the mapped memory from a file */
	size_t mmap_size;
	/* memory mapped from a file is persistent */
	int mmap_is_pmem;
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

	/* start a listening endpoint at addr:port */
	ret = rpma_ep_listen(sd->peer, o->bindname, o->port, &sd->ep);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_ep_listen");
		goto err_peer_delete;
	}

	td->io_ops_data = sd;

	return 0;

err_peer_delete:
	(void) rpma_peer_delete(&sd->peer);

err_free_sd:
	free(sd);

	return ret;
}

static int server_post_init(struct thread_data *td)
{
	struct server_data *sd =  td->io_ops_data;
	size_t io_us_size;
	int ret;
	int i;

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
			RPMA_MR_USAGE_SEND | RPMA_MR_USAGE_RECV |
			RPMA_MR_USAGE_FLUSH_TYPE_VISIBILITY,
			&sd->msg_mr);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_mr_reg");
		return 1;
	}

	/* receive an incoming connection request */
	if ((ret = rpma_ep_next_conn_req(sd->ep, NULL, &sd->conn_req)))
		goto err_mr_dereg;

	/* prepare buffers for a flush requests */
	for (i = 0; i < td->o.iodepth; i++)
		if ((ret = rpma_conn_req_recv(sd->conn_req, sd->msg_mr,
				i * td_max_bs(td), td_max_bs(td), NULL)))
			goto err_req_delete;

	return 0;

err_req_delete:
	if (sd->conn_req)
		(void) rpma_conn_req_delete(&sd->conn_req);

err_mr_dereg:
	(void) rpma_mr_dereg(&sd->msg_mr);

	return ret;
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
	enum rpma_conn_event conn_event = RPMA_CONN_UNDEFINED;
	struct rpma_conn_private_data pdata;
	struct rpma_mr_local *mmap_mr;
	struct common_data data;
	struct rpma_conn *conn;
	size_t mr_desc_size;
	size_t mmap_size = 0;
	void *mmap_ptr;
	int mmap_is_pmem;
	int ret;

	if (!td->o.mmapfile) {
		log_err("fio: mmapfile is not set\n");
		return 1;
	}

	/* map the file */
	mmap_ptr = pmem_map_file(td->o.mmapfile, 0 /* len */, 0 /* flags */,
			0 /* mode */, &mmap_size, &mmap_is_pmem);
	if (mmap_ptr == NULL) {
		log_err("fio: pmem_map_file(%s) failed\n", td->o.mmapfile);
		/* pmem_map_file() sets errno on failure */
		td_verror(td, errno, "pmem_map_file");
		return 1;
	}

	if (!mmap_is_pmem)
		log_info("fio: %s is not located in persistent memory\n",
			td->o.mmapfile);

	log_info("fio: size of memory mapped from the file %s: %zu\n",
		td->o.mmapfile, mmap_size);

	ret = rpma_mr_reg(sd->peer, mmap_ptr, mmap_size,
			RPMA_MR_USAGE_READ_DST | RPMA_MR_USAGE_READ_SRC |
			RPMA_MR_USAGE_WRITE_DST | RPMA_MR_USAGE_WRITE_SRC |
			(mmap_is_pmem ? RPMA_MR_USAGE_FLUSH_TYPE_PERSISTENT :
				RPMA_MR_USAGE_FLUSH_TYPE_VISIBILITY),
			&mmap_mr);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_mr_reg");
		goto err_pmem_unmap;
	}

	/* get size of the memory region's descriptor */
	ret = rpma_mr_get_descriptor_size(mmap_mr, &mr_desc_size);
	if (ret)
		goto err_mr_dereg;

	/* calculate data for the server read */
	data.mr_desc_size = mr_desc_size;
	data.data_offset = 0;

	/* get the memory region's descriptor */
	if ((ret = rpma_mr_get_descriptor(mmap_mr, &data.descriptors[0])))
		goto err_mr_dereg;

	/*
	 * Wait for an incoming connection request, accept it and wait for its
	 * establishment.
	 */
	pdata.ptr = &data;
	pdata.len = sizeof(struct common_data);

	/* accept the connection request and obtain the connection object */
	if ((ret = rpma_conn_req_connect(&sd->conn_req, &pdata, &conn)))
		goto err_mr_dereg;

	/* wait for the connection to be established */
	ret = rpma_conn_next_event(sd->conn, &conn_event);
	if (!ret && conn_event != RPMA_CONN_ESTABLISHED) {
		log_err("rpma_conn_next_event returned an unexptected event\n");
		ret = 1;
	}
	if (ret)
		goto err_conn_delete;

	sd->mmap_mr = mmap_mr;
	sd->mmap_ptr = mmap_ptr;
	sd->mmap_size = mmap_size;
	sd->mmap_is_pmem = mmap_is_pmem;
	sd->conn = conn;

	return 0;

err_conn_delete:
	sd->conn_req = NULL; /* do not call rpma_conn_req_delete() */
	(void) rpma_conn_delete(&conn);

err_mr_dereg:
	(void) rpma_mr_dereg(&mmap_mr);

err_pmem_unmap:
	(void) pmem_unmap(mmap_ptr, mmap_size);

	if (sd->conn_req)
		(void) rpma_conn_req_delete(&sd->conn_req);

	return ret;
}

static int server_close_file(struct thread_data *td, struct fio_file *f)
{
	struct server_data *sd =  td->io_ops_data;
	int ret;

	if ((ret = rpma_mr_dereg(&sd->mmap_mr)))
		rpma_td_verror(td, ret, "rpma_mr_dereg");

	if (pmem_unmap(sd->mmap_ptr, sd->mmap_size))
		td_verror(td, errno, "pmem_unmap");

	if (sd->conn_req)
		(void) rpma_conn_req_delete(&sd->conn_req);

	return 0;
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
