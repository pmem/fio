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

#include <librpma.h>

#define rpma_td_verror(td, err, func) \
	td_vmsg((td), (err), rpma_err_2str(err), (func))

/* client's and server's common */

/* XXX a private data structure borrowed from RPMA examples */
#define DESCRIPTORS_MAX_SIZE 24
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

	/* ious's base address memory registration (td->orig_buffer) */
	struct rpma_mr_local *orig_mr;

	/* a server's memory representation */
	struct rpma_mr_remote *server_mr;

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
	struct rpma_conn_req *req = NULL;
	enum rpma_conn_event event;
	struct rpma_conn_private_data pdata;
	struct example_common_data *data;
	int ret = 1;

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

	/* create a new peer object */
	ret = rpma_peer_new(dev, &cd->peer);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_peer_new");
		goto err_free_io_us_completed;
	}

	/* create a connection request */
	ret = rpma_conn_req_new(cd->peer, o->hostname, o->port, NULL, &req);
	if (ret) {
		rpma_td_verror(td, ret, "rpma_conn_req_new");
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
			"rpma_conn_next_event returned an unexptected event: %s\n",
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
	int ret;

	if ((ret = rpma_mr_reg(cd->peer, td->orig_buffer, td->orig_buffer_size,
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

static int client_setup(struct thread_data *td)
{
	struct client_data *cd = td->io_ops_data;

	/*
	 * FIO says:
	 * The setup() hook has to find out physical size of files or devices
	 * for this thread, before we determine I/O size and range of our
	 * targets. It is responsible for opening the files and setting
	 * f->real_file_size to indicate the valid range for that file.
	 */
	struct fio_file *f = td->files[0];
	int ret;
	if ((ret = rpma_mr_remote_get_size(cd->server_mr, &f->real_file_size)))
		rpma_td_verror(td, ret, "rpma_mr_remote_get_size");

	return ret;
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

/*
 * XXX current implementation ignores provided min and max
 */
static int client_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, const struct timespec *t)
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

	/* wait for a completion */
	if ((ret = rpma_conn_completion_wait(cd->conn))) {
		rpma_td_verror(td, ret, "rpma_conn_completion_wait");
		return -1;
	}

	/* get the completion */
	if ((ret = rpma_conn_completion_get(cd->conn, &cmpl))) {
		rpma_td_verror(td, ret, "rpma_conn_completion_get");
		return -1;
	}

	/* if io_us have completed with error */
	if (cmpl.op_status != IBV_WC_SUCCESS)
		io_us_error = cmpl.op_status;

	/* lookup an io_u being completed */
	memcpy(&io_u_index, &cmpl.op_context, sizeof(unsigned int));
	for (i = 0; i < cd->io_u_flight_nr; ++i) {
		if (cd->io_us_flight[i]->index == io_u_index) {
			cmpl_num = i + 1;
			break;
		}
	}

	/* if no matching io_u have been found */
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

FIO_STATIC struct ioengine_ops ioengine_client = {
	.name			= "librpma_client",
	.version		= FIO_IOOPS_VERSION,
	.init			= client_init,
	.post_init		= client_post_init,
	.setup			= client_setup,
	.open_file		= client_open_file,
	.queue			= client_queue,
	.commit			= client_commit,
	.getevents		= client_getevents,
	.event			= client_event,
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
	int dummy;
};

static struct fio_option fio_server_options[] = {
	{
		.name	= NULL,
	},
};

static int server_init(struct thread_data *td)
{
	return 0;
}

static int server_post_init(struct thread_data *td)
{
	return 0;
}

static void server_cleanup(struct thread_data *td)
{
}

static int server_setup(struct thread_data *td)
{
	/*
	 * FIO says:
	 * The setup() hook has to find out physical size of files or devices
	 * for this thread, before we determine I/O size and range of our
	 * targets. It is responsible for opening the files and setting
	 * f->real_file_size to indicate the valid range for that file.
	 */

	return 0;
}

static int server_open_file(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static int server_close_file(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static enum fio_q_status server_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	return FIO_Q_BUSY;
}

static int server_commit(struct thread_data *td)
{
	return 0;
}

static int server_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, const struct timespec *t)
{
	return 0;
}

static struct io_u *server_event(struct thread_data *td, int event)
{
	return 0;
}

FIO_STATIC struct ioengine_ops ioengine_server = {
	.name			= "librpma_server",
	.version		= FIO_IOOPS_VERSION,
	.init			= server_init,
	.post_init		= server_post_init,
	.setup			= server_setup,
	.open_file		= server_open_file,
	.close_file		= server_close_file,
	.queue			= server_queue,
	.commit			= server_commit,
	.getevents		= server_getevents,
	.event			= server_event,
	.cleanup		= server_cleanup,
	/* XXX flags require consideration */
	.flags			= FIO_DISKLESSIO | FIO_UNIDIR | FIO_PIPEIO,
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
