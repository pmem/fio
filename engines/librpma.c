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

	/* an RPMA connection to the server */
	struct rpma_conn *conn;

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
	 * - allocate server's data
	 * - allocate all in-memory queues
	 * - find ibv_context using o->hostname
	 * - create new peer
	 * - create a connection request (o->hostname, o->port) and connect it
	 */

	return 0;
}

static int client_post_init(struct thread_data *td)
{
	/*
	 * - rpma_mr_reg td->org_buffer
	 */

	return 0;
}

static void client_cleanup(struct thread_data *td)
{
	/*
	 * - rpma_mr_dereg
	 * - free peer
	 */
}

static int client_setup(struct thread_data *td)
{
	struct client_data *cd = td->io_ops_data;
	struct client_options *o = td->eo;
	int ret;

	/* no files are expected at this point */
	if (td->files_index > 0)
		return -1;

	/* create a connection request */
	struct rpma_conn_req *req;
	if ((ret = rpma_conn_req_new(cd->peer, o->hostname, o->port, NULL,
			&req)))
		return ret;

	/* initiate establishing the connection */
	if ((ret = rpma_conn_req_connect(&req, NULL, &cd->conn))) {
		(void) rpma_conn_req_delete(&req);
		return ret;
	}

	/* wait for the connection to finalize the establishment */
	enum rpma_conn_event ev;
	if ((ret = rpma_conn_next_event(cd->conn, &ev)))
		goto err_conn_disconnect;

	/* if any other event happened instead */
	if (ev != RPMA_CONN_ESTABLISHED) {
		goto err_conn_disconnect;
	}

	/* get connections private data send from the server */
	struct rpma_conn_private_data pdata;
	if ((ret = rpma_conn_get_private_data(cd->conn, &pdata)))
		goto err_conn_disconnect;

	/* create server's memory representation */
	struct example_common_data *data = pdata.ptr;
	struct rpma_mr_remote *file_mr;
	if ((ret = rpma_mr_remote_from_descriptor(&data->descriptors[0],
			data->mr_desc_size, &file_mr)))
		goto err_conn_disconnect;

	/* add a server's memory FIO file */
	if (add_file(td, "server", 0, 0) != 1)
		goto err_file_mr_delete;

	/* attach RPMA memory representation to the FIO file */
	struct fio_file *f = td->files[0];
	f->engine_data = file_mr;

	/*
	 * FIO says:
	 * The setup() hook has to find out physical size of files or devices
	 * for this thread, before we determine I/O size and range of our
	 * targets. It is responsible for opening the files and setting
	 * f->real_file_size to indicate the valid range for that file.
	 */
	if ((ret = rpma_mr_remote_get_size(file_mr, &f->real_file_size)))
		goto err_file_mr_delete;

	return 0;

err_file_mr_delete:
	(void) rpma_mr_remote_delete(&file_mr);
err_conn_disconnect:
	(void) rpma_conn_disconnect(cd->conn);
	(void) rpma_conn_next_event(cd->conn, &ev);
	(void) rpma_conn_delete(&cd->conn);

	return ret;
}

static int client_open_file(struct thread_data *td, struct fio_file *f)
{
	/*
	 * This function does nothing because to be able to provide
	 * f->real_file_size the librpma engine has to add an artificial
	 * file and set it up in the engine specific way anyway.
	 * So at this point, the file is ready.
	 */

	return 0;
}

static int client_close_file(struct thread_data *td, struct fio_file *f)
{
	struct rpma_mr_remote *file_mr = f->engine_data;
	int ret;

	/* delete the server's remote memory representation */
	f->engine_data = NULL;
	if ((ret = rpma_mr_remote_delete(&file_mr)))
		return ret;

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
