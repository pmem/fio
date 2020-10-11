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

struct client_options {
	unsigned dummy;
};

static struct fio_option fio_client_options[] = {
	{
		.name	= NULL,
	},
};

/* client side implementation */

static int client_init(struct thread_data *td)
{
	return 0;
}

static int client_post_init(struct thread_data *td)
{
	return 0;
}

static void client_cleanup(struct thread_data *td)
{
}

static int client_setup(struct thread_data *td)
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

static int client_open_file(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static int client_close_file(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static enum fio_q_status client_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	return FIO_Q_BUSY;
}

static int client_commit(struct thread_data *td)
{
	return 0;
}

static int client_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, const struct timespec *t)
{
	return 0;
}

static struct io_u *client_event(struct thread_data *td, int event)
{
	return 0;
}

FIO_STATIC struct ioengine_ops ioengine_client = {
	.name			= "librpma_client",
	.version		= FIO_IOOPS_VERSION,
	.init			= client_init,
	.post_init		= client_post_init,
	.setup			= client_setup,
	.open_file		= client_open_file,
	.close_file		= client_close_file,
	.queue			= client_queue,
	.commit			= client_commit,
	.getevents		= client_getevents,
	.event			= client_event,
	.cleanup		= client_cleanup,
	/* XXX flags require consideration */
	.flags			= FIO_DISKLESSIO | FIO_UNIDIR | FIO_PIPEIO,
	.options		= fio_client_options,
	.option_struct_size	= sizeof(struct client_options),
};

/* server side implementation */

struct server_options {
	char *bindname;
	char *port;
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
		.def    = "8765",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA,
	},
	{
		.name	= NULL,
	},
};

struct server_data {
	struct rpma_peer *peer;
};

static int server_init(struct thread_data *td)
{
	struct server_options *o = td->eo;
	(void) o; /* XXX delete when o will be used */

	/*
	 * - allocate server's data
	 * - find ibv_context using o->bindname
	 * - create new peer and endpoint (o->bindname and o->port)
	 */

	return 0;
}

static void server_cleanup(struct thread_data *td)
{
	/*
	 * - shutdown ep
	 * - free peer
	 */
}

static int server_open_file(struct thread_data *td, struct fio_file *f)
{
	/*
	 * - pmem_map_file
	 * - rpma_mr_reg -> f->engine_data
	 */

	return 0;
}

static int server_close_file(struct thread_data *td, struct fio_file *f)
{
	/*
	 * - rpma_mr_dereg
	 * - pmem_unmap
	 */

	return 0;
}

static enum fio_q_status server_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	/*
	 * - XXX make sure it is called only once!
	 * - accept a single connection
	 * - wait for the connection to close and cleanup
	 */

	return FIO_Q_BUSY;
}

FIO_STATIC struct ioengine_ops ioengine_server = {
	.name			= "librpma_server",
	.version		= FIO_IOOPS_VERSION,
	.init			= server_init,
	.open_file		= server_open_file,
	.close_file		= server_close_file,
	.queue			= server_queue,
	.cleanup		= server_cleanup,
	.flags			= FIO_SYNCIO | FIO_NOEXTEND | FIO_FAKEIO |
				  FIO_NOSTATS,
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
