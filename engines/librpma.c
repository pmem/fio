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

struct rpma_options {
	unsigned dummy;
};

static struct fio_option options[] = {
	{
		.name	= NULL,
	},
};

static int rpma_init(struct thread_data *td)
{
	return 0;
}

static int rpma_post_init(struct thread_data *td)
{
	return 0;
}

static void rpma_cleanup(struct thread_data *td)
{
}

static int rpma_setup(struct thread_data *td)
{
	return 0;
}

static int rpma_open_file(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static int rpma_close_file(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static enum fio_q_status rpma_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	return FIO_Q_BUSY;
}

static int rpma_commit(struct thread_data *td)
{
	return ret;
}

static int rpma_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, const struct timespec *t)
{
	return 0;
}

static struct io_u *rpma_event(struct thread_data *td, int event)
{
	return 0;
}

FIO_STATIC struct ioengine_ops ioengine_client = {
	.name			= "librpma_client",
	.version		= FIO_IOOPS_VERSION,
	.init			= rpma_init,
	.post_init		= rpma_post_init,
	.setup			= rpma_setup,
	.open_file		= rpma_open_file,
	.close_file		= rpma_close_file,
	.queue			= rpma_queue,
	.commit			= rpma_commit,
	.getevents		= rpma_getevents,
	.event			= rpma_event,
	.cleanup		= rpma_cleanup,
	/* XXX flags require consideration */
	.flags			= FIO_DISKLESSIO | FIO_UNIDIR | FIO_PIPEIO,
	.options		= options,
	.option_struct_size	= sizeof(struct rpma_options),
};

FIO_STATIC struct ioengine_ops ioengine_server = {
	.name			= "librpma_server",
	.version		= FIO_IOOPS_VERSION,
	.init			= rpma_init,
	.post_init		= rpma_post_init,
	.setup			= rpma_setup,
	.open_file		= rpma_open_file,
	.close_file		= rpma_close_file,
	.queue			= rpma_queue,
	.commit			= rpma_commit,
	.getevents		= rpma_getevents,
	.event			= rpma_event,
	.cleanup		= rpma_cleanup,
	/* XXX flags require consideration */
	.flags			= FIO_DISKLESSIO | FIO_UNIDIR | FIO_PIPEIO,
	.options		= options,
	.option_struct_size	= sizeof(struct rpma_options),
};

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
