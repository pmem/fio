/*
 * librpma_aof: librpma AOF engine (XXX)
 *
 * Copyright 2021, Intel Corporation
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

#include "librpma_fio.h"

#include <libpmem.h>

/* client side implementation */

struct client_data {
	/* the messaging buffer (sending and receiving) */
	char *io_us_msgs;

	/* resources for the messaging buffer */
	uint32_t msg_num;
	uint32_t msg_curr;
	struct rpma_mr_local *msg_mr;
};

static int client_init(struct thread_data *td)
{
	/* XXX */
	return 0;
}

static int client_post_init(struct thread_data *td)
{
	/* XXX */
	return 0;
}

static int client_get_file_size(struct thread_data *td,
		struct fio_file *f)
{
	/* XXX */
	return 0;
}

static enum fio_q_status client_queue(struct thread_data *td,
		struct io_u *io_u)
{
	/*
	 * XXX
	 * - queue_sync()
	 *    rpma_write()
	 *    rpma_send() # atomic write
	 *    rpma_recv()
	 *
	 * - queue()
	 *    - if (sync == 1)
	 *        return queue_sync()
	 *    - queued[] = io_u
	 */
	return FIO_Q_BUSY;
}

static int client_commit(struct thread_data *td)
{
	/*
	 * XXX
	 *    for io_u in queued[]:
	 *        rpma_write()
	 *        rpma_send() # atomic write
	 *
	 *    for:
	 *        rpma_recv()
	 */
	return 0;
}

static int client_getevents(struct thread_data *td, unsigned int min,
		unsigned int max, const struct timespec *t)
{
	/* XXX */
	return 0;
}

static struct io_u *client_event(struct thread_data *td, int event)
{
	/* XXX */
	return NULL;
}

static void client_cleanup(struct thread_data *td)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;
	struct client_data *cd;
	int ret;

	if (ccd == NULL)
		return;

	cd = ccd->client_data;
	if (cd == NULL) {
		librpma_fio_client_cleanup(td);
		return;
	}

	/*
	 * Make sure all SEND completions are collected ergo there are free
	 * slots in the SQ for the last SEND message.
	 *
	 * Note: If any operation will fail we still can send the termination
	 * notice.
	 */
	(void) librpma_fio_client_io_complete_all_sends(td);

	/* deregister the messaging buffer memory */
	if ((ret = rpma_mr_dereg(&cd->msg_mr)))
		librpma_td_verror(td, ret, "rpma_mr_dereg");

	free(ccd->client_data);

	librpma_fio_client_cleanup(td);
}

FIO_STATIC struct ioengine_ops ioengine_client = {
	.name			= "librpma_aof_client",
	.version		= FIO_IOOPS_VERSION,
	.init			= client_init,
	.post_init		= client_post_init,
	.get_file_size		= client_get_file_size,
	.open_file		= librpma_fio_file_nop,
	.queue			= client_queue,
	.commit			= client_commit,
	.getevents		= client_getevents,
	.event			= client_event,
	.errdetails		= librpma_fio_client_errdetails,
	.close_file		= librpma_fio_file_nop,
	.cleanup		= client_cleanup,
	.flags			= FIO_DISKLESSIO,
	.options		= librpma_fio_options,
	.option_struct_size	= sizeof(struct librpma_fio_options_values),
};

/* server side implementation */

struct server_data {
	int XXX;
};

static int server_init(struct thread_data *td)
{
	/* XXX */
	return 0;
}

static int server_post_init(struct thread_data *td)
{
	/* XXX */
	return 0;
}

static void server_cleanup(struct thread_data *td)
{
	/* XXX */
}

static int server_open_file(struct thread_data *td, struct fio_file *f)
{
	/* XXX */
	return 0;
}

static int server_close_file(struct thread_data *td, struct fio_file *f)
{
	/* XXX */
	return 0;
}

static enum fio_q_status server_queue(struct thread_data *td, struct io_u *io_u)
{
	/* XXX */
	return FIO_Q_BUSY;
}

FIO_STATIC struct ioengine_ops ioengine_server = {
	.name			= "librpma_aof_server",
	.version		= FIO_IOOPS_VERSION,
	.init			= server_init,
	.post_init		= server_post_init,
	.open_file		= server_open_file,
	.close_file		= server_close_file,
	.queue			= server_queue,
	.invalidate		= librpma_fio_file_nop,
	.cleanup		= server_cleanup,
	.flags			= FIO_SYNCIO,
	.options		= librpma_fio_options,
	.option_struct_size	= sizeof(struct librpma_fio_options_values),
};

/* register both engines */

static void fio_init fio_librpma_aof_register(void)
{
	register_ioengine(&ioengine_client);
	register_ioengine(&ioengine_server);
}

static void fio_exit fio_librpma_aof_unregister(void)
{
	unregister_ioengine(&ioengine_client);
	unregister_ioengine(&ioengine_server);
}
