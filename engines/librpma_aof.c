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
	struct librpma_fio_client_data *ccd;
	struct client_data *cd;
	uint32_t write_num = 1;
	struct rpma_conn_cfg *cfg = NULL;
	int ret;

	/* allocate client's data */
	cd = calloc(1, sizeof(*cd));
	if (cd == NULL) {
		td_verror(td, errno, "calloc");
		return -1;
	}

	/* create a connection configuration object */
	if ((ret = rpma_conn_cfg_new(&cfg))) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_new");
		goto err_free_cd;
	}

	/*
	 * Calculate the required queue sizes where:
	 * - the send queue (SQ) has to be big enough to accommodate
	 *   all io_us (WRITEs) and all flush requests (SENDs)
	 * - the receive queue (RQ) has to be big enough to accommodate
	 *   all flush responses (RECVs)
	 * - the completion queue (CQ) has to be big enough to accommodate all
	 *   success and error completions (sq_size + rq_size)
	 */
	if ((ret = rpma_conn_cfg_set_sq_size(cfg, write_num + cd->msg_num))) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_set_sq_size");
		goto err_cfg_delete;
	}
	if ((ret = rpma_conn_cfg_set_rq_size(cfg, cd->msg_num))) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_set_rq_size");
		goto err_cfg_delete;
	}
	if ((ret = rpma_conn_cfg_set_cq_size(cfg, write_num + cd->msg_num * 2))) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_set_cq_size");
		goto err_cfg_delete;
	}

	if (librpma_fio_client_init(td, cfg))
		goto err_cfg_delete;

	ccd = td->io_ops_data;

	ccd->client_data = cd;

	return 0;

err_cfg_delete:
	(void) rpma_conn_cfg_delete(&cfg);

err_free_cd:
	free(cd);

	return -1;
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
	/* XXX */
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
