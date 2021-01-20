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

#include "librpma_common.h"

#include <librpma.h>

/* client side implementation */

struct client_data {
	enum rpma_flush_type flush_type;
};

static inline int client_io_flush(struct thread_data *td,
		struct io_u *first_io_u, struct io_u *last_io_u,
		unsigned long long int len);

static int client_get_io_u_index(struct rpma_completion *cmpl,
		unsigned int *io_u_index);

static int client_init(struct thread_data *td)
{
	struct librpma_common_client_data *ccd;
	struct client_data *cd;
	unsigned int sq_size;
	uint32_t cq_size;
	struct rpma_conn_cfg *cfg = NULL;
	int remote_flush_type;
	struct rpma_peer_cfg *pcfg = NULL;
	int ret;

	/* not supported readwrite = trim / randtrim / trimwrite */
	if (td_trim(td)) {
		log_err("Not supported mode.\n");
		return -1;
	}

	/* allocate client's data */
	cd = calloc(1, sizeof(*cd));
	if (cd == NULL) {
		td_verror(td, errno, "calloc");
		return -1;
	}

	/*
	 * Calculate the required queue sizes where:
	 * - the send queue (SQ) has to be big enough to accommodate
	 *   all io_us (WRITEs) and all flush requests (FLUSHes)
	 * - the completion queue (CQ) has to be big enough to accommodate all
	 *   success and error completions (cq_size = sq_size)
	 */
	if (td_random(td) || td_rw(td)) {
		/*
		 * sq_size = max(rand_read_sq_size, rand_write_sq_size)
		 * where rand_read_sq_size < rand_write_sq_size because read
		 * does not require flush afterwards
		 * rand_write_sq_size = N * (WRITE + FLUSH)
		 *
		 * Note: rw is no different from random write since having
		 * interleaved reads with writes in extreme forces you to flush
		 * as often as when the writes are random.
		 */
		sq_size = 2 * td->o.iodepth;
	} else if (td_write(td)) {
		/* sequential TD_DDIR_WRITE only */
		if (td->o.sync_io) {
			sq_size = 2; /* WRITE + FLUSH */
		} else {
			/*
			 * N * WRITE + B * FLUSH where:
			 * - B == ceil(iodepth / iodepth_batch)
			 *   which is the number of batches for N writes
			 */
			sq_size = td->o.iodepth +
				LIBRPMA_CEIL(td->o.iodepth, td->o.iodepth_batch);
		}
	} else {
		/* TD_DDIR_READ only */
		if (td->o.sync_io) {
			sq_size = 1; /* READ */
		} else {
			sq_size = td->o.iodepth; /* N x READ */
		}
	}
	cq_size = sq_size;

	/* create a connection configuration object */
	if ((ret = rpma_conn_cfg_new(&cfg))) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_new");
		goto err_free_cd;
	}

	/* apply queue sizes */
	if ((ret = rpma_conn_cfg_set_sq_size(cfg, sq_size))) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_set_sq_size");
		goto err_cfg_delete;
	}
	if ((ret = rpma_conn_cfg_set_cq_size(cfg, cq_size))) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_set_cq_size");
		goto err_cfg_delete;
	}

	if ((ret = librpma_common_client_init(td, cfg)))
		goto err_cfg_delete;

	ccd = td->io_ops_data;

	/* get flush type of the remote node */
	if ((ret = rpma_mr_remote_get_flush_type(ccd->server_mr, &remote_flush_type))) {
		librpma_td_verror(td, ret, "rpma_mr_remote_get_flush_type");
		goto err_cleanup_common;
	}

	cd->flush_type = (remote_flush_type & RPMA_MR_USAGE_FLUSH_TYPE_PERSISTENT) ?
		RPMA_FLUSH_TYPE_PERSISTENT : RPMA_FLUSH_TYPE_VISIBILITY;

	if (cd->flush_type == RPMA_FLUSH_TYPE_PERSISTENT) {
		/* configure peer's direct write to pmem support */
		if ((ret = rpma_peer_cfg_new(&pcfg))) {
			librpma_td_verror(td, ret, "rpma_peer_cfg_new");
			goto err_cleanup_common;
		}

		if ((ret = rpma_peer_cfg_set_direct_write_to_pmem(pcfg, true))) {
			librpma_td_verror(td, ret, "rpma_peer_cfg_set_direct_write_to_pmem");
			goto err_cleanup_common;
		}

		if ((ret = rpma_conn_apply_remote_peer_cfg(ccd->conn, pcfg))) {
			librpma_td_verror(td, ret, "rpma_conn_apply_remote_peer_cfg");
			goto err_cleanup_common;
		}

		(void) rpma_peer_cfg_delete(&pcfg);
	}

	ccd->flush = client_io_flush;
	ccd->get_io_u_index = client_get_io_u_index;
	ccd->client_data = cd;

	return 0;

err_cleanup_common:
	librpma_common_client_cleanup(td);

err_cfg_delete:
	(void) rpma_conn_cfg_delete(&cfg);

err_free_cd:
	free(cd);

	return -1;
}

static void client_cleanup(struct thread_data *td)
{
	struct librpma_common_client_data *ccd = td->io_ops_data;

	free(ccd->client_data);

	librpma_common_client_cleanup(td);
}

static inline int client_io_flush(struct thread_data *td,
		struct io_u *first_io_u, struct io_u *last_io_u,
		unsigned long long int len)
{
	struct librpma_common_client_data *ccd = td->io_ops_data;
	struct client_data *cd = ccd->client_data;
	size_t dst_offset = first_io_u->offset;
	int ret;

	if ((ret = rpma_flush(ccd->conn, ccd->server_mr, dst_offset, len,
		cd->flush_type, RPMA_F_COMPLETION_ALWAYS,
		(void *)(uintptr_t)last_io_u->index))) {
		librpma_td_verror(td, ret, "rpma_flush");
		return -1;
	}

	return 0;
}

static int client_get_io_u_index(struct rpma_completion *cmpl,
		unsigned int *io_u_index)
{
	memcpy(io_u_index, &cmpl->op_context, sizeof(*io_u_index));

	return 1;
}

FIO_STATIC struct ioengine_ops ioengine_client = {
	.name			= "librpma_client",
	.version		= FIO_IOOPS_VERSION,
	.init			= client_init,
	.post_init		= librpma_common_client_post_init,
	.get_file_size		= librpma_common_client_get_file_size,
	.open_file		= librpma_common_file_nop,
	.queue			= librpma_common_client_queue,
	.commit			= librpma_common_client_commit,
	.getevents		= librpma_common_client_getevents,
	.event			= librpma_common_client_event,
	.errdetails		= librpma_common_client_errdetails,
	.close_file		= librpma_common_file_nop,
	.cleanup		= client_cleanup,
	/* XXX flags require consideration */
	.flags			= FIO_DISKLESSIO | FIO_UNIDIR | FIO_PIPEIO,
	.options		= librpma_common_fio_options,
	.option_struct_size	= sizeof(struct librpma_common_options),
};

/* server side implementation */

static int server_open_file(struct thread_data *td, struct fio_file *f)
{
	return librpma_common_server_open_file(td, f, NULL);
}

static enum fio_q_status server_queue(struct thread_data *td, struct io_u *io_u)
{
	return FIO_Q_COMPLETED;
}

FIO_STATIC struct ioengine_ops ioengine_server = {
	.name			= "librpma_server",
	.version		= FIO_IOOPS_VERSION,
	.init			= librpma_common_server_init,
	.open_file		= server_open_file,
	.close_file		= librpma_common_server_close_file,
	.queue			= server_queue,
	.invalidate		= librpma_common_file_nop,
	.cleanup		= librpma_common_server_cleanup,
	.flags			= FIO_SYNCIO | FIO_NOEXTEND | FIO_FAKEIO |
				  FIO_NOSTATS,
	.options		= librpma_common_fio_options,
	.option_struct_size	= sizeof(struct librpma_common_options),
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
