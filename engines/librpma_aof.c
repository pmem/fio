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

/* Generated by the protocol buffer compiler from: librpma_aof_update.proto */
#include "librpma_aof_update.pb-c.h"

#define MAX_MSG_SIZE (512)
#define IO_U_BUF_LEN (2 * MAX_MSG_SIZE)
#define SEND_OFFSET (0)
#define RECV_OFFSET (SEND_OFFSET + MAX_MSG_SIZE)

static int client_io_send(struct thread_data *td,
	struct io_u *first_io_u, struct io_u *last_io_u,
	unsigned long long int len);

static int client_get_io_u_index(struct rpma_completion *cmpl,
	unsigned int *io_u_index);

/* client side implementation */

/* get next io_u message buffer in the round-robin fashion */
#define IO_U_NEXT_BUF_OFF_CLIENT(cd) \
	(IO_U_BUF_LEN * ((cd->msg_curr++) % cd->msg_num))

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
	uint32_t write_num;
	struct rpma_conn_cfg *cfg = NULL;
	int ret;

	/* only sequential writes are allowed in AOF */
	if (!td_write(td)) {
		td_verror(td, EINVAL,
			"Not supported mode (only sequential writes are allowed in AOF).");
		return -1;
	}

	/* allocate client's data */
	cd = calloc(1, sizeof(*cd));
	if (cd == NULL) {
		td_verror(td, errno, "calloc");
		return -1;
	}

	write_num = 1; /* WRITE */
	cd->msg_num = 1; /* AOF update */

	/* create a connection configuration object */
	if ((ret = rpma_conn_cfg_new(&cfg))) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_new");
		goto err_free_cd;
	}

	/*
	 * Calculate the required queue sizes where:
	 * - the send queue (SQ) has to be big enough to accommodate
	 *   all io_us (WRITEs) and all AOF update requests (SENDs)
	 * - the receive queue (RQ) has to be big enough to accommodate
	 *   all AOF update responses (RECVs)
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

	/* validate the server's RQ capacity */
	if (cd->msg_num > ccd->ws->max_msg_num) {
		log_err(
			"server's RQ size (iodepth) too small to handle the client's workspace requirements (%u < %u)\n",
			ccd->ws->max_msg_num, cd->msg_num);
		goto err_cleanup_common;
	}

	if ((ret = rpma_conn_cfg_delete(&cfg))) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_delete");
		/* non fatal error - continue */
	}

	ccd->flush = client_io_send;
	ccd->get_io_u_index = client_get_io_u_index;
	ccd->client_data = cd;

	return 0;

err_cleanup_common:
	librpma_fio_client_cleanup(td);

err_cfg_delete:
	(void) rpma_conn_cfg_delete(&cfg);

err_free_cd:
	free(cd);

	return -1;
}

static int client_post_init(struct thread_data *td)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;
	struct client_data *cd = ccd->client_data;
	unsigned int io_us_msgs_size;
	int ret;

	/* message buffers initialization and registration */
	io_us_msgs_size = cd->msg_num * IO_U_BUF_LEN;
	if ((ret = posix_memalign((void **)&cd->io_us_msgs, page_size,
			io_us_msgs_size))) {
		td_verror(td, ret, "posix_memalign");
		return ret;
	}
	if ((ret = rpma_mr_reg(ccd->peer, cd->io_us_msgs, io_us_msgs_size,
			RPMA_MR_USAGE_SEND | RPMA_MR_USAGE_RECV,
			&cd->msg_mr))) {
		librpma_td_verror(td, ret, "rpma_mr_reg");
		return ret;
	}

	return librpma_fio_client_post_init(td);
}

static int client_get_file_size(struct thread_data *td, struct fio_file *f)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;

	/* reserve space for the AOF pointer */
	ccd->ws_size -= sizeof(uint64_t);

	f->real_file_size = ccd->ws_size;
	fio_file_set_size_known(f);

	return 0;
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

	/* XXX here the last message should be sent */

	/* deregister the messaging buffer memory */
	if ((ret = rpma_mr_dereg(&cd->msg_mr)))
		librpma_td_verror(td, ret, "rpma_mr_dereg");

	free(ccd->client_data);

	librpma_fio_client_cleanup(td);
}

static int client_io_send(struct thread_data *td,
		struct io_u *first_io_u, struct io_u *last_io_u,
		unsigned long long int len)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;
	struct client_data *cd = ccd->client_data;
	size_t io_u_buf_off = IO_U_NEXT_BUF_OFF_CLIENT(cd);
	size_t send_offset = io_u_buf_off + SEND_OFFSET;
	size_t recv_offset = io_u_buf_off + RECV_OFFSET;
	void *send_ptr = cd->io_us_msgs + send_offset;
	void *recv_ptr = cd->io_us_msgs + recv_offset;
	AOFUpdateRequest update_req = AOF_UPDATE_REQUEST__INIT;
	size_t update_req_size = 0;
	int ret;

	/* prepare a response buffer */
	if ((ret = rpma_recv(ccd->conn, cd->msg_mr, recv_offset, MAX_MSG_SIZE,
			recv_ptr))) {
		librpma_td_verror(td, ret, "rpma_recv");
		return -1;
	}

	/* prepare the AOF update message and pack it to a send buffer */
	update_req.append_offset = first_io_u->offset;
	update_req.append_length = len;
	update_req.pointer_offset = ccd->ws_size; /* AOF pointer */
	update_req.op_context = last_io_u->index;
	update_req_size = aof_update_request__get_packed_size(&update_req);
	if (update_req_size > MAX_MSG_SIZE) {
		log_err(
			"Packed AOF update request size is bigger than available send buffer space (%"
			PRIu64 " > %d\n", update_req_size, MAX_MSG_SIZE);
		return -1;
	}
	(void) aof_update_request__pack(&update_req, send_ptr);

	/* send the AOF update message */
	if ((ret = rpma_send(ccd->conn, cd->msg_mr, send_offset, update_req_size,
			RPMA_F_COMPLETION_ALWAYS, NULL))) {
		librpma_td_verror(td, ret, "rpma_send");
		return -1;
	}

	++ccd->op_send_posted;

	return 0;
}

static int client_get_io_u_index(struct rpma_completion *cmpl,
		unsigned int *io_u_index)
{
	AOFUpdateResponse *update_resp;

	if (cmpl->op != RPMA_OP_RECV)
		return 0;

	/* unpack a response from the received buffer */
	update_resp = aof_update_response__unpack(NULL,
			cmpl->byte_len, cmpl->op_context);
	if (update_resp == NULL) {
		log_err("Cannot unpack the update response buffer\n");
		return -1;
	}

	memcpy(io_u_index, &update_resp->op_context, sizeof(*io_u_index));

	aof_update_response__free_unpacked(update_resp, NULL);

	return 1;
}

FIO_STATIC struct ioengine_ops ioengine_client = {
	.name			= "librpma_aof_client",
	.version		= FIO_IOOPS_VERSION,
	.init			= client_init,
	.post_init		= client_post_init,
	.get_file_size		= client_get_file_size,
	.open_file		= librpma_fio_file_nop,
	.queue			= librpma_fio_client_queue,
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
	/* aligned td->orig_buffer - the messaging buffer (sending and receiving) */
	char *orig_buffer_aligned;

	/* resources for the messaging buffer */
	struct rpma_mr_local *msg_mr;

	uint32_t msg_sqe_available; /* # of free SQ slots */

	/* in-memory queues */
	struct rpma_completion *msgs_queued;
	uint32_t msg_queued_nr;
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
