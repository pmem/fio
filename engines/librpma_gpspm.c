/*
 * librpma_gpspm: IO engine that uses PMDK librpma to write data,
 *		based on General Purpose Server Persistency Method
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

#include "librpma_fio.h"

#include <libpmem.h>

/* Generated by the protocol buffer compiler from: librpma_gpspm_flush.proto */
#include "librpma_gpspm_flush.pb-c.h"

#define MAX_MSG_SIZE (512)
#define IO_U_BUF_LEN (2 * MAX_MSG_SIZE)
#define SEND_OFFSET (0)
#define RECV_OFFSET (SEND_OFFSET + MAX_MSG_SIZE)

#define GPSPM_FLUSH_REQUEST__LAST \
	{ PROTOBUF_C_MESSAGE_INIT(&gpspm_flush_request__descriptor), 0, 0, 0 }

/*
 * 'Flush_req_last' is the last flush request
 * the client has to send to server to indicate
 * that the client is done.
 */
static const GPSPMFlushRequest Flush_req_last = GPSPM_FLUSH_REQUEST__LAST;

#define IS_NOT_THE_LAST_MESSAGE(flush_req) \
	(flush_req->length != Flush_req_last.length || \
	flush_req->offset != Flush_req_last.offset)

/* client side implementation */

/* get next io_u message buffer in the round-robin fashion */
#define IO_U_NEXT_BUF_OFF_CLIENT(cd) \
	(IO_U_BUF_LEN * ((cd->msg_curr++) % cd->msg_num))

struct client_data {
	/* memory for sending and receiving buffered */
	char *io_us_msgs;

	/* resources for messaging buffer */
	uint32_t msg_num;
	uint32_t msg_curr;
	struct rpma_mr_local *msg_mr;
};

static inline int client_io_flush(struct thread_data *td,
		struct io_u *first_io_u, struct io_u *last_io_u,
		unsigned long long int len);

static int client_get_io_u_index(struct rpma_completion *cmpl,
		unsigned int *io_u_index);

static int client_init(struct thread_data *td)
{
	struct librpma_fio_client_data *ccd;
	struct client_data *cd;
	uint32_t write_num;
	struct rpma_conn_cfg *cfg = NULL;
	int ret;

	/*
	 * not supported:
	 * - readwrite = read / trim / randread / randtrim /
	 *               / rw / randrw / trimwrite
	 */
	if (td_read(td) || td_trim(td)) {
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
	 * Calculate the required number of WRITEs and FLUSHes.
	 *
	 * Note: Each flush is a request (SEND) and response (RECV) pair.
	 */
	if (td_random(td)) {
		write_num = td->o.iodepth; /* WRITE * N */
		cd->msg_num = td->o.iodepth; /* FLUSH * N */
	} else {
		if (td->o.sync_io) {
			write_num = 1; /* WRITE */
			cd->msg_num = 1; /* FLUSH */
		} else {
			write_num = td->o.iodepth; /* WRITE * N */
			/*
			 * FLUSH * B where:
			 * - B == ceil(iodepth / iodepth_batch)
			 *   which is the number of batches for N writes
			 */
			cd->msg_num = LIBRPMA_FIO_CEIL(td->o.iodepth,
					td->o.iodepth_batch);
		}
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

	if (ccd->ws->direct_write_to_pmem) {
		if (ccd->server_mr_flush_type == RPMA_FLUSH_TYPE_PERSISTENT &&
		    td->thread_number == 1) {
			/* XXX log_info mixes with the JSON output */
			log_err(
				"Note: The server side supports Direct Write to PMem and it is equipped with PMem (direct_write_to_pmem).\n"
				"You can use librpma_client and librpma_server engines for better performance instead of GPSPM.\n");
		}
	}

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

	ccd->flush = client_io_flush;
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

static void client_cleanup(struct thread_data *td)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;
	struct client_data *cd;
	size_t flush_req_size;
	size_t io_u_buf_off;
	size_t send_offset;
	void *send_ptr;
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

	/* prepare the last flush message and pack it to the send buffer */
	flush_req_size = gpspm_flush_request__get_packed_size(&Flush_req_last);
	if (flush_req_size > MAX_MSG_SIZE) {
		log_err(
			"Packed flush request size is bigger than available send buffer space (%zu > %d\n",
			flush_req_size, MAX_MSG_SIZE);
	} else {
		io_u_buf_off = IO_U_NEXT_BUF_OFF_CLIENT(cd);
		send_offset = io_u_buf_off + SEND_OFFSET;
		send_ptr = cd->io_us_msgs + send_offset;
		(void) gpspm_flush_request__pack(&Flush_req_last, send_ptr);

		/* send the flush message */
		if ((ret = rpma_send(ccd->conn, cd->msg_mr, send_offset,
				flush_req_size, RPMA_F_COMPLETION_ALWAYS,
				NULL)))
			librpma_td_verror(td, ret, "rpma_send");

		++ccd->op_send_posted;

		/* Wait for the SEND to complete */
		(void) librpma_fio_client_io_complete_all_sends(td);
	}

	/* deregister the messaging buffer memory */
	if ((ret = rpma_mr_dereg(&cd->msg_mr)))
		librpma_td_verror(td, ret, "rpma_mr_dereg");

	free(ccd->client_data);

	librpma_fio_client_cleanup(td);
}

static inline int client_io_flush(struct thread_data *td,
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
	GPSPMFlushRequest flush_req = GPSPM_FLUSH_REQUEST__INIT;
	size_t flush_req_size = 0;
	int ret;

	/* prepare a response buffer */
	if ((ret = rpma_recv(ccd->conn, cd->msg_mr, recv_offset, MAX_MSG_SIZE,
			recv_ptr))) {
		librpma_td_verror(td, ret, "rpma_recv");
		return -1;
	}

	/* prepare a flush message and pack it to a send buffer */
	flush_req.offset = first_io_u->offset;
	flush_req.length = len;
	flush_req.op_context = last_io_u->index;
	flush_req_size = gpspm_flush_request__get_packed_size(&flush_req);
	if (flush_req_size > MAX_MSG_SIZE) {
		log_err(
			"Packed flush request size is bigger than available send buffer space (%"
			PRIu64 " > %d\n", flush_req_size, MAX_MSG_SIZE);
		return -1;
	}
	(void) gpspm_flush_request__pack(&flush_req, send_ptr);

	/* send the flush message */
	if ((ret = rpma_send(ccd->conn, cd->msg_mr, send_offset, flush_req_size,
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
	GPSPMFlushResponse *flush_resp;

	if (cmpl->op != RPMA_OP_RECV)
		return 0;

	/* unpack a response from the received buffer */
	flush_resp = gpspm_flush_response__unpack(NULL,
			cmpl->byte_len, cmpl->op_context);
	if (flush_resp == NULL) {
		log_err("Cannot unpack the flush response buffer\n");
		return -1;
	}

	memcpy(io_u_index, &flush_resp->op_context, sizeof(*io_u_index));

	gpspm_flush_response__free_unpacked(flush_resp, NULL);

	return 1;
}

FIO_STATIC struct ioengine_ops ioengine_client = {
	.name			= "librpma_gpspm_client",
	.version		= FIO_IOOPS_VERSION,
	.init			= client_init,
	.post_init		= client_post_init,
	.get_file_size		= librpma_fio_client_get_file_size,
	.open_file		= librpma_fio_file_nop,
	.queue			= librpma_fio_client_queue,
	.commit			= librpma_fio_client_commit,
	.getevents		= librpma_fio_client_getevents,
	.event			= librpma_fio_client_event,
	.errdetails		= librpma_fio_client_errdetails,
	.close_file		= librpma_fio_file_nop,
	.cleanup		= client_cleanup,
	.flags			= FIO_DISKLESSIO,
	.options		= librpma_fio_options,
	.option_struct_size	= sizeof(struct librpma_fio_options_values),
};

/* server side implementation */

#define IO_U_BUFF_OFF_SERVER(i) (i * IO_U_BUF_LEN)

struct server_data {
	/* aligned td->orig_buffer */
	char *orig_buffer_aligned;

	/* resources for messaging buffer from DRAM allocated by fio */
	struct rpma_mr_local *msg_mr;

	uint32_t msg_sqe_available; /* # of free SQ slots */

	/* in-memory queues */
	struct rpma_completion *msgs_queued;
	uint32_t msg_queued_nr;
};

static int server_init(struct thread_data *td)
{
	struct librpma_fio_server_data *csd;
	struct server_data *sd;
	int ret = -1;

	if ((ret = librpma_fio_server_init(td)))
		return ret;

	csd = td->io_ops_data;

	/* allocate server's data */
	sd = calloc(1, sizeof(*sd));
	if (sd == NULL) {
		td_verror(td, errno, "calloc");
		goto err_server_cleanup;
	}

	/* allocate in-memory queue */
	sd->msgs_queued = calloc(td->o.iodepth, sizeof(*sd->msgs_queued));
	if (sd->msgs_queued == NULL) {
		td_verror(td, errno, "calloc");
		goto err_free_sd;
	}

	/*
	 * Assure a single io_u buffer can store both SEND and RECV messages and
	 * an io_us buffer allocation is page-size-aligned which is required
	 * to register for RDMA. User-provided values are intentionally ignored.
	 */
	td->o.max_bs[DDIR_READ] = IO_U_BUF_LEN;
	td->o.mem_align = page_size;

	csd->server_data = sd;

	return 0;

err_free_sd:
	free(sd);

err_server_cleanup:
	librpma_fio_server_cleanup(td);

	return -1;
}

static int server_post_init(struct thread_data *td)
{
	struct librpma_fio_server_data *csd = td->io_ops_data;
	struct server_data *sd = csd->server_data;
	size_t io_us_size;
	size_t io_u_buflen;
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
	 * Aligning each of those buffers may potentially give
	 * some performance benefits.
	 */
	io_u_buflen = td_max_bs(td);

	/* check whether io_u buffer is big enough */
	if (io_u_buflen < IO_U_BUF_LEN) {
		log_err(
			"blocksize too small to accommodate assumed maximal request/response pair size (%" PRIu64 " < %d)\n",
			io_u_buflen, IO_U_BUF_LEN);
		return -1;
	}

	/*
	 * td->orig_buffer_size beside the space really consumed by io_us
	 * has paddings which can be omitted for the memory registration.
	 */
	io_us_size = (unsigned long long)io_u_buflen *
			(unsigned long long)td->o.iodepth;

	if ((ret = rpma_mr_reg(csd->peer, sd->orig_buffer_aligned, io_us_size,
			RPMA_MR_USAGE_SEND | RPMA_MR_USAGE_RECV,
			&sd->msg_mr))) {
		librpma_td_verror(td, ret, "rpma_mr_reg");
		return -1;
	}

	return 0;
}

static void server_cleanup(struct thread_data *td)
{
	struct librpma_fio_server_data *csd = td->io_ops_data;
	struct server_data *sd;
	int ret;

	if (csd == NULL)
		return;

	sd = csd->server_data;

	if (sd != NULL) {
		/* rpma_mr_dereg(messaging buffer from DRAM) */
		if ((ret = rpma_mr_dereg(&sd->msg_mr)))
			librpma_td_verror(td, ret, "rpma_mr_dereg");

		free(sd->msgs_queued);
		free(sd);
	}

	librpma_fio_server_cleanup(td);
}

static int prepare_connection(struct thread_data *td,
		struct rpma_conn_req *conn_req)
{
	struct librpma_fio_server_data *csd = td->io_ops_data;
	struct server_data *sd = csd->server_data;
	int ret;
	int i;

	/* prepare buffers for a flush requests */
	sd->msg_sqe_available = td->o.iodepth;
	for (i = 0; i < td->o.iodepth; i++) {
		size_t offset_recv_msg = IO_U_BUFF_OFF_SERVER(i) + RECV_OFFSET;
		if ((ret = rpma_conn_req_recv(conn_req, sd->msg_mr,
				offset_recv_msg, MAX_MSG_SIZE,
				(const void *)(uintptr_t)i))) {
			librpma_td_verror(td, ret, "rpma_conn_req_recv");
			return ret;
		}
	}

	return 0;
}

static int server_open_file(struct thread_data *td, struct fio_file *f)
{
	struct librpma_fio_server_data *csd = td->io_ops_data;
	struct rpma_conn_cfg *cfg = NULL;
	uint16_t max_msg_num = td->o.iodepth;
	int ret;

	csd->prepare_connection = prepare_connection;

	/* create a connection configuration object */
	if ((ret = rpma_conn_cfg_new(&cfg))) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_new");
		return -1;
	}

	/*
	 * Calculate the required queue sizes where:
	 * - the send queue (SQ) has to be big enough to accommodate
	 *   all possible flush requests (SENDs)
	 * - the receive queue (RQ) has to be big enough to accommodate
	 *   all flush responses (RECVs)
	 * - the completion queue (CQ) has to be big enough to accommodate
	 *   all success and error completions (sq_size + rq_size)
	 */
	if ((ret = rpma_conn_cfg_set_sq_size(cfg, max_msg_num))) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_set_sq_size");
		goto err_cfg_delete;
	}
	if ((ret = rpma_conn_cfg_set_rq_size(cfg, max_msg_num))) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_set_rq_size");
		goto err_cfg_delete;
	}
	if ((ret = rpma_conn_cfg_set_cq_size(cfg, max_msg_num * 2))) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_set_cq_size");
		goto err_cfg_delete;
	}

	ret = librpma_fio_server_open_file(td, f, cfg);

err_cfg_delete:
	(void) rpma_conn_cfg_delete(&cfg);

	return ret;
}

static int server_qe_process(struct thread_data *td,
		struct rpma_completion *cmpl)
{
	struct librpma_fio_server_data *csd = td->io_ops_data;
	struct server_data *sd = csd->server_data;
	GPSPMFlushRequest *flush_req;
	GPSPMFlushResponse flush_resp = GPSPM_FLUSH_RESPONSE__INIT;
	size_t flush_resp_size = 0;
	size_t send_buff_offset;
	size_t recv_buff_offset;
	size_t io_u_buff_offset;
	void *send_buff_ptr;
	void *recv_buff_ptr;
	void *op_ptr;
	int msg_index;
	int ret;

	/* calculate SEND/RECV pair parameters */
	msg_index = (int)(uintptr_t)cmpl->op_context;
	io_u_buff_offset = IO_U_BUFF_OFF_SERVER(msg_index);
	send_buff_offset = io_u_buff_offset + SEND_OFFSET;
	recv_buff_offset = io_u_buff_offset + RECV_OFFSET;
	send_buff_ptr = sd->orig_buffer_aligned + send_buff_offset;
	recv_buff_ptr = sd->orig_buffer_aligned + recv_buff_offset;

	/* unpack a flush request from the received buffer */
	flush_req = gpspm_flush_request__unpack(NULL, cmpl->byte_len,
			recv_buff_ptr);
	if (flush_req == NULL) {
		log_err("cannot unpack the flush request buffer\n");
		goto err_terminate;
	}

	if (IS_NOT_THE_LAST_MESSAGE(flush_req)) {
		op_ptr = csd->ws_ptr + flush_req->offset;
		pmem_persist(op_ptr, flush_req->length);
	} else {
		/*
		 * This is the last message - the client is done.
		 */
		gpspm_flush_request__free_unpacked(flush_req, NULL);
		td->done = true;
		return 0;
	}

	/* initiate the next receive operation */
	if ((ret = rpma_recv(csd->conn, sd->msg_mr, recv_buff_offset,
			MAX_MSG_SIZE,
			(const void *)(uintptr_t)msg_index))) {
		librpma_td_verror(td, ret, "rpma_recv");
		goto err_free_unpacked;
	}

	/* prepare a flush response and pack it to a send buffer */
	flush_resp.op_context = flush_req->op_context;
	flush_resp_size = gpspm_flush_response__get_packed_size(&flush_resp);
	if (flush_resp_size > MAX_MSG_SIZE) {
		log_err(
			"Size of the packed flush response is bigger than the available space of the send buffer (%"
			PRIu64 " > %i\n", flush_resp_size, MAX_MSG_SIZE);
		goto err_free_unpacked;
	}

	(void) gpspm_flush_response__pack(&flush_resp, send_buff_ptr);

	/* send the flush response */
	if ((ret = rpma_send(csd->conn, sd->msg_mr, send_buff_offset,
			flush_resp_size, RPMA_F_COMPLETION_ALWAYS, NULL))) {
		librpma_td_verror(td, ret, "rpma_send");
		goto err_free_unpacked;
	}
	--sd->msg_sqe_available;

	gpspm_flush_request__free_unpacked(flush_req, NULL);

	return 0;

err_free_unpacked:
	gpspm_flush_request__free_unpacked(flush_req, NULL);

err_terminate:
	td->terminate = true;

	return -1;
}

static inline int server_queue_process(struct thread_data *td)
{
	struct librpma_fio_server_data *csd = td->io_ops_data;
	struct server_data *sd = csd->server_data;
	int ret;
	int i;

	/* min(# of queue entries, # of SQ entries available) */
	uint32_t qes_to_process = min(sd->msg_queued_nr, sd->msg_sqe_available);
	if (qes_to_process == 0)
		return 0;

	/* process queued completions */
	for (i = 0; i < qes_to_process; ++i) {
		if ((ret = server_qe_process(td, &sd->msgs_queued[i])))
			return ret;
	}

	/* progress the queue */
	for (i = 0; i < sd->msg_queued_nr - qes_to_process; ++i) {
		memcpy(&sd->msgs_queued[i],
			&sd->msgs_queued[qes_to_process + i],
			sizeof(sd->msgs_queued[i]));
	}

	sd->msg_queued_nr -= qes_to_process;

	return 0;
}

static int server_cmpl_process(struct thread_data *td)
{
	struct librpma_fio_server_data *csd = td->io_ops_data;
	struct server_data *sd = csd->server_data;
	struct rpma_completion *cmpl = &sd->msgs_queued[sd->msg_queued_nr];
	int ret;

	ret = rpma_conn_completion_get(csd->conn, cmpl);
	if (ret == RPMA_E_NO_COMPLETION) {
		/* lack of completion is not an error */
		return 0;
	} else if (ret != 0) {
		librpma_td_verror(td, ret, "rpma_conn_completion_get");
		goto err_terminate;
	}

	/* validate the completion */
	if (cmpl->op_status != IBV_WC_SUCCESS)
		goto err_terminate;

	if (cmpl->op == RPMA_OP_RECV)
		++sd->msg_queued_nr;
	else if (cmpl->op == RPMA_OP_SEND)
		++sd->msg_sqe_available;

	return 0;

err_terminate:
	td->terminate = true;

	return -1;
}

static enum fio_q_status server_queue(struct thread_data *td, struct io_u *io_u)
{
	do {
		if (server_cmpl_process(td))
			return FIO_Q_BUSY;

		if (server_queue_process(td))
			return FIO_Q_BUSY;

	} while (!td->done);

	return FIO_Q_COMPLETED;
}

FIO_STATIC struct ioengine_ops ioengine_server = {
	.name			= "librpma_gpspm_server",
	.version		= FIO_IOOPS_VERSION,
	.init			= server_init,
	.post_init		= server_post_init,
	.open_file		= server_open_file,
	.close_file		= librpma_fio_server_close_file,
	.queue			= server_queue,
	.invalidate		= librpma_fio_file_nop,
	.cleanup		= server_cleanup,
	.flags			= FIO_SYNCIO,
	.options		= librpma_fio_options,
	.option_struct_size	= sizeof(struct librpma_fio_options_values),
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
