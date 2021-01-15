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

#include "librpma_common.h"

#include <libpmem.h>
#include <librpma.h>

/* Generated by the protocol buffer compiler from: librpma_gpspm_flush.proto */
#include "librpma_gpspm_flush.pb-c.h"

#define MAX_MSG_SIZE (512)
#define IO_U_BUF_LEN (2 * MAX_MSG_SIZE)
#define SEND_OFFSET (0)
#define RECV_OFFSET (SEND_OFFSET + MAX_MSG_SIZE)

#define GPSPM_FLUSH_REQUEST__LAST \
	{ PROTOBUF_C_MESSAGE_INIT (&gpspm_flush_request__descriptor), 0, 0, 0 }

/*
 * 'Flush_req_last' is the last flush request
 * the client has to send to server to indicate
 * that the client is done.
 */
static const GPSPMFlushRequest Flush_req_last = GPSPM_FLUSH_REQUEST__LAST;

#define IS_NOT_THE_LAST_MESSAGE(flush_req) \
	(flush_req->length != Flush_req_last.length || \
	flush_req->offset != Flush_req_last.offset)

/*
 * Limited by the maximum length of the private data
 * for rdma_connect() in case of RDMA_PS_TCP (28 bytes).
 */
#define DESCRIPTORS_MAX_SIZE 25

struct workspace {
	uint16_t max_msg_num;	/* # of RQ slots */
	uint8_t mr_desc_size;	/* size of mr_desc in descriptors[] */
	/* buffer containing mr_desc */
	char descriptors[DESCRIPTORS_MAX_SIZE];
};

/* client side implementation */

/* get next io_u message buffer in the round-robin fashion */
#define IO_U_NEXT_BUF_OFF_CLIENT(cd) \
    (IO_U_BUF_LEN * ((cd->msg_curr++) % cd->msg_num))

static struct fio_option fio_client_options[] = {
	{
		.name	= "hostname",
		.lname	= "rpma_client hostname",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct librpma_common_client_options, hostname),
		.help	= "IP address the server is listening on",
		.def    = "",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA_GPSPM,
	},
	{
		.name	= "port",
		.lname	= "rpma_client port",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct librpma_common_client_options, port),
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
	char common[sizeof(struct librpma_common_client_data)];

	/* memory for sending and receiving buffered */
	char *io_us_msgs;

	/* resources for messaging buffer */
	uint32_t msg_num;
	uint32_t msg_curr;
	uint32_t msg_send_completed;
	struct rpma_mr_local *msg_mr;
};

static int client_init(struct thread_data *td)
{
	struct librpma_common_client_data *ccd;
	struct client_data *cd;
	uint32_t write_num;
	struct rpma_conn_cfg *cfg = NULL;
	struct rpma_conn_private_data pdata;
	struct workspace *ws;
	size_t server_mr_size;
	int ret;
	
	/* not supported readwrite = read / trim / randread / randtrim / rw / randrw / trimwrite */
	if (td_read(td) || td_trim(td)) {
		log_err("Not supported mode.\n");
		return 1;
	}

	/* allocate client's data */
	cd = calloc(1, sizeof(struct client_data));
	if (cd == NULL) {
		td_verror(td, errno, "calloc");
		return 1;
	}
	ccd = (struct librpma_common_client_data *)cd;

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
			cd->msg_num = LIBRPMA_CEIL(td->o.iodepth, td->o.iodepth_batch);
		}
	}

	/* create a connection configuration object */
	ret = rpma_conn_cfg_new(&cfg);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_new");
		goto err_free_cd;
	}

	/*
	 * Calculate the required queue sizes where:
	 * - the send queue (SQ) has to be big enough to accommodate
	 *   all io_us (WRITEs) and all flush requests (SENDs)
	 * - the receive queue (RQ) has to be big enough to accommodate all flush
	 *   responses (RECVs)
	 * - the completion queue (CQ) has to be big enough to accommodate all
	 *   success and error completions (sq_size + rq_size)
	 */
	ret = rpma_conn_cfg_set_sq_size(cfg, write_num + cd->msg_num);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_set_sq_size");
		goto err_cfg_delete;
	}
	ret = rpma_conn_cfg_set_rq_size(cfg, cd->msg_num);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_set_rq_size");
		goto err_cfg_delete;
	}
	ret = rpma_conn_cfg_set_cq_size(cfg, write_num + cd->msg_num * 2);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_set_cq_size");
		goto err_cfg_delete;
	}
	
	if ((ret = librpma_common_client_init(td, ccd, cfg)))
		goto err_cfg_delete;

	/* get the connection's private data sent from the server */
	if ((ret = rpma_conn_get_private_data(ccd->conn, &pdata)))
		goto err_cleanup_common;

	/* create the server's workspace representation */
	ws = pdata.ptr;

	/* validate the server's RQ capacity */
	if (cd->msg_num > ws->max_msg_num) {
		log_err(
			"server's RQ size (iodepth) too small to handle the client's workspace requirements (%u < %u)\n",
			ws->max_msg_num, cd->msg_num);
		goto err_cleanup_common;
	}

	/* create the server's memory representation */
	if ((ret = rpma_mr_remote_from_descriptor(&ws->descriptors[0],
			ws->mr_desc_size, &ccd->server_mr)))
		goto err_cleanup_common;

	/* get the total size of the shared server memory */
	if ((ret = rpma_mr_remote_get_size(ccd->server_mr, &server_mr_size))) {
		librpma_td_verror(td, ret, "rpma_mr_remote_get_size");
		goto err_cleanup_common;
	}

	ccd->ws_size = server_mr_size;
	td->io_ops_data = ccd;

	return 0;

err_cleanup_common:
	/* XXX to be replaced with librpma_common_client_cleanup */
	(void) rpma_conn_disconnect(ccd->conn);
	(void) rpma_conn_delete(&ccd->conn);
	(void) rpma_peer_delete(&ccd->peer);
	free(ccd->io_us_queued);
	free(ccd->io_us_flight);
	free(ccd->io_us_completed);

err_cfg_delete:
	(void) rpma_conn_cfg_delete(&cfg);

err_free_cd:
	free(ccd);

	return 1;
}

static int client_post_init(struct thread_data *td)
{
	struct librpma_common_client_data *ccd = td->io_ops_data;
	struct client_data *cd = (struct client_data *)ccd;
	size_t io_us_size;
	unsigned int io_us_msgs_size;
	int ret;

	/* message buffers initialization and registration */
	cd->msg_curr = 0;
	cd->msg_send_completed = 0;
	io_us_msgs_size = cd->msg_num * IO_U_BUF_LEN;
	if ((ret = posix_memalign((void **)&cd->io_us_msgs,
			page_size, io_us_msgs_size))) {
		td_verror(td, ret, "posix_memalign");
		return ret;
	}
	if ((ret = rpma_mr_reg(ccd->peer, cd->io_us_msgs, io_us_msgs_size,
			RPMA_MR_USAGE_SEND | RPMA_MR_USAGE_RECV,
			&cd->msg_mr))) {
		librpma_td_verror(td, ret, "rpma_mr_reg");
		return ret;
	}

	/*
	 * td->orig_buffer is not aligned. The engine requires aligned io_us
	 * so FIO alignes up the address using the formula below.
	 */
	ccd->orig_buffer_aligned = PTR_ALIGN(td->orig_buffer, page_mask) +
			td->o.mem_align;

	/*
	 * td->orig_buffer_size beside the space really consumed by io_us
	 * has paddings which can be omitted for the memory registration.
	 */
	io_us_size = (unsigned long long)td_max_bs(td) *
			(unsigned long long)td->o.iodepth;

	if ((ret = rpma_mr_reg(ccd->peer, ccd->orig_buffer_aligned, io_us_size,
			RPMA_MR_USAGE_READ_DST | RPMA_MR_USAGE_READ_SRC |
			RPMA_MR_USAGE_WRITE_DST | RPMA_MR_USAGE_WRITE_SRC,
			&ccd->orig_mr)))
		librpma_td_verror(td, ret, "rpma_mr_reg");

	return ret;
}

static void client_cleanup(struct thread_data *td)
{
	struct librpma_common_client_data *ccd = td->io_ops_data;
	struct client_data *cd = (struct client_data *)ccd;
	struct rpma_completion cmpl;
	size_t flush_req_size;
	size_t io_u_buf_off;
	size_t send_offset;
	void *send_ptr;
	enum rpma_conn_event ev;
	int ret;

	if (cd == NULL)
		return;

	/*
	 * Make sure all SEND completions are collected ergo there are free
	 * slots in the SQ for the last SEND message.
	 *
	 * Note: If any operation will fail we still can send the termination
	 * notice.
	 */
	while (cd->msg_curr > cd->msg_send_completed) {
		/* get a completion */
		ret = rpma_conn_completion_get(ccd->conn, &cmpl);
		if (ret == RPMA_E_NO_COMPLETION) {
			/* lack of completion is not an error */
			continue;
		} else if (ret != 0) {
			/* an error occurred */
			librpma_td_verror(td, ret, "rpma_conn_completion_get");
			break;
		}

		if (cmpl.op_status != IBV_WC_SUCCESS)
			break;

		if (cmpl.op == RPMA_OP_SEND)
			++cd->msg_send_completed;
	}

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
		if ((ret = rpma_send(ccd->conn, cd->msg_mr, send_offset, flush_req_size,
					RPMA_F_COMPLETION_ON_ERROR, NULL)))
			librpma_td_verror(td, ret, "rpma_send");
	}

	/* deregister the iou's memory */
	if ((ret = rpma_mr_dereg(&ccd->orig_mr)))
		librpma_td_verror(td, ret, "rpma_mr_dereg");

	/* deregister the messaging buffer memory */
	if ((ret = rpma_mr_dereg(&cd->msg_mr)))
		librpma_td_verror(td, ret, "rpma_mr_dereg");

	/* delete the iou's memory registration */
	if ((ret = rpma_mr_remote_delete(&ccd->server_mr)))
		librpma_td_verror(td, ret, "rpma_mr_remote_delete");

	/* initiate disconnection */
	if ((ret = rpma_conn_disconnect(ccd->conn)))
		librpma_td_verror(td, ret, "rpma_conn_disconnect");

	/* wait for disconnection to end up */
	if ((ret = rpma_conn_next_event(ccd->conn, &ev))) {
		librpma_td_verror(td, ret, "rpma_conn_next_event");
	} else if (ev != RPMA_CONN_CLOSED) {
		log_err(
			"client_cleanup received an unexpected event (%s != RPMA_CONN_CLOSED)\n",
			rpma_utils_conn_event_2str(ev));
	}

	/* delete the connection */
	if ((ret = rpma_conn_delete(&ccd->conn)))
		librpma_td_verror(td, ret, "rpma_conn_delete");

	/* delete the peer */
	if ((ret = rpma_peer_delete(&ccd->peer)))
		librpma_td_verror(td, ret, "rpma_peer_delete");

	/* free message buffers */
	free(cd->io_us_msgs);

	/* free the software queues */
	free(ccd->io_us_queued);
	free(ccd->io_us_flight);
	free(ccd->io_us_completed);

	/* free the client's data */
	free(td->io_ops_data);
}

static int client_get_file_size(struct thread_data *td, struct fio_file *f)
{
	struct librpma_common_client_data *ccd = td->io_ops_data;

	f->real_file_size = ccd->ws_size;
	fio_file_set_size_known(f);

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

static inline int client_io_write(struct thread_data *td, struct io_u *io_u)
{
	struct librpma_common_client_data *ccd = td->io_ops_data;
	size_t src_offset = (char *)(io_u->xfer_buf) - ccd->orig_buffer_aligned;
	size_t dst_offset = io_u->offset;

	int ret = rpma_write(ccd->conn,
			ccd->server_mr, dst_offset,
			ccd->orig_mr, src_offset,
			io_u->xfer_buflen,
			RPMA_F_COMPLETION_ON_ERROR,
			NULL);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_write");
		return -1;
	}

	return 0;
}

static inline int client_io_flush(struct thread_data *td,
		struct io_u *first_io_u, struct io_u *last_io_u,
		unsigned long long int len)
{
	struct librpma_common_client_data *ccd = td->io_ops_data;
	struct client_data *cd = (struct client_data *)ccd;
	size_t io_u_buf_off = IO_U_NEXT_BUF_OFF_CLIENT(cd);
	size_t send_offset = io_u_buf_off + SEND_OFFSET;
	size_t recv_offset = io_u_buf_off + RECV_OFFSET;
	void *send_ptr = cd->io_us_msgs + send_offset;
	void *recv_ptr = cd->io_us_msgs + recv_offset;
	GPSPMFlushRequest flush_req = GPSPM_FLUSH_REQUEST__INIT;
	size_t flush_req_size = 0;

	/* prepare a response buffer */
	int ret = rpma_recv(ccd->conn, cd->msg_mr, recv_offset, MAX_MSG_SIZE,
			recv_ptr);
	if (ret) {
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
			PRIu64 " > %d\n", flush_req_size,
			MAX_MSG_SIZE);
		return -1;
	}
	(void) gpspm_flush_request__pack(&flush_req, send_ptr);

	/* send the flush message */
	if ((ret = rpma_send(ccd->conn, cd->msg_mr, send_offset, flush_req_size,
			RPMA_F_COMPLETION_ALWAYS, NULL))) {
		librpma_td_verror(td, ret, "rpma_send");
		return -1;
	}

	return 0;
}

static enum fio_q_status client_queue_sync(struct thread_data *td,
					  struct io_u *io_u)
{
	struct librpma_common_client_data *ccd = td->io_ops_data;
	struct client_data *cd = (struct client_data *)ccd;
	struct rpma_completion cmpl;
	GPSPMFlushResponse *flush_resp;
	/* io_u->index of completed io_u (flush_resp->op_context) */
	unsigned int io_u_index;
	int ret;

	if (io_u->ddir != DDIR_WRITE) {
		log_err("unsupported IO mode: %s\n", io_ddir_name(io_u->ddir));
		return -1;
	}

	/* post an RDMA write operation */
	if ((ret = client_io_write(td, io_u)))
		goto err;
	if ((ret = client_io_flush(td, io_u, io_u, io_u->xfer_buflen)))
		goto err;

	do {
		/* get a completion */
		ret = rpma_conn_completion_get(ccd->conn, &cmpl);
		if (ret == RPMA_E_NO_COMPLETION) {
			/* lack of completion is not an error */
			continue;
		} else if (ret != 0) {
			/* an error occurred */
			librpma_td_verror(td, ret, "rpma_conn_completion_get");
			goto err;
		}

		/* if io_us has completed with an error */
		if (cmpl.op_status != IBV_WC_SUCCESS)
			goto err;

		if (cmpl.op == RPMA_OP_SEND)
			++cd->msg_send_completed;
		else if (cmpl.op == RPMA_OP_RECV)
			break;
	} while (1);

	/* unpack a response from the received buffer */
	flush_resp = gpspm_flush_response__unpack(NULL, cmpl.byte_len,
			cmpl.op_context);
	if (flush_resp == NULL) {
		log_err("Cannot unpack the flush response buffer\n");
		goto err;
	}

	memcpy(&io_u_index, &flush_resp->op_context, sizeof(unsigned int));
	if (io_u->index != io_u_index) {
		log_err(
			"no matching io_u for received completion found (io_u_index=%u)\n",
			io_u_index);
		goto err;
	}

	return FIO_Q_COMPLETED;

err:
	io_u->error = -1;
	return FIO_Q_COMPLETED;
}

static enum fio_q_status client_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	struct librpma_common_client_data *ccd = td->io_ops_data;

	if (ccd->io_u_queued_nr == (int)td->o.iodepth)
		return FIO_Q_BUSY;

	if (td->o.sync_io)
		return client_queue_sync(td, io_u);

	/* io_u -> queued[] */
	ccd->io_us_queued[ccd->io_u_queued_nr] = io_u;
	ccd->io_u_queued_nr++;

	return FIO_Q_QUEUED;
}

static int client_commit(struct thread_data *td)
{
	struct librpma_common_client_data *ccd = td->io_ops_data;
	struct timespec now;
	bool fill_time;
	int ret;
	int i;
	struct io_u *flush_first_io_u = NULL;
	unsigned long long int flush_len = 0;

	if (!ccd->io_us_queued)
		return -1;

	/* execute all io_us from queued[] */
	for (i = 0; i < ccd->io_u_queued_nr; i++) {
		struct io_u *io_u = ccd->io_us_queued[i];

		if (io_u->ddir != DDIR_WRITE) {
			log_err("unsupported IO mode: %s\n", io_ddir_name(io_u->ddir));
			return -1;
		}

		/* post an RDMA write operation */
		ret = client_io_write(td, io_u);
		if (ret)
			return -1;

		/* cache the first io_u in the sequence */
		if (flush_first_io_u == NULL)
			flush_first_io_u = io_u;

		/*
		 * the flush length is the sum of all io_u's creating
		 * the sequence
		 */
		flush_len += io_u->xfer_buflen;

		/*
		 * if io_u's are random the rpma_flush is required after
		 * each one of them
		 */
		if (!td_random(td)) {
			/*
			 * When the io_u's are sequential and the current
			 * io_u is not the last one and the next one is also
			 * a write operation the flush can be postponed by
			 * one io_u and cover all of them which build up
			 * a continuous sequence.
			 */
			if (i + 1 < ccd->io_u_queued_nr &&
					ccd->io_us_queued[i + 1]->ddir == DDIR_WRITE)
				continue;
		}

		/* flush all writes which build a continuous sequence */
		ret = client_io_flush(td, flush_first_io_u, io_u, flush_len);
		if (ret)
			return -1;

		/*
		 * reset the flush parameters in preparation for
		 * the next one
		 */
		flush_first_io_u = NULL;
		flush_len = 0;
	}

	if ((fill_time = fio_fill_issue_time(td)))
		fio_gettime(&now, NULL);

	/* move executed io_us from queued[] to flight[] */
	for (i = 0; i < ccd->io_u_queued_nr; i++) {
		struct io_u *io_u = ccd->io_us_queued[i];

		/* FIO does not do this if the engine is asynchronous */
		if (fill_time)
			memcpy(&io_u->issue_time, &now, sizeof(now));

		/* move executed io_us from queued[] to flight[] */
		ccd->io_us_flight[ccd->io_u_flight_nr] = io_u;
		ccd->io_u_flight_nr++;

		/*
		 * FIO says:
		 * If an engine has the commit hook it has to call io_u_queued() itself.
		 */
		io_u_queued(td, io_u);
	}

	/* FIO does not do this if an engine has the commit hook. */
	io_u_mark_submit(td, ccd->io_u_queued_nr);
	ccd->io_u_queued_nr = 0;

	return 0;
}

static int client_getevent_process(struct thread_data *td)
{
	struct librpma_common_client_data *ccd = td->io_ops_data;
	struct client_data *cd = (struct client_data *)ccd;
	struct rpma_completion cmpl;
	/* io_u->index of completed io_u (cmpl.op_context) */
	unsigned int io_u_index;
	/* # of completed io_us */
	int cmpl_num = 0;
	/* helpers */
	struct io_u *io_u;
	GPSPMFlushResponse *flush_resp;
	int i;
	int ret;

	/* get a completion */
	if ((ret = rpma_conn_completion_get(ccd->conn, &cmpl))) {
		/* lack of completion is not an error */
		if (ret == RPMA_E_NO_COMPLETION) {
			/* lack of completion is not an error */
			return 0;
		}

		/* an error occurred */
		librpma_td_verror(td, ret, "rpma_conn_completion_get");
		return -1;
	}

	/* if io_us has completed with an error */
	if (cmpl.op_status != IBV_WC_SUCCESS) {
		td->error = cmpl.op_status;
		return -1;
	}

	if (cmpl.op != RPMA_OP_RECV) {
		if (cmpl.op == RPMA_OP_SEND)
			++cd->msg_send_completed;

		return 0;
	}

	/* unpack a response from the received buffer */
	flush_resp = gpspm_flush_response__unpack(NULL, cmpl.byte_len,
			cmpl.op_context);
	if (flush_resp == NULL) {
		log_err("Cannot unpack the flush response buffer\n");
		return -1;
	}

	/* look for an io_u being completed */
	memcpy(&io_u_index, &flush_resp->op_context, sizeof(unsigned int));
	for (i = 0; i < ccd->io_u_flight_nr; ++i) {
		if (ccd->io_us_flight[i]->index == io_u_index) {
			cmpl_num = i + 1;
			break;
		}
	}

	gpspm_flush_response__free_unpacked(flush_resp, NULL);

	/* if no matching io_u has been found */
	if (cmpl_num == 0) {
		log_err(
			"no matching io_u for received completion found (io_u_index=%u)\n",
			io_u_index);
		return -1;
	}

	/* move completed io_us to the completed in-memory queue */
	for (i = 0; i < cmpl_num; ++i) {
		/* get and prepare io_u */
		io_u = ccd->io_us_flight[i];

		/* append to the queue */
		ccd->io_us_completed[ccd->io_u_completed_nr] = io_u;
		ccd->io_u_completed_nr++;
	}

	/* remove completed io_us from the flight queue */
	for (i = cmpl_num; i < ccd->io_u_flight_nr; ++i)
		ccd->io_us_flight[i - cmpl_num] = ccd->io_us_flight[i];
	ccd->io_u_flight_nr -= cmpl_num;

	return cmpl_num;
}

static int client_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, const struct timespec *t)
{
	/* total # of completed io_us */
	int cmpl_num_total = 0;
	/* # of completed io_us from a single event */
	int cmpl_num;

	do {
		cmpl_num = client_getevent_process(td);
		if (cmpl_num > 0) {
			/* new completions collected */
			cmpl_num_total += cmpl_num;
		} else if (cmpl_num == 0) {
			if (cmpl_num_total >= min)
				break;

			/* To reduce CPU consumption one can use
			 * the rpma_conn_completion_wait() function.
			 * Note this greatly increase the latency
			 * and make the results less stable.
			 * The bandwidth stays more or less the same.
			 */
		} else {
			/* an error occurred */
			return -1;
		}
	} while (cmpl_num_total < max);

	return cmpl_num_total;
}

static struct io_u *client_event(struct thread_data *td, int event)
{
	struct librpma_common_client_data *ccd = td->io_ops_data;
	struct io_u *io_u;
	int i;

	/* get the first io_u from the queue */
	io_u = ccd->io_us_completed[0];

	/* remove the first io_u from the queue */
	for (i = 1; i < ccd->io_u_completed_nr; ++i)
		ccd->io_us_completed[i - 1] = ccd->io_us_completed[i];
	ccd->io_u_completed_nr--;

	dprint_io_u(io_u, "client_event");

	return io_u;
}

static char *client_errdetails(struct io_u *io_u)
{
	/* get the string representation of an error */
	enum ibv_wc_status status = io_u->error;
	const char *status_str = ibv_wc_status_str(status);

	/* allocate and copy the error string representation */
	char *details = malloc(strlen(status_str) + 1);
	strcpy(details, status_str);

	/* FIO frees the returned string when it becomes obsolete */
	return details;
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
	.option_struct_size	= sizeof(struct librpma_common_client_options),
};

/* server side implementation */

#define IO_U_BUFF_OFF_SERVER(i) (i * IO_U_BUF_LEN)

struct server_options {
	/*
	 * FIO considers .off1 == 0 absent so the first meaningful field has to
	 * have padding ahead of it.
	 */
	void *pad;
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
		.name	= NULL,
	},
};

struct server_data {
	struct rpma_peer *peer;

	/* aligned td->orig_buffer */
	char *orig_buffer_aligned;

	/* resources of an incoming connection */
	struct rpma_conn *conn;

	struct librpma_common_mem mem;
	char *ws_ptr;
	struct rpma_mr_local *ws_mr;

	/* resources for messaging buffer from DRAM allocated by fio */
	struct rpma_mr_local *msg_mr;

	uint32_t msg_sqe_available; /* # of free SQ slots */

	/* in-memory queues */
	struct rpma_completion *msgs_queued;
	uint32_t msg_queued_nr;
};

static int server_init(struct thread_data *td)
{
	struct server_options *o = td->eo;
	struct server_data *sd;
	struct ibv_context *dev = NULL;
	int ret = 1;

	/* configure logging thresholds to see more details */
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD, RPMA_LOG_LEVEL_INFO);
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD_AUX, RPMA_LOG_LEVEL_INFO);

	/* allocate server's data */
	sd = calloc(1, sizeof(struct server_data));
	if (sd == NULL) {
		td_verror(td, errno, "calloc");
		return 1;
	}

	/* allocate in-memory queue */
	sd->msgs_queued = calloc(td->o.iodepth, sizeof(struct rpma_completion));
	if (sd->msgs_queued == NULL) {
		td_verror(td, errno, "calloc");
		goto err_free_sd;
	}

	/* obtain an IBV context for a local IP address */
	ret = rpma_utils_get_ibv_context(o->bindname,
				RPMA_UTIL_IBV_CONTEXT_LOCAL,
				&dev);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_utils_get_ibv_context");
		goto err_free_msg_queue;
	}

	/* create a new peer object */
	ret = rpma_peer_new(dev, &sd->peer);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_peer_new");
		goto err_free_sd;
	}

	td->io_ops_data = sd;

	return 0;

err_free_msg_queue:
	free(sd->msgs_queued);

err_free_sd:
	free(sd);

	return 1;
}

static int server_post_init(struct thread_data *td)
{
	struct server_data *sd = td->io_ops_data;
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
	 * Aligning each of those buffers may potentially give some performance benefits.
	 */
	io_u_buflen = td_max_bs(td);

	/* check whether io_u buffer is big enough */
	if (io_u_buflen < IO_U_BUF_LEN) {
		log_err("blocksize too small to accommodate assumed maximal request/response pair size (%" PRIu64 " < %d)\n",
				io_u_buflen, IO_U_BUF_LEN);
		return 1;
	}

	/*
	 * td->orig_buffer_size beside the space really consumed by io_us
	 * has paddings which can be omitted for the memory registration.
	 */
	io_us_size = (unsigned long long)io_u_buflen *
			(unsigned long long)td->o.iodepth;

	ret = rpma_mr_reg(sd->peer, sd->orig_buffer_aligned, io_us_size,
			RPMA_MR_USAGE_SEND | RPMA_MR_USAGE_RECV,
			&sd->msg_mr);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_mr_reg");
		return 1;
	}

	return 0;
}

static void server_cleanup(struct thread_data *td)
{
	struct server_data *sd =  td->io_ops_data;
	int ret;

	if (sd == NULL)
		return;

	/* rpma_mr_dereg(messaging buffer from DRAM) */
	if ((ret = rpma_mr_dereg(&sd->msg_mr)))
		librpma_td_verror(td, ret, "rpma_mr_dereg");

	/* free the peer */
	if ((ret = rpma_peer_delete(&sd->peer)))
		librpma_td_verror(td, ret, "rpma_peer_delete");

	free(sd->msgs_queued);
	free(sd);
}

static int server_open_file(struct thread_data *td, struct fio_file *f)
{
	struct server_data *sd =  td->io_ops_data;
	struct server_options *o = td->eo;
	enum rpma_conn_event conn_event = RPMA_CONN_UNDEFINED;
	size_t mem_size = td->o.size;
	struct rpma_conn_private_data pdata;
	struct rpma_mr_local *mmap_mr;
	struct workspace ws;
	struct rpma_conn_cfg *cfg = NULL;
	struct rpma_conn_req *conn_req;
	struct rpma_conn *conn;
	char port_td[LIBRPMA_COMMON_PORT_STR_LEN_MAX];
	struct rpma_ep *ep;
	size_t mr_desc_size;
	void *ws_ptr;
	int ret;
	int i;

	if (!f->file_name) {
		log_err("fio: filename is not set\n");
		return 1;
	}

	/* verify whether iodepth fits into uint16_t */
	if (td->o.iodepth > UINT16_MAX) {
		log_err("fio: iodepth too big (%u > %u)\n", td->o.iodepth, UINT16_MAX);
		return 1;
	}
	ws.max_msg_num = td->o.iodepth;

	/* start a listening endpoint at addr:port */
	if ((ret = librpma_common_td_port(o->port, td, port_td)))
		return 1;

	ret = rpma_ep_listen(sd->peer, o->bindname, port_td, &ep);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_ep_listen");
		return 1;
	}

	/* allocation from PMEM using pmem_map_file() */
	ws_ptr = librpma_common_allocate_pmem(td, f->file_name, mem_size,
			&sd->mem);
	if (ws_ptr == NULL)
		goto err_ep_shutdown;

	f->real_file_size = mem_size;

	ret = rpma_mr_reg(sd->peer, ws_ptr, mem_size,
			RPMA_MR_USAGE_READ_DST | RPMA_MR_USAGE_READ_SRC |
			RPMA_MR_USAGE_WRITE_DST | RPMA_MR_USAGE_WRITE_SRC,
			&mmap_mr);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_mr_reg");
		goto err_pmem_unmap;
	}

	/* get size of the memory region's descriptor */
	ret = rpma_mr_get_descriptor_size(mmap_mr, &mr_desc_size);
	if (ret)
		goto err_mr_dereg;

	/* get the memory region's descriptor */
	if ((ret = rpma_mr_get_descriptor(mmap_mr, &ws.descriptors[0])))
		goto err_mr_dereg;

	/* calculate data for the server read */
	ws.mr_desc_size = mr_desc_size;
	pdata.ptr = &ws;
	pdata.len = sizeof(struct workspace);

	/* create a connection configuration object */
	ret = rpma_conn_cfg_new(&cfg);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_new");
		goto err_mr_dereg;
	}

	/*
	 * Calculate the required queue sizes where:
	 * - the send queue (SQ) has to be big enough to accommodate
	 *   all possible flush requests (SENDs)
	 * - the receive queue (RQ) has to be big enough to accommodate all flush
	 *   responses (RECVs)
	 * - the completion queue (CQ) has to be big enough to accommodate all
	 *   success and error completions (sq_size + rq_size)
	 */
	ret = rpma_conn_cfg_set_sq_size(cfg, ws.max_msg_num);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_set_sq_size");
		goto err_cfg_delete;
	}
	ret = rpma_conn_cfg_set_rq_size(cfg, ws.max_msg_num);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_set_rq_size");
		goto err_cfg_delete;
	}
	ret = rpma_conn_cfg_set_cq_size(cfg, ws.max_msg_num * 2);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_set_cq_size");
		goto err_cfg_delete;
	}

	/* receive an incoming connection request */
	if ((ret = rpma_ep_next_conn_req(ep, cfg, &conn_req)))
		goto err_cfg_delete;

	ret = rpma_conn_cfg_delete(&cfg);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_delete");
		goto err_req_delete;
	}

	/* prepare buffers for a flush requests */
	sd->msg_sqe_available = td->o.iodepth;
	for (i = 0; i < td->o.iodepth; i++) {
		size_t offset_recv_msg = IO_U_BUFF_OFF_SERVER(i) + RECV_OFFSET;
		if ((ret = rpma_conn_req_recv(conn_req, sd->msg_mr,
				offset_recv_msg, MAX_MSG_SIZE,
				(const void *)(uintptr_t)i)))
			goto err_req_delete;
	}

	/* accept the connection request and obtain the connection object */
	if ((ret = rpma_conn_req_connect(&conn_req, &pdata, &conn)))
		goto err_conn_delete;

	/* wait for the connection to be established */
	ret = rpma_conn_next_event(conn, &conn_event);
	if (ret)
		librpma_td_verror(td, ret, "rpma_conn_next_event");
	if (!ret && conn_event != RPMA_CONN_ESTABLISHED)
		log_err("rpma_conn_next_event returned an unexptected event\n");
	if (ret)
		goto err_conn_delete;

	/* end-point is no longer needed */
	(void) rpma_ep_shutdown(&ep);

	sd->ws_ptr = ws_ptr;
	sd->ws_mr = mmap_mr;
	sd->conn = conn;

	return 0;

err_conn_delete:
	(void) rpma_conn_delete(&conn);

err_req_delete:
	(void) rpma_conn_req_delete(&conn_req);

err_cfg_delete:
	(void) rpma_conn_cfg_delete(&cfg);

err_mr_dereg:
	(void) rpma_mr_dereg(&mmap_mr);

err_pmem_unmap:
	librpma_common_free(&sd->mem);

err_ep_shutdown:
	(void) rpma_ep_shutdown(&ep);

	return 1;
}

static int server_close_file(struct thread_data *td, struct fio_file *f)
{
	struct server_data *sd =  td->io_ops_data;
	enum rpma_conn_event conn_event = RPMA_CONN_UNDEFINED;
	int ret;
	int rv;

	/* wait for the connection to be closed */
	ret = rpma_conn_next_event(sd->conn, &conn_event);
	if (!ret && conn_event != RPMA_CONN_CLOSED) {
		log_err("rpma_conn_next_event returned an unexptected event\n");
		rv = 1;
	}

	if ((ret = rpma_conn_disconnect(sd->conn))) {
		librpma_td_verror(td, ret, "rpma_conn_disconnect");
		rv |= ret;
	}

	if ((ret = rpma_conn_delete(&sd->conn))) {
		librpma_td_verror(td, ret, "rpma_conn_delete");
		rv |= ret;
	}

	if ((ret = rpma_mr_dereg(&sd->ws_mr))) {
		librpma_td_verror(td, ret, "rpma_mr_dereg");
		rv |= ret;
	}

	librpma_common_free(&sd->mem);

	return rv ? -1 : 0;
}

static int server_qe_process(struct thread_data *td, struct rpma_completion *cmpl)
{
	struct server_data *sd = td->io_ops_data;
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
	flush_req = gpspm_flush_request__unpack(NULL, cmpl->byte_len, recv_buff_ptr);
	if (flush_req == NULL) {
		log_err("cannot unpack the flush request buffer\n");
		goto err_terminate;
	}

	if (IS_NOT_THE_LAST_MESSAGE(flush_req)) {
		op_ptr = sd->ws_ptr + flush_req->offset;
		pmem_persist(op_ptr, flush_req->length);
	} else {
		/*
		 * This is the last message - the client is done.
		 */
		td->done = true;
		return 0;
	}

	/* initiate the next receive operation */
	ret = rpma_recv(sd->conn, sd->msg_mr, recv_buff_offset,
			MAX_MSG_SIZE, (const void *)(uintptr_t)msg_index);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_recv");
		goto err_terminate;
	}

	/* prepare a flush response and pack it to a send buffer */
	flush_resp.op_context = flush_req->op_context;
	flush_resp_size = gpspm_flush_response__get_packed_size(&flush_resp);
	if (flush_resp_size > MAX_MSG_SIZE) {
		log_err("Size of the packed flush response is bigger than the available space of the send buffer (%"
			PRIu64 " > %i\n", flush_resp_size, MAX_MSG_SIZE);
		goto err_terminate;
	}

	(void) gpspm_flush_response__pack(&flush_resp, send_buff_ptr);
	gpspm_flush_request__free_unpacked(flush_req, NULL);

	/* send the flush response */
	if ((ret = rpma_send(sd->conn, sd->msg_mr, send_buff_offset, flush_resp_size,
			RPMA_F_COMPLETION_ALWAYS, NULL)))
		goto err_terminate;
	--sd->msg_sqe_available;

	return 0;

err_terminate:
	td->terminate = true;

	return -1;
}

static inline int server_queue_process(struct thread_data *td)
{
	struct server_data *sd = td->io_ops_data;
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
		memcpy(&sd->msgs_queued[i], &sd->msgs_queued[qes_to_process + i],
				sizeof(struct rpma_completion));
	}
	sd->msg_queued_nr -= qes_to_process;

	return 0;
}

static int server_cmpl_process(struct thread_data *td)
{
	struct server_data *sd = td->io_ops_data;
	struct rpma_completion *cmpl = &sd->msgs_queued[sd->msg_queued_nr];
	int ret;

	ret = rpma_conn_completion_get(sd->conn, cmpl);
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

static enum fio_q_status server_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	int ret;

	do {
		if ((ret = server_cmpl_process(td)))
			return FIO_Q_BUSY;

		if ((ret = server_queue_process(td)))
			return FIO_Q_BUSY;

	} while (!td->done);

	return FIO_Q_COMPLETED;
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
