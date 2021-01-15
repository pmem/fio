/*
 * librpma_common: librpma and librpma_gpspm engine's common.
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

#include "../fio.h"

#include "librpma_common.h"

#include <libpmem.h>

int librpma_common_td_port(const char *port_base_str,
		struct thread_data *td, char *port_out)
{
	unsigned long int port_ul = strtoul(port_base_str, NULL, 10);
	unsigned int port_new;

	port_out[0] = '\0';

	if (port_ul == ULONG_MAX) {
		td_verror(td, errno, "strtoul");
		return -1;
	}
	port_ul += td->thread_number - 1;
	if (port_ul >= UINT_MAX) {
		log_err("[%u] port number (%lu) bigger than UINT_MAX\n",
			td->thread_number, port_ul);
		return -1;
	}

	port_new = port_ul;
	snprintf(port_out, LIBRPMA_COMMON_PORT_STR_LEN_MAX - 1, "%u", port_new);

	return 0;
}


char *librpma_common_allocate_pmem(struct thread_data *td, const char *filename,
	size_t size, struct librpma_common_mem *mem)
{
	size_t size_mmap = 0;
	char *mem_ptr = NULL;
	int is_pmem = 0;
	/* XXX assuming size is page aligned */
	size_t ws_offset = (td->thread_number - 1) * size;

	if (!filename) {
		log_err("fio: filename is not set\n");
		return NULL;
	}

	/* map the file */
	mem_ptr = pmem_map_file(filename, 0 /* len */, 0 /* flags */,
			0 /* mode */, &size_mmap, &is_pmem);
	if (mem_ptr == NULL) {
		log_err("fio: pmem_map_file(%s) failed\n", filename);
		/* pmem_map_file() sets errno on failure */
		td_verror(td, errno, "pmem_map_file");
		return NULL;
	}

	/* pmem is expected */
	if (!is_pmem) {
		log_err("fio: %s is not located in persistent memory\n", filename);
		goto err_unmap;
	}

	/* check size of allocated persistent memory */
	if (size_mmap < ws_offset + size) {
		log_err(
			"fio: %s is too small to handle so many threads (%zu < %zu)\n",
			filename, size_mmap, ws_offset + size);
		goto err_unmap;
	}

	log_info("fio: size of memory mapped from the file %s: %zu\n",
		filename, size_mmap);

	mem->mem_ptr = mem_ptr;
	mem->size_mmap = size_mmap;

	return mem_ptr + ws_offset;

err_unmap:
	(void) pmem_unmap(mem_ptr, size_mmap);
	return NULL;
}

void librpma_common_free(struct librpma_common_mem *mem)
{
	if (mem->size_mmap)
		(void) pmem_unmap(mem->mem_ptr, mem->size_mmap);
	else
		free(mem->mem_ptr);
}

int librpma_common_client_init(struct thread_data *td,
		struct librpma_common_client_data *ccd,
		struct rpma_conn_cfg *cfg)
{
	struct librpma_common_client_options *o = td->eo;
	struct ibv_context *dev = NULL;
	char port_td[LIBRPMA_COMMON_PORT_STR_LEN_MAX];
	struct rpma_conn_req *req = NULL;
	enum rpma_conn_event event;
	struct rpma_conn_private_data pdata;
	int ret;

	/* configure logging thresholds to see more details */
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD, RPMA_LOG_LEVEL_INFO);
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD_AUX, RPMA_LOG_LEVEL_INFO);

	/* allocate all in-memory queues */
	ccd->io_us_queued = calloc(td->o.iodepth, sizeof(struct io_u *));
	if (ccd->io_us_queued == NULL) {
		td_verror(td, errno, "calloc");
		return 1;
	}

	ccd->io_us_flight = calloc(td->o.iodepth, sizeof(struct io_u *));
	if (ccd->io_us_flight == NULL) {
		td_verror(td, errno, "calloc");
		free(ccd->io_us_queued);
		return 1;
	}

	ccd->io_us_completed = calloc(td->o.iodepth, sizeof(struct io_u *));
	if (ccd->io_us_completed == NULL) {
		td_verror(td, errno, "calloc");
		free(ccd->io_us_queued);
		free(ccd->io_us_flight);
		return 1;
	}

	/* obtain an IBV context for a remote IP address */
	ret = rpma_utils_get_ibv_context(o->hostname,
				RPMA_UTIL_IBV_CONTEXT_REMOTE,
				&dev);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_utils_get_ibv_context");
		goto err_free_io_u_queues;
	}

	/* create a new peer object */
	ret = rpma_peer_new(dev, &ccd->peer);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_peer_new");
		goto err_free_io_u_queues;
	}

	/* create a connection request */
	if ((ret = librpma_common_td_port(o->port, td, port_td)))
		goto err_peer_delete;
	ret = rpma_conn_req_new(ccd->peer, o->hostname, port_td, cfg, &req);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_conn_req_new");
		goto err_peer_delete;
	}

	ret = rpma_conn_cfg_delete(&cfg);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_conn_cfg_delete");
		goto err_peer_delete;
	}

	/* connect the connection request and obtain the connection object */
	ret = rpma_conn_req_connect(&req, NULL, &ccd->conn);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_conn_req_connect");
		goto err_req_delete;
	}

	/* wait for the connection to establish */
	ret = rpma_conn_next_event(ccd->conn, &event);
	if (ret) {
		goto err_conn_delete;
	} else if (event != RPMA_CONN_ESTABLISHED) {
		log_err(
			"rpma_conn_next_event returned an unexptected event: (%s != RPMA_CONN_ESTABLISHED)\n",
			rpma_utils_conn_event_2str(event));
		goto err_conn_delete;
	}

	/* get the connection's private data sent from the server */
	if ((ret = rpma_conn_get_private_data(ccd->conn, &pdata)))
		goto err_conn_delete;

	/* get the server's workspace representation */
	ccd->ws = pdata.ptr;

	/* create the server's memory representation */
	if ((ret = rpma_mr_remote_from_descriptor(&ccd->ws->descriptors[0],
			ccd->ws->mr_desc_size, &ccd->server_mr)))
		goto err_conn_delete;

	/* get the total size of the shared server memory */
	if ((ret = rpma_mr_remote_get_size(ccd->server_mr, &ccd->ws_size))) {
		librpma_td_verror(td, ret, "rpma_mr_remote_get_size");
		goto err_conn_delete;
	}

	return 0;

err_conn_delete:
	(void) rpma_conn_disconnect(ccd->conn);
	(void) rpma_conn_delete(&ccd->conn);

err_req_delete:
	(void) rpma_conn_req_delete(&req);

err_peer_delete:
	(void) rpma_peer_delete(&ccd->peer);

err_free_io_u_queues:
	free(ccd->io_us_queued);
	free(ccd->io_us_flight);
	free(ccd->io_us_completed);

	return 1;
}

int librpma_common_file_nop(struct thread_data *td, struct fio_file *f)
{
	/* NOP */
	return 0;
}

static enum fio_q_status client_queue_sync(struct thread_data *td,
					  struct io_u *io_u)
{
	struct librpma_common_client_data *ccd = td->io_ops_data;
	struct rpma_completion cmpl;
	unsigned int io_u_index;
	int ret;

	/* execute io_u */
	if (io_u->ddir == DDIR_READ) {
		/* post an RDMA read operation */
		if ((ret = librpma_common_client_io_read(td, io_u, RPMA_F_COMPLETION_ALWAYS)))
			goto err;
	} else if (io_u->ddir == DDIR_WRITE) {
		/* post an RDMA write operation */
		if ((ret = librpma_common_client_io_write(td, io_u)))
			goto err;
		if ((ret = ccd->flush(td, io_u, io_u, io_u->xfer_buflen)))
			goto err;
	} else {
		log_err("unsupported IO mode: %s\n", io_ddir_name(io_u->ddir));
		goto err;
	}

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
			++ccd->op_send_completed;
		else
			break;
	} while (1);

	if (ccd->get_io_u(&cmpl, &io_u_index))
		goto err;

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

enum fio_q_status librpma_common_client_queue(struct thread_data *td,
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
