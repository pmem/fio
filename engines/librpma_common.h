/*
 * librpma_common: librpma and librpma_gpspm engine's common header
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

#ifndef LIBRPMA_COMMON_H
#define LIBRPMA_COMMON_H 1

#include "../fio.h"
#include "../optgroup.h"

#include <librpma.h>

#define librpma_td_verror(td, err, func) \
	td_vmsg((td), (err), rpma_err_2str(err), (func))

/* ceil(a / b) = (a + b - 1) / b */
#define LIBRPMA_CEIL(a, b) (((a) + (b) - 1) / (b))

/*
 * Limited by the maximum length of the private data
 * for rdma_connect() in case of RDMA_PS_TCP (28 bytes).
 */
#define DESCRIPTORS_MAX_SIZE 25

struct librpma_common_workspace {
	uint16_t max_msg_num;	/* # of RQ slots */
	uint8_t mr_desc_size;	/* size of mr_desc in descriptors[] */
	/* buffer containing mr_desc */
	char descriptors[DESCRIPTORS_MAX_SIZE];
};

/* clients' common */

struct librpma_common_client_options {
	/*
	 * FIO considers .off1 == 0 absent so the first meaningful field has to
	 * have padding ahead of it.
	 */
	void *pad;
	char *hostname;
	char *port;
};

extern struct fio_option librpma_common_fio_client_options[];

#define LIBRPMA_COMMON_PORT_STR_LEN_MAX 12

int librpma_common_td_port(const char *port_base_str, struct thread_data *td,
	char *port_out);

struct librpma_common_mem {
	/* memory buffer */
	char *mem_ptr;

	/* size of the mapped persistent memory */
	size_t size_mmap;
};

char *librpma_common_allocate_pmem(struct thread_data *td, const char *filename,
	size_t size, struct librpma_common_mem *mem);

void librpma_common_free(struct librpma_common_mem *mem);

typedef int (*flush_t)(struct thread_data *td,
		struct io_u *first_io_u, struct io_u *last_io_u,
		unsigned long long int len);

typedef int (*get_io_u_index_t)(struct rpma_completion *cmpl,
		unsigned int *io_u_index);

struct librpma_common_client_data {
	struct rpma_peer *peer;
	struct rpma_conn *conn;

	/* aligned td->orig_buffer */
	char *orig_buffer_aligned;

	/* ious's base address memory registration (cd->orig_buffer_aligned) */
	struct rpma_mr_local *orig_mr;

	struct librpma_common_workspace *ws;

	/* a server's memory representation */
	struct rpma_mr_remote *server_mr;

	/* remote workspace description */
	size_t ws_size;

	/* in-memory queues */
	struct io_u **io_us_queued;
	int io_u_queued_nr;
	struct io_u **io_us_flight;
	int io_u_flight_nr;
	struct io_u **io_us_completed;
	int io_u_completed_nr;

	/* completion counter */
	uint32_t op_send_completed;

	flush_t flush;
	get_io_u_index_t get_io_u_index;

	/* engine-specific client data */
	void *client_data;
};

int librpma_common_client_init(struct thread_data *td,
		struct rpma_conn_cfg *cfg);
void librpma_common_client_cleanup(struct thread_data *td);

int librpma_common_file_nop(struct thread_data *td, struct fio_file *f);
int librpma_common_client_get_file_size(struct thread_data *td,
		struct fio_file *f);

int librpma_common_client_post_init(struct thread_data *td);

enum fio_q_status librpma_common_client_queue(struct thread_data *td,
		struct io_u *io_u);

int librpma_common_client_commit(struct thread_data *td);

int librpma_common_client_getevents(struct thread_data *td, unsigned int min,
		unsigned int max, const struct timespec *t);

struct io_u *librpma_common_client_event(struct thread_data *td, int event);

char *librpma_common_client_errdetails(struct io_u *io_u);

static inline int librpma_common_client_io_read(struct thread_data *td,
		struct io_u *io_u, int flags)
{
	struct librpma_common_client_data *ccd = td->io_ops_data;
	size_t dst_offset = (char *)(io_u->xfer_buf) - ccd->orig_buffer_aligned;
	size_t src_offset = io_u->offset;
	int ret = rpma_read(ccd->conn,
			ccd->orig_mr, dst_offset,
			ccd->server_mr, src_offset,
			io_u->xfer_buflen,
			flags,
			(void *)(uintptr_t)io_u->index);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_read");
		return -1;
	}

	return 0;
}

static inline int librpma_common_client_io_write(struct thread_data *td,
		struct io_u *io_u)
{
	struct librpma_common_client_data *ccd = td->io_ops_data;
	size_t src_offset = (char *)(io_u->xfer_buf) - ccd->orig_buffer_aligned;
	size_t dst_offset = io_u->offset;

	int ret = rpma_write(ccd->conn,
			ccd->server_mr, dst_offset,
			ccd->orig_mr, src_offset,
			io_u->xfer_buflen,
			RPMA_F_COMPLETION_ON_ERROR,
			(void *)(uintptr_t)io_u->index);
	if (ret) {
		librpma_td_verror(td, ret, "rpma_write");
		return -1;
	}

	return 0;
}

/* servers' common */

struct librpma_common_server_options {
	/*
	 * FIO considers .off1 == 0 absent so the first meaningful field has to
	 * have padding ahead of it.
	 */
	void *pad;
	char *bindname;
	char *port;
};

extern struct fio_option librpma_common_fio_server_options[];

struct librpma_common_server_data {
	struct rpma_peer *peer;

	/* resources of an incoming connection */
	struct rpma_conn *conn;

	struct librpma_common_mem mem;

	/* engine-specific server data */
	void *server_data;
};

int librpma_common_server_init(struct thread_data *td);

void librpma_common_server_cleanup(struct thread_data *td);

#endif /* LIBRPMA_COMMON_H */
