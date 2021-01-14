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

#define librpma_td_verror(td, err, func) \
	td_vmsg((td), (err), rpma_err_2str(err), (func))

/* ceil(a / b) = (a + b - 1) / b */
#define LIBRPMA_CEIL(a, b) (((a) + (b) - 1) / (b))

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

struct librpma_common_client_data {
	struct rpma_peer *peer;
	struct rpma_conn *conn;

	/* in-memory queues */
	struct io_u **io_us_queued;
	int io_u_queued_nr;
	struct io_u **io_us_flight;
	int io_u_flight_nr;
	struct io_u **io_us_completed;
	int io_u_completed_nr;
};

int librpma_common_client_init(struct thread_data *td, struct rpma_conn_cfg *cfg,
		struct librpma_common_client_data *ccd);

#endif /* LIBRPMA_COMMON_H */
