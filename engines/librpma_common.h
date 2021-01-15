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

#endif /* LIBRPMA_COMMON_H */
