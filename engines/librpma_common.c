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
