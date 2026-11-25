// SPDX-License-Identifier: GPL-3.0-or-later
/* The RAAT manager: device list, JSON-RPC over LL framing on TCP 9200-9250
 * (spec 5.2, 10, 13.1), persistent identity and per-device config (spec 5.5). */
#ifndef RAAT_MANAGER_H
#define RAAT_MANAGER_H

#include "common.h"

struct manager_opts {
	const char *data_dir;
	const char *bind_addr;
	int port; /* -1 = first free in 9200-9250, 0 = ephemeral */
	const char *raat_version;
};

int manager_start(const struct manager_opts *o);
int manager_port(void);
const char *manager_unique_id(void);
void manager_shutdown(void);

#endif
