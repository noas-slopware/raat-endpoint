// SPDX-License-Identifier: GPL-3.0-or-later
/* SOOD discovery (spec 4): answers 'Q' queries for the RAAT service id with a
 * unicast 'R', and announces itself with a multicast 'Q' at start and when the
 * interface addresses change (with multicast enabled only). */
#ifndef RAAT_SOOD_H
#define RAAT_SOOD_H

#include "common.h"

#define RAAT_SERVICE_ID "d7634b85-8190-470f-aa51-6cb5538dc1b9"

struct sood_kv {
	const char *key, *value;
};

/* kv: reply keys (service_id included), NULL-terminated, copied. */
int sood_start(const char *bind_addr, int port, bool join_multicast, const struct sood_kv *kv);
int sood_port(void);
/* a Core connected to the manager: stop the announce backoff */
void sood_core_connected(void);
void sood_stop(void);

#endif
