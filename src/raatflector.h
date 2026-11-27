// SPDX-License-Identifier: GPL-3.0-or-later
/* Optional RAATflector client (ENABLE_RAATFLECTOR): receives reflected SOOD
 * queries from a RAATflector server over an L3 VPN (e.g. Tailscale) and feeds
 * them to sood_inject_query() so replies go directly to the Core over L3. */
#ifndef RAAT_RAATFLECTOR_H
#define RAAT_RAATFLECTOR_H

#include "common.h"

#ifdef ENABLE_RAATFLECTOR

int raatflector_start(const char *server, const char *token);
void raatflector_stop(void);

#else

static inline int raatflector_start(const char *server, const char *token)
{
	(void)server;
	(void)token;
	LOGE("[raatflector] not enabled in this build (rebuild with RAATFLECTOR=1)");
	return -1;
}
static inline void raatflector_stop(void) {}

#endif /* ENABLE_RAATFLECTOR */
#endif
