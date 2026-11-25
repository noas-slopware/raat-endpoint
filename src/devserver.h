// SPDX-License-Identifier: GPL-3.0-or-later
/* Per-device LL server on an ephemeral IPv4 port (spec 5.3): get_info,
 * get_log, clear_log, load_script, and session messages to and from Lua. */
#ifndef RAAT_DEVSERVER_H
#define RAAT_DEVSERVER_H

#include "device.h"

typedef struct devserver devserver_t;

devserver_t *devserver_start(mdev_t *d, const char *bindaddr);
/* Destroys every session (shutdown handlers run), closes the listener. */
void devserver_stop(devserver_t *ds);
int devserver_port(devserver_t *ds);

/* The device info dictionary (spec 5.3, 13.1), without tcp_port. */
struct cJSON *device_info_json(mdev_t *d);

#endif
