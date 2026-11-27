// SPDX-License-Identifier: GPL-3.0-or-later
/* Shared library smoke test: links against libraat-endpoint.so and verifies
 * start -> live ports -> log callback -> stop -> restart in the same process. */
#define _POSIX_C_SOURCE 200809L
#include "raat_endpoint.h"

#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static _Atomic int g_logs;

static void on_log(int level, const char *msg, void *ud)
{
	(void)level;
	(void)msg;
	(void)ud;
	atomic_fetch_add(&g_logs, 1);
}

int main(void)
{
	char tmp[] = "/tmp/raat-lib-test-XXXXXX";
	assert(mkdtemp(tmp) != NULL);

	raat_endpoint_config_t cfg;
	raat_endpoint_config_init(&cfg);
	cfg.data_dir = tmp;
	cfg.bind_addr = "127.0.0.1";
	cfg.manager_port = 0;
	cfg.sood_port = 0;
	cfg.no_multicast = true;
	cfg.log_level = RAAT_LOG_INFO;
	cfg.log_cb = on_log;

	assert(raat_endpoint_start(&cfg) == 0);
	int mp1 = raat_endpoint_manager_port();
	int sp1 = raat_endpoint_sood_port();
	char uid1[64];
	snprintf(uid1, sizeof uid1, "%s", raat_endpoint_unique_id());
	assert(mp1 > 0);
	assert(sp1 > 0);
	assert(strlen(uid1) == 36);
	assert(atomic_load(&g_logs) > 0);

	raat_endpoint_stop();

	/* Restart in the same process: state must be clean and unique_id preserved. */
	assert(raat_endpoint_start(&cfg) == 0);
	assert(raat_endpoint_manager_port() > 0);
	assert(raat_endpoint_sood_port() > 0);
	assert(strcmp(raat_endpoint_unique_id(), uid1) == 0);
	raat_endpoint_stop();

	printf("libraat-endpoint.so test passed (pipewire=%d, raatflector=%d, logs=%d)\n",
	       raat_endpoint_has_pipewire(), raat_endpoint_has_raatflector(),
	       atomic_load(&g_logs));
	return 0;
}
