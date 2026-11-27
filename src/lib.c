// SPDX-License-Identifier: GPL-3.0-or-later
/* Library facade for raat-endpoint (shared by libraat-endpoint.so and the CLI). */
#include "raat_endpoint.h"
#include "common.h"
#include "loop.h"
#include "manager.h"
#include "output.h"
#include "platform.h"
#include "raatflector.h"
#include "session.h"
#include "sood.h"
#include "stream.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct {
	bool inited;
	bool no_sood;
	bool has_thread;
	pthread_t th;
	pthread_mutex_t mu;
	pthread_cond_t cv;
	bool ready;
	int init_rc;
	raat_endpoint_config_t bg_cfg;
	char *bg_strs[10];
	char default_data_dir[1024];
} L = { .mu = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER };

static void machine_id_derive(char out[37], const char *fallback)
{
	char *m = file_read("/etc/machine-id", NULL);
	if (m) {
		str_rtrim(m);
		if (strlen(m) == 32) {
			snprintf(out, 37, "%.8s-%.4s-%.4s-%.4s-%.12s", m, m + 8, m + 12, m + 16, m + 20);
			free(m);
			return;
		}
		free(m);
	}
	strlcpy0(out, fallback, 37);
}

static void machine_id(char out[37], const char *data_dir, const char *fallback)
{
	char path[1100];
	snprintf(path, sizeof path, "%s/Settings/machine_id", data_dir);
	char *m = file_read(path, NULL);
	if (m) {
		str_rtrim(m);
		if (strlen(m) == 36) {
			strlcpy0(out, m, 37);
			free(m);
			return;
		}
		free(m);
	}
	machine_id_derive(out, fallback);
	if (file_write(path, out, 36) < 0)
		LOGW("cannot persist machine_id: %s", strerror(errno));
}

static const char *resolve_data_dir(const char *given)
{
	if (given && given[0])
		return given;
	if (geteuid() == 0)
		return "/var/lib/raat-endpoint";
	const char *xdg = getenv("XDG_DATA_HOME");
	if (xdg && xdg[0]) {
		snprintf(L.default_data_dir, sizeof L.default_data_dir, "%s/raat-endpoint", xdg);
		return L.default_data_dir;
	}
	const char *home = getenv("HOME");
	if (home && home[0]) {
		snprintf(L.default_data_dir, sizeof L.default_data_dir,
			 "%s/.local/share/raat-endpoint", home);
		return L.default_data_dir;
	}
	return "/var/lib/raat-endpoint";
}

RAAT_API void raat_endpoint_config_init(raat_endpoint_config_t *cfg)
{
	if (!cfg)
		return;
	memset(cfg, 0, sizeof *cfg);
	cfg->manager_port = -1;
	cfg->sood_port = 9003;
	cfg->backend = RAAT_BACKEND_ALSA;
	cfg->raat_version = "1.1.38";
	cfg->alsa_buffer_ms = 40;
	cfg->log_level = RAAT_LOG_INFO;
}

RAAT_API int raat_endpoint_init(const raat_endpoint_config_t *cfg)
{
	if (!cfg || L.inited)
		return -1;

	g_log_level = cfg->log_level;
	log_set_cb(cfg->log_cb, cfg->log_ud);

	const char *data_dir = resolve_data_dir(cfg->data_dir);
	const char *bind_addr = (cfg->bind_addr && cfg->bind_addr[0]) ? cfg->bind_addr : "0.0.0.0";
	const char *raat_version =
		(cfg->raat_version && cfg->raat_version[0]) ? cfg->raat_version : "1.1.38";
	int sport = cfg->sood_port >= 0 ? cfg->sood_port : 9003;

	g_alsa_buffer_ms = cfg->alsa_buffer_ms >= 20 ? cfg->alsa_buffer_ms : 40;
	if (cfg->stream_max_bytes > 0)
		g_stream_max_bytes = cfg->stream_max_bytes;
	if (cfg->lua_mem_limit > 0)
		g_lua_mem_limit = cfg->lua_mem_limit;
	g_null_sink_dir = (char *)cfg->null_sink_dir;

	free(g_bind_override);
	g_bind_override = strcmp(bind_addr, "0.0.0.0") ? xstrdup(bind_addr) : NULL;

	if (cfg->backend == RAAT_BACKEND_PIPEWIRE && !raat_endpoint_has_pipewire()) {
		LOGE("PipeWire backend requested, but not compiled in (rebuild with PIPEWIRE=1)");
		goto fail_early;
	}
	if (cfg->raatflector_server && cfg->raatflector_server[0] && !raat_endpoint_has_raatflector()) {
		LOGE("RAATflector requested, but not compiled in (rebuild with RAATFLECTOR=1)");
		goto fail_early;
	}

	if (loop_init() < 0) {
		LOGE("epoll init failed: %s", strerror(errno));
		goto fail_early;
	}
	if (platform_init(cfg->fixture_path, cfg->backend == RAAT_BACKEND_PIPEWIRE) < 0)
		goto fail_loop;

	struct manager_opts mo = { data_dir, bind_addr, cfg->manager_port, raat_version };
	if (manager_start(&mo) < 0)
		goto fail_plat;

	L.no_sood = cfg->no_sood;
	if (!cfg->no_sood) {
		char host[256] = "";
		if (cfg->name && cfg->name[0]) {
			strlcpy0(host, cfg->name, sizeof host);
		} else {
			gethostname(host, sizeof host - 1);
			char *dot = strchr(host, '.');
			if (dot)
				*dot = 0;
		}
		const struct platform_uname *u = platform_uname();
		char osv[160], mid[37], tcp_port[16];
		snprintf(osv, sizeof osv, "%s %s", u->sysname, u->release);
		machine_id(mid, data_dir, manager_unique_id());
		snprintf(tcp_port, sizeof tcp_port, "%d", manager_port());
		struct sood_kv kv[] = {
			{ "service_id", RAAT_SERVICE_ID },
			{ "tcp_port", tcp_port },
			{ "unique_id", manager_unique_id() },
			{ "machine_id", mid },
			{ "machine_name", host },
			{ "os_version", osv },
			{ cfg->vendor ? "vendor" : NULL, cfg->vendor },
			{ cfg->model ? "model" : NULL, cfg->model },
			{ "raat_version", raat_version },
			{ "protocol_version", "1" },
			{ "config_version", "1" },
			{ "is_dev", "0" },
			{ NULL, NULL },
		};
		size_t nk = 0;
		for (size_t i = 0; i < sizeof kv / sizeof kv[0] - 1; i++)
			if (kv[i].key)
				kv[nk++] = kv[i];
		kv[nk] = (struct sood_kv){ NULL, NULL };
		if (sood_start(bind_addr, sport, !cfg->no_multicast, kv) < 0)
			LOGW("[sood] discovery disabled");
	}

	if (cfg->raatflector_server && cfg->raatflector_server[0]) {
		if (raatflector_start(cfg->raatflector_server, cfg->raatflector_token) < 0) {
			sood_stop();
			manager_shutdown();
			goto fail_plat;
		}
	}

	L.inited = true;
	return 0;

fail_plat:
	platform_shutdown();
fail_loop:
	loop_shutdown();
fail_early:
	free(g_bind_override);
	g_bind_override = NULL;
	log_set_cb(NULL, NULL);
	return -1;
}

RAAT_API int raat_endpoint_run(void)
{
	if (!L.inited)
		return -1;
	loop_run();
	return 0;
}

RAAT_API void raat_endpoint_shutdown(void)
{
	if (!L.inited)
		return;
	raatflector_stop();
	manager_shutdown();
	sood_stop();
	loop_run_pending();
	platform_shutdown();
	loop_shutdown();
	free(g_bind_override);
	g_bind_override = NULL;
	log_set_cb(NULL, NULL);
	L.inited = false;
}

static char *dup_opt(const char *s, int slot)
{
	L.bg_strs[slot] = s ? xstrdup(s) : NULL;
	return L.bg_strs[slot];
}

static void free_bg_strs(void)
{
	for (int i = 0; i < 10; i++) {
		free(L.bg_strs[i]);
		L.bg_strs[i] = NULL;
	}
}

static void *bg_thread(void *arg)
{
	(void)arg;
	int rc = raat_endpoint_init(&L.bg_cfg);
	pthread_mutex_lock(&L.mu);
	L.init_rc = rc;
	L.ready = true;
	pthread_cond_signal(&L.cv);
	pthread_mutex_unlock(&L.mu);
	if (rc == 0) {
		raat_endpoint_run();
		raat_endpoint_shutdown();
	}
	free_bg_strs();
	return NULL;
}

RAAT_API int raat_endpoint_start(const raat_endpoint_config_t *cfg)
{
	if (!cfg)
		return -1;
	pthread_mutex_lock(&L.mu);
	if (L.has_thread || L.inited) {
		pthread_mutex_unlock(&L.mu);
		return -1;
	}
	L.bg_cfg = *cfg;
	L.bg_cfg.data_dir = dup_opt(cfg->data_dir, 0);
	L.bg_cfg.bind_addr = dup_opt(cfg->bind_addr, 1);
	L.bg_cfg.fixture_path = dup_opt(cfg->fixture_path, 2);
	L.bg_cfg.name = dup_opt(cfg->name, 3);
	L.bg_cfg.vendor = dup_opt(cfg->vendor, 4);
	L.bg_cfg.model = dup_opt(cfg->model, 5);
	L.bg_cfg.raat_version = dup_opt(cfg->raat_version, 6);
	L.bg_cfg.null_sink_dir = dup_opt(cfg->null_sink_dir, 7);
	L.bg_cfg.raatflector_server = dup_opt(cfg->raatflector_server, 8);
	L.bg_cfg.raatflector_token = dup_opt(cfg->raatflector_token, 9);
	L.ready = false;
	L.init_rc = -1;
	if (pthread_create(&L.th, NULL, bg_thread, NULL) != 0) {
		free_bg_strs();
		pthread_mutex_unlock(&L.mu);
		return -1;
	}
	while (!L.ready)
		pthread_cond_wait(&L.cv, &L.mu);
	int rc = L.init_rc;
	if (rc == 0) {
		L.has_thread = true;
		pthread_mutex_unlock(&L.mu);
		return 0;
	}
	pthread_mutex_unlock(&L.mu);
	pthread_join(L.th, NULL);
	return -1;
}

RAAT_API void raat_endpoint_stop(void)
{
	loop_stop();
	pthread_mutex_lock(&L.mu);
	bool join = L.has_thread;
	L.has_thread = false;
	pthread_mutex_unlock(&L.mu);
	if (join)
		pthread_join(L.th, NULL);
}

RAAT_API int raat_endpoint_manager_port(void)
{
	return L.inited ? manager_port() : 0;
}

RAAT_API int raat_endpoint_sood_port(void)
{
	return (L.inited && !L.no_sood) ? sood_port() : 0;
}

RAAT_API const char *raat_endpoint_unique_id(void)
{
	return L.inited ? manager_unique_id() : "";
}

RAAT_API int raat_endpoint_has_pipewire(void)
{
#ifdef ENABLE_PIPEWIRE
	return 1;
#else
	return 0;
#endif
}

RAAT_API int raat_endpoint_has_raatflector(void)
{
#ifdef ENABLE_RAATFLECTOR
	return 1;
#else
	return 0;
#endif
}
