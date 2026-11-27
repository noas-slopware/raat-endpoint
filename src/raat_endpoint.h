// SPDX-License-Identifier: GPL-3.0-or-later
/* Public C API for embedding raat-endpoint as a shared library (libraat-endpoint.so). */
#ifndef RAAT_ENDPOINT_H
#define RAAT_ENDPOINT_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) && __GNUC__ >= 4
#define RAAT_API __attribute__((visibility("default")))
#else
#define RAAT_API
#endif

typedef enum {
	RAAT_BACKEND_ALSA = 0,     /* bit-perfect ALSA hw: (default) */
	RAAT_BACKEND_PIPEWIRE = 1, /* PipeWire user-process mode (requires ENABLE_PIPEWIRE) */
} raat_backend_t;

enum {
	RAAT_LOG_TRACE = 0,
	RAAT_LOG_DEBUG = 1,
	RAAT_LOG_INFO  = 2,
	RAAT_LOG_WARN  = 3,
	RAAT_LOG_ERROR = 4,
	RAAT_LOG_CRIT  = 5,
};

typedef void (*raat_log_cb_t)(int level, const char *msg, void *userdata);

typedef struct {
	const char *data_dir;           /* NULL -> /var/lib/raat-endpoint (root) or XDG data dir */
	const char *bind_addr;          /* NULL -> "0.0.0.0" */
	int manager_port;               /* -1 = first free in 9200-9250, 0 = ephemeral */
	int sood_port;                  /* 0 = ephemeral, <0 -> default 9003 (config_init sets 9003) */
	bool no_sood;                   /* do not open SOOD UDP socket */
	bool no_multicast;              /* do not join 239.255.90.90 */
	raat_backend_t backend;         /* default RAAT_BACKEND_ALSA */
	const char *fixture_path;       /* test fixture JSON, NULL in normal use */
	const char *name;               /* machine_name, NULL -> hostname */
	const char *vendor;             /* discovery vendor, NULL -> omitted */
	const char *model;              /* discovery model, NULL -> omitted */
	const char *raat_version;       /* NULL -> "1.1.38" */
	int alsa_buffer_ms;             /* 0 -> default 40 */
	size_t stream_max_bytes;        /* 0 -> default 32 MiB */
	size_t lua_mem_limit;           /* 0 -> default 24 MiB */
	const char *null_sink_dir;      /* tests only */
	int log_level;                  /* RAAT_LOG_*, default RAAT_LOG_INFO */
	raat_log_cb_t log_cb;           /* NULL -> stderr */
	void *log_ud;
	/* RAATflector client (requires ENABLE_RAATFLECTOR build) */
	const char *raatflector_server; /* "host:port" or "host" (default 9004), NULL = disabled */
	const char *raatflector_token;  /* optional shared auth token, NULL = none */
} raat_endpoint_config_t;

/* Populate cfg with defaults. Always call this before overriding fields. */
RAAT_API void raat_endpoint_config_init(raat_endpoint_config_t *cfg);

/* Background-thread lifecycle (recommended for embedding in GUI/app hosts).
 * raat_endpoint_start() blocks until the listeners are bound and ready (or init fails).
 * raat_endpoint_stop() is thread-safe, wakes the loop, joins the thread, and frees all state. */
RAAT_API int raat_endpoint_start(const raat_endpoint_config_t *cfg);
RAAT_API void raat_endpoint_stop(void);

/* Caller-thread lifecycle (used by the CLI binary). */
RAAT_API int raat_endpoint_init(const raat_endpoint_config_t *cfg);
RAAT_API int raat_endpoint_run(void);
RAAT_API void raat_endpoint_shutdown(void);

/* Live state accessors (valid after init/start returns 0). */
RAAT_API int raat_endpoint_manager_port(void);
RAAT_API int raat_endpoint_sood_port(void);
RAAT_API const char *raat_endpoint_unique_id(void);

/* Build-time feature probes. */
RAAT_API int raat_endpoint_has_pipewire(void);
RAAT_API int raat_endpoint_has_raatflector(void);

#ifdef __cplusplus
}
#endif

#endif
