// SPDX-License-Identifier: GPL-3.0-or-later
/* Optional PipeWire backend for user-process mode (ENABLE_PIPEWIRE).
 * Exposes "PipeWire Default Output" plus every discovered Audio/Sink node. */
#ifndef RAAT_PW_BACKEND_H
#define RAAT_PW_BACKEND_H

#include "common.h"
#include "platform.h"

typedef struct output output_t;
typedef struct pw_output pw_output_t;

/* Called from PipeWire's RT process callback to pull wire PCM frames and update the clock. */
void output_pw_process(output_t *o, uint8_t *dst, int64_t nframes, int64_t queued_frames);
/* Called if the PipeWire stream enters PW_STREAM_STATE_ERROR. */
void output_pw_lost(output_t *o);

#ifdef ENABLE_PIPEWIRE

int pw_platform_init(void);
void pw_platform_shutdown(void);
int pw_platform_scan(pdev_t **out, int *n);
int pw_platform_watch_fd(void);
void pw_platform_watch_drain(int fd);

pw_output_t *pw_output_open(output_t *o, const pdev_t *pd, int rate, int bits, int channels,
			    int buffer_ms, int64_t *period_out, int64_t *bufsize_out,
			    const char **status);
void pw_output_close(pw_output_t *pwo);

#else

static inline int pw_platform_init(void) { return -1; }
static inline void pw_platform_shutdown(void) {}
static inline int pw_platform_scan(pdev_t **out, int *n) { *out = NULL; *n = 0; return -1; }
static inline int pw_platform_watch_fd(void) { return -1; }
static inline void pw_platform_watch_drain(int fd) { (void)fd; }
static inline pw_output_t *pw_output_open(output_t *o, const pdev_t *pd, int rate, int bits,
					  int channels, int buffer_ms, int64_t *period_out,
					  int64_t *bufsize_out, const char **status)
{
	(void)o; (void)pd; (void)rate; (void)bits; (void)channels;
	(void)buffer_ms; (void)period_out; (void)bufsize_out;
	*status = "RAAT__OUTPUT_PLUGIN_STATUS_DEVICE_OPEN_FAILED";
	return NULL;
}
static inline void pw_output_close(pw_output_t *pwo) { (void)pwo; }

#endif /* ENABLE_PIPEWIRE */
#endif
