// SPDX-License-Identifier: GPL-3.0-or-later
/* Output device: an audio thread that keeps the DAC fed from setup to teardown
 * (silence until start, then the stream), plus the playback-position clock that
 * raat.output.get_local_time reports (spec 7, 8.4, 13.4.1). */
#ifndef RAAT_OUTPUT_H
#define RAAT_OUTPUT_H

#include "common.h"
#include "platform.h"
#include "stream.h"

typedef struct output output_t;

extern int g_alsa_buffer_ms;
extern int64_t g_extra_delay_ns;
extern char *g_null_sink_dir; /* tests: null backend writes sink-<n>.raw here */

/* Opens the device at exactly this format and starts the thread (silence).
 * On failure returns NULL and sets *status to a RAAT__OUTPUT_PLUGIN_STATUS_* name. */
output_t *output_open(const pdev_t *pd, int rate, int bits, int channels, int64_t clock_base,
		      const char **status);
/* Returns the local time at close, the base for the device's next setup. */
int64_t output_close(output_t *o);

int output_start(output_t *o, int64_t time_ns, int64_t stream_sample, stream_t *st, const char **err);
int output_stop(output_t *o, const char **err);
bool output_is_playing(output_t *o);

int64_t output_local_time(output_t *o);
int64_t output_delay_ns(output_t *o);
void output_set_remote_time(output_t *o, double offset_ns, bool reset);

/* eventfd that becomes readable when the device is lost. */
int output_event_fd(output_t *o);
bool output_lost(output_t *o);

/* {"signal_path":[...]} for raat.output.message_handlers (spec 8.6). malloc'd. */
char *output_signal_path_json(output_t *o);

#endif
