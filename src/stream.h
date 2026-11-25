// SPDX-License-Identifier: GPL-3.0-or-later
/* The sample ring between the session script (writer, main thread) and the
 * output thread (reader). Addressed by absolute stream sample (frame) index,
 * as the script's stream:write(stream_sample, ...) is (spec 7, 13.5). */
#ifndef RAAT_STREAM_H
#define RAAT_STREAM_H

#include "common.h"
#include <pthread.h>

typedef struct stream {
	int refs; /* atomic */
	pthread_mutex_t mu;

	char sample_type[16];
	int rate, bits, channels;
	int bpf; /* bytes per frame on the wire */
	int64_t capacity;
	uint8_t *data;

	bool empty;
	int64_t lo, hi; /* retained absolute samples are [lo, hi), hi - lo <= capacity */
	bool reading;
	bool has_read; /* rd is meaningful (reading now, or stopped after reading) */
	int64_t rd;    /* next sample the reader takes */

	double gain, peak; /* last per-packet normalization (metadata only) */
	int32_t chmap;

	int64_t write_count, read_count, samples_in, samples_out;
	int64_t dropout_count, samples_dropped, overrun_count, samples_overrun;
} stream_t;

extern size_t g_stream_max_bytes;

stream_t *stream_new(const char *sample_type, int rate, int bits, int channels, int64_t capacity,
		     const char **err);
void stream_ref(stream_t *s);
void stream_unref(stream_t *s);

/* Writer side. Returns 0, or -1 with *err set. */
int stream_write(stream_t *s, int64_t sample, double gain, double peak, const uint8_t *data,
		 size_t len, int64_t nsamples, int32_t chmap, bool has_chmap, const char **err);
void stream_clear(stream_t *s);

/* Reader side. */
void stream_begin_read(stream_t *s, int64_t sample);
void stream_end_read(stream_t *s);
/* Copy n frames from the read position; missing frames become silence and count
 * as a dropout. */
void stream_read(stream_t *s, uint8_t *dst, int64_t n);

#endif
