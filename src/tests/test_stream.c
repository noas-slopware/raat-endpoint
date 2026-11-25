// SPDX-License-Identifier: GPL-3.0-or-later
/* Unit tests for the stream ring's CHMAP handling (stream_write with a channel
 * mask). Built and run by `make test`. */
#include "../stream.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails, passes;

#define CHECK(cond, ...)                                                    \
	do {                                                                \
		if (cond) {                                                 \
			passes++;                                           \
		} else {                                                    \
			fails++;                                            \
			printf("  FAIL %s:%d: ", __FILE__, __LINE__);       \
			printf(__VA_ARGS__);                                \
			printf("\n");                                       \
		}                                                           \
	} while (0)

static stream_t *mk(int bits, int ch, int64_t cap)
{
	const char *err = NULL;
	stream_t *s = stream_new("pcm", 44100, bits, ch, cap, &err);
	if (!s) {
		printf("stream_new: %s\n", err);
		exit(1);
	}
	return s;
}

static bool all_zero(const uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (p[i])
			return false;
	return true;
}

/* chmap 0 with an empty payload: nsamples frames of silence, at the position. */
static void test_chmap0_silence(void)
{
	stream_t *s = mk(16, 2, 100000);
	const char *err = NULL;
	int r = stream_write(s, 0, 0, 0, (const uint8_t *)"", 0, 15000, 0, true, &err);
	CHECK(r == 0, "chmap 0 empty payload accepted (%s)", err ? err : "");
	uint8_t full[400 * 4];
	for (size_t i = 0; i < sizeof full; i++)
		full[i] = (uint8_t)(i * 7 + 3);
	r = stream_write(s, 15000, 0, 0, full, sizeof full, 400, -1, true, &err);
	CHECK(r == 0, "chmap -1 after it accepted");
	CHECK(s->lo == 0 && s->hi == 15400, "window [0, 15400) got [%lld, %lld)", (long long)s->lo,
	      (long long)s->hi);
	uint8_t *out = malloc(15400 * 4);
	stream_begin_read(s, 0);
	stream_read(s, out, 15400);
	CHECK(all_zero(out, 15000 * 4), "first 15000 frames are silence");
	CHECK(!memcmp(out + 15000 * 4, full, sizeof full), "then the full frames, unchanged");
	CHECK(s->samples_dropped == 0, "no dropout (%lld)", (long long)s->samples_dropped);
	free(out);
	stream_unref(s);
}

/* A partial mask puts each packed sample into its channel, the rest silent. */
static void test_partial(int bits, int32_t mask)
{
	int bps = bits / 8, n = 64;
	stream_t *s = mk(bits, 2, 1000);
	uint8_t in[64 * 4];
	for (int i = 0; i < n * bps; i++)
		in[i] = (uint8_t)(0x80 | (i & 0x7f)); /* never zero */
	const char *err = NULL;
	int r = stream_write(s, 10, 0, 0, in, (size_t)(n * bps), n, mask, true, &err);
	CHECK(r == 0, "%d-bit mask 0x%x accepted (%s)", bits, mask, err ? err : "");
	uint8_t out[64 * 8];
	stream_begin_read(s, 10);
	stream_read(s, out, n);
	int present = mask == 1 ? 0 : 1, absent = 1 - present;
	bool ok = true;
	for (int f = 0; f < n; f++) {
		ok &= !memcmp(out + f * 2 * bps + present * bps, in + f * bps, (size_t)bps);
		ok &= all_zero(out + f * 2 * bps + absent * bps, (size_t)bps);
	}
	CHECK(ok, "%d-bit mask 0x%x: samples in channel %d, channel %d silent", bits, mask, present,
	      absent);
	stream_unref(s);
}

static void test_short_rejected(void)
{
	stream_t *s = mk(24, 2, 1000);
	uint8_t in[100 * 3];
	memset(in, 1, sizeof in);
	const char *err = NULL;
	int r = stream_write(s, 0, 0, 0, in, 99 * 3, 100, 0x1, true, &err);
	CHECK(r < 0 && err, "mask 0x1, one sample short: rejected");
	err = NULL;
	r = stream_write(s, 0, 0, 0, in, 100 * 3, 100, 0x3, true, &err);
	CHECK(r < 0 && err, "mask 0x3 with mono-sized data: rejected");
	err = NULL;
	r = stream_write(s, 0, 0, 0, in, 100 * 3, 100, -1, true, &err);
	CHECK(r < 0 && err, "chmap -1 with half the data: rejected");
	CHECK(s->empty, "nothing was written by the rejected calls");
	stream_unref(s);
}

/* -1 (and no chmap at all) stores the payload byte for byte. */
static void test_full_unchanged(void)
{
	for (int with = 0; with < 2; with++) {
		stream_t *s = mk(24, 2, 1000);
		uint8_t in[50 * 6], out[50 * 6];
		for (size_t i = 0; i < sizeof in; i++)
			in[i] = (uint8_t)(i * 13 + 1);
		const char *err = NULL;
		int r = stream_write(s, 5, 0, 0, in, sizeof in, 50, -1, with, &err);
		stream_begin_read(s, 5);
		stream_read(s, out, 50);
		CHECK(r == 0 && !memcmp(in, out, sizeof in), "full frames unchanged (%s chmap)",
		      with ? "-1" : "no");
		stream_unref(s);
	}
}

/* stop, then start again at an earlier sample (resume in the Core's pause
 * window): frames already read must still be there. */
static void test_resume_rewind(void)
{
	stream_t *s = mk(16, 2, 100000);
	uint8_t *in = malloc(30000 * 4), *out = malloc(30000 * 4);
	for (int i = 0; i < 30000 * 4; i++)
		in[i] = (uint8_t)(i * 31 + 7);
	const char *err = NULL;
	stream_write(s, 0, 0, 0, in, 30000 * 4, 30000, -1, true, &err);
	stream_begin_read(s, 0);
	stream_read(s, out, 20000);
	stream_end_read(s);
	stream_begin_read(s, 17000); /* 3000 frames back, as after a stop */
	stream_read(s, out, 5000);
	CHECK(!memcmp(out, in + 17000 * 4, 5000 * 4), "resume 3000 frames back reads the retained frames");
	CHECK(s->samples_dropped == 0, "no dropout on resume (%lld)", (long long)s->samples_dropped);
	free(in);
	free(out);
	stream_unref(s);
}

/* Retention never costs room ahead of the reader: played frames give way. */
static void test_retention_bounded(void)
{
	stream_t *s = mk(16, 2, 1000);
	uint8_t in[400 * 4], out[400 * 4];
	memset(in, 5, sizeof in);
	const char *err = NULL;
	stream_begin_read(s, 0);
	for (int i = 0; i < 10; i++) {
		CHECK(stream_write(s, i * 400, 0, 0, in, sizeof in, 400, -1, true, &err) == 0, "write %d", i);
		stream_read(s, out, 400);
	}
	CHECK(s->overrun_count == 0, "sequential write/read never overruns (%lld)", (long long)s->overrun_count);
	CHECK(s->hi - s->lo <= s->capacity && s->hi == 4000, "window [%lld, %lld) within capacity",
	      (long long)s->lo, (long long)s->hi);
	/* ahead of the reader by more than the capacity: refused, not overwritten */
	stream_write(s, 4000, 0, 0, in, sizeof in, 400, -1, true, &err);
	stream_write(s, 4400, 0, 0, in, sizeof in, 400, -1, true, &err);
	stream_write(s, 4800, 0, 0, in, sizeof in, 400, -1, true, &err);
	CHECK(s->overrun_count > 0 && s->hi <= s->rd + s->capacity, "never more than one capacity past the reader");
	stream_unref(s);
}

int main(void)
{
	test_chmap0_silence();
	test_partial(16, 0x1);
	test_partial(16, 0x2);
	test_partial(24, 0x1);
	test_partial(24, 0x2);
	test_short_rejected();
	test_full_unchanged();
	test_resume_rewind();
	test_retention_bounded();
	printf("stream unit tests: %d passed, %d failed\n", passes, fails);
	return fails ? 1 : 0;
}
