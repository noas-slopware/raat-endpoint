#include "stream.h"

#include <stdlib.h>
#include <string.h>

/* TODO(playback capture: `stream` request `buffer_size`): the script asks for
 * 2 * buffer_size * sample_rate frames (spec 11.5). The real buffer_size is not
 * in any capture yet. Until it is known, cap the ring so one stream cannot eat
 * the 128 MiB box; the cap never goes below half the request (= buffer_size,
 * the amount the Core keeps in flight). Tune once a capture shows the value. */
size_t g_stream_max_bytes = 32u << 20;

stream_t *stream_new(const char *sample_type, int rate, int bits, int channels, int64_t capacity,
		     const char **err)
{
	int bps;
	if (!strcmp(sample_type, "pcm")) {
		if (bits != 16 && bits != 24 && bits != 32) {
			*err = "unsupported bits_per_sample";
			return NULL;
		}
		bps = bits / 8;
	} else if (!strcmp(sample_type, "pcm_float32")) {
		bps = 4;
	} else if (!strcmp(sample_type, "pcm_float64")) {
		bps = 8;
	} else {
		*err = "unsupported sample_type";
		return NULL;
	}
	if (rate <= 0 || channels <= 0 || channels > 32 || capacity <= 0) {
		*err = "invalid stream format";
		return NULL;
	}
	int bpf = bps * channels;
	int64_t want = capacity;
	if ((uint64_t)capacity * (uint64_t)bpf > g_stream_max_bytes) {
		int64_t capped = (int64_t)(g_stream_max_bytes / (size_t)bpf);
		if (capped < capacity / 2)
			capped = capacity / 2;
		capacity = capped;
		LOGW("[stream] capacity %lld frames (%lld bytes) above budget; using %lld frames",
		     (long long)want, (long long)want * bpf, (long long)capacity);
	}
	uint8_t *data = malloc((size_t)capacity * (size_t)bpf);
	if (!data) {
		*err = "out of memory";
		return NULL;
	}
	stream_t *s = xcalloc(1, sizeof *s);
	s->refs = 1;
	pthread_mutex_init(&s->mu, NULL);
	strlcpy0(s->sample_type, sample_type, sizeof s->sample_type);
	s->rate = rate;
	s->bits = bits;
	s->channels = channels;
	s->bpf = bpf;
	s->capacity = capacity;
	s->data = data;
	s->empty = true;
	LOGD("[stream] new %s %d/%d/%d capacity=%lld frames", sample_type, rate, bits, channels,
	     (long long)capacity);
	return s;
}

void stream_ref(stream_t *s)
{
	__atomic_add_fetch(&s->refs, 1, __ATOMIC_RELAXED);
}

void stream_unref(stream_t *s)
{
	if (!s || __atomic_sub_fetch(&s->refs, 1, __ATOMIC_ACQ_REL))
		return;
	pthread_mutex_destroy(&s->mu);
	free(s->data);
	free(s);
}

/* Copy frames [sample, sample+n) between dst/src and the ring (n <= capacity). */
static void ring_put(stream_t *s, int64_t sample, const uint8_t *src, int64_t n)
{
	int64_t slot = sample % s->capacity;
	int64_t first = s->capacity - slot < n ? s->capacity - slot : n;
	memcpy(s->data + slot * s->bpf, src, (size_t)(first * s->bpf));
	if (n > first)
		memcpy(s->data, src + first * s->bpf, (size_t)((n - first) * s->bpf));
}

static void ring_get(stream_t *s, int64_t sample, uint8_t *dst, int64_t n)
{
	int64_t slot = sample % s->capacity;
	int64_t first = s->capacity - slot < n ? s->capacity - slot : n;
	memcpy(dst, s->data + slot * s->bpf, (size_t)(first * s->bpf));
	if (n > first)
		memcpy(dst + first * s->bpf, s->data, (size_t)((n - first) * s->bpf));
}

static void ring_zero(stream_t *s, int64_t sample, int64_t n)
{
	int64_t slot = sample % s->capacity;
	int64_t first = s->capacity - slot < n ? s->capacity - slot : n;
	memset(s->data + slot * s->bpf, 0, (size_t)(first * s->bpf));
	if (n > first)
		memset(s->data, 0, (size_t)((n - first) * s->bpf));
}

int stream_write(stream_t *s, int64_t sample, double gain, double peak, const uint8_t *data,
		 size_t len, int64_t n, int32_t chmap, bool has_chmap, const char **err)
{
	if (n < 0 || sample < 0) {
		*err = "invalid sample or nsamples";
		return -1;
	}
	if (n > s->capacity) {
		*err = "nsamples is larger than the stream buffer";
		return -1;
	}
	if ((uint64_t)n * (uint64_t)s->bpf > len) {
		*err = "data is shorter than nsamples";
		return -1;
	}
	pthread_mutex_lock(&s->mu);
	s->write_count++;
	s->samples_in += n;
	/* TODO(playback capture: COMMAND_NORMALIZATION values): gain/peak are kept
	 * as metadata only and never applied, so output stays bit-perfect. */
	s->gain = gain;
	s->peak = peak;
	/* TODO(playback capture: COMMAND_CHMAP values): the map is recorded, not
	 * applied; frames go out in wire order. */
	if (has_chmap)
		s->chmap = chmap;
	if (s->empty) {
		s->lo = s->hi = s->reading && s->rd > sample ? s->rd : sample;
		s->empty = false;
	}
	/* Late data (before the window) is dropped. */
	if (sample < s->lo) {
		int64_t skip = s->lo - sample;
		if (skip >= n) {
			pthread_mutex_unlock(&s->mu);
			return 0;
		}
		data += skip * s->bpf;
		n -= skip;
		sample = s->lo;
	}
	/* A gap ahead of the window is filled with silence. */
	if (sample > s->hi) {
		int64_t gap = sample - s->hi;
		if (sample + n - s->lo > s->capacity) {
			s->overrun_count++;
			s->samples_overrun += n;
			pthread_mutex_unlock(&s->mu);
			LOGW("[stream] ring full, %lld samples thrown away", (long long)n);
			return 0;
		}
		ring_zero(s, s->hi, gap);
		s->hi = sample;
	}
	/* Never overwrite what the reader has not consumed. */
	int64_t room = s->lo + s->capacity - sample;
	if (n > room) {
		s->overrun_count++;
		s->samples_overrun += n - room;
		LOGW("[stream] ring full, %lld samples thrown away", (long long)(n - room));
		n = room;
	}
	if (n > 0) {
		ring_put(s, sample, data, n);
		if (sample + n > s->hi)
			s->hi = sample + n;
	}
	pthread_mutex_unlock(&s->mu);
	return 0;
}

void stream_clear(stream_t *s)
{
	pthread_mutex_lock(&s->mu);
	s->empty = true;
	s->lo = s->hi = s->reading ? s->rd : 0;
	pthread_mutex_unlock(&s->mu);
}

void stream_begin_read(stream_t *s, int64_t sample)
{
	pthread_mutex_lock(&s->mu);
	s->reading = true;
	s->rd = sample;
	if (s->empty) {
		s->lo = s->hi = sample;
	} else if (sample > s->lo) {
		s->lo = sample < s->hi ? sample : s->hi;
		if (sample > s->hi) {
			s->lo = s->hi = sample;
			s->empty = true;
		}
	}
	pthread_mutex_unlock(&s->mu);
}

void stream_end_read(stream_t *s)
{
	pthread_mutex_lock(&s->mu);
	s->reading = false;
	pthread_mutex_unlock(&s->mu);
}

void stream_read(stream_t *s, uint8_t *dst, int64_t n)
{
	pthread_mutex_lock(&s->mu);
	s->read_count++;
	int64_t got = 0;
	if (!s->empty && s->rd >= s->lo && s->rd < s->hi) {
		got = s->hi - s->rd < n ? s->hi - s->rd : n;
		ring_get(s, s->rd, dst, got);
	}
	if (got < n) {
		memset(dst + got * s->bpf, 0, (size_t)((n - got) * s->bpf));
		s->dropout_count++;
		s->samples_dropped += n - got;
	}
	s->samples_out += got;
	s->rd += n;
	if (!s->empty) {
		if (s->rd >= s->hi) {
			s->lo = s->hi = s->rd;
		} else if (s->rd > s->lo) {
			s->lo = s->rd;
		}
	}
	pthread_mutex_unlock(&s->mu);
	if (got < n)
		LOGT("[stream] short by %lld samples, padded with silence", (long long)(n - got));
}
