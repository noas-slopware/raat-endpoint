#include "output.h"

#include <alsa/asoundlib.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "third_party/cjson/cJSON.h"

int g_alsa_buffer_ms = 100;
int64_t g_extra_delay_ns = 0;

struct output {
	pdev_t pd;
	int rate, bits, channels;
	int wire_bpf;
	double nspf; /* ns per frame */

	/* ALSA */
	snd_pcm_t *pcm;
	snd_pcm_format_t hwfmt;
	int hw_bps; /* container bytes per sample */
	/* null backend: a paced fake DAC with the same buffer model */
	int tfd;
	int64_t null_t0;

	int64_t period, bufsize; /* frames */
	uint8_t *pbuf, *cbuf;

	pthread_t th;
	pthread_mutex_t mu;
	pthread_cond_t cv;
	bool quit;

	stream_t *st;
	bool playing, start_pending;
	int64_t start_time, start_sample, start_idx;
	int64_t written; /* frames handed to the device */

	/* Clock: local time = L0 + DAC position * nspf, followed smoothly. */
	int64_t L0;
	bool clk_valid;
	double off; /* local - now_ns */
	double remote_offset;
	bool remote_valid;

	bool lost;
	int evfd;
};

/* ---- busy registry (main thread) ---- */

#define MAX_OPEN 8
static output_t *open_outputs[MAX_OPEN];

bool platform_device_busy(const char *id)
{
	for (int i = 0; i < MAX_OPEN; i++)
		if (open_outputs[i] && !strcmp(open_outputs[i]->pd.id, id))
			return true;
	return false;
}

/* ---- ALSA backend ---- */

static const char *alsa_open(output_t *o)
{
	snd_pcm_t *pcm;
	int err = snd_pcm_open_lconf(&pcm, o->pd.id, SND_PCM_STREAM_PLAYBACK, SND_PCM_NONBLOCK,
				     platform_alsa_lconf());
	if (err < 0) {
		LOGW("[alsa] open %s: %s", o->pd.id, snd_strerror(err));
		return err == -EBUSY ? "RAAT__OUTPUT_PLUGIN_STATUS_DEVICE_IN_USE"
				     : "RAAT__OUTPUT_PLUGIN_STATUS_DEVICE_OPEN_FAILED";
	}
	snd_pcm_nonblock(pcm, 0);
	snd_pcm_hw_params_t *hw;
	snd_pcm_sw_params_t *sw;
	snd_pcm_hw_params_alloca(&hw);
	snd_pcm_sw_params_alloca(&sw);
	const char *fail = "RAAT__OUTPUT_PLUGIN_STATUS_DEVICE_INIT_FAILED";

	snd_pcm_format_t cand[3];
	int ncand = 0;
	if (o->bits == 16) {
		cand[ncand++] = SND_PCM_FORMAT_S16_LE;
	} else if (o->bits == 24) {
		/* packed first: no conversion at all */
		cand[ncand++] = SND_PCM_FORMAT_S24_3LE;
		cand[ncand++] = SND_PCM_FORMAT_S32_LE;
		cand[ncand++] = SND_PCM_FORMAT_S24_LE;
	} else {
		cand[ncand++] = SND_PCM_FORMAT_S32_LE;
	}
	if (snd_pcm_hw_params_any(pcm, hw) < 0)
		goto bad;
	snd_pcm_hw_params_set_rate_resample(pcm, hw, 0); /* never resample */
	if (snd_pcm_hw_params_set_access(pcm, hw, SND_PCM_ACCESS_RW_INTERLEAVED) < 0)
		goto bad;
	int i;
	for (i = 0; i < ncand; i++)
		if (snd_pcm_hw_params_test_format(pcm, hw, cand[i]) == 0)
			break;
	if (i == ncand || snd_pcm_hw_params_set_format(pcm, hw, cand[i]) < 0) {
		fail = "RAAT__OUTPUT_PLUGIN_STATUS_FORMAT_NOT_SUPPORTED";
		goto bad;
	}
	o->hwfmt = cand[i];
	o->hw_bps = snd_pcm_format_physical_width(o->hwfmt) / 8;
	if (snd_pcm_hw_params_set_channels(pcm, hw, (unsigned)o->channels) < 0 ||
	    snd_pcm_hw_params_set_rate(pcm, hw, (unsigned)o->rate, 0) < 0) {
		fail = "RAAT__OUTPUT_PLUGIN_STATUS_FORMAT_NOT_SUPPORTED";
		goto bad;
	}
	unsigned buf_us = (unsigned)g_alsa_buffer_ms * 1000u, per_us = buf_us / 4;
	int dir = 0;
	snd_pcm_hw_params_set_buffer_time_near(pcm, hw, &buf_us, &dir);
	dir = 0;
	snd_pcm_hw_params_set_period_time_near(pcm, hw, &per_us, &dir);
	if ((err = snd_pcm_hw_params(pcm, hw)) < 0) {
		LOGW("[alsa] hw_params %s: %s", o->pd.id, snd_strerror(err));
		goto bad;
	}
	unsigned rate = 0;
	snd_pcm_hw_params_get_rate(hw, &rate, &dir);
	if ((int)rate != o->rate) {
		LOGE("[alsa] %s: got rate %u for %d; refusing (no resampling)", o->pd.id, rate, o->rate);
		fail = "RAAT__OUTPUT_PLUGIN_STATUS_FORMAT_NOT_SUPPORTED";
		goto bad;
	}
	snd_pcm_uframes_t period, bufsize;
	snd_pcm_hw_params_get_period_size(hw, &period, &dir);
	snd_pcm_hw_params_get_buffer_size(hw, &bufsize);
	o->period = (int64_t)period;
	o->bufsize = (int64_t)bufsize;
	snd_pcm_sw_params_current(pcm, sw);
	snd_pcm_sw_params_set_start_threshold(pcm, sw, bufsize);
	snd_pcm_sw_params_set_avail_min(pcm, sw, period);
	if (snd_pcm_sw_params(pcm, sw) < 0)
		goto bad;
	LOGI("[alsa] %s open %d/%d/%d as %s, period %lu, buffer %lu frames", o->pd.id, o->rate,
	     o->bits, o->channels, snd_pcm_format_name(o->hwfmt), (unsigned long)period,
	     (unsigned long)bufsize);
	o->pcm = pcm;
	return NULL;
bad:
	snd_pcm_close(pcm);
	return fail;
}

/* Wire PCM is packed little-endian signed (spec 13.6). Widening into a larger
 * container keeps every bit. */
static const uint8_t *to_container(output_t *o, const uint8_t *src, int64_t frames)
{
	int wbps = o->bits / 8;
	if (o->hw_bps == wbps && !(o->bits == 24 && o->hwfmt == SND_PCM_FORMAT_S24_LE))
		return src;
	int64_t ns = frames * o->channels;
	uint8_t *d = o->cbuf;
	if (o->hwfmt == SND_PCM_FORMAT_S32_LE) { /* 24 -> S32_LE (left-justified) */
		for (int64_t i = 0; i < ns; i++, src += 3, d += 4) {
			d[0] = 0;
			d[1] = src[0];
			d[2] = src[1];
			d[3] = src[2];
		}
	} else { /* 24 -> S24_LE (right-justified, sign-extended) */
		for (int64_t i = 0; i < ns; i++, src += 3, d += 4) {
			d[0] = src[0];
			d[1] = src[1];
			d[2] = src[2];
			d[3] = (src[2] & 0x80) ? 0xff : 0;
		}
	}
	return o->cbuf;
}

static int alsa_write(output_t *o, const uint8_t *buf, int64_t frames)
{
	while (frames > 0) {
		snd_pcm_sframes_t n = snd_pcm_writei(o->pcm, buf, (snd_pcm_uframes_t)frames);
		if (n == -EINTR)
			continue;
		if (n == -EPIPE) {
			/* TODO(playback capture: how the Core reacts to an endpoint underrun):
			 * the position clock jumps here; we only log and recover. */
			LOGW("[alsa] %s underrun", o->pd.id);
			if (snd_pcm_prepare(o->pcm) < 0)
				return -1;
			continue;
		}
		if (n == -ESTRPIPE) {
			/* suspended: restart the stream instead of spinning on resume */
			if (snd_pcm_prepare(o->pcm) < 0)
				return -1;
			continue;
		}
		if (n < 0) {
			LOGE("[alsa] %s write: %s", o->pd.id, snd_strerror((int)n));
			return -1;
		}
		buf += n * o->hw_bps * o->channels;
		frames -= n;
	}
	return 0;
}

/* DAC position in frames, or -1 when the device is not running yet. */
static int64_t alsa_position(output_t *o)
{
	if (snd_pcm_state(o->pcm) != SND_PCM_STATE_RUNNING)
		return -1;
	snd_pcm_sframes_t d;
	if (snd_pcm_delay(o->pcm, &d) < 0)
		return -1;
	return o->written - d;
}

/* ---- null backend ---- */

static int null_open(output_t *o)
{
	o->tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
	if (o->tfd < 0)
		return -1;
	o->bufsize = (int64_t)o->rate * g_alsa_buffer_ms / 1000;
	o->period = o->bufsize / 4;
	o->hw_bps = o->bits / 8;
	return 0;
}

static int64_t null_consumed(output_t *o, int64_t t)
{
	if (!o->null_t0)
		return 0;
	int64_t c = (int64_t)((double)(t - o->null_t0) / o->nspf);
	return c > o->written ? o->written : c;
}

/* Blocks on a timerfd until the fake DAC has room, like a blocking writei. */
static int null_write(output_t *o, int64_t frames)
{
	if (!o->null_t0 && o->written + frames >= o->bufsize)
		o->null_t0 = now_ns(); /* "start threshold" reached */
	if (!o->null_t0)
		return 0;
	for (;;) {
		int64_t now = now_ns();
		int64_t need = o->written + frames - o->bufsize; /* must be consumed first */
		int64_t at = o->null_t0 + (int64_t)ceil((double)need * o->nspf);
		if (need <= 0 || at <= now)
			return 0;
		int64_t wait = at - now;
		struct itimerspec its = { .it_value = { wait / 1000000000, wait % 1000000000 } };
		if (timerfd_settime(o->tfd, 0, &its, NULL) < 0)
			return -1;
		uint64_t exp;
		if (read(o->tfd, &exp, sizeof exp) < 0 && errno != EINTR)
			return -1;
	}
}

/* ---- thread ---- */

static void clock_update(output_t *o, int64_t pos)
{
	if (pos < 0)
		return;
	int64_t t = now_ns();
	double meas = (double)o->L0 + (double)pos * o->nspf - (double)t;
	if (!o->clk_valid) {
		o->off = meas;
		o->clk_valid = true;
	} else {
		/* TODO(playback capture: RAATCLKQ rate and the jitter the Core tolerates):
		 * a first-order filter over period-granular position readings. */
		o->off += (meas - o->off) / 16.0;
	}
}

static void *output_thread(void *arg)
{
	output_t *o = arg;
	for (;;) {
		pthread_mutex_lock(&o->mu);
		if (o->quit) {
			pthread_mutex_unlock(&o->mu);
			break;
		}
		if (o->start_pending) {
			int64_t k = (int64_t)ceil((double)(o->start_time - o->L0) / o->nspf);
			int64_t s0 = o->start_sample;
			if (k < o->written) {
				LOGW("[output] start time is %lld frames late; skipping them",
				     (long long)(o->written - k));
				s0 += o->written - k;
				k = o->written;
			}
			LOGI("[output] stream begins at device frame %lld (written so far %lld), first sample %lld",
			     (long long)k, (long long)o->written, (long long)s0);
			stream_begin_read(o->st, s0);
			o->start_idx = k;
			o->playing = true;
			o->start_pending = false;
		}
		stream_t *st = o->playing ? o->st : NULL;
		if (st)
			stream_ref(st);
		int64_t start_idx = o->start_idx, written = o->written;
		pthread_mutex_unlock(&o->mu);

		int64_t n = o->period;
		size_t fb = (size_t)o->wire_bpf;
		if (!st) {
			memset(o->pbuf, 0, (size_t)n * fb);
		} else {
			int64_t sil = start_idx > written ? start_idx - written : 0;
			if (sil > n)
				sil = n;
			if (sil)
				memset(o->pbuf, 0, (size_t)sil * fb);
			if (n - sil)
				stream_read(st, o->pbuf + (size_t)sil * fb, n - sil);
			stream_unref(st);
		}
		int rc;
		if (o->pcm)
			rc = alsa_write(o, to_container(o, o->pbuf, n), n);
		else
			rc = null_write(o, n);

		pthread_mutex_lock(&o->mu);
		if (rc < 0) {
			o->lost = true;
			uint64_t one = 1;
			if (write(o->evfd, &one, sizeof one) < 0)
				LOGE("[output] eventfd: %s", strerror(errno));
			while (!o->quit)
				pthread_cond_wait(&o->cv, &o->mu);
			pthread_mutex_unlock(&o->mu);
			break;
		}
		o->written += n;
		clock_update(o, o->pcm ? alsa_position(o) : null_consumed(o, now_ns()));
		pthread_mutex_unlock(&o->mu);
	}
	return NULL;
}

/* ---- API ---- */

output_t *output_open(const pdev_t *pd, int rate, int bits, int channels, const char **status)
{
	if (!pdev_supports(pd, rate, bits, channels)) {
		*status = "RAAT__OUTPUT_PLUGIN_STATUS_FORMAT_NOT_SUPPORTED";
		return NULL;
	}
	int slot;
	for (slot = 0; slot < MAX_OPEN && open_outputs[slot]; slot++)
		;
	if (slot == MAX_OPEN) {
		*status = "RAAT__OUTPUT_PLUGIN_STATUS_DEVICE_IN_USE";
		return NULL;
	}
	output_t *o = xcalloc(1, sizeof *o);
	pdev_copy(&o->pd, pd);
	o->rate = rate;
	o->bits = bits;
	o->channels = channels;
	o->wire_bpf = bits / 8 * channels;
	o->nspf = 1e9 / rate;
	o->tfd = -1;
	o->evfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (pd->backend == BACKEND_ALSA) {
		*status = alsa_open(o);
		if (*status)
			goto fail;
	} else if (null_open(o) < 0) {
		*status = "RAAT__OUTPUT_PLUGIN_STATUS_DEVICE_INIT_FAILED";
		goto fail;
	}
	o->pbuf = xmalloc((size_t)o->period * (size_t)o->wire_bpf);
	o->cbuf = xmalloc((size_t)o->period * (size_t)o->channels * 4);
	pthread_mutex_init(&o->mu, NULL);
	pthread_cond_init(&o->cv, NULL);
	o->L0 = now_ns();
	o->off = 0;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 128 * 1024);
	if (pthread_create(&o->th, &attr, output_thread, o) != 0) {
		pthread_attr_destroy(&attr);
		*status = "RAAT__OUTPUT_PLUGIN_STATUS_DEVICE_INIT_FAILED";
		goto fail;
	}
	pthread_attr_destroy(&attr);
	open_outputs[slot] = o;
	*status = NULL;
	return o;
fail:
	if (o->pcm)
		snd_pcm_close(o->pcm);
	if (o->tfd >= 0)
		close(o->tfd);
	close(o->evfd);
	free(o->pbuf);
	free(o->cbuf);
	pdev_clear(&o->pd);
	free(o);
	return NULL;
}

void output_close(output_t *o)
{
	if (!o)
		return;
	pthread_mutex_lock(&o->mu);
	o->quit = true;
	pthread_cond_broadcast(&o->cv);
	pthread_mutex_unlock(&o->mu);
	/* The thread finishes its current period write (at most one period). */
	pthread_join(o->th, NULL);
	for (int i = 0; i < MAX_OPEN; i++)
		if (open_outputs[i] == o)
			open_outputs[i] = NULL;
	if (o->st) {
		stream_end_read(o->st);
		stream_unref(o->st);
	}
	if (o->pcm) {
		snd_pcm_drop(o->pcm);
		snd_pcm_close(o->pcm);
	}
	if (o->tfd >= 0)
		close(o->tfd);
	close(o->evfd);
	pthread_mutex_destroy(&o->mu);
	pthread_cond_destroy(&o->cv);
	free(o->pbuf);
	free(o->cbuf);
	pdev_clear(&o->pd);
	free(o);
}

int output_start(output_t *o, int64_t time_ns, int64_t stream_sample, stream_t *st, const char **err)
{
	if (st->rate != o->rate || st->bits != o->bits || st->channels != o->channels ||
	    strcmp(st->sample_type, "pcm")) {
		*err = "RAAT__OUTPUT_PLUGIN_STATUS_FORMAT_NOT_SUPPORTED";
		return -1;
	}
	pthread_mutex_lock(&o->mu);
	if (o->playing || o->start_pending || o->lost) {
		pthread_mutex_unlock(&o->mu);
		*err = "RAAT__OUTPUT_PLUGIN_STATUS_INVALID_STATE";
		return -1;
	}
	/* TODO(playback capture: `start` request `time` vs `min_offset`): `time` is
	 * taken as an instant in the get_local_time domain (spec 13.4.1); frame k of
	 * the device timeline plays at L0 + k * ns_per_frame. */
	stream_ref(st);
	if (o->st) {
		stream_end_read(o->st);
		stream_unref(o->st);
	}
	o->st = st;
	o->start_time = time_ns;
	o->start_sample = stream_sample;
	o->start_pending = true;
	pthread_mutex_unlock(&o->mu);
	return 0;
}

int output_stop(output_t *o, const char **err)
{
	pthread_mutex_lock(&o->mu);
	if (!o->playing && !o->start_pending) {
		pthread_mutex_unlock(&o->mu);
		*err = "RAAT__OUTPUT_PLUGIN_STATUS_INVALID_STATE";
		return -1;
	}
	stream_t *st = o->st;
	o->st = NULL;
	o->playing = o->start_pending = false;
	pthread_mutex_unlock(&o->mu);
	if (st) {
		stream_end_read(st);
		stream_unref(st);
	}
	return 0;
}

bool output_is_playing(output_t *o)
{
	pthread_mutex_lock(&o->mu);
	bool p = o->playing || o->start_pending;
	pthread_mutex_unlock(&o->mu);
	return p;
}

int64_t output_local_time(output_t *o)
{
	pthread_mutex_lock(&o->mu);
	double off = o->off;
	pthread_mutex_unlock(&o->mu);
	return now_ns() + (int64_t)llround(off);
}

int64_t output_delay_ns(output_t *o)
{
	/* TODO(playback capture: RAATCLKR delay the Core expects): local time is the
	 * DAC play position, so the delay reported is the device queue (buffer) plus
	 * any configured extra (sync_offset_ns in the reference). */
	return (int64_t)llround((double)o->bufsize * o->nspf) + g_extra_delay_ns;
}

void output_set_remote_time(output_t *o, double offset_ns, bool reset)
{
	/* TODO(playback capture: `sync` request host/port for a lone zone): the
	 * reference feeds this to drift correction, which inserts or drops dithered
	 * samples. Bit-perfect is a hard rule here, so the offset is recorded and
	 * nothing is ever inserted or dropped. Multi-zone sync needs this designed. */
	pthread_mutex_lock(&o->mu);
	if (reset || !o->remote_valid)
		LOGD("[output] remote clock %s: offset %.3f ms", reset ? "reset" : "set", offset_ns / 1e6);
	o->remote_offset = offset_ns;
	o->remote_valid = true;
	pthread_mutex_unlock(&o->mu);
}

int output_event_fd(output_t *o)
{
	return o->evfd;
}

bool output_lost(output_t *o)
{
	pthread_mutex_lock(&o->mu);
	bool l = o->lost;
	pthread_mutex_unlock(&o->mu);
	return l;
}

char *output_signal_path_json(output_t *o)
{
	cJSON *root = cJSON_CreateObject();
	cJSON *arr = cJSON_AddArrayToObject(root, "signal_path");
	cJSON *e = cJSON_CreateObject();
	cJSON_AddStringToObject(e, "type", "output");
	cJSON_AddStringToObject(e, "method", o->pcm ? "alsa" : "null");
	cJSON_AddStringToObject(e, "quality", "lossless");
	if (o->pcm)
		cJSON_AddStringToObject(e, "alsa_device", o->pd.id);
	cJSON_AddItemToArray(arr, e);
	char *s = cJSON_PrintUnformatted(root);
	cJSON_Delete(root);
	return s;
}
