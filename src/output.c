// SPDX-License-Identifier: GPL-3.0-or-later
#include "output.h"
#include "pw_backend.h"

#include <alsa/asoundlib.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "third_party/cjson/cJSON.h"

/* The R26's own stack ran the G20 with a 1764-frame buffer of two 882-frame
 * periods at 44.1 kHz, i.e. 40 ms in two periods (capture3/hw_params.txt). */
int g_alsa_buffer_ms = 40;
int64_t g_extra_delay_ns = 0;
char *g_null_sink_dir;
static int sink_seq;

struct output {
	pdev_t pd;
	bool is_dsd;
	int dsd_mode;         /* DSD_MODE_* */
	int dsd_bpf_bits;     /* DSD 1-bit samples per ALSA frame (32/16/8 native, 16 DoP) */
	uint8_t dop_marker;   /* alternates 0x05 / 0xFA per PCM frame in DoP mode */
	uint8_t silence_byte; /* 0x00 for PCM, 0x69 for DSD */
	int rate, bits, channels;
	int wire_bpf;
	double nspf; /* ns per device frame */

	/* ALSA */
	snd_pcm_t *pcm;
	snd_pcm_format_t hwfmt;
	int hw_bps; /* container bytes per sample */
	/* PipeWire */
	pw_output_t *pw;
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

	/* Device queue after a write (frames), followed smoothly: the RAATCLKR delay. */
	double qdelay;
	bool q_valid;

	bool lost;
	int evfd;
	int sink_fd; /* null backend: optional dump of what the "DAC" got */
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

	/* Widening into a larger container keeps every bit. The R26's stack played
	 * 16-bit tracks as S32_LE on the G20, whose only container is S32_LE. */
	snd_pcm_format_t cand[6];
	int ncand = 0;
	unsigned alsa_rate = (unsigned)o->rate;
	if (o->is_dsd) {
		if (o->dsd_mode == DSD_MODE_NATIVE) {
			cand[ncand++] = SND_PCM_FORMAT_DSD_U32_BE;
			cand[ncand++] = SND_PCM_FORMAT_DSD_U32_LE;
			cand[ncand++] = SND_PCM_FORMAT_DSD_U16_BE;
			cand[ncand++] = SND_PCM_FORMAT_DSD_U16_LE;
			cand[ncand++] = SND_PCM_FORMAT_DSD_U8;
		} else if (o->dsd_mode == DSD_MODE_DOP) {
			cand[ncand++] = SND_PCM_FORMAT_S24_3LE;
			cand[ncand++] = SND_PCM_FORMAT_S32_LE;
			cand[ncand++] = SND_PCM_FORMAT_S24_LE;
		} else {
			fail = "RAAT__OUTPUT_PLUGIN_STATUS_FORMAT_NOT_SUPPORTED";
			goto bad;
		}
	} else if (o->bits == 16) {
		cand[ncand++] = SND_PCM_FORMAT_S16_LE;
		cand[ncand++] = SND_PCM_FORMAT_S32_LE;
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
	for (i = 0; i < ncand; i++) {
		if (snd_pcm_hw_params_test_format(pcm, hw, cand[i]) != 0)
			continue;
		if (o->is_dsd) {
			int w = snd_pcm_format_physical_width(cand[i]);
			unsigned r = o->dsd_mode == DSD_MODE_NATIVE ? (unsigned)o->rate / (unsigned)w
								    : (unsigned)o->rate / 16u;
			snd_pcm_hw_params_t *tmp;
			snd_pcm_hw_params_alloca(&tmp);
			snd_pcm_hw_params_copy(tmp, hw);
			if (snd_pcm_hw_params_set_format(pcm, tmp, cand[i]) == 0 &&
			    snd_pcm_hw_params_set_channels(pcm, tmp, (unsigned)o->channels) == 0 &&
			    snd_pcm_hw_params_test_rate(pcm, tmp, r, 0) == 0) {
				alsa_rate = r;
				break;
			}
		} else {
			break;
		}
	}
	if (i == ncand || snd_pcm_hw_params_set_format(pcm, hw, cand[i]) < 0) {
		LOGW("[alsa] %s: no sample format for %s %d-bit", o->pd.id,
		     o->is_dsd ? "dsd" : "pcm", o->bits);
		fail = "RAAT__OUTPUT_PLUGIN_STATUS_FORMAT_NOT_SUPPORTED";
		goto bad;
	}
	o->hwfmt = cand[i];
	o->hw_bps = snd_pcm_format_physical_width(o->hwfmt) / 8;
	if (o->is_dsd) {
		o->dsd_bpf_bits = o->dsd_mode == DSD_MODE_NATIVE ? o->hw_bps * 8 : 16;
		o->wire_bpf = (o->dsd_bpf_bits / 8) * o->channels;
		o->nspf = 1e9 / (double)alsa_rate;
		o->dop_marker = 0x05;
	}
	if (snd_pcm_hw_params_set_channels(pcm, hw, (unsigned)o->channels) < 0 ||
	    snd_pcm_hw_params_set_rate(pcm, hw, alsa_rate, 0) < 0) {
		LOGW("[alsa] %s: %d ch / %u Hz refused with %s", o->pd.id, o->channels, alsa_rate,
		     snd_pcm_format_name(o->hwfmt));
		fail = "RAAT__OUTPUT_PLUGIN_STATUS_FORMAT_NOT_SUPPORTED";
		goto bad;
	}
	unsigned buf_us = (unsigned)g_alsa_buffer_ms * 1000u, per_us = buf_us / 2;
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
	if (rate != alsa_rate) {
		LOGE("[alsa] %s: got rate %u for %u; refusing (no resampling)", o->pd.id, rate,
		     alsa_rate);
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
 * container keeps every bit; nothing else is ever done to the samples. */
static bool container_is_wire(output_t *o)
{
	return (o->bits == 16 && o->hwfmt == SND_PCM_FORMAT_S16_LE) ||
	       (o->bits == 24 && o->hwfmt == SND_PCM_FORMAT_S24_3LE) ||
	       (o->bits == 32 && o->hwfmt == SND_PCM_FORMAT_S32_LE);
}

static const uint8_t *to_container_dsd(output_t *o, const uint8_t *src, int64_t frames)
{
	int ch = o->channels;
	uint8_t *d = o->cbuf;
	if (o->dsd_mode == DSD_MODE_NATIVE) {
		if (o->hwfmt == SND_PCM_FORMAT_DSD_U8)
			return src;
		int bpc = o->hw_bps; /* 2 or 4 bytes per channel per ALSA frame */
		bool le = (o->hwfmt == SND_PCM_FORMAT_DSD_U32_LE ||
			   o->hwfmt == SND_PCM_FORMAT_DSD_U16_LE);
		for (int64_t f = 0; f < frames; f++, src += bpc * ch) {
			for (int c = 0; c < ch; c++, d += bpc) {
				if (le) {
					for (int k = 0; k < bpc; k++)
						d[k] = src[(bpc - 1 - k) * ch + c];
				} else {
					for (int k = 0; k < bpc; k++)
						d[k] = src[k * ch + c];
				}
			}
		}
		return o->cbuf;
	}
	/* DoP v1.1: 2 wire DSD bytes per channel per 24/32-bit PCM frame + 0x05/0xFA marker. */
	for (int64_t f = 0; f < frames; f++, src += 2 * ch) {
		uint8_t m = o->dop_marker;
		o->dop_marker = (m == 0x05) ? 0xFA : 0x05;
		for (int c = 0; c < ch; c++) {
			uint8_t b0 = src[c];       /* earlier 8 DSD bits (MSB) */
			uint8_t b1 = src[ch + c];  /* later 8 DSD bits (LSB) */
			if (o->hwfmt == SND_PCM_FORMAT_S24_3LE) {
				d[0] = b1;
				d[1] = b0;
				d[2] = m;
				d += 3;
			} else if (o->hwfmt == SND_PCM_FORMAT_S32_LE) {
				d[0] = 0;
				d[1] = b1;
				d[2] = b0;
				d[3] = m;
				d += 4;
			} else { /* S24_LE, right-justified */
				d[0] = b1;
				d[1] = b0;
				d[2] = m;
				d[3] = 0;
				d += 4;
			}
		}
	}
	return o->cbuf;
}

static const uint8_t *to_container(output_t *o, const uint8_t *src, int64_t frames)
{
	if (o->is_dsd)
		return to_container_dsd(o, src, frames);
	if (container_is_wire(o))
		return src;
	int64_t ns = frames * o->channels;
	uint8_t *d = o->cbuf;
	if (o->bits == 16) { /* 16 -> S32_LE, left-justified */
		for (int64_t i = 0; i < ns; i++, src += 2, d += 4) {
			d[0] = 0;
			d[1] = 0;
			d[2] = src[0];
			d[3] = src[1];
		}
	} else if (o->hwfmt == SND_PCM_FORMAT_S32_LE) { /* 24 -> S32_LE, left-justified */
		for (int64_t i = 0; i < ns; i++, src += 3, d += 4) {
			d[0] = 0;
			d[1] = src[0];
			d[2] = src[1];
			d[3] = src[2];
		}
	} else { /* 24 -> S24_LE, right-justified, sign-extended */
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
			/* Not seen in capture3 (no Dropout reported). The position
			 * clock jumps here; we log and recover. */
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
	o->period = o->bufsize / 2;
	/* The fixture may name the container the real device would get, so the
	 * widening path is exercised and visible in the sink dump. */
	const char *c = o->pd.container;
	if (!strcmp(c, "S32_LE") && o->bits <= 32)
		o->hwfmt = SND_PCM_FORMAT_S32_LE;
	else if (!strcmp(c, "S24_LE") && o->bits == 24)
		o->hwfmt = SND_PCM_FORMAT_S24_LE;
	else
		o->hwfmt = o->bits == 16 ? SND_PCM_FORMAT_S16_LE
			 : o->bits == 24 ? SND_PCM_FORMAT_S24_3LE : SND_PCM_FORMAT_S32_LE;
	o->hw_bps = snd_pcm_format_physical_width(o->hwfmt) / 8;
	o->sink_fd = -1;
	if (g_null_sink_dir) {
		char path[1024];
		snprintf(path, sizeof path, "%s/sink-%d.raw", g_null_sink_dir, ++sink_seq);
		o->sink_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	}
	return 0;
}

/* Fake DAC position, or -1 before it starts (like a PCM not yet running). */
static int64_t null_consumed(output_t *o, int64_t t)
{
	if (!o->null_t0)
		return -1;
	int64_t c = (int64_t)((double)(t - o->null_t0) / o->nspf);
	return c > o->written ? o->written : c;
}

/* Blocks on a timerfd until the fake DAC has room, like a blocking writei. */
static int null_write(output_t *o, const uint8_t *buf, int64_t frames)
{
	if (o->sink_fd >= 0) {
		size_t len = (size_t)frames * (size_t)o->hw_bps * (size_t)o->channels;
		if (write(o->sink_fd, buf, len) != (ssize_t)len)
			return -1;
	}
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
		/* The Core reads the clock in bursts of three RAATCLKQ 5 ms apart,
		 * every 2 s, from setup until stop (capture3); RTTs were 0.2-0.7 ms.
		 * A first-order filter over period-granular readings keeps the
		 * clock smooth at that resolution. */
		o->off += (meas - o->off) / 16.0;
	}
	/* Reported delay: a decaying maximum of the queue right after a write,
	 * never below what was just measured. Starting from buffer + period, it
	 * is at least the real queue from the first query after setup on, when
	 * USB in flight is not yet visible in the first readings. An average
	 * here let starts land a few ms late right after an ALSA reopen. */
	double q = (double)(o->written - pos);
	if (!o->q_valid) {
		o->qdelay = (double)(o->bufsize + o->period);
		o->q_valid = true;
	}
	if (q > o->qdelay)
		o->qdelay = q;
	else
		o->qdelay += (q - o->qdelay) / 256.0;
}

static void *output_thread(void *arg)
{
	output_t *o = arg;
	/* RoonBridge runs its ALSA thread SCHED_RR at priority 95 (spec 14.9). Needs
	 * CAP_SYS_NICE; without it the thread stays SCHED_OTHER. */
	struct sched_param sp = { .sched_priority = 95 };
	int se = pthread_setschedparam(pthread_self(), SCHED_RR, &sp);
	if (se)
		LOGI("[output] no real-time priority for the output thread: %s", strerror(se));
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
				/* Too late for the requested instant. RoonBridge skips the
				 * missed samples (spec 14.9); here nothing is dropped: the
				 * stream starts at the next frame, late by that much. */
				LOGW("[output] start time is %lld frames late; starting late instead of "
				     "dropping them", (long long)(o->written - k));
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
			memset(o->pbuf, o->silence_byte, (size_t)n * fb);
		} else {
			int64_t sil = start_idx > written ? start_idx - written : 0;
			if (sil > n)
				sil = n;
			if (sil)
				memset(o->pbuf, o->silence_byte, (size_t)sil * fb);
			if (n - sil) {
				int64_t scale = o->is_dsd ? o->dsd_bpf_bits : 1;
				stream_read(st, o->pbuf + (size_t)sil * fb, (n - sil) * scale);
			}
			stream_unref(st);
		}
		int rc;
		if (o->pcm)
			rc = alsa_write(o, to_container(o, o->pbuf, n), n);
		else
			rc = null_write(o, to_container(o, o->pbuf, n), n);

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

void output_pw_process(output_t *o, uint8_t *dst, int64_t nframes, int64_t queued_frames)
{
	pthread_mutex_lock(&o->mu);
	if (o->quit) {
		pthread_mutex_unlock(&o->mu);
		memset(dst, 0, (size_t)nframes * (size_t)o->wire_bpf);
		return;
	}
	if (o->start_pending) {
		int64_t k = (int64_t)ceil((double)(o->start_time - o->L0) / o->nspf);
		int64_t s0 = o->start_sample;
		if (k < o->written) {
			LOGW("[output] start time is %lld frames late; starting late instead of "
			     "dropping them", (long long)(o->written - k));
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

	size_t fb = (size_t)o->wire_bpf;
	if (!st) {
		memset(dst, 0, (size_t)nframes * fb);
	} else {
		int64_t sil = start_idx > written ? start_idx - written : 0;
		if (sil > nframes)
			sil = nframes;
		if (sil)
			memset(dst, 0, (size_t)sil * fb);
		if (nframes - sil)
			stream_read(st, dst + (size_t)sil * fb, nframes - sil);
		stream_unref(st);
	}

	pthread_mutex_lock(&o->mu);
	o->written += nframes;
	int64_t pos = o->written - queued_frames;
	if (pos < 0)
		pos = 0;
	clock_update(o, pos);
	pthread_mutex_unlock(&o->mu);
}

void output_pw_lost(output_t *o)
{
	pthread_mutex_lock(&o->mu);
	if (!o->lost) {
		o->lost = true;
		uint64_t one = 1;
		if (write(o->evfd, &one, sizeof one) < 0)
			LOGE("[output] eventfd: %s", strerror(errno));
	}
	pthread_mutex_unlock(&o->mu);
}

/* ---- API ---- */

output_t *output_open(const pdev_t *pd, const char *sample_type, int rate, int bits, int channels,
		      int dsd_mode, int64_t clock_base, const char **status)
{
	bool is_dsd = sample_type && !strcmp(sample_type, "dsd");
	if (!pdev_supports(pd, rate, bits, channels) || (is_dsd && bits != 1) ||
	    (!is_dsd && bits == 1)) {
		LOGW("[output] %s: %s %d/%d/%d is not in the device's format list", pd->id,
		     sample_type ? sample_type : "?", rate, bits, channels);
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
	o->is_dsd = is_dsd;
	o->dsd_mode = is_dsd ? dsd_mode : DSD_MODE_NONE;
	o->silence_byte = is_dsd ? 0x69 : 0x00;
	o->rate = rate;
	o->bits = bits;
	o->channels = channels;
	o->wire_bpf = is_dsd ? 4 * channels : (bits / 8) * channels;
	o->nspf = 1e9 / rate;
	o->tfd = -1;
	o->sink_fd = -1;
	o->evfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	pthread_mutex_init(&o->mu, NULL);
	pthread_cond_init(&o->cv, NULL);
	/* The clock starts at 0 with the first setup and resumes from where it
	 * stopped on the next one: capture3 shows ~0.05 s right after the first
	 * setup and, after a 1 s teardown gap, a value that had paused (spec 13.7). */
	o->L0 = clock_base;
	o->off = (double)clock_base - (double)now_ns();
	if (pd->backend == BACKEND_ALSA) {
		*status = alsa_open(o);
		if (*status)
			goto fail;
	} else if (pd->backend == BACKEND_PIPEWIRE) {
		o->pw = pw_output_open(o, pd, rate, bits, channels, g_alsa_buffer_ms,
				       &o->period, &o->bufsize, status);
		if (!o->pw)
			goto fail;
	} else if (null_open(o) < 0) {
		*status = "RAAT__OUTPUT_PLUGIN_STATUS_DEVICE_INIT_FAILED";
		goto fail;
	}
	if (!o->pw) {
		o->pbuf = xmalloc((size_t)o->period * (size_t)o->wire_bpf);
		o->cbuf = xmalloc((size_t)o->period * (size_t)o->channels * 4);
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, 128 * 1024);
		if (pthread_create(&o->th, &attr, output_thread, o) != 0) {
			pthread_attr_destroy(&attr);
			*status = "RAAT__OUTPUT_PLUGIN_STATUS_DEVICE_INIT_FAILED";
			goto fail;
		}
		pthread_attr_destroy(&attr);
	}
	open_outputs[slot] = o;
	*status = NULL;
	return o;
fail:
	if (o->pw)
		pw_output_close(o->pw);
	if (o->pcm)
		snd_pcm_close(o->pcm);
	if (o->tfd >= 0)
		close(o->tfd);
	if (o->sink_fd >= 0)
		close(o->sink_fd);
	close(o->evfd);
	pthread_mutex_destroy(&o->mu);
	pthread_cond_destroy(&o->cv);
	free(o->pbuf);
	free(o->cbuf);
	pdev_clear(&o->pd);
	free(o);
	return NULL;
}

int64_t output_close(output_t *o)
{
	if (!o)
		return 0;
	int64_t clock_end = output_local_time(o);
	pthread_mutex_lock(&o->mu);
	o->quit = true;
	pthread_cond_broadcast(&o->cv);
	pthread_mutex_unlock(&o->mu);
	if (o->pw) {
		pw_output_close(o->pw);
		o->pw = NULL;
	} else {
		/* The thread finishes its current period write (at most one period). */
		pthread_join(o->th, NULL);
	}
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
	if (o->sink_fd >= 0)
		close(o->sink_fd);
	close(o->evfd);
	pthread_mutex_destroy(&o->mu);
	pthread_cond_destroy(&o->cv);
	free(o->pbuf);
	free(o->cbuf);
	pdev_clear(&o->pd);
	free(o);
	return clock_end;
}

int output_start(output_t *o, int64_t time_ns, int64_t stream_sample, stream_t *st, const char **err)
{
	if (st->rate != o->rate || st->bits != o->bits || st->channels != o->channels ||
	    strcmp(st->sample_type, o->is_dsd ? "dsd" : "pcm")) {
		*err = "RAAT__OUTPUT_PLUGIN_STATUS_FORMAT_NOT_SUPPORTED";
		return -1;
	}
	pthread_mutex_lock(&o->mu);
	if (o->playing || o->start_pending || o->lost) {
		pthread_mutex_unlock(&o->mu);
		*err = "RAAT__OUTPUT_PLUGIN_STATUS_INVALID_STATE";
		return -1;
	}
	/* time_ns is in the get_local_time domain. In capture3 the Core never sent
	 * `time`: the script used get_local_time + min_offset, and min_offset was
	 * the last RAATCLKR delay + 20 ms. Frame k of the device timeline plays at
	 * L0 + k * ns_per_frame, so the stream starts at frame ceil((t - L0)/nspf). */
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
	/* Local time is the DAC play position, so the delay is how far ahead of it
	 * a frame written now lands: the device queue right after a write. The R26
	 * reported 49.09-49.21 ms for a 40 ms ALSA buffer (USB in flight on top),
	 * steady from setup on, and the Core set min_offset = delay + 20 ms. */
	pthread_mutex_lock(&o->mu);
	double q = o->q_valid ? o->qdelay : (double)(o->bufsize + o->period);
	pthread_mutex_unlock(&o->mu);
	return (int64_t)llround(q * o->nspf) + g_extra_delay_ns;
}

void output_set_remote_time(output_t *o, double offset_ns, bool reset)
{
	/* A lone zone gets no `sync` at all (capture3): the Core paces itself to
	 * this clock. sync only matters for grouped zones, which no capture covers
	 * yet. The reference feeds the offset to drift correction, which inserts or
	 * drops dithered samples; bit-perfect is a hard rule here, so the offset is
	 * recorded and nothing is ever inserted or dropped. */
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
	if (o->is_dsd && o->dsd_mode == DSD_MODE_DOP) {
		cJSON *de = cJSON_CreateObject();
		cJSON_AddStringToObject(de, "type", "dsd_encapsulate");
		cJSON_AddStringToObject(de, "method", "dop");
		cJSON_AddStringToObject(de, "quality", "lossless");
		cJSON_AddItemToArray(arr, de);
	}
	cJSON *e = cJSON_CreateObject();
	/* Shape as sent by the R26 (capture3): alsa_device is the card info. */
	cJSON_AddStringToObject(e, "type", "output");
	cJSON_AddStringToObject(e, "method",
				o->pw ? "os_mixer" : (o->pcm ? "alsa" : "null"));
	cJSON_AddStringToObject(e, "quality", o->pw ? "high" : "lossless");
	cJSON *ad = cJSON_AddObjectToObject(e, "alsa_device");
	cJSON_AddStringToObject(ad, "name", o->pd.name);
	cJSON_AddStringToObject(ad, "id", o->pd.card_id);
	cJSON_AddStringToObject(ad, "longname", o->pd.longname);
	/* RoonBridge fills "components" from snd_ctl_card_info_get_id (spec 14.9). */
	cJSON_AddStringToObject(ad, "components", o->pd.card_id);
	if (o->pd.usb_id[0])
		cJSON_AddStringToObject(ad, "usbid", o->pd.usb_id);
	cJSON_AddStringToObject(ad, "driver", o->pd.driver);
	cJSON_AddStringToObject(ad, "mixername", o->pd.mixername);
	cJSON_AddItemToArray(arr, e);
	char *s = cJSON_PrintUnformatted(root);
	cJSON_Delete(root);
	return s;
}
