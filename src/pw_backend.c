// SPDX-License-Identifier: GPL-3.0-or-later
#ifdef ENABLE_PIPEWIRE

#include "pw_backend.h"

#include <errno.h>
#include <fcntl.h>
#include <pipewire/pipewire.h>
#include <pthread.h>
#include <spa/param/audio/format-utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

static bool g_pw_inited;

static void ensure_pw_init(void)
{
	if (!g_pw_inited) {
		pw_init(NULL, NULL);
		g_pw_inited = true;
	}
}

/* ---- discovery ---- */

typedef struct {
	uint32_t id;
	char node_name[128];
	char desc[128];
	char vendor[128];
	int channels;
} pw_sink_t;

static struct {
	struct pw_thread_loop *loop;
	struct pw_context *ctx;
	struct pw_core *core;
	struct spa_hook core_listener;
	struct pw_registry *registry;
	struct spa_hook reg_listener;
	int sync_seq;
	bool synced;
	int hotplug_fd;
	pthread_mutex_t mu;
	pw_sink_t *sinks;
	int nsinks;
} D = { .hotplug_fd = -1, .mu = PTHREAD_MUTEX_INITIALIZER };

static void signal_hotplug(void)
{
	if (D.hotplug_fd >= 0) {
		uint64_t one = 1;
		ssize_t r = write(D.hotplug_fd, &one, sizeof one);
		(void)r;
	}
}

static void on_core_done(void *data, uint32_t id, int seq)
{
	(void)data;
	if (id == PW_ID_CORE && seq == D.sync_seq) {
		D.synced = true;
		pw_thread_loop_signal(D.loop, false);
	}
}

static void on_core_error(void *data, uint32_t id, int seq, int res, const char *message)
{
	(void)data;
	(void)seq;
	LOGW("[pipewire] core error id=%u res=%d: %s", id, res, message ? message : "");
	if (id == PW_ID_CORE) {
		D.synced = true;
		pw_thread_loop_signal(D.loop, false);
	}
}

static const struct pw_core_events core_events = {
	PW_VERSION_CORE_EVENTS,
	.done = on_core_done,
	.error = on_core_error,
};

static void on_reg_global(void *data, uint32_t id, uint32_t permissions, const char *type,
			  uint32_t version, const struct spa_dict *props)
{
	(void)data;
	(void)permissions;
	(void)version;
	if (!props || strcmp(type, PW_TYPE_INTERFACE_Node) != 0)
		return;
	const char *mclass = spa_dict_lookup(props, PW_KEY_MEDIA_CLASS);
	if (!mclass || (strcmp(mclass, "Audio/Sink") != 0 && strcmp(mclass, "Audio/Duplex") != 0))
		return;
	const char *nname = spa_dict_lookup(props, PW_KEY_NODE_NAME);
	if (!nname || !nname[0])
		return;
	const char *desc = spa_dict_lookup(props, PW_KEY_NODE_DESCRIPTION);
	if (!desc || !desc[0])
		desc = spa_dict_lookup(props, PW_KEY_NODE_NICK);
	if (!desc || !desc[0])
		desc = nname;
	const char *vendor = spa_dict_lookup(props, "device.vendor.name");
	const char *ch_s = spa_dict_lookup(props, PW_KEY_AUDIO_CHANNELS);
	int ch = ch_s ? atoi(ch_s) : 2;
	if (ch < 1 || ch > 8)
		ch = 2;

	pthread_mutex_lock(&D.mu);
	int idx = -1;
	for (int i = 0; i < D.nsinks; i++) {
		if (D.sinks[i].id == id) {
			idx = i;
			break;
		}
	}
	if (idx < 0) {
		idx = D.nsinks++;
		D.sinks = xrealloc(D.sinks, sizeof *D.sinks * (size_t)D.nsinks);
	}
	memset(&D.sinks[idx], 0, sizeof D.sinks[idx]);
	D.sinks[idx].id = id;
	strlcpy0(D.sinks[idx].node_name, nname, sizeof D.sinks[idx].node_name);
	strlcpy0(D.sinks[idx].desc, desc, sizeof D.sinks[idx].desc);
	strlcpy0(D.sinks[idx].vendor, vendor ? vendor : "", sizeof D.sinks[idx].vendor);
	D.sinks[idx].channels = ch;
	pthread_mutex_unlock(&D.mu);

	LOGD("[pipewire] discovered sink #%u: %s (%s)", id, desc, nname);
	signal_hotplug();
}

static void on_reg_global_remove(void *data, uint32_t id)
{
	(void)data;
	bool removed = false;
	pthread_mutex_lock(&D.mu);
	for (int i = 0; i < D.nsinks; i++) {
		if (D.sinks[i].id == id) {
			LOGD("[pipewire] removed sink #%u: %s", id, D.sinks[i].desc);
			if (i + 1 < D.nsinks)
				memmove(&D.sinks[i], &D.sinks[i + 1],
					sizeof *D.sinks * (size_t)(D.nsinks - i - 1));
			D.nsinks--;
			removed = true;
			break;
		}
	}
	pthread_mutex_unlock(&D.mu);
	if (removed)
		signal_hotplug();
}

static const struct pw_registry_events reg_events = {
	PW_VERSION_REGISTRY_EVENTS,
	.global = on_reg_global,
	.global_remove = on_reg_global_remove,
};

int pw_platform_init(void)
{
	ensure_pw_init();
	D.hotplug_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	D.synced = false;
	D.loop = pw_thread_loop_new("raat-pw-disc", NULL);
	if (!D.loop) {
		LOGE("[pipewire] failed to create discovery loop");
		goto fail;
	}
	D.ctx = pw_context_new(pw_thread_loop_get_loop(D.loop), NULL, 0);
	if (!D.ctx) {
		LOGE("[pipewire] failed to create context");
		goto fail;
	}
	if (pw_thread_loop_start(D.loop) < 0) {
		LOGE("[pipewire] failed to start discovery loop");
		goto fail;
	}
	pw_thread_loop_lock(D.loop);
	D.core = pw_context_connect(D.ctx, NULL, 0);
	if (!D.core) {
		pw_thread_loop_unlock(D.loop);
		LOGE("[pipewire] failed to connect to PipeWire daemon");
		goto fail;
	}
	pw_core_add_listener(D.core, &D.core_listener, &core_events, NULL);
	D.registry = pw_core_get_registry(D.core, PW_VERSION_REGISTRY, 0);
	pw_registry_add_listener(D.registry, &D.reg_listener, &reg_events, NULL);
	D.sync_seq = pw_core_sync(D.core, PW_ID_CORE, 0);
	if (!D.synced)
		pw_thread_loop_timed_wait(D.loop, 2);
	pw_thread_loop_unlock(D.loop);
	LOGI("[pipewire] connected (%d sinks discovered)", D.nsinks);
	return 0;
fail:
	pw_platform_shutdown();
	return -1;
}

void pw_platform_shutdown(void)
{
	if (D.loop) {
		pw_thread_loop_lock(D.loop);
		if (D.registry) {
			spa_hook_remove(&D.reg_listener);
			pw_proxy_destroy((struct pw_proxy *)D.registry);
			D.registry = NULL;
		}
		if (D.core) {
			spa_hook_remove(&D.core_listener);
			pw_core_disconnect(D.core);
			D.core = NULL;
		}
		pw_thread_loop_unlock(D.loop);
		pw_thread_loop_stop(D.loop);
		if (D.ctx) {
			pw_context_destroy(D.ctx);
			D.ctx = NULL;
		}
		pw_thread_loop_destroy(D.loop);
		D.loop = NULL;
	}
	pthread_mutex_lock(&D.mu);
	free(D.sinks);
	D.sinks = NULL;
	D.nsinks = 0;
	pthread_mutex_unlock(&D.mu);
	if (D.hotplug_fd >= 0) {
		close(D.hotplug_fd);
		D.hotplug_fd = -1;
	}
}

static const int pw_rates[] = { 44100, 48000, 88200, 96000, 176400, 192000, 352800, 384000 };
static const int pw_bits[] = { 16, 24, 32 };

static void fill_pw_formats(pdev_t *d, int extra_ch)
{
	int nch = (extra_ch > 2 && extra_ch <= 8) ? 2 : 1;
	int chs[2] = { 2, extra_ch };
	int nr = (int)(sizeof pw_rates / sizeof pw_rates[0]);
	int nb = (int)(sizeof pw_bits / sizeof pw_bits[0]);
	d->fmts = xmalloc(sizeof *d->fmts * (size_t)(nr * nb * nch));
	int k = 0;
	for (int r = 0; r < nr; r++)
		for (int b = 0; b < nb; b++)
			for (int c = 0; c < nch; c++)
				d->fmts[k++] = (pcm_fmt_t){ pw_rates[r], pw_bits[b], chs[c] };
	d->nfmts = k;
}

int pw_platform_scan(pdev_t **out, int *n)
{
	pthread_mutex_lock(&D.mu);
	int cnt = 1 + D.nsinks;
	pdev_t *list = xcalloc((size_t)cnt, sizeof *list);

	/* Entry 0: PipeWire Default Output (follows desktop default sink). */
	pdev_t *def = &list[0];
	strlcpy0(def->id, "pw:default", sizeof def->id);
	strlcpy0(def->name, "PipeWire Default Output", sizeof def->name);
	strlcpy0(def->card_id, "pw_default", sizeof def->card_id);
	strlcpy0(def->longname, "PipeWire Default Output", sizeof def->longname);
	strlcpy0(def->driver, "pipewire", sizeof def->driver);
	def->card = 0;
	def->dev = 0;
	def->backend = BACKEND_PIPEWIRE;
	fill_pw_formats(def, 2);

	for (int i = 0; i < D.nsinks; i++) {
		pdev_t *d = &list[1 + i];
		const pw_sink_t *s = &D.sinks[i];
		snprintf(d->id, sizeof d->id, "pw:%s", s->node_name);
		strlcpy0(d->name, s->desc, sizeof d->name);
		strlcpy0(d->vendor, s->vendor, sizeof d->vendor);
		snprintf(d->card_id, sizeof d->card_id, "pw_%u", s->id);
		strlcpy0(d->longname, s->desc, sizeof d->longname);
		strlcpy0(d->driver, "pipewire", sizeof d->driver);
		d->card = (int)s->id;
		d->dev = 0;
		d->backend = BACKEND_PIPEWIRE;
		fill_pw_formats(d, s->channels);
	}
	pthread_mutex_unlock(&D.mu);
	*out = list;
	*n = cnt;
	return 0;
}

int pw_platform_watch_fd(void)
{
	if (D.hotplug_fd < 0)
		return -1;
	return fcntl(D.hotplug_fd, F_DUPFD_CLOEXEC, 0);
}

void pw_platform_watch_drain(int fd)
{
	uint64_t v;
	while (read(fd, &v, sizeof v) > 0)
		;
}

/* ---- playback stream ---- */

struct pw_output {
	output_t *parent;
	struct pw_thread_loop *loop;
	struct pw_stream *stream;
	int rate, channels, wire_bpf;
	int64_t period;
};

static void on_stream_process(void *userdata)
{
	pw_output_t *p = userdata;
	struct pw_buffer *b = pw_stream_dequeue_buffer(p->stream);
	if (!b)
		return;
	struct spa_buffer *buf = b->buffer;
	uint8_t *dst = buf->datas[0].data;
	if (!dst) {
		pw_stream_queue_buffer(p->stream, b);
		return;
	}
	uint32_t max_frames = buf->datas[0].maxsize / (uint32_t)p->wire_bpf;
	uint32_t nframes = b->requested ? (uint32_t)b->requested : max_frames;
	if (nframes > max_frames)
		nframes = max_frames;
	if (nframes == 0) {
		pw_stream_queue_buffer(p->stream, b);
		return;
	}

	struct pw_time t;
	int64_t queued = p->period;
	if (pw_stream_get_time_n(p->stream, &t, sizeof t) == 0 && t.rate.denom > 0) {
		double delay_f = (double)t.delay * (double)p->rate * (double)t.rate.num /
				 (double)t.rate.denom;
		queued = (int64_t)t.queued + (int64_t)delay_f + (int64_t)nframes;
		if (queued < 0)
			queued = 0;
	}

	output_pw_process(p->parent, dst, (int64_t)nframes, queued);

	buf->datas[0].chunk->offset = 0;
	buf->datas[0].chunk->stride = p->wire_bpf;
	buf->datas[0].chunk->size = nframes * (uint32_t)p->wire_bpf;
	pw_stream_queue_buffer(p->stream, b);
}

static void on_stream_state(void *userdata, enum pw_stream_state old, enum pw_stream_state state,
			    const char *error)
{
	pw_output_t *p = userdata;
	LOGD("[pipewire] stream state %s -> %s%s%s", pw_stream_state_as_string(old),
	     pw_stream_state_as_string(state), error ? ": " : "", error ? error : "");
	if (state == PW_STREAM_STATE_ERROR)
		output_pw_lost(p->parent);
}

static const struct pw_stream_events stream_events = {
	PW_VERSION_STREAM_EVENTS,
	.state_changed = on_stream_state,
	.process = on_stream_process,
};

pw_output_t *pw_output_open(output_t *o, const pdev_t *pd, int rate, int bits, int channels,
			    int buffer_ms, int64_t *period_out, int64_t *bufsize_out,
			    const char **status)
{
	ensure_pw_init();
	enum spa_audio_format fmt;
	if (bits == 16)
		fmt = SPA_AUDIO_FORMAT_S16_LE;
	else if (bits == 24)
		fmt = SPA_AUDIO_FORMAT_S24_LE;
	else if (bits == 32)
		fmt = SPA_AUDIO_FORMAT_S32_LE;
	else {
		*status = "RAAT__OUTPUT_PLUGIN_STATUS_FORMAT_NOT_SUPPORTED";
		return NULL;
	}

	pw_output_t *p = xcalloc(1, sizeof *p);
	p->parent = o;
	p->rate = rate;
	p->channels = channels;
	p->wire_bpf = (bits / 8) * channels;
	int64_t bufsize = (int64_t)rate * buffer_ms / 1000;
	if (bufsize < 256)
		bufsize = 256;
	p->period = bufsize / 2;
	*period_out = p->period;
	*bufsize_out = bufsize;

	p->loop = pw_thread_loop_new("raat-pw-out", NULL);
	if (!p->loop) {
		free(p);
		*status = "RAAT__OUTPUT_PLUGIN_STATUS_DEVICE_INIT_FAILED";
		return NULL;
	}

	char rate_str[32], lat_str[32];
	snprintf(rate_str, sizeof rate_str, "1/%d", rate);
	snprintf(lat_str, sizeof lat_str, "%lld/%d", (long long)p->period, rate);

	struct pw_properties *props = pw_properties_new(
		PW_KEY_MEDIA_TYPE, "Audio",
		PW_KEY_MEDIA_CATEGORY, "Playback",
		PW_KEY_MEDIA_ROLE, "Music",
		PW_KEY_APP_NAME, "raat-endpoint",
		PW_KEY_NODE_NAME, "raat-endpoint",
		PW_KEY_NODE_RATE, rate_str,
		PW_KEY_NODE_LATENCY, lat_str,
		NULL);
	if (strncmp(pd->id, "pw:", 3) == 0 && strcmp(pd->id, "pw:default") != 0)
		pw_properties_set(props, PW_KEY_TARGET_OBJECT, pd->id + 3);

	p->stream = pw_stream_new_simple(pw_thread_loop_get_loop(p->loop), "raat-endpoint", props,
					 &stream_events, p);
	if (!p->stream) {
		pw_thread_loop_destroy(p->loop);
		free(p);
		*status = "RAAT__OUTPUT_PLUGIN_STATUS_DEVICE_OPEN_FAILED";
		return NULL;
	}

	uint8_t pod_buf[1024];
	struct spa_pod_builder b = SPA_POD_BUILDER_INIT(pod_buf, sizeof pod_buf);
	struct spa_audio_info_raw info = {
		.format = fmt,
		.rate = (uint32_t)rate,
		.channels = (uint32_t)channels,
	};
	if (channels == 2) {
		info.position[0] = SPA_AUDIO_CHANNEL_FL;
		info.position[1] = SPA_AUDIO_CHANNEL_FR;
	}
	const struct spa_pod *params[1];
	params[0] = spa_format_audio_raw_build(&b, SPA_PARAM_EnumFormat, &info);

	if (pw_stream_connect(p->stream, PW_DIRECTION_OUTPUT, PW_ID_ANY,
			      PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS |
				      PW_STREAM_FLAG_RT_PROCESS,
			      params, 1) < 0) {
		LOGW("[pipewire] stream connect failed for %s", pd->id);
		pw_stream_destroy(p->stream);
		pw_thread_loop_destroy(p->loop);
		free(p);
		*status = "RAAT__OUTPUT_PLUGIN_STATUS_DEVICE_OPEN_FAILED";
		return NULL;
	}

	if (pw_thread_loop_start(p->loop) < 0) {
		pw_stream_destroy(p->stream);
		pw_thread_loop_destroy(p->loop);
		free(p);
		*status = "RAAT__OUTPUT_PLUGIN_STATUS_DEVICE_INIT_FAILED";
		return NULL;
	}

	LOGI("[pipewire] %s open %d/%d/%d (target %s)", pd->id, rate, bits, channels,
	     strcmp(pd->id, "pw:default") == 0 ? "default" : pd->id + 3);
	*status = NULL;
	return p;
}

void pw_output_close(pw_output_t *p)
{
	if (!p)
		return;
	pw_thread_loop_stop(p->loop);
	pw_stream_destroy(p->stream);
	pw_thread_loop_destroy(p->loop);
	free(p);
}

#endif /* ENABLE_PIPEWIRE */
