// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform.h"
#include "pw_backend.h"

#include <alsa/asoundlib.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "third_party/cjson/cJSON.h"

static char *fixture;
static bool use_pw;
static struct platform_uname uname_info;
static snd_config_t *lconf;

/* Minimal pcm.hw / ctl.hw definitions (the same argument shape as alsa.conf). */
static const char lconf_text[] =
	"pcm.hw {\n"
	"  @args [ CARD DEV SUBDEV ]\n"
	"  @args.CARD { type string }\n"
	"  @args.DEV { type integer default 0 }\n"
	"  @args.SUBDEV { type integer default -1 }\n"
	"  type hw\n"
	"  card $CARD\n"
	"  device $DEV\n"
	"  subdevice $SUBDEV\n"
	"}\n"
	"ctl.hw {\n"
	"  @args [ CARD ]\n"
	"  @args.CARD { type string }\n"
	"  type hw\n"
	"  card $CARD\n"
	"}\n";

snd_config_t *platform_alsa_lconf(void)
{
	if (lconf)
		return lconf;
	snd_input_t *in;
	if (snd_config_top(&lconf) < 0)
		return NULL;
	if (snd_input_buffer_open(&in, lconf_text, sizeof lconf_text - 1) < 0)
		return NULL;
	int err = snd_config_load(lconf, in);
	snd_input_close(in);
	if (err < 0) {
		LOGE("alsa: embedded config: %s", snd_strerror(err));
		snd_config_delete(lconf);
		lconf = NULL;
	}
	return lconf;
}

static void copy_json_str(char *dst, size_t n, const cJSON *obj, const char *key)
{
	const cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
	strlcpy0(dst, cJSON_IsString(v) ? v->valuestring : "", n);
}

int platform_init(const char *fixture_path, bool use_pipewire)
{
	use_pw = false;
	struct utsname u;
	uname(&u);
	strlcpy0(uname_info.sysname, u.sysname, sizeof uname_info.sysname);
	strlcpy0(uname_info.nodename, u.nodename, sizeof uname_info.nodename);
	strlcpy0(uname_info.release, u.release, sizeof uname_info.release);
	strlcpy0(uname_info.version, u.version, sizeof uname_info.version);
	strlcpy0(uname_info.machine, u.machine, sizeof uname_info.machine);
	if (fixture_path) {
		fixture = xstrdup(fixture_path);
		char *txt = file_read(fixture, NULL);
		cJSON *j = txt ? cJSON_Parse(txt) : NULL;
		free(txt);
		if (!j) {
			LOGE("fixture %s: unreadable or invalid JSON", fixture);
			free(fixture);
			fixture = NULL;
			return -1;
		}
		const cJSON *un = cJSON_GetObjectItemCaseSensitive(j, "uname");
		if (cJSON_IsObject(un)) {
			copy_json_str(uname_info.sysname, sizeof uname_info.sysname, un, "sysname");
			copy_json_str(uname_info.nodename, sizeof uname_info.nodename, un, "nodename");
			copy_json_str(uname_info.release, sizeof uname_info.release, un, "release");
			copy_json_str(uname_info.version, sizeof uname_info.version, un, "version");
			copy_json_str(uname_info.machine, sizeof uname_info.machine, un, "machine");
		}
		cJSON_Delete(j);
	} else if (use_pipewire) {
		if (pw_platform_init() < 0)
			return -1;
		use_pw = true;
	}
	return 0;
}

void platform_shutdown(void)
{
	if (use_pw) {
		pw_platform_shutdown();
		use_pw = false;
	}
	free(fixture);
	fixture = NULL;
	if (lconf) {
		snd_config_delete(lconf);
		lconf = NULL;
	}
}

const struct platform_uname *platform_uname(void)
{
	return &uname_info;
}

void pdev_clear(pdev_t *d)
{
	free(d->fmts);
	memset(d, 0, sizeof *d);
}

void pdev_copy(pdev_t *dst, const pdev_t *src)
{
	*dst = *src;
	dst->fmts = NULL;
	if (src->nfmts) {
		dst->fmts = xmalloc(sizeof *dst->fmts * (size_t)src->nfmts);
		memcpy(dst->fmts, src->fmts, sizeof *dst->fmts * (size_t)src->nfmts);
	}
}

bool pdev_same(const pdev_t *a, const pdev_t *b)
{
	if (strcmp(a->id, b->id) || strcmp(a->name, b->name) || strcmp(a->vendor, b->vendor) ||
	    strcmp(a->usb_id, b->usb_id) || a->nfmts != b->nfmts)
		return false;
	return a->nfmts == 0 || memcmp(a->fmts, b->fmts, sizeof *a->fmts * (size_t)a->nfmts) == 0;
}

bool pdev_supports(const pdev_t *d, int rate, int bits, int channels)
{
	for (int i = 0; i < d->nfmts; i++)
		if (d->fmts[i].rate == rate && d->fmts[i].bits == bits && d->fmts[i].channels == channels)
			return true;
	return false;
}

void platform_free_list(pdev_t *list, int n)
{
	for (int i = 0; i < n; i++)
		free(list[i].fmts);
	free(list);
}

static void add_fmt(pdev_t *d, int rate, int bits, int ch)
{
	if (pdev_supports(d, rate, bits, ch))
		return;
	d->fmts = xrealloc(d->fmts, sizeof *d->fmts * (size_t)(d->nfmts + 1));
	d->fmts[d->nfmts++] = (pcm_fmt_t){ rate, bits, ch };
}

static int fmt_cmp(const void *a, const void *b)
{
	const pcm_fmt_t *x = a, *y = b;
	if (x->rate != y->rate)
		return x->rate - y->rate;
	if (x->bits != y->bits)
		return x->bits - y->bits;
	return x->channels - y->channels;
}

/* ---- fixture ---- */

static void fixture_formats(pdev_t *d, const cJSON *sf)
{
	if (cJSON_IsString(sf)) {
		/* compressed form: "rate/bits/ch|ch,rate/bits/ch" (spec 13.4) */
		char *s = xstrdup(sf->valuestring), *save = NULL;
		for (char *e = strtok_r(s, ",", &save); e; e = strtok_r(NULL, ",", &save)) {
			int rate, bits, off = 0;
			if (sscanf(e, "%d/%d/%n", &rate, &bits, &off) < 2 || !off)
				continue;
			for (char *c = e + off; *c;) {
				int ch = (int)strtol(c, &c, 10);
				if (bits == 16 || bits == 24 || bits == 32)
					add_fmt(d, rate, bits, ch);
				if (*c == '|')
					c++;
				else
					break;
			}
		}
		free(s);
	} else if (cJSON_IsArray(sf)) {
		const cJSON *f;
		cJSON_ArrayForEach(f, sf) {
			int rate = cJSON_GetObjectItem(f, "sample_rate")->valueint;
			int bits = cJSON_GetObjectItem(f, "bits_per_sample")->valueint;
			int ch = cJSON_GetObjectItem(f, "channels")->valueint;
			if (bits == 16 || bits == 24 || bits == 32)
				add_fmt(d, rate, bits, ch);
		}
	}
}

static int scan_fixture(pdev_t **out, int *n)
{
	char *txt = file_read(fixture, NULL);
	cJSON *j = txt ? cJSON_Parse(txt) : NULL;
	free(txt);
	if (!j)
		return -1;
	const cJSON *devs = cJSON_GetObjectItemCaseSensitive(j, "devices"), *dj;
	int cnt = cJSON_GetArraySize(devs);
	pdev_t *list = xcalloc((size_t)(cnt ? cnt : 1), sizeof *list);
	int k = 0;
	cJSON_ArrayForEach(dj, devs) {
		pdev_t *d = &list[k++];
		copy_json_str(d->id, sizeof d->id, dj, "device_id");
		copy_json_str(d->name, sizeof d->name, dj, "name");
		copy_json_str(d->vendor, sizeof d->vendor, dj, "vendor");
		copy_json_str(d->usb_id, sizeof d->usb_id, dj, "usb_id");
		copy_json_str(d->card_id, sizeof d->card_id, dj, "card_id");
		copy_json_str(d->longname, sizeof d->longname, dj, "longname");
		copy_json_str(d->components, sizeof d->components, dj, "components");
		copy_json_str(d->driver, sizeof d->driver, dj, "driver");
		copy_json_str(d->mixername, sizeof d->mixername, dj, "mixername");
		copy_json_str(d->container, sizeof d->container, dj, "container");
		d->card = k - 1;
		d->backend = BACKEND_NULL;
		fixture_formats(d, cJSON_GetObjectItemCaseSensitive(dj, "supported_formats"));
		qsort(d->fmts, (size_t)d->nfmts, sizeof *d->fmts, fmt_cmp);
	}
	cJSON_Delete(j);
	*out = list;
	*n = k;
	return 0;
}

/* ---- ALSA ---- */

static const unsigned std_rates[] = { 44100, 48000, 88200, 96000, 176400, 192000,
				      352800, 384000, 705600, 768000 };

static const unsigned dsd_rates[] = { 2822400, 5644800, 11289600, 22579200, 45158400 };

static const struct {
	snd_pcm_format_t f;
	unsigned bits_per_frame;
} dsd_containers[] = {
	{ SND_PCM_FORMAT_DSD_U32_BE, 32 },
	{ SND_PCM_FORMAT_DSD_U32_LE, 32 },
	{ SND_PCM_FORMAT_DSD_U16_BE, 16 },
	{ SND_PCM_FORMAT_DSD_U16_LE, 16 },
	{ SND_PCM_FORMAT_DSD_U8, 8 },
};

/* Container formats per wire bit depth. Wire PCM is packed little-endian
 * (spec 13.6); 16- and 24-bit may also go into a 32-bit container, which is
 * lossless. The R26 offered 16/24/32 bits on the G20, whose only container is
 * S32_LE, and played 16-bit tracks as S32_LE (capture3). */
static const struct {
	snd_pcm_format_t f;
	int bits;
} containers[] = {
	{ SND_PCM_FORMAT_S16_LE, 16 },
	{ SND_PCM_FORMAT_S32_LE, 16 },
	{ SND_PCM_FORMAT_S24_3LE, 24 },
	{ SND_PCM_FORMAT_S24_LE, 24 },
	{ SND_PCM_FORMAT_S32_LE, 24 },
	{ SND_PCM_FORMAT_S32_LE, 32 },
};

static void probe_formats(pdev_t *d)
{
	snd_pcm_t *pcm;
	int err = snd_pcm_open_lconf(&pcm, d->id, SND_PCM_STREAM_PLAYBACK, SND_PCM_NONBLOCK,
				     platform_alsa_lconf());
	if (err < 0) {
		LOGW("[alsa] %s: cannot open for probing: %s", d->id, snd_strerror(err));
		return;
	}
	snd_pcm_hw_params_t *any, *hw;
	snd_pcm_hw_params_alloca(&any);
	snd_pcm_hw_params_alloca(&hw);
	if (snd_pcm_hw_params_any(pcm, any) < 0)
		goto out;
	snd_pcm_hw_params_set_rate_resample(pcm, any, 0);
	snd_pcm_hw_params_set_access(pcm, any, SND_PCM_ACCESS_RW_INTERLEAVED);
	unsigned chmin = 0, chmax = 0;
	snd_pcm_hw_params_get_channels_min(any, &chmin);
	snd_pcm_hw_params_get_channels_max(any, &chmax);
	if (chmax > 8)
		chmax = 8;
	for (size_t ci = 0; ci < sizeof containers / sizeof containers[0]; ci++) {
		for (unsigned ch = chmin ? chmin : 1; ch <= chmax; ch++) {
			for (size_t ri = 0; ri < sizeof std_rates / sizeof std_rates[0]; ri++) {
				snd_pcm_hw_params_copy(hw, any);
				if (snd_pcm_hw_params_set_format(pcm, hw, containers[ci].f) < 0)
					break;
				if (snd_pcm_hw_params_set_channels(pcm, hw, ch) < 0)
					break;
				if (snd_pcm_hw_params_test_rate(pcm, hw, std_rates[ri], 0) == 0) {
					LOGD("[alsa] %s takes %u/%d/%u as %s", d->id, std_rates[ri],
					     containers[ci].bits, ch, snd_pcm_format_name(containers[ci].f));
					add_fmt(d, (int)std_rates[ri], containers[ci].bits, (int)ch);
				}
			}
		}
	}
	/* Probe native DSD (DSD_U32_BE/LE, DSD_U16_BE/LE, DSD_U8). */
	for (size_t ci = 0; ci < sizeof dsd_containers / sizeof dsd_containers[0]; ci++) {
		for (unsigned ch = chmin ? chmin : 1; ch <= chmax; ch++) {
			for (size_t ri = 0; ri < sizeof dsd_rates / sizeof dsd_rates[0]; ri++) {
				unsigned alsa_rate = dsd_rates[ri] / dsd_containers[ci].bits_per_frame;
				snd_pcm_hw_params_copy(hw, any);
				if (snd_pcm_hw_params_set_format(pcm, hw, dsd_containers[ci].f) < 0)
					break;
				if (snd_pcm_hw_params_set_channels(pcm, hw, ch) < 0)
					break;
				if (snd_pcm_hw_params_test_rate(pcm, hw, alsa_rate, 0) == 0) {
					LOGD("[alsa] %s takes DSD %u/1/%u as %s (alsa %u Hz)", d->id,
					     dsd_rates[ri], ch, snd_pcm_format_name(dsd_containers[ci].f),
					     alsa_rate);
					d->has_native_dsd = true;
					add_fmt(d, (int)dsd_rates[ri], 1, (int)ch);
				}
			}
		}
	}
	/* Probe DoP (16 DSD bits per 24/32-bit PCM frame at rate/16). */
	for (size_t ri = 0; ri < sizeof dsd_rates / sizeof dsd_rates[0]; ri++) {
		int dop_pcm_rate = (int)(dsd_rates[ri] / 16);
		for (unsigned ch = chmin ? chmin : 1; ch <= chmax; ch++) {
			if (pdev_supports(d, dop_pcm_rate, 24, (int)ch) ||
			    pdev_supports(d, dop_pcm_rate, 32, (int)ch)) {
				d->has_dop = true;
				add_fmt(d, (int)dsd_rates[ri], 1, (int)ch);
			}
		}
	}
	qsort(d->fmts, (size_t)d->nfmts, sizeof *d->fmts, fmt_cmp);
out:
	snd_pcm_close(pcm);
}

static void read_sysfs_line(char *dst, size_t n, const char *fmt, int card)
{
	char path[256];
	snprintf(path, sizeof path, fmt, card);
	char *s = file_read(path, NULL);
	if (s) {
		str_rtrim(s);
		strlcpy0(dst, s, n);
		free(s);
	}
}

static int scan_alsa(pdev_t **out, int *n, const pdev_t *prev, int nprev)
{
	pdev_t *list = NULL;
	int cnt = 0;
	int card = -1;
	while (snd_card_next(&card) == 0 && card >= 0) {
		char cname[32];
		snprintf(cname, sizeof cname, "hw:%d", card);
		snd_ctl_t *ctl;
		if (snd_ctl_open_lconf(&ctl, cname, 0, platform_alsa_lconf()) < 0)
			continue;
		snd_ctl_card_info_t *ci;
		snd_ctl_card_info_alloca(&ci);
		if (snd_ctl_card_info(ctl, ci) < 0) {
			snd_ctl_close(ctl);
			continue;
		}
		int dev = -1;
		while (snd_ctl_pcm_next_device(ctl, &dev) == 0 && dev >= 0) {
			snd_pcm_info_t *pi;
			snd_pcm_info_alloca(&pi);
			snd_pcm_info_set_device(pi, (unsigned)dev);
			snd_pcm_info_set_subdevice(pi, 0);
			snd_pcm_info_set_stream(pi, SND_PCM_STREAM_PLAYBACK);
			if (snd_ctl_pcm_info(ctl, pi) < 0)
				continue; /* no playback on this device */
			list = xrealloc(list, sizeof *list * (size_t)(cnt + 1));
			pdev_t *d = &list[cnt++];
			memset(d, 0, sizeof *d);
			d->card = card;
			d->dev = dev;
			d->backend = BACKEND_ALSA;
			strlcpy0(d->card_id, snd_ctl_card_info_get_id(ci), sizeof d->card_id);
			snprintf(d->id, sizeof d->id, "hw:CARD=%s,DEV=%d", d->card_id, dev);
			strlcpy0(d->name, snd_ctl_card_info_get_name(ci), sizeof d->name);
			strlcpy0(d->longname, snd_ctl_card_info_get_longname(ci), sizeof d->longname);
			strlcpy0(d->components, snd_ctl_card_info_get_components(ci), sizeof d->components);
			strlcpy0(d->driver, snd_ctl_card_info_get_driver(ci), sizeof d->driver);
			strlcpy0(d->mixername, snd_ctl_card_info_get_mixername(ci), sizeof d->mixername);
			read_sysfs_line(d->usb_id, sizeof d->usb_id, "/proc/asound/card%d/usbid", card);
			if (d->usb_id[0])
				read_sysfs_line(d->vendor, sizeof d->vendor,
						"/sys/class/sound/card%d/device/../manufacturer", card);
			const pdev_t *old = NULL;
			for (int i = 0; i < nprev; i++)
				if (!strcmp(prev[i].id, d->id))
					old = &prev[i];
			if (old && platform_device_busy(d->id)) {
				if (old->nfmts) {
					d->fmts = xmalloc(sizeof *d->fmts * (size_t)old->nfmts);
					memcpy(d->fmts, old->fmts, sizeof *d->fmts * (size_t)old->nfmts);
					d->nfmts = old->nfmts;
				}
			} else {
				probe_formats(d);
				if (!d->nfmts && old && old->nfmts) {
					/* busy elsewhere right now: keep what we knew */
					d->fmts = xmalloc(sizeof *d->fmts * (size_t)old->nfmts);
					memcpy(d->fmts, old->fmts, sizeof *d->fmts * (size_t)old->nfmts);
					d->nfmts = old->nfmts;
				}
			}
		}
		snd_ctl_close(ctl);
	}
	*out = list;
	*n = cnt;
	return 0;
}

int platform_scan(pdev_t **out, int *n, const pdev_t *prev, int nprev)
{
	*out = NULL;
	*n = 0;
	if (fixture)
		return scan_fixture(out, n);
	if (use_pw)
		return pw_platform_scan(out, n);
	return scan_alsa(out, n, prev, nprev);
}

int platform_watch_fd(void)
{
	if (fixture)
		return -1;
	if (use_pw)
		return pw_platform_watch_fd();
	int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (fd < 0)
		return -1;
	if (inotify_add_watch(fd, "/dev/snd", IN_CREATE | IN_DELETE) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

void platform_watch_drain(int fd)
{
	if (use_pw) {
		pw_platform_watch_drain(fd);
		return;
	}
	char buf[4096];
	while (read(fd, buf, sizeof buf) > 0)
		;
}
