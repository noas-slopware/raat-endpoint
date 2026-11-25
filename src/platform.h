// SPDX-License-Identifier: GPL-3.0-or-later
/* Platform layer: which outputs exist and what PCM formats they take natively.
 * Two sources: ALSA (cards, playback PCMs, hw_params probing) or a fixture JSON
 * file (tests; outputs then use the paced null backend). */
#ifndef RAAT_PLATFORM_H
#define RAAT_PLATFORM_H

#include "common.h"

struct cJSON;

typedef struct {
	int rate, bits, channels;
} pcm_fmt_t;

enum { BACKEND_ALSA, BACKEND_NULL };

typedef struct pdev {
	char id[96];          /* "hw:CARD=<id>,DEV=<n>" */
	char name[128];       /* card name (USB product string for USB audio) */
	char vendor[128];     /* USB manufacturer, "" if unknown */
	char usb_id[16];      /* "vvvv:pppp", "" if not USB */
	char card_id[32];
	char longname[256];
	char components[128];
	char driver[64];
	char mixername[128];
	char container[16];   /* fixture only: ALSA container the null backend mimics */
	int card, dev;
	int backend;
	pcm_fmt_t *fmts;
	int nfmts;
} pdev_t;

struct platform_uname {
	char sysname[65], nodename[65], release[65], version[129], machine[65];
};

/* fixture_path NULL = ALSA. */
int platform_init(const char *fixture_path);
/* Fresh scan; caller frees with platform_free_list(). Devices we hold open
 * (platform_device_busy) keep their formats from `prev` instead of re-probing. */
int platform_scan(pdev_t **out, int *n, const pdev_t *prev, int nprev);
void platform_free_list(pdev_t *list, int n);
void pdev_copy(pdev_t *dst, const pdev_t *src);
void pdev_clear(pdev_t *d);
bool pdev_same(const pdev_t *a, const pdev_t *b);
bool pdev_supports(const pdev_t *d, int rate, int bits, int channels);
const struct platform_uname *platform_uname(void);

/* Set by the output layer while a device is open (skip probing it). */
bool platform_device_busy(const char *id);

/* inotify fd on /dev/snd (readable on hotplug), -1 when unavailable or with a fixture. */
int platform_watch_fd(void);
void platform_watch_drain(int fd);

/* Embedded ALSA config so a static build does not need alsa.conf on the target. */
struct _snd_config;
struct _snd_config *platform_alsa_lconf(void);

#endif
