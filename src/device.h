/* A manager-side output device and the state shared by its sessions. */
#ifndef RAAT_DEVICE_H
#define RAAT_DEVICE_H

#include "common.h"
#include "loop.h"
#include "output.h"
#include "platform.h"

struct cJSON;
struct devserver;
struct session;

typedef struct mdev {
	pdev_t pd;
	bool present;
	char unique_id[37];
	struct cJSON *config; /* persisted device config (spec 5.5, 13.1) */
	int refcount;         /* enable_device count (spec 5.2) */
	bool failed;
	struct devserver *srv;

	/* The single active output setup (spec 10 item 4). */
	output_t *out;
	int token;
	int next_token;
	struct session *owner;
	int owner_cb_ref; /* {on_setup, on_output_lost} in the owner's registry */
	io_watch_t out_w;

	struct mdev *next;
} mdev_t;

/* Release the output: close the device, forget the token. When notify is true
 * and an owner exists, its on_output_lost(reason_json) is called (deferred). */
void dev_output_release(mdev_t *d, bool notify, const char *reason_json);

/* Manager hooks used by sessions. */
void manager_refresh_devices(void);
const char *manager_raat_version(void);

#endif
