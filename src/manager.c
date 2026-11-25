// SPDX-License-Identifier: GPL-3.0-or-later
#include "manager.h"
#include "sood.h"
#include "device.h"
#include "devserver.h"
#include "ll.h"
#include "loop.h"
#include "session.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "third_party/cjson/cJSON.h"

enum { SUB_ENUM, SUB_ENABLE };

typedef struct sub {
	int kind;
	char *sub_id;
	llconn_t *conn; /* NULL once the Core's connection is gone */
	uint32_t rid;
	mdev_t *dev;
	struct sub *next;
} sub_t;

static struct {
	char data_dir[1024];
	char bind_addr[64];
	char raat_version[32];
	char unique_id[37];
	int port;
	io_watch_t lw;
	mdev_t *devs;
	sub_t *subs;
	int watch_fd;
	io_watch_t ww;
	ltimer_t debounce;
	bool refresh_queued;
} M;

const char *manager_raat_version(void) { return M.raat_version; }
const char *manager_unique_id(void) { return M.unique_id; }
int manager_port(void) { return M.port; }

/* ---- persistence ---- */

static void settings_path(char *out, size_t n, const char *name)
{
	snprintf(out, n, "%s/Settings/%s", M.data_dir, name);
}

static void device_config_path(char *out, size_t n, const char *id)
{
	char safe[128];
	size_t k = 0;
	for (const char *p = id; *p && k + 1 < sizeof safe; p++)
		safe[k++] = (char)((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
					   (*p >= '0' && *p <= '9') || *p == '-' || *p == '.'
				   ? *p
				   : '_');
	safe[k] = 0;
	char name[160];
	snprintf(name, sizeof name, "device_%s.json", safe);
	settings_path(out, n, name);
}

static void save_device_config(mdev_t *d)
{
	char path[1200];
	device_config_path(path, sizeof path, d->pd.id);
	char *t = cJSON_Print(d->config);
	if (file_write(path, t, strlen(t)) < 0)
		LOGW("[manager] cannot write %s: %s", path, strerror(errno));
	cJSON_free(t);
}

static cJSON *default_config(mdev_t *d)
{
	cJSON *c = cJSON_CreateObject();
	cJSON_AddStringToObject(c, "unique_id", d->unique_id);
	cJSON_AddObjectToObject(c, "external_config");
	cJSON *o = cJSON_AddObjectToObject(c, "output");
	cJSON_AddStringToObject(o, "dsd_mode", "none"); /* PCM only (spec 11.3) */
	cJSON_AddStringToObject(o, "type", "alsa");
	cJSON_AddStringToObject(o, "device", d->pd.id);
	cJSON_AddStringToObject(o, "name", d->pd.name);
	cJSON *v = cJSON_AddObjectToObject(c, "volume");
	cJSON_AddStringToObject(v, "type", "alsa");
	cJSON_AddStringToObject(v, "device", d->pd.id);
	return c;
}

/* The Core's config is kept as sent; unique_id is ours unless it brings one. */
static void adopt_config(mdev_t *d, cJSON *cfg)
{
	cJSON_Delete(d->config);
	d->config = cfg;
	cJSON *u = cJSON_GetObjectItemCaseSensitive(cfg, "unique_id");
	if (cJSON_IsString(u) && strlen(u->valuestring) == 36)
		strlcpy0(d->unique_id, u->valuestring, sizeof d->unique_id);
	else {
		cJSON_DeleteItemFromObjectCaseSensitive(cfg, "unique_id");
		cJSON_AddStringToObject(cfg, "unique_id", d->unique_id);
	}
}

static void load_device_config(mdev_t *d)
{
	char path[1200];
	device_config_path(path, sizeof path, d->pd.id);
	char *t = file_read(path, NULL);
	cJSON *c = t ? cJSON_Parse(t) : NULL;
	free(t);
	if (cJSON_IsObject(c)) {
		adopt_config(d, c);
		return;
	}
	cJSON_Delete(c);
	guid_new(d->unique_id);
	d->config = default_config(d);
	save_device_config(d);
}

/* ---- device objects (spec 5.2, 13.1) ---- */

static cJSON *device_json(mdev_t *d)
{
	cJSON *j = cJSON_CreateObject();
	if (d->pd.vendor[0])
		cJSON_AddStringToObject(j, "vendor", d->pd.vendor);
	cJSON_AddStringToObject(j, "name", d->pd.name);
	cJSON_AddStringToObject(j, "device_id", d->pd.id);
	cJSON_AddItemToObject(j, "config", cJSON_Duplicate(d->config, 1));
	if (d->pd.usb_id[0])
		cJSON_AddStringToObject(j, "usb_id", d->pd.usb_id);
	cJSON_AddStringToObject(j, "type", "alsa");
	if (d->srv) {
		cJSON *dd = device_info_json(d);
		cJSON_AddNumberToObject(dd, "tcp_port", devserver_port(d->srv));
		/* no code_signing_keys: scripts are accepted unsigned (spec 13.2) */
		cJSON_AddItemToObject(j, "discovery_data", dd);
	} else if (d->failed) {
		cJSON_AddStringToObject(j, "error_message", "device init failed");
	}
	return j;
}

static void send_json(llconn_t *c, uint32_t rid, bool final, cJSON *j)
{
	char *t = cJSON_PrintUnformatted(j);
	ll_respond(c, rid, final, t);
	cJSON_free(t);
	cJSON_Delete(j);
}

static void send_status(llconn_t *c, uint32_t rid, bool final, const char *status)
{
	cJSON *j = cJSON_CreateObject();
	cJSON_AddStringToObject(j, "status", status);
	send_json(c, rid, final, j);
}

static void notify(const char *status, mdev_t *d)
{
	for (sub_t *s = M.subs; s; s = s->next) {
		if (s->kind != SUB_ENUM || !s->conn)
			continue;
		cJSON *j = cJSON_CreateObject();
		cJSON_AddStringToObject(j, "status", status);
		cJSON_AddItemToObject(j, "device", device_json(d));
		send_json(s->conn, s->rid, false, j);
	}
}

/* ---- device lifecycle ---- */

static bool device_start(mdev_t *d)
{
	if (d->srv)
		return true;
	d->srv = devserver_start(d, M.bind_addr);
	d->failed = d->srv == NULL;
	return d->srv != NULL;
}

static void device_stop(mdev_t *d)
{
	if (d->srv)
		devserver_stop(d->srv); /* sessions shut down, output released */
	d->srv = NULL;
	dev_output_release(d, true, NULL);
}

static mdev_t *find_dev(const char *id)
{
	for (mdev_t *d = M.devs; d; d = d->next)
		if (!strcmp(d->pd.id, id))
			return d;
	return NULL;
}

static void refresh_now(void)
{
	M.refresh_queued = false;
	int nprev = 0;
	for (mdev_t *d = M.devs; d; d = d->next)
		nprev++;
	pdev_t *prev = xcalloc((size_t)(nprev ? nprev : 1), sizeof *prev);
	int k = 0;
	for (mdev_t *d = M.devs; d; d = d->next)
		if (d->present)
			prev[k++] = d->pd; /* shallow, read-only */
	pdev_t *list;
	int n;
	if (platform_scan(&list, &n, prev, k) < 0) {
		LOGE("[manager] device scan failed");
		free(prev);
		return;
	}
	free(prev);
	for (mdev_t *d = M.devs; d; d = d->next) {
		bool found = false;
		for (int i = 0; i < n; i++)
			found |= !strcmp(list[i].id, d->pd.id);
		if (d->present && !found) {
			LOGI("[manager] device removed: %s", d->pd.id);
			d->present = false;
			device_stop(d);
			notify("DeviceRemoved", d);
		}
	}
	for (int i = 0; i < n; i++) {
		mdev_t *d = find_dev(list[i].id);
		if (!d) {
			d = xcalloc(1, sizeof *d);
			pdev_copy(&d->pd, &list[i]);
			d->owner_cb_ref = LUA_NOREF;
			d->out_w.fd = -1;
			load_device_config(d);
			d->next = M.devs;
			M.devs = d;
		} else if (d->present && pdev_same(&d->pd, &list[i])) {
			continue;
		} else {
			pdev_clear(&d->pd);
			pdev_copy(&d->pd, &list[i]);
		}
		bool added = !d->present;
		d->present = true;
		LOGI("[manager] device %s: %s \"%s\" (%d PCM formats)", added ? "added" : "changed",
		     d->pd.id, d->pd.name, d->pd.nfmts);
		if (d->refcount > 0)
			device_start(d);
		notify(added ? "DeviceAdded" : "DeviceChanged", d);
	}
	platform_free_list(list, n);
}

static void refresh_task(void *arg)
{
	(void)arg;
	if (M.refresh_queued)
		refresh_now();
}

/* May be called from inside a Lua call chain, so the work is deferred. */
void manager_refresh_devices(void)
{
	if (M.refresh_queued)
		return;
	M.refresh_queued = true;
	loop_defer(refresh_task, NULL);
}

static void debounce_fire(ltimer_t *t)
{
	(void)t;
	manager_refresh_devices();
}

static void watch_io(io_watch_t *w, uint32_t ev)
{
	(void)ev;
	platform_watch_drain(w->fd);
	loop_timer_start(&M.debounce, 500, 0);
}

/* ---- requests ---- */

static const char *jstr(const cJSON *o, const char *k)
{
	const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
	return cJSON_IsString(v) ? v->valuestring : NULL;
}

static void sub_add(int kind, const char *id, llconn_t *c, uint32_t rid, mdev_t *d)
{
	sub_t *s = xcalloc(1, sizeof *s);
	s->kind = kind;
	s->sub_id = xstrdup(id);
	s->conn = c;
	s->rid = rid;
	s->dev = d;
	s->next = M.subs;
	M.subs = s;
}

static sub_t *sub_take(int kind, const char *id)
{
	for (sub_t **pp = &M.subs; *pp; pp = &(*pp)->next) {
		sub_t *s = *pp;
		if (s->kind == kind && !strcmp(s->sub_id, id)) {
			*pp = s->next;
			return s;
		}
	}
	return NULL;
}

static void sub_free(sub_t *s)
{
	free(s->sub_id);
	free(s);
}

static void req_enumerate(llconn_t *c, uint32_t rid, const cJSON *r)
{
	const char *sid = jstr(r, "subscription_id");
	if (!sid) {
		send_status(c, rid, true, "InvalidRequest");
		return;
	}
	sub_add(SUB_ENUM, sid, c, rid, NULL);
	cJSON *j = cJSON_CreateObject();
	cJSON_AddStringToObject(j, "status", "Success");
	cJSON *arr = cJSON_AddArrayToObject(j, "devices");
	for (mdev_t *d = M.devs; d; d = d->next)
		if (d->present)
			cJSON_AddItemToArray(arr, device_json(d));
	send_json(c, rid, false, j);
}

static void req_cancel_enumerate(llconn_t *c, uint32_t rid, const cJSON *r)
{
	const char *sid = jstr(r, "subscription_id");
	if (!sid) {
		send_status(c, rid, true, "InvalidRequest");
		return;
	}
	sub_t *s = sub_take(SUB_ENUM, sid);
	if (!s) {
		send_status(c, rid, true, "NotFound");
		return;
	}
	if (s->conn)
		send_status(s->conn, s->rid, true, "Canceled");
	sub_free(s);
	send_status(c, rid, true, "Success");
}

static void req_enable(llconn_t *c, uint32_t rid, const cJSON *r)
{
	const char *sid = jstr(r, "subscription_id"), *did = jstr(r, "device_id");
	if (!sid || !did) {
		send_status(c, rid, true, "InvalidRequest");
		return;
	}
	mdev_t *d = find_dev(did);
	if (!d || !d->present) {
		send_status(c, rid, true, "NotFound");
		return;
	}
	sub_add(SUB_ENABLE, sid, c, rid, d);
	bool ok = true;
	if (++d->refcount == 1 || !d->srv) {
		ok = device_start(d);
		/* The enumerate subscription learns the port first (c2:6, then c2:7). */
		notify("DeviceChanged", d);
	}
	send_status(c, rid, false, ok ? "Success" : "DeviceInitFailed");
}

static void req_disable(llconn_t *c, uint32_t rid, const cJSON *r)
{
	const char *sid = jstr(r, "subscription_id");
	if (!sid) {
		send_status(c, rid, true, "InvalidRequest");
		return;
	}
	sub_t *s = sub_take(SUB_ENABLE, sid);
	if (!s) {
		send_status(c, rid, true, "NotFound");
		return;
	}
	if (s->conn)
		send_status(s->conn, s->rid, true, "Canceled");
	mdev_t *d = s->dev;
	sub_free(s);
	if (d->refcount > 0 && --d->refcount == 0) {
		device_stop(d);
		d->failed = false;
		notify("DeviceChanged", d);
	}
	send_status(c, rid, true, "Success");
}

static void req_retry(llconn_t *c, uint32_t rid, const cJSON *r)
{
	const char *did = jstr(r, "device_id");
	if (!did) {
		send_status(c, rid, true, "InvalidRequest");
		return;
	}
	mdev_t *d = find_dev(did);
	if (!d || !d->present) {
		send_status(c, rid, true, "NotFound");
		return;
	}
	bool ok = d->refcount == 0 || device_start(d);
	if (ok && d->refcount)
		notify("DeviceChanged", d);
	send_status(c, rid, true, ok ? "Success" : "DeviceEnableFailed");
}

static void req_get_config(llconn_t *c, uint32_t rid, const cJSON *r)
{
	const char *did = jstr(r, "device_id");
	mdev_t *d = did ? find_dev(did) : NULL;
	if (!did) {
		send_status(c, rid, true, "InvalidRequest");
		return;
	}
	if (!d) {
		send_status(c, rid, true, "NotFound");
		return;
	}
	cJSON *j = cJSON_CreateObject();
	cJSON_AddStringToObject(j, "status", "Success");
	cJSON_AddItemToObject(j, "config", cJSON_Duplicate(d->config, 1));
	cJSON_AddItemToObject(j, "device_info", device_json(d));
	/* TODO(capture of a get_device_config exchange, e.g. opening the device
	 * settings in Roon): the config_info settings-UI schema is unknown
	 * (spec 5.2, 12), so none is offered. */
	cJSON_AddObjectToObject(j, "config_info");
	send_json(c, rid, true, j);
}

static void req_set_config(llconn_t *c, uint32_t rid, const cJSON *r)
{
	const char *did = jstr(r, "device_id");
	const cJSON *cfg = cJSON_GetObjectItemCaseSensitive(r, "config");
	if (!did || !cfg) {
		send_status(c, rid, true, "InvalidRequest");
		return;
	}
	mdev_t *d = find_dev(did);
	if (!d) {
		send_status(c, rid, true, "NotFound");
		return;
	}
	if (cJSON_IsObject(cfg)) {
		adopt_config(d, cJSON_Duplicate(cfg, 1));
		save_device_config(d);
	} else {
		/* null: forget the Core's config, keep our unique id (spec 5.5) */
		char path[1200];
		device_config_path(path, sizeof path, d->pd.id);
		unlink(path);
		cJSON_Delete(d->config);
		d->config = default_config(d);
		save_device_config(d);
	}
	/* TODO(capture of the config keys the Core sets): no config key changes
	 * output behaviour yet; dsd_mode is ignored (PCM only, spec 8.2). */
	if (d->srv) {
		device_stop(d);
		device_start(d);
	}
	notify("DeviceChanged", d);
	send_status(c, rid, true, "Success");
}

static void mgr_frame(llconn_t *c, uint32_t type, const uint8_t *body, size_t len)
{
	if (type != LL_REQUEST)
		return;
	if (len < 4) {
		ll_close(c, "short request");
		return;
	}
	uint32_t rid = be32_get(body);
	cJSON *r = cJSON_ParseWithLength((const char *)body + 4, len - 4);
	const char *req = cJSON_IsObject(r) ? jstr(r, "request") : NULL;
	if (!cJSON_IsObject(r)) {
		cJSON *j = cJSON_CreateObject();
		cJSON_AddStringToObject(j, "status", "InvalidJson");
		cJSON_AddStringToObject(j, "text", "invalid JSON");
		send_json(c, rid, true, j);
	} else if (!req) {
		send_status(c, rid, true, "InvalidRequest");
	} else {
		LOGD("[manager] request %u: %s", rid, req);
		if (!strcmp(req, "enumerate_devices"))
			req_enumerate(c, rid, r);
		else if (!strcmp(req, "cancel_enumerate_devices"))
			req_cancel_enumerate(c, rid, r);
		else if (!strcmp(req, "enable_device"))
			req_enable(c, rid, r);
		else if (!strcmp(req, "disable_device"))
			req_disable(c, rid, r);
		else if (!strcmp(req, "retry_device"))
			req_retry(c, rid, r);
		else if (!strcmp(req, "refresh")) {
			refresh_now();
			send_status(c, rid, true, "Success");
		} else if (!strcmp(req, "get_device_config"))
			req_get_config(c, rid, r);
		else if (!strcmp(req, "set_device_config"))
			req_set_config(c, rid, r);
		else
			send_status(c, rid, true, "NotSupported");
	}
	cJSON_Delete(r);
}

/* Enumerate subscriptions die with the connection; enable subscriptions keep
 * the device enabled until disable_device (spec 10 item 3). */
static void mgr_close(llconn_t *c)
{
	for (sub_t **pp = &M.subs; *pp;) {
		sub_t *s = *pp;
		if (s->conn == c && s->kind == SUB_ENUM) {
			*pp = s->next;
			sub_free(s);
			continue;
		}
		if (s->conn == c)
			s->conn = NULL;
		pp = &s->next;
	}
}

static const struct llconn_ops mgr_ops = { mgr_frame, mgr_close };

static void mgr_accept(io_watch_t *w, uint32_t ev)
{
	(void)ev;
	for (;;) {
		int fd = accept4(w->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno != EAGAIN && errno != EINTR)
				LOGW("[manager] accept: %s", strerror(errno));
			return;
		}
		if (ll_new(fd, &mgr_ops, NULL, "manager"))
			sood_core_connected(); /* found: no more announcing needed */
	}
}

int manager_start(const struct manager_opts *o)
{
	strlcpy0(M.data_dir, o->data_dir, sizeof M.data_dir);
	strlcpy0(M.bind_addr, o->bind_addr, sizeof M.bind_addr);
	strlcpy0(M.raat_version, o->raat_version, sizeof M.raat_version);
	char path[1200];
	settings_path(path, sizeof path, "");
	if (mkdir_p(path) < 0) {
		LOGE("[manager] cannot create %s: %s", path, strerror(errno));
		return -1;
	}
	settings_path(path, sizeof path, "unique_id");
	char *u = file_read(path, NULL);
	if (u) {
		str_rtrim(u);
		strlcpy0(M.unique_id, u, sizeof M.unique_id);
		free(u);
	}
	if (strlen(M.unique_id) != 36) {
		guid_new(M.unique_id);
		if (file_write(path, M.unique_id, 36) < 0)
			LOGW("[manager] cannot persist unique_id: %s", strerror(errno));
	}
	int fd = o->port >= 0 ? tcp_listen_fd(M.bind_addr, o->port, 16)
			 : tcp_listen_range(M.bind_addr, 9200, 9250, 16, NULL);
	if (fd < 0) {
		LOGE("[manager] listen: %s", strerror(errno));
		return -1;
	}
	M.port = sock_local_port(fd);
	loop_io_add(&M.lw, fd, EPOLLIN, mgr_accept, NULL);
	loop_timer_init(&M.debounce, debounce_fire, NULL);
	M.watch_fd = platform_watch_fd();
	if (M.watch_fd >= 0)
		loop_io_add(&M.ww, M.watch_fd, EPOLLIN, watch_io, NULL);
	refresh_now();
	LOGI("[manager] listening on tcp port %d, unique_id %s", M.port, M.unique_id);
	return 0;
}

void manager_shutdown(void)
{
	/* Every open subscription gets its final Canceled (spec 10 item 2). */
	while (M.subs) {
		sub_t *s = M.subs;
		M.subs = s->next;
		if (s->conn)
			send_status(s->conn, s->rid, true, "Canceled");
		sub_free(s);
	}
	for (mdev_t *d = M.devs; d; d = d->next)
		device_stop(d);
	int fd = M.lw.fd;
	loop_io_del(&M.lw);
	if (fd >= 0)
		close(fd);
}
