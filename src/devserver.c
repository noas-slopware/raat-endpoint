// SPDX-License-Identifier: GPL-3.0-or-later
#include "devserver.h"
#include "ll.h"
#include "loop.h"
#include "session.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "third_party/cjson/cJSON.h"

struct devserver {
	mdev_t *dev;
	io_watch_t w;
	int port;
	session_t *sessions;
};

cJSON *device_info_json(mdev_t *d)
{
	cJSON *j = cJSON_CreateObject();
	cJSON_AddStringToObject(j, "unique_id", d->unique_id);
	cJSON_AddStringToObject(j, "raat_version", manager_raat_version());
	cJSON_AddStringToObject(j, "version", "N/A");
	cJSON_AddStringToObject(j, "model", "N/A");
	cJSON_AddStringToObject(j, "protocol_version", "3");
	cJSON_AddStringToObject(j, "vendor", "N/A");
	return j;
}

static void reply(llconn_t *c, uint32_t rid, cJSON *j)
{
	char *t = cJSON_PrintUnformatted(j);
	ll_respond(c, rid, true, t);
	cJSON_free(t);
	cJSON_Delete(j);
}

static void reply_status(llconn_t *c, uint32_t rid, const char *status)
{
	cJSON *j = cJSON_CreateObject();
	cJSON_AddStringToObject(j, "status", status);
	reply(c, rid, j);
}

static const char *jstr(const cJSON *o, const char *k)
{
	const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
	return cJSON_IsString(v) ? v->valuestring : NULL;
}

static void handle_request(llconn_t *c, session_t *s, const uint8_t *body, size_t len)
{
	if (len < 4) {
		ll_close(c, "short request");
		return;
	}
	uint32_t rid = be32_get(body);
	const char *txt = (const char *)body + 4;
	size_t tlen = len - 4;
	cJSON *req = cJSON_ParseWithLength(txt, tlen);
	if (!cJSON_IsObject(req)) {
		const char *ep = cJSON_GetErrorPtr();
		cJSON *j = cJSON_CreateObject();
		cJSON_AddStringToObject(j, "status", "InvalidJson");
		cJSON_AddStringToObject(j, "text", "invalid JSON");
		long pos = ep && ep >= txt && ep <= txt + tlen ? (long)(ep - txt) : -1;
		cJSON_AddNumberToObject(j, "position", (double)pos);
		reply(c, rid, j);
		cJSON_Delete(req);
		return;
	}
	const char *r = jstr(req, "request");
	if (!r) {
		reply_status(c, rid, "InvalidRequest");
	} else if (!strcmp(r, "load_script")) {
		const cJSON *sc = cJSON_GetObjectItemCaseSensitive(req, "script");
		if (!cJSON_IsString(sc)) {
			reply_status(c, rid, "NotFound");
		} else {
			const char *sig = jstr(req, "signature");
			/* No code_signing_keys are advertised, so, like the 1.1.38 stack
			 * with no registered keys, every script is accepted (spec 13.2). */
			if (sig)
				LOGI("[device] script carries a signature; no keys registered, not checked");
			session_load_script(s, rid, sc->valuestring, strlen(sc->valuestring),
					    jstr(req, "name"), jstr(req, "module"));
		}
	} else if (!strcmp(r, "get_info")) {
		cJSON *j = cJSON_CreateObject();
		cJSON_AddStringToObject(j, "status", "Success");
		cJSON_AddItemToObject(j, "info", device_info_json(s->dev));
		reply(c, rid, j);
	} else if (!strcmp(r, "get_log")) {
		const cJSON *ms = cJSON_GetObjectItemCaseSensitive(req, "min_seq");
		cJSON *j = cJSON_CreateObject();
		cJSON_AddStringToObject(j, "status", "Success");
		cJSON_AddItemToObject(j, "entries",
				      log_entries_json(cJSON_IsNumber(ms) ? (int64_t)ms->valuedouble : 0));
		reply(c, rid, j);
	} else if (!strcmp(r, "clear_log")) {
		log_clear();
		reply_status(c, rid, "Success");
	} else {
		reply_status(c, rid, "NotImplemented");
	}
	cJSON_Delete(req);
}

static void ds_frame(llconn_t *c, uint32_t type, const uint8_t *body, size_t len)
{
	session_t *s = ll_ud(c);
	if (!s || s->failed)
		return;
	if (type == LL_REQUEST)
		handle_request(c, s, body, len);
	else if (type < 0x80000000u)
		session_deliver(s, type, body, len);
	/* 0x80000002 and unknown control types are ignored */
}

static void unlink_session(session_t *s)
{
	if (!s->dev || !s->dev->srv)
		return;
	session_t **pp = &s->dev->srv->sessions;
	while (*pp && *pp != s)
		pp = &(*pp)->next;
	if (*pp)
		*pp = s->next;
}

static void ds_close(llconn_t *c)
{
	session_t *s = ll_ud(c);
	if (!s)
		return;
	unlink_session(s);
	session_destroy(s);
}

static const struct llconn_ops ds_ops = { ds_frame, ds_close };

static void ds_accept(io_watch_t *w, uint32_t ev)
{
	devserver_t *ds = w->ud;
	(void)ev;
	for (;;) {
		int fd = accept4(w->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno != EAGAIN && errno != EINTR)
				LOGW("[device] accept: %s", strerror(errno));
			return;
		}
		llconn_t *c = ll_new(fd, &ds_ops, NULL, "device");
		if (!c)
			continue;
		/* A fresh Lua VM per connection (spec 3). */
		session_t *s = session_new(ds->dev, c);
		if (!s) {
			ll_close(c, "cannot create Lua VM");
			continue;
		}
		ll_set_ud(c, s);
		s->next = ds->sessions;
		ds->sessions = s;
		LOGI("[device] %s: Core connected from %s:%d", ds->dev->pd.id, ll_peer_ip(c),
		     ll_peer_port(c));
	}
}

devserver_t *devserver_start(mdev_t *d, const char *bindaddr)
{
	int fd = tcp_listen_fd(bindaddr, 0, 10);
	if (fd < 0) {
		LOGE("[device] %s: listen: %s", d->pd.id, strerror(errno));
		return NULL;
	}
	devserver_t *ds = xcalloc(1, sizeof *ds);
	ds->dev = d;
	ds->port = sock_local_port(fd);
	if (loop_io_add(&ds->w, fd, EPOLLIN, ds_accept, ds) < 0) {
		close(fd);
		free(ds);
		return NULL;
	}
	LOGI("[device] %s: listening on tcp port %d", d->pd.id, ds->port);
	return ds;
}

int devserver_port(devserver_t *ds)
{
	return ds->port;
}

void devserver_stop(devserver_t *ds)
{
	if (!ds)
		return;
	while (ds->sessions) {
		session_t *s = ds->sessions;
		ds->sessions = s->next;
		llconn_t *c = s->conn;
		session_destroy(s); /* shutdown handlers may still send on c */
		if (c) {
			ll_set_ud(c, NULL);
			ll_close(c, "device stopped");
		}
	}
	int fd = ds->w.fd;
	loop_io_del(&ds->w);
	if (fd >= 0)
		close(fd);
	if (ds->dev && ds->dev->srv == ds)
		ds->dev->srv = NULL;
	loop_defer(free, ds);
}
