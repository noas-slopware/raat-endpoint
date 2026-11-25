// SPDX-License-Identifier: GPL-3.0-or-later
/* A small luv-compatible `uv` module on the main epoll loop.
 *
 * It covers what the Core's scripts call (spec 13.10): TCP listen/accept/read,
 * UDP bind/send/recv/multicast, timers, getsockname and recv_buffer_size, in
 * both method form (h:bind(...)) and function form (uv.udp_send(h, ...)).
 * Return conventions follow luv: 0 on success, or nil, message, errname.
 * As in luv, a handle stays referenced from creation until close().
 * The Roon-specific *_noalloc variants are left out; the scripts probe for them
 * and fall back (spec 11.5). */
#include "session.h"
#include "loop.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

char *g_bind_override;

enum { UVH_TCP, UVH_UDP, UVH_TIMER };
static const char *const mt_names[] = { "uv_tcp", "uv_udp", "uv_timer" };

typedef struct uvh {
	int type;
	session_t *s;
	io_watch_t w;
	int fd;
	ltimer_t timer;
	int self_ref, cb_ref, close_cb_ref;
	bool closed, listening, reading;
	int pending_fd; /* accepted connection waiting for accept() */
	uint8_t *rbuf;
} uvh_t;

typedef struct {
	uvh_t *h;
} uvud_t;

#define RBUF 65536

static uvh_t *checkh(lua_State *L, int idx, int type)
{
	uvud_t *u = NULL;
	if (type >= 0)
		u = luaL_checkudata(L, idx, mt_names[type]);
	else {
		for (int t = 0; t < 3 && !u; t++)
			u = luaL_testudata(L, idx, mt_names[t]);
		if (!u)
			luaL_argerror(L, idx, "expected a uv handle");
	}
	if (!u->h || u->h->closed)
		luaL_error(L, "handle %p is closing", (void *)u);
	return u->h;
}

static const char *err_name(int err)
{
	switch (err) {
	case EADDRINUSE: return "EADDRINUSE";
	case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
	case EACCES: return "EACCES";
	case EAGAIN: return "EAGAIN";
	case EBADF: return "EBADF";
	case ECONNREFUSED: return "ECONNREFUSED";
	case ECONNRESET: return "ECONNRESET";
	case EINVAL: return "EINVAL";
	case EISCONN: return "EISCONN";
	case EMFILE: return "EMFILE";
	case ENETUNREACH: return "ENETUNREACH";
	case ENOBUFS: return "ENOBUFS";
	case ENOTCONN: return "ENOTCONN";
	case EPIPE: return "EPIPE";
	default: return "EIO";
	}
}

/* luv convention: nil, "ENAME: message", "ENAME" */
static int push_err(lua_State *L, int err)
{
	lua_pushnil(L);
	lua_pushfstring(L, "%s: %s", err_name(err), strerror(err));
	lua_pushstring(L, err_name(err));
	return 3;
}

static void push_addr(lua_State *L, const struct sockaddr_in *sa)
{
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof ip);
	lua_createtable(L, 0, 3);
	lua_pushstring(L, ip);
	lua_setfield(L, -2, "ip");
	lua_pushinteger(L, ntohs(sa->sin_port));
	lua_setfield(L, -2, "port");
	lua_pushstring(L, "inet");
	lua_setfield(L, -2, "family");
}

static int parse_addr(lua_State *L, int idx_host, int idx_port, struct sockaddr_in *sa)
{
	const char *host = luaL_checkstring(L, idx_host);
	lua_Integer port = luaL_checkinteger(L, idx_port);
	if (g_bind_override && !strcmp(host, "0.0.0.0"))
		host = g_bind_override;
	memset(sa, 0, sizeof *sa);
	sa->sin_family = AF_INET;
	sa->sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, host, &sa->sin_addr) != 1)
		return EINVAL; /* IPv4 literals only; no resolver in a static build */
	return 0;
}

/* ---- handle lifetime ---- */

static void free_handle(void *arg)
{
	uvh_t *h = arg;
	free(h->rbuf);
	free(h);
}

static void close_cb_task(void *arg);

struct close_task {
	session_t *s;
	int ref;
};

/* Close the OS side. Lua references are dropped only when L is usable. */
static void handle_close(lua_State *L, uvh_t *h, bool from_gc)
{
	if (h->closed)
		return;
	h->closed = true;
	loop_io_del(&h->w);
	loop_timer_stop(&h->timer);
	if (h->fd >= 0)
		close(h->fd);
	if (h->pending_fd >= 0)
		close(h->pending_fd);
	h->fd = h->pending_fd = -1;
	if (!from_gc && L) {
		luaL_unref(L, LUA_REGISTRYINDEX, h->cb_ref);
		h->cb_ref = LUA_NOREF;
		luaL_unref(L, LUA_REGISTRYINDEX, h->self_ref);
		h->self_ref = LUA_NOREF;
		if (h->close_cb_ref != LUA_NOREF) {
			struct close_task *t = xmalloc(sizeof *t);
			t->s = h->s;
			t->ref = h->close_cb_ref;
			h->close_cb_ref = LUA_NOREF;
			session_hold(t->s);
			loop_defer(close_cb_task, t);
		}
	}
}

static void close_cb_task(void *arg)
{
	struct close_task *t = arg;
	session_t *s = t->s;
	if (!s->destroyed && !s->failed) {
		lua_rawgeti(s->L, LUA_REGISTRYINDEX, t->ref);
		luaL_unref(s->L, LUA_REGISTRYINDEX, t->ref);
		session_call(s, 0, 0, "close callback");
	}
	session_release(s);
	free(t);
}

static int h_gc(lua_State *L)
{
	uvud_t *u = lua_touserdata(L, 1);
	if (u && u->h) {
		handle_close(L, u->h, true);
		loop_defer(free_handle, u->h);
		u->h = NULL;
	}
	return 0;
}

static int h_close(lua_State *L)
{
	uvh_t *h = checkh(L, 1, -1);
	if (lua_isfunction(L, 2)) {
		lua_pushvalue(L, 2);
		h->close_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	}
	handle_close(L, h, false);
	return 0;
}

static int h_is_closing(lua_State *L)
{
	uvud_t *u = lua_touserdata(L, 1);
	lua_pushboolean(L, !u || !u->h || u->h->closed);
	return 1;
}

static uvh_t *new_handle(lua_State *L, int type)
{
	uvud_t *u = lua_newuserdata(L, sizeof *u);
	u->h = NULL;
	luaL_setmetatable(L, mt_names[type]);
	uvh_t *h = xcalloc(1, sizeof *h);
	h->type = type;
	h->s = session_of(L);
	h->fd = h->pending_fd = -1;
	h->w.fd = -1;
	h->cb_ref = h->close_cb_ref = LUA_NOREF;
	loop_timer_init(&h->timer, NULL, h);
	u->h = h;
	lua_pushvalue(L, -1);
	h->self_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	return h;
}

/* Run the handle's callback with nargs already pushed above it. */
static bool call_cb(uvh_t *h, int ref, int nargs, const char *what)
{
	session_t *s = h->s;
	lua_State *L = s->L;
	if (s->failed || s->destroyed || ref == LUA_NOREF) {
		lua_pop(L, nargs);
		return false;
	}
	lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
	lua_insert(L, -1 - nargs);
	return session_call(s, nargs, 0, what) == 0;
}

static void tcp_io(io_watch_t *w, uint32_t ev);
static void udp_io(io_watch_t *w, uint32_t ev);

/* Watch the fd only while something wants input. An idle fd is removed from
 * epoll entirely, so a hung-up socket cannot keep waking the loop. */
static void watch_update(uvh_t *h)
{
	uint32_t ev = 0;
	if (h->reading || (h->listening && h->pending_fd < 0))
		ev |= EPOLLIN;
	if (!ev || h->fd < 0 || h->closed) {
		loop_io_del(&h->w);
		return;
	}
	if (h->w.fd < 0)
		loop_io_add(&h->w, h->fd, ev, h->type == UVH_UDP ? udp_io : tcp_io, h);
	else
		loop_io_mod(&h->w, ev);
}

/* ---- TCP ---- */

static int ensure_socket(lua_State *L, uvh_t *h, int stype)
{
	(void)L;
	if (h->fd >= 0)
		return 0;
	h->fd = socket(AF_INET, stype | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	return h->fd < 0 ? errno : 0;
}

static int new_tcp(lua_State *L)
{
	new_handle(L, UVH_TCP);
	return 1;
}

static int tcp_bind(lua_State *L)
{
	uvh_t *h = checkh(L, 1, UVH_TCP);
	struct sockaddr_in sa;
	int err = parse_addr(L, 2, 3, &sa);
	if (!err)
		err = ensure_socket(L, h, SOCK_STREAM);
	if (!err) {
		int one = 1;
		setsockopt(h->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
		if (bind(h->fd, (struct sockaddr *)&sa, sizeof sa) < 0)
			err = errno;
	}
	if (err)
		return push_err(L, err);
	lua_pushinteger(L, 0);
	return 1;
}

static int tcp_listen(lua_State *L)
{
	uvh_t *h = checkh(L, 1, UVH_TCP);
	lua_Integer backlog = luaL_checkinteger(L, 2);
	luaL_checktype(L, 3, LUA_TFUNCTION);
	int err = ensure_socket(L, h, SOCK_STREAM);
	if (!err && listen(h->fd, (int)backlog) < 0)
		err = errno;
	if (err)
		return push_err(L, err);
	luaL_unref(L, LUA_REGISTRYINDEX, h->cb_ref);
	lua_pushvalue(L, 3);
	h->cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	h->listening = true;
	watch_update(h);
	lua_pushinteger(L, 0);
	return 1;
}

static int tcp_accept(lua_State *L)
{
	uvh_t *srv = checkh(L, 1, UVH_TCP);
	uvh_t *cl = checkh(L, 2, UVH_TCP);
	if (srv->pending_fd < 0)
		return push_err(L, EAGAIN);
	if (cl->fd >= 0)
		return push_err(L, EISCONN);
	cl->fd = srv->pending_fd;
	srv->pending_fd = -1;
	watch_update(srv);
	lua_pushinteger(L, 0);
	return 1;
}

static void tcp_on_listen(uvh_t *h)
{
	while (h->listening && !h->closed && h->pending_fd < 0) {
		int fd = accept4(h->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0)
			break;
		h->pending_fd = fd;
		lua_pushnil(h->s->L);
		call_cb(h, h->cb_ref, 1, "connection callback");
	}
	if (!h->closed)
		watch_update(h);
}

static void tcp_on_read(uvh_t *h)
{
	if (!h->rbuf)
		h->rbuf = xmalloc(RBUF);
	ssize_t n = recv(h->fd, h->rbuf, RBUF, 0);
	if (n < 0 && (errno == EAGAIN || errno == EINTR))
		return;
	lua_State *L = h->s->L;
	if (n > 0) {
		lua_pushnil(L);
		lua_pushlstring(L, (const char *)h->rbuf, (size_t)n);
		call_cb(h, h->cb_ref, 2, "read callback");
		return;
	}
	/* EOF or error: deliver once, then stop reading (as libuv does). */
	int e = n < 0 ? errno : 0;
	h->reading = false;
	watch_update(h);
	if (e)
		lua_pushstring(L, strerror(e));
	else
		lua_pushnil(L);
	lua_pushnil(L);
	call_cb(h, h->cb_ref, 2, "read callback");
}

static void tcp_io(io_watch_t *w, uint32_t ev)
{
	uvh_t *h = w->ud;
	(void)ev;
	if (h->closed)
		return;
	if (h->listening)
		tcp_on_listen(h);
	else if (h->reading)
		tcp_on_read(h);
}

static int read_start(lua_State *L)
{
	uvh_t *h = checkh(L, 1, UVH_TCP);
	luaL_checktype(L, 2, LUA_TFUNCTION);
	if (h->fd < 0)
		return push_err(L, ENOTCONN);
	luaL_unref(L, LUA_REGISTRYINDEX, h->cb_ref);
	lua_pushvalue(L, 2);
	h->cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	h->reading = true;
	watch_update(h);
	lua_pushinteger(L, 0);
	return 1;
}

static int read_stop(lua_State *L)
{
	uvh_t *h = checkh(L, 1, UVH_TCP);
	h->reading = false;
	watch_update(h);
	lua_pushinteger(L, 0);
	return 1;
}

static int sockname(lua_State *L, int type)
{
	uvh_t *h = checkh(L, 1, type);
	struct sockaddr_in sa;
	socklen_t sl = sizeof sa;
	if (h->fd < 0 || getsockname(h->fd, (struct sockaddr *)&sa, &sl) < 0)
		return push_err(L, h->fd < 0 ? EBADF : errno);
	push_addr(L, &sa);
	return 1;
}

static int tcp_getsockname(lua_State *L) { return sockname(L, UVH_TCP); }
static int udp_getsockname(lua_State *L) { return sockname(L, UVH_UDP); }

static int recv_buffer_size(lua_State *L)
{
	uvh_t *h = checkh(L, 1, -1);
	if (h->fd < 0)
		return push_err(L, EBADF);
	if (lua_isnoneornil(L, 2)) {
		int v = 0;
		socklen_t sl = sizeof v;
		if (getsockopt(h->fd, SOL_SOCKET, SO_RCVBUF, &v, &sl) < 0)
			return push_err(L, errno);
		lua_pushinteger(L, v);
		return 1;
	}
	int v = (int)luaL_checkinteger(L, 2);
	if (setsockopt(h->fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof v) < 0)
		return push_err(L, errno);
	lua_pushinteger(L, 0);
	return 1;
}

/* ---- UDP ---- */

static int new_udp(lua_State *L)
{
	new_handle(L, UVH_UDP);
	return 1;
}

static int udp_bind(lua_State *L)
{
	uvh_t *h = checkh(L, 1, UVH_UDP);
	struct sockaddr_in sa;
	int err = parse_addr(L, 2, 3, &sa);
	if (!err)
		err = ensure_socket(L, h, SOCK_DGRAM);
	if (!err && lua_istable(L, 4)) {
		lua_getfield(L, 4, "reuseaddr");
		if (lua_toboolean(L, -1)) {
			int one = 1;
			setsockopt(h->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
		}
		lua_pop(L, 1);
	}
	if (!err && bind(h->fd, (struct sockaddr *)&sa, sizeof sa) < 0)
		err = errno;
	if (err)
		return push_err(L, err);
	lua_pushinteger(L, 0);
	return 1;
}

static void udp_io(io_watch_t *w, uint32_t ev)
{
	uvh_t *h = w->ud;
	(void)ev;
	if (!h->rbuf)
		h->rbuf = xmalloc(RBUF);
	for (int i = 0; i < 32 && h->reading && !h->closed; i++) {
		struct sockaddr_in sa;
		socklen_t sl = sizeof sa;
		ssize_t n = recvfrom(h->fd, h->rbuf, RBUF, 0, (struct sockaddr *)&sa, &sl);
		if (n < 0)
			break;
		lua_State *L = h->s->L;
		lua_pushnil(L);
		lua_pushlstring(L, (const char *)h->rbuf, (size_t)n);
		push_addr(L, &sa);
		lua_newtable(L); /* flags */
		if (!call_cb(h, h->cb_ref, 4, "udp recv callback"))
			break;
	}
}

static int udp_recv_start(lua_State *L)
{
	uvh_t *h = checkh(L, 1, UVH_UDP);
	luaL_checktype(L, 2, LUA_TFUNCTION);
	int err = ensure_socket(L, h, SOCK_DGRAM);
	if (err)
		return push_err(L, err);
	luaL_unref(L, LUA_REGISTRYINDEX, h->cb_ref);
	lua_pushvalue(L, 2);
	h->cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	h->reading = true;
	watch_update(h);
	lua_pushinteger(L, 0);
	return 1;
}

static int udp_recv_stop(lua_State *L)
{
	uvh_t *h = checkh(L, 1, UVH_UDP);
	h->reading = false;
	watch_update(h);
	lua_pushinteger(L, 0);
	return 1;
}

struct send_task {
	session_t *s;
	int ref;
	int err;
};

static void send_cb_task(void *arg)
{
	struct send_task *t = arg;
	session_t *s = t->s;
	if (!s->destroyed && !s->failed) {
		lua_rawgeti(s->L, LUA_REGISTRYINDEX, t->ref);
		luaL_unref(s->L, LUA_REGISTRYINDEX, t->ref);
		if (t->err)
			lua_pushstring(s->L, strerror(t->err));
		else
			lua_pushnil(s->L);
		session_call(s, 1, 0, "udp send callback");
	}
	session_release(s);
	free(t);
}

/* udp:send(data, host, port[, cb]) */
static int udp_send(lua_State *L)
{
	uvh_t *h = checkh(L, 1, UVH_UDP);
	size_t len;
	const uint8_t *data = raat_checkbytes(L, 2, &len);
	struct sockaddr_in sa;
	const char *host = luaL_checkstring(L, 3);
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)luaL_checkinteger(L, 4));
	if (inet_pton(AF_INET, host, &sa.sin_addr) != 1)
		return push_err(L, EINVAL);
	int err = ensure_socket(L, h, SOCK_DGRAM);
	if (!err && sendto(h->fd, data, len, MSG_NOSIGNAL, (struct sockaddr *)&sa, sizeof sa) < 0)
		err = errno;
	if (lua_isfunction(L, 5)) {
		struct send_task *t = xmalloc(sizeof *t);
		t->s = h->s;
		lua_pushvalue(L, 5);
		t->ref = luaL_ref(L, LUA_REGISTRYINDEX);
		t->err = err;
		session_hold(t->s);
		loop_defer(send_cb_task, t);
	}
	if (err)
		return push_err(L, err);
	lua_pushinteger(L, 0);
	return 1;
}

static int udp_set_membership(lua_State *L)
{
	uvh_t *h = checkh(L, 1, UVH_UDP);
	const char *group = luaL_checkstring(L, 2);
	const char *iface = luaL_optstring(L, 3, "0.0.0.0");
	const char *op = luaL_checkstring(L, 4);
	struct ip_mreq mr;
	if (inet_pton(AF_INET, group, &mr.imr_multiaddr) != 1 ||
	    inet_pton(AF_INET, iface, &mr.imr_interface) != 1)
		return push_err(L, EINVAL);
	int err = ensure_socket(L, h, SOCK_DGRAM);
	int opt = !strcmp(op, "leave") ? IP_DROP_MEMBERSHIP : IP_ADD_MEMBERSHIP;
	if (!err && setsockopt(h->fd, IPPROTO_IP, opt, &mr, sizeof mr) < 0)
		err = errno;
	if (err)
		return push_err(L, err);
	lua_pushinteger(L, 0);
	return 1;
}

static int udp_set_multicast_ttl(lua_State *L)
{
	uvh_t *h = checkh(L, 1, UVH_UDP);
	int ttl = (int)luaL_checkinteger(L, 2);
	int err = ensure_socket(L, h, SOCK_DGRAM);
	if (!err && setsockopt(h->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl) < 0)
		err = errno;
	if (err)
		return push_err(L, err);
	lua_pushinteger(L, 0);
	return 1;
}

/* ---- timers ---- */

static void timer_fire(ltimer_t *t)
{
	uvh_t *h = t->ud;
	if (h->closed)
		return;
	call_cb(h, h->cb_ref, 0, "timer callback");
}

static int new_timer(lua_State *L)
{
	uvh_t *h = new_handle(L, UVH_TIMER);
	h->timer.cb = timer_fire;
	return 1;
}

static int timer_start(lua_State *L)
{
	uvh_t *h = checkh(L, 1, UVH_TIMER);
	lua_Integer timeout = luaL_checkinteger(L, 2);
	lua_Integer repeat = luaL_checkinteger(L, 3);
	luaL_checktype(L, 4, LUA_TFUNCTION);
	luaL_unref(L, LUA_REGISTRYINDEX, h->cb_ref);
	lua_pushvalue(L, 4);
	h->cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	loop_timer_start(&h->timer, timeout, repeat);
	lua_pushinteger(L, 0);
	return 1;
}

static int timer_stop(lua_State *L)
{
	uvh_t *h = checkh(L, 1, UVH_TIMER);
	loop_timer_stop(&h->timer);
	lua_pushinteger(L, 0);
	return 1;
}

static int timer_again(lua_State *L)
{
	uvh_t *h = checkh(L, 1, UVH_TIMER);
	if (h->timer.repeat_ms)
		loop_timer_start(&h->timer, h->timer.repeat_ms, h->timer.repeat_ms);
	lua_pushinteger(L, 0);
	return 1;
}

static int is_active(lua_State *L)
{
	uvh_t *h = checkh(L, 1, -1);
	lua_pushboolean(L, h->type == UVH_TIMER ? loop_timer_active(&h->timer)
						: (h->reading || h->listening));
	return 1;
}

static int uv_hrtime(lua_State *L)
{
	lua_pushinteger(L, (lua_Integer)now_ns());
	return 1;
}

static int uv_now(lua_State *L)
{
	lua_pushinteger(L, (lua_Integer)now_ms());
	return 1;
}

/* ---- registration ---- */

static const luaL_Reg tcp_methods[] = {
	{ "bind", tcp_bind },         { "listen", tcp_listen },     { "accept", tcp_accept },
	{ "read_start", read_start }, { "read_stop", read_stop },   { "getsockname", tcp_getsockname },
	{ "close", h_close },         { "is_closing", h_is_closing }, { "is_active", is_active },
	{ "recv_buffer_size", recv_buffer_size }, { NULL, NULL }
};

static const luaL_Reg udp_methods[] = {
	{ "bind", udp_bind },
	{ "send", udp_send },
	{ "recv_start", udp_recv_start },
	{ "recv_stop", udp_recv_stop },
	{ "set_membership", udp_set_membership },
	{ "set_multicast_ttl", udp_set_multicast_ttl },
	{ "getsockname", udp_getsockname },
	{ "close", h_close },
	{ "is_closing", h_is_closing },
	{ "is_active", is_active },
	{ "recv_buffer_size", recv_buffer_size },
	{ NULL, NULL }
};

static const luaL_Reg timer_methods[] = {
	{ "start", timer_start },   { "stop", timer_stop },         { "again", timer_again },
	{ "close", h_close },       { "is_closing", h_is_closing }, { "is_active", is_active },
	{ NULL, NULL }
};

static const luaL_Reg uv_funcs[] = {
	{ "new_tcp", new_tcp },
	{ "new_udp", new_udp },
	{ "new_timer", new_timer },
	{ "tcp_bind", tcp_bind },
	{ "tcp_getsockname", tcp_getsockname },
	{ "listen", tcp_listen },
	{ "accept", tcp_accept },
	{ "read_start", read_start },
	{ "read_stop", read_stop },
	{ "udp_bind", udp_bind },
	{ "udp_getsockname", udp_getsockname },
	{ "udp_send", udp_send },
	{ "udp_recv_start", udp_recv_start },
	{ "udp_recv_stop", udp_recv_stop },
	{ "udp_set_membership", udp_set_membership },
	{ "udp_set_multicast_ttl", udp_set_multicast_ttl },
	{ "recv_buffer_size", recv_buffer_size },
	{ "timer_start", timer_start },
	{ "timer_stop", timer_stop },
	{ "timer_again", timer_again },
	{ "close", h_close },
	{ "is_closing", h_is_closing },
	{ "is_active", is_active },
	{ "hrtime", uv_hrtime },
	{ "now", uv_now },
	{ NULL, NULL }
};

int luaopen_raat_uv(lua_State *L)
{
	const luaL_Reg *methods[] = { tcp_methods, udp_methods, timer_methods };
	for (int t = 0; t < 3; t++) {
		luaL_newmetatable(L, mt_names[t]);
		lua_newtable(L);
		luaL_setfuncs(L, methods[t], 0);
		lua_setfield(L, -2, "__index");
		lua_pushcfunction(L, h_gc);
		lua_setfield(L, -2, "__gc");
		lua_pop(L, 1);
	}
	luaL_newlib(L, uv_funcs);
	return 1;
}
