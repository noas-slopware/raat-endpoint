#include "session.h"

#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include "third_party/cjson/cJSON.h"
#include "third_party/lua-5.3.6/lualib.h"

size_t g_lua_mem_limit = 24u << 20;

session_t *session_of(lua_State *L)
{
	return *(session_t **)lua_getextraspace(L);
}

static void *l_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	session_t *s = ud;
	if (!ptr)
		osize = 0;
	if (nsize == 0) {
		free(ptr);
		s->mem -= osize;
		return NULL;
	}
	if (nsize > osize && s->mem - osize + nsize > s->mem_limit)
		return NULL;
	void *p = realloc(ptr, nsize);
	if (!p)
		return NULL;
	s->mem = s->mem - osize + nsize;
	if (s->mem > s->mem_peak)
		s->mem_peak = s->mem;
	return p;
}

void session_hold(session_t *s)
{
	s->refs++;
}

void session_release(session_t *s)
{
	if (--s->refs == 0)
		free(s);
}

static int traceback(lua_State *L)
{
	const char *msg = lua_tostring(L, 1);
	if (!msg)
		msg = luaL_tolstring(L, 1, NULL);
	luaL_traceback(L, L, msg, 1);
	return 1;
}

int session_call(session_t *s, int nargs, int nres, const char *what)
{
	lua_State *L = s->L;
	int fn = lua_gettop(L) - nargs;
	lua_pushcfunction(L, traceback);
	lua_insert(L, fn);
	int rc = lua_pcall(L, nargs, nres, fn);
	lua_remove(L, fn);
	if (rc != LUA_OK) {
		log_msg(s->exiting ? LOG_DEBUG : LOG_ERROR, "[lua] error in %s: %s", what,
			lua_tostring(L, -1));
		lua_pop(L, 1);
		session_fail(s, "script error");
		return -1;
	}
	return 0;
}

void session_fail(session_t *s, const char *why)
{
	if (s->failed)
		return;
	s->failed = true;
	LOGW("[session] tearing down connection: %s", why);
	if (s->conn)
		ll_close(s->conn, why);
}

/* ---- raat.log ---- */

static int log_level(lua_State *L, int level)
{
	luaL_Buffer b;
	luaL_buffinit(L, &b);
	int n = lua_gettop(L);
	for (int i = 1; i <= n; i++) {
		if (i > 1)
			luaL_addchar(&b, ' ');
		luaL_tolstring(L, i, NULL);
		luaL_addvalue(&b);
	}
	luaL_pushresult(&b);
	log_msg(level, "[lua] %s", lua_tostring(L, -1));
	return 0;
}

static int l_trace(lua_State *L) { return log_level(L, LOG_TRACE); }
static int l_debug(lua_State *L) { return log_level(L, LOG_DEBUG); }
static int l_info(lua_State *L) { return log_level(L, LOG_INFO); }
static int l_warning(lua_State *L) { return log_level(L, LOG_WARN); }
static int l_error(lua_State *L) { return log_level(L, LOG_ERROR); }
static int l_critical(lua_State *L) { return log_level(L, LOG_CRIT); }

/* ---- raat.session ---- */

static int s_send_message(lua_State *L)
{
	session_t *s = session_of(L);
	lua_Integer type = luaL_checkinteger(L, 1);
	luaL_argcheck(L, type >= 0 && type < 0x80000000LL, 1, "invalid message type");
	size_t len;
	const uint8_t *data = raat_checkbytes(L, 2, &len);
	if (len > LL_MAX_BODY)
		return luaL_error(L, "message too large");
	if (s->conn && !s->failed)
		ll_send(s->conn, (uint32_t)type, data, len);
	return 0;
}

static int s_set_client_type(lua_State *L)
{
	session_t *s = session_of(L);
	strlcpy0(s->client_type, luaL_checkstring(L, 1), sizeof s->client_type);
	LOGI("[session] client type %s", s->client_type);
	return 0;
}

/* force_exit calls os.exit(1) (spec 13.11): close this session, not the process. */
static int os_exit(lua_State *L)
{
	session_t *s = session_of(L);
	LOGW("[session] script called os.exit(%d)", (int)luaL_optinteger(L, 1, 0));
	s->exiting = true;
	session_fail(s, "os.exit");
	return luaL_error(L, "os.exit: session closed");
}

static void set_str(lua_State *L, const char *k, const char *v)
{
	lua_pushstring(L, v);
	lua_setfield(L, -2, k);
}

static void push_unsupported(lua_State *L)
{
	lua_createtable(L, 0, 1);
	lua_pushboolean(L, 0);
	lua_setfield(L, -2, "is_supported");
}

static void build_raat(lua_State *L, session_t *s)
{
	lua_newtable(L); /* raat */

	static const luaL_Reg logf[] = { { "trace", l_trace },     { "debug", l_debug },
					 { "info", l_info },       { "warning", l_warning },
					 { "error", l_error },     { "critical", l_critical },
					 { NULL, NULL } };
	luaL_newlib(L, logf);
	lua_setfield(L, -2, "log");

	/* 1.1.38 shape: raat.info carries only the unique id (spec 13.4). */
	lua_newtable(L);
	set_str(L, "unique_id", s->dev->unique_id);
	lua_setfield(L, -2, "info");

	const struct platform_uname *u = platform_uname();
	lua_newtable(L);
	set_str(L, "os", "linux");
	lua_newtable(L);
	set_str(L, "sysname", u->sysname);
	set_str(L, "nodename", u->nodename);
	set_str(L, "release", u->release);
	set_str(L, "version", u->version);
	set_str(L, "machine", u->machine);
	lua_setfield(L, -2, "uname");
	lua_setfield(L, -2, "platform");

	static const luaL_Reg sessf[] = { { "send_message", s_send_message },
					  { "set_client_type", s_set_client_type },
					  { NULL, NULL } };
	luaL_newlib(L, sessf);
	lua_newtable(L);
	lua_pushvalue(L, -1);
	s->msg_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	lua_setfield(L, -2, "message_handlers");
	lua_newtable(L);
	lua_pushvalue(L, -1);
	s->shutdown_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	lua_setfield(L, -2, "shutdown_handlers");
	lua_newtable(L);
	set_str(L, "family", "inet");
	set_str(L, "ip", s->conn ? ll_peer_ip(s->conn) : "0.0.0.0");
	lua_pushinteger(L, s->conn ? ll_peer_port(s->conn) : 0);
	lua_setfield(L, -2, "port");
	lua_setfield(L, -2, "remote_address");
	lua_setfield(L, -2, "session");

	raat_push_output(L, s);
	lua_setfield(L, -2, "output");

	/* No device volume, transport, source selection or app channel
	 * (spec 11.5, 11.8, 13.8, 13.9): fixed volume, no front panel. */
	push_unsupported(L);
	lua_setfield(L, -2, "volume");
	push_unsupported(L);
	lua_setfield(L, -2, "transport");
	push_unsupported(L);
	lua_setfield(L, -2, "source_selection");
	push_unsupported(L);
	lua_setfield(L, -2, "app_channel");
	/* raat.codecs stays nil (spec 13.4). raat.port_range is absent, as on RoonBridge. */

	lua_setglobal(L, "raat");
}

/* Scripts arrive unsigned from the LAN, so the VM gets no file or process
 * access. The captured scripts use none of it (spec 13.10). */
static void sandbox(lua_State *L)
{
	lua_getglobal(L, "package");
	lua_pushstring(L, "");
	lua_setfield(L, -2, "path");
	lua_pushstring(L, "");
	lua_setfield(L, -2, "cpath");
	lua_pushnil(L);
	lua_setfield(L, -2, "loadlib");
	lua_getfield(L, -1, "searchers");
	for (int i = 4; i >= 2; i--) {
		lua_pushnil(L);
		lua_rawseti(L, -2, i); /* keep only the preload searcher */
	}
	lua_pop(L, 1);
	lua_getfield(L, -1, "loaded");
	lua_pushnil(L);
	lua_setfield(L, -2, "io");
	lua_pop(L, 2);
	lua_pushnil(L);
	lua_setglobal(L, "io");
	lua_pushnil(L);
	lua_setglobal(L, "dofile");
	lua_pushnil(L);
	lua_setglobal(L, "loadfile");
	lua_getglobal(L, "os");
	static const char *const drop[] = { "execute", "remove", "rename", "tmpname", "getenv",
					    "setlocale", NULL };
	for (int i = 0; drop[i]; i++) {
		lua_pushnil(L);
		lua_setfield(L, -2, drop[i]);
	}
	lua_pushcfunction(L, os_exit);
	lua_setfield(L, -2, "exit");
	lua_pop(L, 1);
}

session_t *session_new(mdev_t *dev, llconn_t *conn)
{
	session_t *s = xcalloc(1, sizeof *s);
	s->refs = 1;
	s->dev = dev;
	s->conn = conn;
	s->mem_limit = g_lua_mem_limit;
	s->msg_ref = s->shutdown_ref = s->out_msg_ref = LUA_NOREF;
	lua_State *L = lua_newstate(l_alloc, s);
	if (!L) {
		free(s);
		return NULL;
	}
	s->L = L;
	*(session_t **)lua_getextraspace(L) = s;
	luaL_openlibs(L);
	sandbox(L);

	luaL_requiref(L, "buffer", luaopen_raat_buffer, 1);
	luaL_requiref(L, "stream", luaopen_raat_stream, 1);
	luaL_requiref(L, "codec", luaopen_raat_codec, 1);
	luaL_requiref(L, "luv", luaopen_raat_uv, 0);
	lua_setglobal(L, "uv"); /* uv = require('luv') */
	lua_pop(L, 3);
	build_raat(L, s);

	uint32_t seed = 0;
	if (getrandom(&seed, sizeof seed, 0) != sizeof seed)
		seed = (uint32_t)now_ns();
	lua_getglobal(L, "math");
	lua_getfield(L, -1, "randomseed");
	lua_pushinteger(L, seed);
	lua_call(L, 1, 0);
	lua_pop(L, 1);
	LOGD("[session] new VM for %s (%zu KiB)", dev->pd.id, s->mem / 1024);
	return s;
}

void session_destroy(session_t *s)
{
	if (s->destroyed)
		return;
	lua_State *L = s->L;
	/* Order from spec 10 item 3: stop reading (the connection is closed by
	 * now), stop delivering events, run shutdown handlers, close the VM. */
	s->failed = true;
	lua_rawgeti(L, LUA_REGISTRYINDEX, s->shutdown_ref);
	int n = (int)luaL_len(L, -1);
	for (int i = 1; i <= n; i++) {
		lua_rawgeti(L, -1, i);
		if (lua_isfunction(L, -1)) {
			lua_pushcfunction(L, traceback);
			lua_insert(L, -2);
			if (lua_pcall(L, 0, 0, -2) != LUA_OK) {
				LOGW("[lua] shutdown handler: %s", lua_tostring(L, -1));
				lua_pop(L, 1);
			}
			lua_pop(L, 1); /* traceback */
		} else {
			lua_pop(L, 1);
		}
	}
	lua_pop(L, 1);
	if (s->dev && s->dev->owner == s)
		dev_output_release(s->dev, false, NULL);
	LOGD("[session] closing VM (peak %zu KiB)", s->mem_peak / 1024);
	s->destroyed = true;
	lua_close(L);
	s->L = NULL;
	s->conn = NULL;
	session_release(s);
}

/* ---- device-server requests ---- */

static void respond(session_t *s, uint32_t rid, cJSON *j)
{
	char *txt = cJSON_PrintUnformatted(j);
	ll_respond(s->conn, rid, true, txt);
	cJSON_free(txt);
	cJSON_Delete(j);
}

static void respond_status(session_t *s, uint32_t rid, const char *status, const char *msg)
{
	cJSON *j = cJSON_CreateObject();
	cJSON_AddStringToObject(j, "status", status);
	if (msg)
		cJSON_AddStringToObject(j, "message", msg);
	respond(s, rid, j);
}

void session_load_script(session_t *s, uint32_t rid, const char *script, size_t len,
			 const char *name, const char *module)
{
	lua_State *L = s->L;
	char chunk[160];
	snprintf(chunk, sizeof chunk, "=%s", name ? name : "script");
	/* "t": text only. Precompiled chunks would bypass the parser's checks. */
	int rc = luaL_loadbufferx(L, script, len, chunk, "t");
	if (rc != LUA_OK) {
		LOGE("[lua] load %s: %s", chunk + 1, lua_tostring(L, -1));
		respond_status(s, rid, "ScriptError", lua_tostring(L, -1));
		lua_pop(L, 1);
		return;
	}
	if (module) {
		/* modules go to package.preload and are not run (spec 5.3) */
		lua_getglobal(L, "package");
		lua_getfield(L, -1, "preload");
		lua_pushvalue(L, -3);
		lua_setfield(L, -2, module);
		lua_pop(L, 3);
		LOGD("[lua] preloaded module %s (%s)", module, chunk + 1);
	} else {
		lua_pushcfunction(L, traceback);
		lua_insert(L, -2);
		rc = lua_pcall(L, 0, 0, -2);
		if (rc != LUA_OK) {
			LOGE("[lua] running %s: %s", chunk + 1, lua_tostring(L, -1));
			respond_status(s, rid, "ScriptError", lua_tostring(L, -1));
			lua_pop(L, 2);
			return;
		}
		lua_pop(L, 1);
		LOGI("[lua] ran %s (VM %zu KiB)", chunk + 1, s->mem / 1024);
	}
	if (!s->failed)
		respond_status(s, rid, "Success", NULL);
}

void session_deliver(session_t *s, uint32_t type, const uint8_t *body, size_t len)
{
	lua_State *L = s->L;
	lua_rawgeti(L, LUA_REGISTRYINDEX, s->msg_ref);
	int n = (int)luaL_len(L, -1);
	for (int i = 1; i <= n && !s->failed; i++) {
		lua_rawgeti(L, -1, i);
		lua_pushinteger(L, type);
		lua_pushlstring(L, (const char *)body, len);
		session_call(s, 2, 0, "session message handler");
	}
	if (!s->destroyed)
		lua_pop(L, 1);
}

/* ---- deferred plugin callbacks ---- */

enum { T_SETUP_OK, T_SETUP_FAIL, T_LOST, T_MESSAGE };

struct stask {
	session_t *s;
	int kind;
	int ref;
	int token;
	char *str;
};

static void stask_run(void *arg)
{
	struct stask *t = arg;
	session_t *s = t->s;
	if (s->destroyed || s->failed)
		goto out;
	lua_State *L = s->L;
	switch (t->kind) {
	case T_SETUP_OK:
		if (!s->dev || s->dev->owner != s || s->dev->token != t->token)
			break; /* torn down before the callback ran */
		/* fallthrough */
	case T_SETUP_FAIL:
		lua_rawgeti(L, LUA_REGISTRYINDEX, t->ref);
		if (t->kind == T_SETUP_FAIL)
			luaL_unref(L, LUA_REGISTRYINDEX, t->ref);
		if (lua_getfield(L, -1, "on_setup") == LUA_TFUNCTION) {
			lua_pushboolean(L, t->kind == T_SETUP_OK);
			if (t->kind == T_SETUP_OK)
				lua_pushinteger(L, t->token);
			else
				lua_pushstring(L, t->str);
			session_call(s, 2, 0, "on_setup");
		} else {
			lua_pop(L, 1);
		}
		if (!s->destroyed)
			lua_pop(L, 1);
		break;
	case T_LOST:
		lua_rawgeti(L, LUA_REGISTRYINDEX, t->ref);
		luaL_unref(L, LUA_REGISTRYINDEX, t->ref);
		if (lua_istable(L, -1) && lua_getfield(L, -1, "on_output_lost") == LUA_TFUNCTION) {
			if (t->str)
				lua_pushstring(L, t->str);
			else
				lua_pushnil(L);
			session_call(s, 1, 0, "on_output_lost");
		} else {
			lua_pop(L, 1);
		}
		if (!s->destroyed)
			lua_pop(L, 1);
		break;
	case T_MESSAGE: {
		lua_rawgeti(L, LUA_REGISTRYINDEX, s->out_msg_ref);
		int n = (int)luaL_len(L, -1);
		for (int i = 1; i <= n && !s->failed; i++) {
			lua_rawgeti(L, -1, i);
			lua_pushstring(L, t->str);
			session_call(s, 1, 0, "output message handler");
		}
		if (!s->destroyed)
			lua_pop(L, 1);
		break;
	}
	}
out:
	session_release(s);
	free(t->str);
	free(t);
}

static void stask_post(session_t *s, int kind, int ref, int token, const char *str)
{
	struct stask *t = xcalloc(1, sizeof *t);
	t->s = s;
	t->kind = kind;
	t->ref = ref;
	t->token = token;
	t->str = str ? xstrdup(str) : NULL;
	session_hold(s);
	loop_defer(stask_run, t);
}

void session_defer_setup_cb(session_t *s, int cb_ref, bool ok, int token, const char *err)
{
	stask_post(s, ok ? T_SETUP_OK : T_SETUP_FAIL, cb_ref, token, err);
}

void session_defer_output_lost(session_t *s, int cb_ref, const char *reason_json)
{
	stask_post(s, T_LOST, cb_ref, 0, reason_json);
}

void session_defer_output_message(session_t *s, const char *json)
{
	stask_post(s, T_MESSAGE, LUA_NOREF, 0, json);
}
