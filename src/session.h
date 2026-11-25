// SPDX-License-Identifier: GPL-3.0-or-later
/* One Lua 5.3 VM per device-server connection, hosting the Core's scripts
 * (spec 3, 5.3, 7, 13.10). Everything runs on the main event loop. */
#ifndef RAAT_SESSION_H
#define RAAT_SESSION_H

#include "common.h"
#include "device.h"
#include "ll.h"
#include "third_party/lua-5.3.6/lua.h"
#include "third_party/lua-5.3.6/lauxlib.h"

typedef struct session session_t;

struct session {
	lua_State *L;
	llconn_t *conn;
	mdev_t *dev;
	int refs;
	bool failed;
	bool destroyed;
	bool exiting; /* os.exit was called */
	size_t mem, mem_limit, mem_peak;
	char client_type[64];
	int msg_ref, shutdown_ref, out_msg_ref; /* raat.session/raat.output handler tables */
	struct session *next; /* devserver list */
};

extern char *g_bind_override; /* replaces "0.0.0.0" in script binds (tests) */
extern size_t g_lua_mem_limit;

session_t *session_new(mdev_t *dev, llconn_t *conn);
/* Runs shutdown handlers, releases the output, closes the VM. */
void session_destroy(session_t *s);
void session_hold(session_t *s);
void session_release(session_t *s);

/* Device-server requests handled by the C layer. */
void session_load_script(session_t *s, uint32_t rid, const char *script, size_t len,
			 const char *name, const char *module);
void session_deliver(session_t *s, uint32_t type, const uint8_t *body, size_t len);

/* Tear the connection down after a script error (spec 10 item 7). */
void session_fail(session_t *s, const char *why);
session_t *session_of(lua_State *L);
/* pcall with traceback; on error logs and fails the session. Returns 0 on success. */
int session_call(session_t *s, int nargs, int nres, const char *what);

/* Call cb_ref[field](args...) later, if the session is still alive. */
void session_defer_setup_cb(session_t *s, int cb_ref, bool ok, int token, const char *err);
void session_defer_output_lost(session_t *s, int cb_ref, const char *reason_json);
void session_defer_output_message(session_t *s, const char *json);

/* Modules (lbuffer.c, lstream.c, luv.c, loutput.c). */
int luaopen_raat_buffer(lua_State *L);
int luaopen_raat_stream(lua_State *L);
int luaopen_raat_codec(lua_State *L);
int luaopen_raat_uv(lua_State *L);
void raat_push_output(lua_State *L, session_t *s);

#define BUFFER_MT "RAAT__ScriptBuffer"
#define STREAM_MT "RAAT__Stream"

typedef struct {
	size_t len;
	uint8_t *data;
} lbuf_t;

/* Accepts a buffer userdata or a string. */
const uint8_t *raat_checkbytes(lua_State *L, int idx, size_t *len);
struct stream *raat_checkstream(lua_State *L, int idx);
int64_t raat_checkint64(lua_State *L, int idx);

#endif
