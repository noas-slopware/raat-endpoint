/* `stream` and `codec` global modules (spec 7, 13.10). */
#include "session.h"
#include "stream.h"

#include <string.h>

typedef struct {
	stream_t *st;
} lstream_t;

stream_t *raat_checkstream(lua_State *L, int idx)
{
	lstream_t *u = luaL_checkudata(L, idx, STREAM_MT);
	if (!u->st)
		luaL_error(L, "stream is closed");
	return u->st;
}

static int field_int(lua_State *L, int t, const char *k)
{
	lua_getfield(L, t, k);
	int isnum;
	lua_Number n = lua_tonumberx(L, -1, &isnum);
	lua_pop(L, 1);
	if (!isnum)
		luaL_error(L, "format: missing or invalid '%s'", k);
	return (int)n;
}

static int s_new(lua_State *L)
{
	luaL_checktype(L, 1, LUA_TTABLE);
	lua_getfield(L, 1, "sample_type");
	const char *type = lua_tostring(L, -1);
	char st[16];
	strlcpy0(st, type ? type : "", sizeof st);
	lua_pop(L, 1);
	int rate = field_int(L, 1, "sample_rate");
	int bits = field_int(L, 1, "bits_per_sample");
	int ch = field_int(L, 1, "channels");
	int64_t cap = raat_checkint64(L, 2);
	const char *err = NULL;
	stream_t *s = stream_new(st, rate, bits, ch, cap, &err);
	if (!s) {
		lua_pushstring(L, err);
		return lua_error(L);
	}
	lstream_t *u = lua_newuserdata(L, sizeof *u);
	u->st = s;
	luaL_setmetatable(L, STREAM_MT);
	return 1;
}

static int s_gc(lua_State *L)
{
	lstream_t *u = luaL_checkudata(L, 1, STREAM_MT);
	if (u->st)
		stream_unref(u->st);
	u->st = NULL;
	return 0;
}

static int do_write(lua_State *L, bool chmap)
{
	stream_t *s = raat_checkstream(L, 1);
	int64_t sample = raat_checkint64(L, 2);
	double gain = luaL_optnumber(L, 3, 0.0);
	double peak = luaL_optnumber(L, 4, 0.0);
	size_t len;
	const uint8_t *data = raat_checkbytes(L, 5, &len);
	int64_t n = raat_checkint64(L, 6);
	int32_t map = chmap ? (int32_t)raat_checkint64(L, 7) : 0;
	const char *err = NULL;
	if (stream_write(s, sample, gain, peak, data, len, n, map, chmap, &err) < 0) {
		lua_pushstring(L, err);
		return lua_error(L);
	}
	return 0;
}

static int s_write(lua_State *L) { return do_write(L, false); }
static int s_write_chmap(lua_State *L) { return do_write(L, true); }

static int s_clear(lua_State *L)
{
	stream_clear(raat_checkstream(L, 1));
	return 0;
}

static int s_get_stats(lua_State *L)
{
	stream_t *s = raat_checkstream(L, 1);
	if (!lua_istable(L, 2)) {
		lua_settop(L, 1);
		lua_newtable(L);
	} else {
		lua_settop(L, 2);
	}
	pthread_mutex_lock(&s->mu);
	int64_t fill = s->empty ? 0 : s->hi - (s->reading ? (s->rd > s->lo ? s->rd : s->lo) : s->lo);
	if (fill < 0)
		fill = 0;
	struct {
		const char *k;
		int64_t v;
	} f[] = {
		{ "write_count", s->write_count },     { "read_count", s->read_count },
		{ "samples_in", s->samples_in },       { "samples_out", s->samples_out },
		{ "dropout_count", s->dropout_count }, { "samples_dropped", s->samples_dropped },
		{ "overrun_count", s->overrun_count }, { "samples_overrun", s->samples_overrun },
		{ "capacity_samples", s->capacity },   { "fill_samples", fill },
	};
	pthread_mutex_unlock(&s->mu);
	for (size_t i = 0; i < sizeof f / sizeof f[0]; i++) {
		lua_pushinteger(L, (lua_Integer)f[i].v);
		lua_setfield(L, 2, f[i].k);
	}
	return 1;
}

static const luaL_Reg stream_methods[] = {
	{ "write", s_write },
	{ "write_chmap", s_write_chmap },
	{ "clear", s_clear },
	{ "get_stats", s_get_stats },
	{ NULL, NULL }
};

int luaopen_raat_stream(lua_State *L)
{
	luaL_newmetatable(L, STREAM_MT);
	luaL_newlib(L, stream_methods);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction(L, s_gc);
	lua_setfield(L, -2, "__gc");
	lua_pop(L, 1);
	lua_newtable(L);
	lua_pushcfunction(L, s_new);
	lua_setfield(L, -2, "new");
	lua_pushboolean(L, 1);
	lua_setfield(L, -2, "has_write_chmap");
	return 1;
}

/* No wire codec: raat.codecs stays nil, as on the captured 1.1.38 endpoint,
 * and the Core's setup requests then carry no `wire_codec` (capture3: plain
 * 16-bit PCM in DATA commands). FLAC would only be needed if codecs were
 * advertised, which no capture covers. */
static int c_new(lua_State *L)
{
	return luaL_error(L, "codec '%s' is not supported", luaL_optstring(L, 1, "?"));
}

int luaopen_raat_codec(lua_State *L)
{
	lua_newtable(L);
	lua_pushcfunction(L, c_new);
	lua_setfield(L, -2, "new");
	return 1;
}
