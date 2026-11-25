// SPDX-License-Identifier: GPL-3.0-or-later
/* `buffer` global module (spec 7, 13.10): byte buffers with 0-based offsets,
 * bounds-checked integer and float accessors in both byte orders. */
#include "session.h"

#include <math.h>
#include <string.h>

static void *lalloc(lua_State *L, void *p, size_t o, size_t n)
{
	void *ud;
	lua_Alloc f = lua_getallocf(L, &ud);
	return f(ud, p, o, n);
}

static lbuf_t *checkbuf(lua_State *L, int idx)
{
	return luaL_checkudata(L, idx, BUFFER_MT);
}

const uint8_t *raat_checkbytes(lua_State *L, int idx, size_t *len)
{
	lbuf_t *b = luaL_testudata(L, idx, BUFFER_MT);
	if (b) {
		*len = b->len;
		return b->data;
	}
	return (const uint8_t *)luaL_checklstring(L, idx, len);
}

int64_t raat_checkint64(lua_State *L, int idx)
{
	int isint;
	lua_Integer i = lua_tointegerx(L, idx, &isint);
	if (isint)
		return (int64_t)i;
	lua_Number n = luaL_checknumber(L, idx);
	if (!isfinite(n))
		luaL_argerror(L, idx, "number is not finite");
	return (int64_t)floor(n);
}

static lbuf_t *newbuf(lua_State *L, size_t len)
{
	lbuf_t *b = lua_newuserdata(L, sizeof *b);
	b->len = 0;
	b->data = NULL;
	luaL_setmetatable(L, BUFFER_MT);
	if (len) {
		b->data = lalloc(L, NULL, 0, len);
		if (!b->data)
			luaL_error(L, "not enough memory");
		memset(b->data, 0, len);
		b->len = len;
	}
	return b;
}

static int b_new(lua_State *L)
{
	if (lua_type(L, 1) == LUA_TSTRING) {
		size_t n;
		const char *s = lua_tolstring(L, 1, &n);
		lbuf_t *b = newbuf(L, n);
		if (n)
			memcpy(b->data, s, n);
		return 1;
	}
	lua_Integer n = luaL_optinteger(L, 1, 0);
	luaL_argcheck(L, n >= 0 && n <= (1 << 26), 1, "invalid size");
	newbuf(L, (size_t)n);
	return 1;
}

static int b_gc(lua_State *L)
{
	lbuf_t *b = checkbuf(L, 1);
	if (b->data)
		lalloc(L, b->data, b->len, 0);
	b->data = NULL;
	b->len = 0;
	return 0;
}

static int b_length(lua_State *L)
{
	lua_pushinteger(L, (lua_Integer)checkbuf(L, 1)->len);
	return 1;
}

static int b_ensure_capacity(lua_State *L)
{
	lbuf_t *b = checkbuf(L, 1);
	lua_Integer n = luaL_checkinteger(L, 2);
	luaL_argcheck(L, n >= 0 && n <= (1 << 26), 2, "invalid size");
	if ((size_t)n > b->len) {
		uint8_t *d = lalloc(L, b->data, b->len, (size_t)n);
		if (!d)
			return luaL_error(L, "not enough memory");
		memset(d + b->len, 0, (size_t)n - b->len);
		b->data = d;
		b->len = (size_t)n;
	}
	lua_settop(L, 1);
	return 1;
}

static size_t checkrange(lua_State *L, lbuf_t *b, int idx, size_t n)
{
	lua_Integer off = luaL_checkinteger(L, idx);
	if (off < 0 || (size_t)off > b->len || n > b->len - (size_t)off)
		luaL_error(L, "buffer access out of range (offset %d, %d bytes, length %d)", (int)off,
			   (int)n, (int)b->len);
	return (size_t)off;
}

/* set_string(off, src[, src_off[, n]]): src is a string or a buffer. */
static int b_set_string(lua_State *L)
{
	lbuf_t *b = checkbuf(L, 1);
	size_t slen;
	const uint8_t *src = raat_checkbytes(L, 3, &slen);
	lua_Integer so = luaL_optinteger(L, 4, 0);
	luaL_argcheck(L, so >= 0 && (size_t)so <= slen, 4, "source offset out of range");
	lua_Integer n = luaL_optinteger(L, 5, (lua_Integer)(slen - (size_t)so));
	luaL_argcheck(L, n >= 0 && (size_t)n <= slen - (size_t)so, 5, "source length out of range");
	size_t off = checkrange(L, b, 2, (size_t)n);
	if (n)
		memmove(b->data + off, src + so, (size_t)n);
	return 0;
}

static int b_get_string(lua_State *L)
{
	lbuf_t *b = checkbuf(L, 1);
	lua_Integer off = luaL_optinteger(L, 2, 0);
	luaL_argcheck(L, off >= 0 && (size_t)off <= b->len, 2, "offset out of range");
	lua_Integer n = luaL_optinteger(L, 3, (lua_Integer)(b->len - (size_t)off));
	luaL_argcheck(L, n >= 0 && (size_t)n <= b->len - (size_t)off, 3, "length out of range");
	lua_pushlstring(L, (const char *)b->data + off, (size_t)n);
	return 1;
}

static int b_to_string(lua_State *L)
{
	lbuf_t *b = checkbuf(L, 1);
	lua_pushlstring(L, (const char *)b->data, b->len);
	return 1;
}

static int b_tostring(lua_State *L)
{
	lbuf_t *b = checkbuf(L, 1);
	lua_pushfstring(L, "buffer(%d)", (int)b->len);
	return 1;
}

static uint64_t rd(const uint8_t *p, int n, bool be)
{
	uint64_t v = 0;
	for (int i = 0; i < n; i++)
		v |= (uint64_t)p[be ? i : n - 1 - i] << (8 * (n - 1 - i));
	return v;
}

static void wr(uint8_t *p, int n, bool be, uint64_t v)
{
	for (int i = 0; i < n; i++)
		p[be ? n - 1 - i : i] = (uint8_t)(v >> (8 * i));
}

static int b_get_int(lua_State *L, int n, bool sgn, bool be)
{
	lbuf_t *b = checkbuf(L, 1);
	size_t off = checkrange(L, b, 2, (size_t)n);
	uint64_t v = rd(b->data + off, n, be);
	if (sgn && n < 8 && (v >> (8 * n - 1)) & 1)
		v |= ~(uint64_t)0 << (8 * n);
	lua_pushinteger(L, (lua_Integer)v);
	return 1;
}

static int b_set_int(lua_State *L, int n, bool be)
{
	lbuf_t *b = checkbuf(L, 1);
	size_t off = checkrange(L, b, 2, (size_t)n);
	wr(b->data + off, n, be, (uint64_t)raat_checkint64(L, 3));
	return 0;
}

static int b_get_f(lua_State *L, int n, bool be)
{
	lbuf_t *b = checkbuf(L, 1);
	size_t off = checkrange(L, b, 2, (size_t)n);
	uint64_t v = rd(b->data + off, n, be);
	if (n == 4) {
		uint32_t u = (uint32_t)v;
		float f;
		memcpy(&f, &u, 4);
		lua_pushnumber(L, f);
	} else {
		double d;
		memcpy(&d, &v, 8);
		lua_pushnumber(L, d);
	}
	return 1;
}

static int b_set_f(lua_State *L, int n, bool be)
{
	lbuf_t *b = checkbuf(L, 1);
	size_t off = checkrange(L, b, 2, (size_t)n);
	lua_Number x = luaL_checknumber(L, 3);
	uint64_t v;
	if (n == 4) {
		float f = (float)x;
		uint32_t u;
		memcpy(&u, &f, 4);
		v = u;
	} else {
		double d = x;
		memcpy(&v, &d, 8);
	}
	wr(b->data + off, n, be, v);
	return 0;
}

#define INTFNS(name, n, sgn)                                                              \
	static int g_##name##_le(lua_State *L) { return b_get_int(L, n, sgn, false); }      \
	static int g_##name##_be(lua_State *L) { return b_get_int(L, n, sgn, true); }       \
	static int s_##name##_le(lua_State *L) { return b_set_int(L, n, false); }           \
	static int s_##name##_be(lua_State *L) { return b_set_int(L, n, true); }
INTFNS(int8, 1, true)
INTFNS(uint8, 1, false)
INTFNS(int16, 2, true)
INTFNS(uint16, 2, false)
INTFNS(int32, 4, true)
INTFNS(uint32, 4, false)
INTFNS(int64, 8, true)
INTFNS(uint64, 8, false)
static int g_float32_le(lua_State *L) { return b_get_f(L, 4, false); }
static int g_float32_be(lua_State *L) { return b_get_f(L, 4, true); }
static int g_float64_le(lua_State *L) { return b_get_f(L, 8, false); }
static int g_float64_be(lua_State *L) { return b_get_f(L, 8, true); }
static int s_float32_le(lua_State *L) { return b_set_f(L, 4, false); }
static int s_float32_be(lua_State *L) { return b_set_f(L, 4, true); }
static int s_float64_le(lua_State *L) { return b_set_f(L, 8, false); }
static int s_float64_be(lua_State *L) { return b_set_f(L, 8, true); }

#define INTREG(name)                                                                   \
	{ "get_" #name "_le", g_##name##_le }, { "get_" #name "_be", g_##name##_be },        \
	{ "set_" #name "_le", s_##name##_le }, { "set_" #name "_be", s_##name##_be }

static const luaL_Reg buf_methods[] = {
	{ "length", b_length },
	{ "ensure_capacity", b_ensure_capacity },
	{ "set_string", b_set_string },
	{ "get_string", b_get_string },
	{ "to_string", b_to_string },
	/* single bytes have no byte order */
	{ "get_int8", g_int8_le },
	{ "get_uint8", g_uint8_le },
	{ "set_int8", s_int8_le },
	{ "set_uint8", s_uint8_le },
	INTREG(int8), INTREG(uint8), INTREG(int16), INTREG(uint16),
	INTREG(int32), INTREG(uint32), INTREG(int64), INTREG(uint64),
	{ "get_float32_le", g_float32_le }, { "get_float32_be", g_float32_be },
	{ "get_float64_le", g_float64_le }, { "get_float64_be", g_float64_be },
	{ "set_float32_le", s_float32_le }, { "set_float32_be", s_float32_be },
	{ "set_float64_le", s_float64_le }, { "set_float64_be", s_float64_be },
	{ NULL, NULL }
};

int luaopen_raat_buffer(lua_State *L)
{
	luaL_newmetatable(L, BUFFER_MT);
	luaL_newlib(L, buf_methods);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction(L, b_gc);
	lua_setfield(L, -2, "__gc");
	lua_pushcfunction(L, b_tostring);
	lua_setfield(L, -2, "__tostring");
	lua_pushcfunction(L, b_length);
	lua_setfield(L, -2, "__len");
	lua_pop(L, 1);

	lua_newtable(L);
	lua_pushcfunction(L, b_new);
	lua_setfield(L, -2, "new");
	uint16_t probe = 1;
	bool le = *(uint8_t *)&probe == 1;
	lua_pushboolean(L, le);
	lua_setfield(L, -2, "is_little_endian");
	lua_pushboolean(L, !le);
	lua_setfield(L, -2, "is_big_endian");
	lua_pushinteger(L, (lua_Integer)sizeof(void *));
	lua_setfield(L, -2, "pointer_size");
	lua_pushboolean(L, 1);
	lua_setfield(L, -2, "has_working_copy_method");
	return 1;
}
