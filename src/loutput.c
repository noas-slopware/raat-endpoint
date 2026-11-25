// SPDX-License-Identifier: GPL-3.0-or-later
/* raat.output: the output plugin surface the scripts drive (spec 7, 13.4.1,
 * 13.10). One active setup per device, identified by an integer token. */
#include "session.h"

#include <string.h>
#include <unistd.h>

#include "third_party/cjson/cJSON.h"

#define ST_INVALID_TOKEN "RAAT__OUTPUT_PLUGIN_STATUS_INVALID_TOKEN"

static int raise_str(lua_State *L, const char *msg)
{
	lua_pushstring(L, msg);
	return lua_error(L);
}

static mdev_t *check_token(lua_State *L, int idx)
{
	session_t *s = session_of(L);
	mdev_t *d = s->dev;
	int isint;
	lua_Integer tok = lua_tointegerx(L, idx, &isint);
	if (!isint || !d || !d->out || d->owner != s || tok != d->token)
		raise_str(L, ST_INVALID_TOKEN);
	return d;
}

static void on_out_event(io_watch_t *w, uint32_t ev)
{
	mdev_t *d = w->ud;
	(void)ev;
	uint64_t v;
	if (read(w->fd, &v, sizeof v) < 0) {
		/* spurious wakeup */
	}
	if (d->out && output_lost(d->out)) {
		LOGW("[output] %s went away", d->pd.id);
		dev_output_release(d, true, NULL);
		manager_refresh_devices();
	}
}

void dev_output_release(mdev_t *d, bool notify, const char *reason_json)
{
	if (!d->out)
		return;
	loop_io_del(&d->out_w);
	d->clock_carry = output_close(d->out);
	d->out = NULL;
	session_t *owner = d->owner;
	int ref = d->owner_cb_ref;
	d->owner = NULL;
	d->owner_cb_ref = LUA_NOREF;
	d->token = 0;
	if (!owner || owner->destroyed)
		return;
	if (notify)
		session_defer_output_lost(owner, ref, reason_json); /* takes the ref */
	else if (owner->L)
		luaL_unref(owner->L, LUA_REGISTRYINDEX, ref);
}

static int field_num(lua_State *L, int t, const char *k, bool *ok)
{
	lua_getfield(L, t, k);
	int isnum;
	lua_Number n = lua_tonumberx(L, -1, &isnum);
	lua_pop(L, 1);
	if (!isnum)
		*ok = false;
	return (int)n;
}

/* setup(format, {on_setup, on_output_lost}): asynchronous, like the reference. */
static int o_setup(lua_State *L)
{
	session_t *s = session_of(L);
	mdev_t *d = s->dev;
	luaL_checktype(L, 1, LUA_TTABLE);
	luaL_checktype(L, 2, LUA_TTABLE);
	lua_getfield(L, 1, "sample_type");
	char type[16];
	strlcpy0(type, lua_isstring(L, -1) ? lua_tostring(L, -1) : "", sizeof type);
	lua_pop(L, 1);
	/*
	 * sample_subtype: "none", "mqa" or "mqa_core", as RoonBridge accepts
	 * (anything else is an error there too). MQA content is ordinary PCM on
	 * the wire and is played unchanged, so the DAC can detect it itself; the
	 * Core sends it with mqa_original_sample_rate for MQA files.
	 */
	lua_getfield(L, 1, "sample_subtype");
	const char *sub = lua_isstring(L, -1) ? lua_tostring(L, -1) : NULL;
	bool plain = lua_isnil(L, -1) ||
		     (sub && (!strcmp(sub, "none") || !strcmp(sub, "mqa") || !strcmp(sub, "mqa_core")));
	if (sub && strcmp(sub, "none"))
		LOGI("[output] setup subtype %s", sub);
	lua_pop(L, 1);
	bool ok = true;
	int rate = field_num(L, 1, "sample_rate", &ok);
	int bits = field_num(L, 1, "bits_per_sample", &ok);
	int ch = field_num(L, 1, "channels", &ok);
	lua_pushvalue(L, 2);
	int cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);

	/* Only one setup at a time: a new one kicks off the old (spec 10 item 4). */
	if (d->out)
		dev_output_release(d, d->owner != s, NULL);

	const char *status = NULL;
	output_t *o = NULL;
	if (!ok || !plain || strcmp(type, "pcm")) {
		LOGW("[output] setup refused: type %s, plain %d, fields ok %d", type, plain, ok);
		status = "RAAT__OUTPUT_PLUGIN_STATUS_FORMAT_NOT_SUPPORTED"; /* PCM only, no DSD */
	}
	else
		o = output_open(&d->pd, rate, bits, ch, d->clock_carry, &status);
	if (!o) {
		LOGW("[output] setup %s %d/%d/%d failed: %s", type, rate, bits, ch, status);
		session_defer_setup_cb(s, cb_ref, false, 0, status);
		return 0;
	}
	d->out = o;
	d->token = ++d->next_token;
	d->owner = s;
	d->owner_cb_ref = cb_ref;
	loop_io_add(&d->out_w, output_event_fd(o), EPOLLIN, on_out_event, d);
	LOGI("[output] setup %s %d/%d/%d token=%d", type, rate, bits, ch, d->token);
	/* The signal path reaches the Core before the setup Success (capture3). */
	char *sp = output_signal_path_json(o);
	session_defer_output_message(s, sp);
	cJSON_free(sp);
	session_defer_setup_cb(s, cb_ref, true, d->token, NULL);
	return 0;
}

static int o_teardown(lua_State *L)
{
	mdev_t *d = check_token(L, 1);
	LOGI("[output] teardown token=%d", d->token);
	dev_output_release(d, false, NULL);
	return 0;
}

static int o_force_teardown(lua_State *L)
{
	session_t *s = session_of(L);
	const char *reason = luaL_optstring(L, 1, NULL);
	if (s->dev && s->dev->out && s->dev->owner == s)
		dev_output_release(s->dev, true, reason);
	return 0;
}

static int o_start(lua_State *L)
{
	mdev_t *d = check_token(L, 1);
	int64_t t = raat_checkint64(L, 2);
	int64_t ss = raat_checkint64(L, 3);
	stream_t *st = raat_checkstream(L, 4);
	const char *err = NULL;
	if (output_start(d->out, t, ss, st, &err) < 0)
		return raise_str(L, err);
	return 0;
}

static int o_stop(lua_State *L)
{
	mdev_t *d = check_token(L, 1);
	const char *err = NULL;
	if (output_stop(d->out, &err) < 0)
		return raise_str(L, err);
	return 0;
}

static int o_get_local_time(lua_State *L)
{
	mdev_t *d = check_token(L, 1);
	lua_pushinteger(L, (lua_Integer)output_local_time(d->out));
	return 1;
}

static int o_get_output_delay(lua_State *L)
{
	mdev_t *d = check_token(L, 1);
	lua_pushinteger(L, (lua_Integer)output_delay_ns(d->out));
	return 1;
}

static int o_set_remote_time(lua_State *L)
{
	mdev_t *d = check_token(L, 1);
	output_set_remote_time(d->out, luaL_checknumber(L, 2), lua_toboolean(L, 3));
	return 0;
}

static int o_send_message(lua_State *L)
{
	LOGD("[output] message from script (ignored by ALSA output): %s", luaL_optstring(L, 1, ""));
	return 0;
}

static void push_formats(lua_State *L, const pdev_t *pd)
{
	lua_createtable(L, pd->nfmts, 0);
	for (int i = 0; i < pd->nfmts; i++) {
		lua_createtable(L, 0, 4);
		lua_pushstring(L, "pcm");
		lua_setfield(L, -2, "sample_type");
		lua_pushinteger(L, pd->fmts[i].rate);
		lua_setfield(L, -2, "sample_rate");
		lua_pushinteger(L, pd->fmts[i].bits);
		lua_setfield(L, -2, "bits_per_sample");
		lua_pushinteger(L, pd->fmts[i].channels);
		lua_setfield(L, -2, "channels");
		lua_rawseti(L, -2, i + 1);
	}
}

static int o_refresh_supported_formats(lua_State *L)
{
	session_t *s = session_of(L);
	manager_refresh_devices();
	if (lua_getglobal(L, "raat") == LUA_TTABLE && lua_getfield(L, -1, "output") == LUA_TTABLE) {
		push_formats(L, &s->dev->pd);
		lua_setfield(L, -2, "supported_formats");
	}
	return 0;
}

static char *output_info_json(mdev_t *d)
{
	cJSON *root = cJSON_CreateObject();
	cJSON *ad = cJSON_AddObjectToObject(root, "alsa_device");
	cJSON_AddStringToObject(ad, "name", d->pd.name);
	cJSON_AddStringToObject(ad, "id", d->pd.card_id);
	cJSON_AddStringToObject(ad, "longname", d->pd.longname);
	/* RoonBridge fills "components" from snd_ctl_card_info_get_id (spec 14.9). */
	cJSON_AddStringToObject(ad, "components", d->pd.card_id);
	if (d->pd.usb_id[0])
		cJSON_AddStringToObject(ad, "usbid", d->pd.usb_id);
	cJSON_AddStringToObject(ad, "driver", d->pd.driver);
	cJSON_AddStringToObject(ad, "mixername", d->pd.mixername);
	cJSON *out = d->config ? cJSON_GetObjectItemCaseSensitive(d->config, "output") : NULL;
	if (out)
		cJSON_AddItemToObject(root, "config", cJSON_Duplicate(out, 1));
	char *s = cJSON_PrintUnformatted(root);
	cJSON_Delete(root);
	return s;
}

void raat_push_output(lua_State *L, session_t *s)
{
	static const luaL_Reg fns[] = {
		{ "setup", o_setup },
		{ "teardown", o_teardown },
		{ "force_teardown", o_force_teardown },
		{ "start", o_start },
		{ "stop", o_stop },
		{ "get_local_time", o_get_local_time },
		{ "get_output_delay", o_get_output_delay },
		{ "set_remote_time", o_set_remote_time },
		{ "send_message", o_send_message },
		{ "refresh_supported_formats", o_refresh_supported_formats },
		{ NULL, NULL }
	};
	luaL_newlib(L, fns);
	lua_pushboolean(L, 1);
	lua_setfield(L, -2, "is_supported");
	lua_pushboolean(L, 1);
	lua_setfield(L, -2, "is_refresh_supported_formats_supported");
	lua_pushboolean(L, 1);
	lua_setfield(L, -2, "is_get_output_delay_supported");
	char *info = output_info_json(s->dev);
	lua_pushstring(L, info);
	cJSON_free(info);
	lua_setfield(L, -2, "info");
	push_formats(L, &s->dev->pd);
	lua_setfield(L, -2, "supported_formats");
	lua_newtable(L);
	lua_pushvalue(L, -1);
	s->out_msg_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	lua_setfield(L, -2, "message_handlers");
}
