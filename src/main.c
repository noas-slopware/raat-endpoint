/* raat-endpoint: a native RAAT (Roon Ready) endpoint for small Linux boxes. */
#include "common.h"
#include "device.h"
#include "loop.h"
#include "manager.h"
#include "output.h"
#include "platform.h"
#include "session.h"
#include "sood.h"
#include "stream.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "third_party/cjson/cJSON.h"

static void usage(void)
{
	fprintf(stderr,
		"usage: raat-endpoint [options]\n"
		"  -d, --data-dir DIR      persistent state (default /var/lib/raat-endpoint)\n"
		"  -b, --bind ADDR         IPv4 address for every listener, including the\n"
		"                          script's audio and clock sockets (default 0.0.0.0)\n"
		"  -p, --manager-port N    manager TCP port, 0 = ephemeral (default: first free\n"
		"                          in 9200-9250)\n"
		"      --sood-port N       SOOD UDP port (default 9003)\n"
		"      --no-sood           do not answer discovery\n"
		"      --no-multicast      do not join 239.255.90.90 (answer unicast only)\n"
		"      --fixture FILE      devices and uname from FILE instead of ALSA (tests)\n"
		"  -n, --name NAME         machine_name (default: host name)\n"
		"      --vendor V, --model M  identity reported in discovery (default: null)\n"
		"      --raat-version V    raat_version to advertise (default 1.1.38)\n"
		"      --alsa-buffer-ms N  device buffer, two periods (default 40)\n"
		"      --null-sink DIR     with --fixture: dump what the null output plays\n"
		"      --stream-max-mb N   cap for one stream ring buffer (default 32)\n"
		"      --lua-mem-mb N      Lua heap limit per session (default 24)\n"
		"      --dump-lua-api      print the Lua API surface and exit\n"
		"  -v                      more logging (twice for script trace)\n"
		"  -q                      warnings and errors only\n");
}

static int sig_fd = -1;
static io_watch_t sig_w;

static void on_signal(io_watch_t *w, uint32_t ev)
{
	(void)ev;
	struct signalfd_siginfo si;
	while (read(w->fd, &si, sizeof si) == sizeof si)
		LOGI("signal %u: shutting down", si.ssi_signo);
	loop_stop();
}

/*
 * machine_id is part of the endpoint's identity for the Core, like unique_id:
 * the Core ties the RAAT server (and so its enabled devices) to the pair.
 * Persist it in <data-dir>/Settings/machine_id; when taking over from
 * RoonBridge, seed that file with RoonBridge's value (its RAATServer log
 * prints it), or the Core sees a new machine and leaves the device disabled.
 */
static void machine_id_derive(char out[37], const char *fallback);

static void machine_id(char out[37], const char *data_dir, const char *fallback)
{
	char path[1100];
	snprintf(path, sizeof path, "%s/Settings/machine_id", data_dir);
	char *m = file_read(path, NULL);
	if (m) {
		str_rtrim(m);
		if (strlen(m) == 36) {
			strlcpy0(out, m, 37);
			free(m);
			return;
		}
		free(m);
	}
	machine_id_derive(out, fallback);
	if (file_write(path, out, 36) < 0)
		LOGW("cannot persist machine_id: %s", strerror(errno));
}

static void machine_id_derive(char out[37], const char *fallback)
{
	char *m = file_read("/etc/machine-id", NULL);
	if (m) {
		str_rtrim(m);
		if (strlen(m) == 32) {
			snprintf(out, 37, "%.8s-%.4s-%.4s-%.4s-%.12s", m, m + 8, m + 12, m + 16, m + 20);
			free(m);
			return;
		}
		free(m);
	}
	strlcpy0(out, fallback, 37);
}

/* Prints every name reachable from the script-facing globals and the handle
 * metatables, so tests can diff it against what the Core's scripts call. */
static const char dump_lua[] =
	"local out = {}\n"
	"local function walk(prefix, t, depth)\n"
	"  for k, v in pairs(t) do\n"
	"    local name = prefix .. '.' .. tostring(k)\n"
	"    out[#out + 1] = name .. ':' .. type(v)\n"
	"    if type(v) == 'table' and depth < 2 then walk(name, v, depth + 1) end\n"
	"  end\n"
	"end\n"
	"for _, g in ipairs({'raat', 'uv', 'buffer', 'stream', 'codec'}) do walk(g, _G[g], 0) end\n"
	"local reg = debug.getregistry()\n"
	"for _, mt in ipairs({'RAAT__ScriptBuffer', 'RAAT__Stream', 'uv_tcp', 'uv_udp', 'uv_timer'}) do\n"
	"  walk('method:' .. mt, reg[mt].__index, 0)\n"
	"end\n"
	"table.sort(out)\n"
	"for _, n in ipairs(out) do print(n) end\n";

static int dump_api(void)
{
	mdev_t d;
	memset(&d, 0, sizeof d);
	strlcpy0(d.pd.id, "hw:CARD=Dump,DEV=0", sizeof d.pd.id);
	strlcpy0(d.unique_id, "00000000-0000-4000-8000-000000000000", sizeof d.unique_id);
	d.owner_cb_ref = LUA_NOREF;
	session_t *s = session_new(&d, NULL);
	if (!s)
		return 1;
	if (luaL_loadbuffer(s->L, dump_lua, sizeof dump_lua - 1, "=dump") != LUA_OK ||
	    lua_pcall(s->L, 0, 0, 0) != LUA_OK) {
		fprintf(stderr, "dump: %s\n", lua_tostring(s->L, -1));
		return 1;
	}
	fflush(stdout);
	session_destroy(s);
	return 0;
}

int main(int argc, char **argv)
{
	const char *data_dir = "/var/lib/raat-endpoint", *bind_addr = "0.0.0.0", *fixture = NULL;
	const char *name = NULL, *vendor = NULL, *model = NULL, *raat_version = "1.1.38";
	int mport = -1, sport = 9003;
	bool no_sood = false, no_mcast = false, dump = false;
	enum { O_SOOD_PORT = 256, O_NO_SOOD, O_NO_MCAST, O_FIXTURE, O_VENDOR, O_MODEL, O_RAATV,
	       O_ABUF, O_SMAX, O_LMEM, O_DUMP, O_SINK };
	static const struct option lo[] = {
		{ "data-dir", required_argument, 0, 'd' },
		{ "bind", required_argument, 0, 'b' },
		{ "manager-port", required_argument, 0, 'p' },
		{ "sood-port", required_argument, 0, O_SOOD_PORT },
		{ "no-sood", no_argument, 0, O_NO_SOOD },
		{ "no-multicast", no_argument, 0, O_NO_MCAST },
		{ "fixture", required_argument, 0, O_FIXTURE },
		{ "name", required_argument, 0, 'n' },
		{ "vendor", required_argument, 0, O_VENDOR },
		{ "model", required_argument, 0, O_MODEL },
		{ "raat-version", required_argument, 0, O_RAATV },
		{ "alsa-buffer-ms", required_argument, 0, O_ABUF },
		{ "stream-max-mb", required_argument, 0, O_SMAX },
		{ "lua-mem-mb", required_argument, 0, O_LMEM },
		{ "dump-lua-api", no_argument, 0, O_DUMP },
		{ "null-sink", required_argument, 0, O_SINK },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};
	int c, verbose = 0;
	while ((c = getopt_long(argc, argv, "d:b:p:n:vqh", lo, NULL)) != -1) {
		switch (c) {
		case 'd': data_dir = optarg; break;
		case 'b': bind_addr = optarg; break;
		case 'p': mport = atoi(optarg); break;
		case O_SOOD_PORT: sport = atoi(optarg); break;
		case O_NO_SOOD: no_sood = true; break;
		case O_NO_MCAST: no_mcast = true; break;
		case O_FIXTURE: fixture = optarg; break;
		case 'n': name = optarg; break;
		case O_VENDOR: vendor = optarg; break;
		case O_MODEL: model = optarg; break;
		case O_RAATV: raat_version = optarg; break;
		case O_ABUF: g_alsa_buffer_ms = atoi(optarg); break;
		case O_SMAX: g_stream_max_bytes = (size_t)atoi(optarg) << 20; break;
		case O_LMEM: g_lua_mem_limit = (size_t)atoi(optarg) << 20; break;
		case O_DUMP: dump = true; break;
		case O_SINK: g_null_sink_dir = optarg; break;
		case 'v': verbose++; break;
		case 'q': g_log_level = LOG_WARN; break;
		default: usage(); return c == 'h' ? 0 : 2;
		}
	}
	if (verbose == 1)
		g_log_level = LOG_DEBUG;
	else if (verbose > 1)
		g_log_level = LOG_TRACE;
	if (g_alsa_buffer_ms < 20)
		g_alsa_buffer_ms = 20;
	if (strcmp(bind_addr, "0.0.0.0"))
		g_bind_override = xstrdup(bind_addr);

	signal(SIGPIPE, SIG_IGN);
	if (loop_init() < 0) {
		perror("epoll");
		return 1;
	}
	if (dump) {
		platform_init(NULL);
		return dump_api();
	}
	if (platform_init(fixture) < 0)
		return 1;

	sigset_t ss;
	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGTERM);
	sigprocmask(SIG_BLOCK, &ss, NULL);
	sig_fd = signalfd(-1, &ss, SFD_NONBLOCK | SFD_CLOEXEC);
	loop_io_add(&sig_w, sig_fd, EPOLLIN, on_signal, NULL);

	struct manager_opts mo = { data_dir, bind_addr, mport, raat_version };
	if (manager_start(&mo) < 0)
		return 1;

	if (!no_sood) {
		char host[256] = "";
		if (name)
			strlcpy0(host, name, sizeof host);
		else {
			gethostname(host, sizeof host - 1);
			char *dot = strchr(host, '.');
			if (dot)
				*dot = 0;
		}
		const struct platform_uname *u = platform_uname();
		char osv[160], mid[37], tcp_port[16];
		snprintf(osv, sizeof osv, "%s %s", u->sysname, u->release);
		machine_id(mid, data_dir, manager_unique_id());
		snprintf(tcp_port, sizeof tcp_port, "%d", manager_port());
		/* spec 4, 11.2; no code_signing_keys (spec 13.2) */
		struct sood_kv kv[] = {
			{ "service_id", RAAT_SERVICE_ID },
			{ "tcp_port", tcp_port },
			{ "unique_id", manager_unique_id() },
			{ "machine_id", mid },
			{ "machine_name", host },
			{ "os_version", osv },
			/* vendor/model: left out when unset, as RoonBridge does */
			{ vendor ? "vendor" : NULL, vendor },
			{ model ? "model" : NULL, model },
			{ "raat_version", raat_version },
			{ "protocol_version", "1" },
			{ "config_version", "1" },
			{ "is_dev", "0" },
			{ NULL, NULL },
		};
		/* drop the unset entries (sood_start stops at the first NULL key) */
		size_t nk = 0;
		for (size_t i = 0; i < sizeof kv / sizeof kv[0] - 1; i++)
			if (kv[i].key)
				kv[nk++] = kv[i];
		kv[nk] = (struct sood_kv){ NULL, NULL };
		if (sood_start(bind_addr, sport, !no_mcast, kv) < 0)
			LOGW("[sood] discovery disabled");
	}

	printf("READY manager_port=%d sood_port=%d\n", manager_port(), no_sood ? 0 : sood_port());
	fflush(stdout);
	loop_run();

	manager_shutdown();
	sood_stop();
	loop_run_pending();
	return 0;
}
