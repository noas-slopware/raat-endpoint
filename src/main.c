// SPDX-License-Identifier: GPL-3.0-or-later
/* raat-endpoint: a native RAAT (Roon Ready) endpoint for Linux. */
#include "common.h"
#include "device.h"
#include "loop.h"
#include "platform.h"
#include "raat_endpoint.h"
#include "session.h"

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <unistd.h>

static void usage(void)
{
	fprintf(stderr,
		"usage: raat-endpoint [options]\n"
		"  -d, --data-dir DIR         persistent state (default /var/lib/raat-endpoint or XDG)\n"
		"  -b, --bind ADDR            IPv4 address for every listener, including the\n"
		"                             script's audio and clock sockets (default 0.0.0.0)\n"
		"  -p, --manager-port N       manager TCP port, 0 = ephemeral (default: 9200-9250)\n"
		"      --sood-port N          SOOD UDP port, 0 = ephemeral (default 9003)\n"
		"      --no-sood              do not answer discovery\n"
		"      --no-multicast         do not join 239.255.90.90 (answer unicast only)\n"
		"      --pipewire             use PipeWire backend (user process mode; ALSA is default)\n"
		"      --raatflector H[:P]    connect to RAATflector server for L3 VPN discovery\n"
		"      --raatflector-token S  shared auth token for RAATflector server\n"
		"      --fixture FILE         devices and uname from FILE instead of ALSA (tests)\n"
		"  -n, --name NAME            machine_name (default: host name)\n"
		"      --vendor V, --model M  identity reported in discovery (default: null)\n"
		"      --raat-version V       raat_version to advertise (default 1.1.38)\n"
		"      --alsa-buffer-ms N     device buffer, two periods (default 40)\n"
		"      --null-sink DIR        with --fixture: dump what the null output plays\n"
		"      --stream-max-mb N      cap for one stream ring buffer (default 32)\n"
		"      --lua-mem-mb N         Lua heap limit per session (default 24)\n"
		"      --dump-lua-api         print the Lua API surface and exit\n"
		"  -v                         more logging (twice for script trace)\n"
		"  -q                         warnings and errors only\n");
}

static int sig_fd = -1;
static io_watch_t sig_w = { .fd = -1 };

static void on_signal(io_watch_t *w, uint32_t ev)
{
	(void)ev;
	struct signalfd_siginfo si;
	while (read(w->fd, &si, sizeof si) == sizeof si)
		LOGI("signal %u: shutting down", si.ssi_signo);
	raat_endpoint_stop();
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
	raat_endpoint_config_t cfg;
	raat_endpoint_config_init(&cfg);
	bool dump = false;

	enum {
		O_SOOD_PORT = 256, O_NO_SOOD, O_NO_MCAST, O_FIXTURE, O_VENDOR, O_MODEL,
		O_RAATV, O_ABUF, O_SMAX, O_LMEM, O_DUMP, O_SINK, O_PW, O_RF, O_RFTOK
	};
	static const struct option lo[] = {
		{ "data-dir", required_argument, 0, 'd' },
		{ "bind", required_argument, 0, 'b' },
		{ "manager-port", required_argument, 0, 'p' },
		{ "sood-port", required_argument, 0, O_SOOD_PORT },
		{ "no-sood", no_argument, 0, O_NO_SOOD },
		{ "no-multicast", no_argument, 0, O_NO_MCAST },
		{ "pipewire", no_argument, 0, O_PW },
		{ "raatflector", required_argument, 0, O_RF },
		{ "raatflector-token", required_argument, 0, O_RFTOK },
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
		case 'd': cfg.data_dir = optarg; break;
		case 'b': cfg.bind_addr = optarg; break;
		case 'p': cfg.manager_port = atoi(optarg); break;
		case O_SOOD_PORT: cfg.sood_port = atoi(optarg); break;
		case O_NO_SOOD: cfg.no_sood = true; break;
		case O_NO_MCAST: cfg.no_multicast = true; break;
		case O_PW: cfg.backend = RAAT_BACKEND_PIPEWIRE; break;
		case O_RF: cfg.raatflector_server = optarg; break;
		case O_RFTOK: cfg.raatflector_token = optarg; break;
		case O_FIXTURE: cfg.fixture_path = optarg; break;
		case 'n': cfg.name = optarg; break;
		case O_VENDOR: cfg.vendor = optarg; break;
		case O_MODEL: cfg.model = optarg; break;
		case O_RAATV: cfg.raat_version = optarg; break;
		case O_ABUF: cfg.alsa_buffer_ms = atoi(optarg); break;
		case O_SMAX: cfg.stream_max_bytes = (size_t)atoi(optarg) << 20; break;
		case O_LMEM: cfg.lua_mem_limit = (size_t)atoi(optarg) << 20; break;
		case O_DUMP: dump = true; break;
		case O_SINK: cfg.null_sink_dir = optarg; break;
		case 'v': verbose++; break;
		case 'q': cfg.log_level = RAAT_LOG_WARN; break;
		default: usage(); return c == 'h' ? 0 : 2;
		}
	}
	if (verbose == 1)
		cfg.log_level = RAAT_LOG_DEBUG;
	else if (verbose > 1)
		cfg.log_level = RAAT_LOG_TRACE;

	signal(SIGPIPE, SIG_IGN);
	if (dump) {
		if (loop_init() < 0) {
			perror("epoll");
			return 1;
		}
		platform_init(NULL, false);
		int rc = dump_api();
		platform_shutdown();
		loop_shutdown();
		return rc;
	}

	if (raat_endpoint_init(&cfg) < 0)
		return 1;

	sigset_t ss;
	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGTERM);
	sigprocmask(SIG_BLOCK, &ss, NULL);
	sig_fd = signalfd(-1, &ss, SFD_NONBLOCK | SFD_CLOEXEC);
	loop_io_add(&sig_w, sig_fd, EPOLLIN, on_signal, NULL);

	printf("READY manager_port=%d sood_port=%d\n", raat_endpoint_manager_port(),
	       raat_endpoint_sood_port());
	fflush(stdout);

	raat_endpoint_run();

	loop_io_del(&sig_w);
	if (sig_fd >= 0) {
		close(sig_fd);
		sig_fd = -1;
	}
	raat_endpoint_shutdown();
	return 0;
}
