// SPDX-License-Identifier: GPL-3.0-or-later
/* raatflector: LAN-to-VPN SOOD reflector server.
 * Listens for Roon Core SOOD queries on LAN multicast (239.255.90.90:9003) and
 * forwards them over TCP to one or more remote raat-endpoint clients connected
 * over an L3 VPN (e.g. Tailscale). Audio, clock, and control connections stay
 * direct peer-to-peer over the VPN; nothing leaves LAN/VPN. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../src/raatflector_proto.h"

#define SOOD_GROUP "239.255.90.90"
#define SOOD_DEFAULT_PORT 9003
#define RAAT_SERVICE_ID "d7634b85-8190-470f-aa51-6cb5538dc1b9"
#define MAX_CLIENTS 64
#define RX_CAP (RAATFLECTOR_HDR_LEN + RAATFLECTOR_MAX_PAYLOAD)
#define TX_CAP 16384

static int log_level = 1; /* 0=quiet, 1=info, 2=debug */
#define LOGI(...) do { if (log_level >= 1) { fprintf(stderr, "[info] "); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)
#define LOGD(...) do { if (log_level >= 2) { fprintf(stderr, "[debug] "); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)
#define LOGW(...) do { fprintf(stderr, "[warning] "); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)
#define LOGE(...) do { fprintf(stderr, "[error] "); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)

typedef struct {
	int fd;
	bool authed;
	char peer[64];
	int64_t last_seen_ms;
	uint8_t rx[RX_CAP];
	size_t rx_n;
	uint8_t tx[TX_CAP];
	size_t tx_off, tx_n;
} client_t;

static int epfd = -1, sood_fd = -1, listen_fd = -1, nl_fd = -1, sig_fd = -1;
static client_t clients[MAX_CLIENTS];
static const char *g_token;
static struct in_addr g_core_override;
static bool g_have_override;
static struct in_addr g_last_core;
static bool g_have_last_core;

static int64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

#define DEDUP_N 64
static struct {
	char tid[64];
	int64_t at_ms;
} g_seen[DEDUP_N];
static int g_seen_next;

static bool seen_tid(const char *tid)
{
	if (!tid[0])
		return false;
	int64_t now = now_ms();
	for (int i = 0; i < DEDUP_N; i++) {
		if (g_seen[i].at_ms && now - g_seen[i].at_ms < 10000 &&
		    strcasecmp(g_seen[i].tid, tid) == 0)
			return true;
	}
	snprintf(g_seen[g_seen_next].tid, sizeof g_seen[0].tid, "%s", tid);
	g_seen[g_seen_next].at_ms = now;
	g_seen_next = (g_seen_next + 1) % DEDUP_N;
	return false;
}

static bool ct_eq(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
	if (alen != blen)
		return false;
	uint8_t diff = 0;
	for (size_t i = 0; i < alen; i++)
		diff |= a[i] ^ b[i];
	return diff == 0;
}

static void join_multicast_all(int fd)
{
	struct ifaddrs *ifa, *i;
	if (getifaddrs(&ifa) < 0)
		return;
	for (i = ifa; i; i = i->ifa_next) {
		if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET || !(i->ifa_flags & IFF_UP) ||
		    !(i->ifa_flags & IFF_MULTICAST))
			continue;
		struct ip_mreq mr;
		inet_pton(AF_INET, SOOD_GROUP, &mr.imr_multiaddr);
		mr.imr_interface = ((struct sockaddr_in *)i->ifa_addr)->sin_addr;
		if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof mr) == 0)
			LOGD("joined %s on %s", SOOD_GROUP, i->ifa_name);
	}
	freeifaddrs(ifa);
}

static void client_mod_epoll(client_t *c)
{
	uint32_t ev = EPOLLIN | (c->tx_off < c->tx_n ? EPOLLOUT : 0);
	struct epoll_event ee = { .events = ev, .data.ptr = c };
	epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ee);
}

static void client_close(client_t *c)
{
	if (c->fd < 0)
		return;
	LOGI("client %s disconnected", c->peer);
	epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
	close(c->fd);
	c->fd = -1;
	c->authed = false;
	c->rx_n = c->tx_off = c->tx_n = 0;
}

static bool client_send(client_t *c, uint8_t type, const uint8_t *payload, size_t len)
{
	if (c->fd < 0 || len > RAATFLECTOR_MAX_PAYLOAD)
		return false;
	if (c->tx_off > 0) {
		size_t rem = c->tx_n - c->tx_off;
		if (rem)
			memmove(c->tx, c->tx + c->tx_off, rem);
		c->tx_off = 0;
		c->tx_n = rem;
	}
	if (c->tx_n + RAATFLECTOR_HDR_LEN + len > TX_CAP) {
		LOGW("client %s tx overflow, dropping", c->peer);
		client_close(c);
		return false;
	}
	rf_put_be32(c->tx + c->tx_n, (uint32_t)len);
	c->tx[c->tx_n + 4] = type;
	if (len)
		memcpy(c->tx + c->tx_n + RAATFLECTOR_HDR_LEN, payload, len);
	c->tx_n += RAATFLECTOR_HDR_LEN + len;
	client_mod_epoll(c);
	return true;
}

static void client_handle_frame(client_t *c, uint8_t type, const uint8_t *p, size_t len)
{
	c->last_seen_ms = now_ms();
	if (!c->authed) {
		if (type != RF_MSG_HELLO || len < 3) {
			const char *msg = "expected HELLO";
			client_send(c, RF_MSG_HELLO_ERR, (const uint8_t *)msg, strlen(msg));
			client_close(c);
			return;
		}
		if (p[0] != RAATFLECTOR_PROTO_VER) {
			const char *msg = "unsupported version";
			client_send(c, RF_MSG_HELLO_ERR, (const uint8_t *)msg, strlen(msg));
			client_close(c);
			return;
		}
		uint16_t tlen = rf_get_be16(p + 1);
		if ((size_t)3 + tlen > len) {
			client_close(c);
			return;
		}
		if (g_token && !ct_eq(p + 3, tlen, (const uint8_t *)g_token, strlen(g_token))) {
			LOGW("client %s bad token", c->peer);
			const char *msg = "bad token";
			client_send(c, RF_MSG_HELLO_ERR, (const uint8_t *)msg, strlen(msg));
			client_close(c);
			return;
		}
		c->authed = true;
		LOGI("client %s authenticated", c->peer);
		if (g_have_override || g_have_last_core) {
			uint8_t ok[7];
			struct in_addr ca = g_have_override ? g_core_override : g_last_core;
			memcpy(ok, &ca.s_addr, 4);
			rf_put_be16(ok + 4, SOOD_DEFAULT_PORT);
			ok[6] = g_have_override ? RF_FLAG_OVERRIDE_ADDR : 0;
			client_send(c, RF_MSG_HELLO_OK, ok, sizeof ok);
		} else {
			client_send(c, RF_MSG_HELLO_OK, NULL, 0);
		}
		return;
	}
	if (type == RF_MSG_PING)
		client_send(c, RF_MSG_PONG, NULL, 0);
}

static void client_io(client_t *c, uint32_t ev)
{
	if (ev & (EPOLLERR | EPOLLHUP)) {
		client_close(c);
		return;
	}
	if (ev & EPOLLOUT) {
		while (c->tx_off < c->tx_n) {
			ssize_t n = send(c->fd, c->tx + c->tx_off, c->tx_n - c->tx_off, MSG_NOSIGNAL);
			if (n < 0) {
				if (errno == EAGAIN || errno == EINTR)
					break;
				client_close(c);
				return;
			}
			c->tx_off += (size_t)n;
		}
		if (c->tx_off == c->tx_n) {
			c->tx_off = c->tx_n = 0;
			client_mod_epoll(c);
		}
	}
	if (ev & EPOLLIN) {
		for (;;) {
			ssize_t n = recv(c->fd, c->rx + c->rx_n, sizeof c->rx - c->rx_n, 0);
			if (n < 0) {
				if (errno == EAGAIN || errno == EINTR)
					break;
				client_close(c);
				return;
			}
			if (n == 0) {
				client_close(c);
				return;
			}
			c->rx_n += (size_t)n;
			while (c->rx_n >= RAATFLECTOR_HDR_LEN) {
				uint32_t plen = rf_get_be32(c->rx);
				uint8_t type = c->rx[4];
				if (plen > RAATFLECTOR_MAX_PAYLOAD) {
					client_close(c);
					return;
				}
				size_t total = RAATFLECTOR_HDR_LEN + plen;
				if (c->rx_n < total)
					break;
				client_handle_frame(c, type, c->rx + RAATFLECTOR_HDR_LEN, plen);
				if (c->fd < 0)
					return;
				if (c->rx_n > total)
					memmove(c->rx, c->rx + total, c->rx_n - total);
				c->rx_n -= total;
			}
		}
	}
}

/* Returns true if pkt is a Core SOOD 'Q' query for RAAT_SERVICE_ID (and not an
 * endpoint's own announce, which carries tcp_port). Extracts _tid into tid_out. */
static bool is_core_raat_query(const uint8_t *p, size_t n, char *tid_out, size_t tid_cap)
{
	if (tid_cap)
		tid_out[0] = 0;
	if (n < 6 || memcmp(p, "SOOD", 4) || p[4] != 2 || p[5] != 'Q')
		return false;
	bool match_svc = false;
	size_t off = 6;
	while (off < n) {
		size_t kl = p[off++];
		if (kl == 0 || off + kl + 2 > n)
			return false;
		const char *k = (const char *)p + off;
		off += kl;
		size_t vl = (size_t)p[off] << 8 | p[off + 1];
		off += 2;
		bool null = vl == 0xFFFF;
		if (null)
			vl = 0;
		if (off + vl > n)
			return false;
		const char *v = (const char *)p + off;
		off += vl;
		if (kl == 8 && !memcmp(k, "tcp_port", 8))
			return false; /* endpoint announce, not a Core query */
		if (kl == 4 && !memcmp(k, "_tid", 4) && !null && vl < tid_cap) {
			memcpy(tid_out, v, vl);
			tid_out[vl] = 0;
		}
		if (kl == 10 && !memcmp(k, "service_id", 10) && !null &&
		    vl == strlen(RAAT_SERVICE_ID) && !strncasecmp(v, RAAT_SERVICE_ID, vl))
			match_svc = true;
	}
	return match_svc;
}

static void handle_sood(void)
{
	uint8_t buf[2048];
	for (int i = 0; i < 64; i++) {
		struct sockaddr_in src;
		socklen_t sl = sizeof src;
		ssize_t n = recvfrom(sood_fd, buf, sizeof buf, 0, (struct sockaddr *)&src, &sl);
		if (n < 0)
			return;
		char tid[64];
		if (!is_core_raat_query(buf, (size_t)n, tid, sizeof tid))
			continue;
		if (seen_tid(tid))
			continue;

		g_last_core = src.sin_addr;
		g_have_last_core = true;

		struct in_addr dst_ip = g_have_override ? g_core_override : src.sin_addr;
		uint8_t frame[7 + sizeof buf];
		if ((size_t)n + 7 > RAATFLECTOR_MAX_PAYLOAD)
			continue;
		memcpy(frame, &dst_ip.s_addr, 4);
		rf_put_be16(frame + 4, ntohs(src.sin_port));
		frame[6] = g_have_override ? RF_FLAG_OVERRIDE_ADDR : 0;
		memcpy(frame + 7, buf, (size_t)n);

		char ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &dst_ip, ip, sizeof ip);
		int sent = 0;
		for (int j = 0; j < MAX_CLIENTS; j++) {
			if (clients[j].fd >= 0 && clients[j].authed) {
				if (client_send(&clients[j], RF_MSG_SOOD_QUERY, frame, 7 + (size_t)n))
					sent++;
			}
		}
		LOGD("reflected SOOD query from %s:%d to %d clients", ip, ntohs(src.sin_port), sent);
	}
}

static void handle_accept(void)
{
	for (;;) {
		struct sockaddr_in sa;
		socklen_t sl = sizeof sa;
		int fd = accept4(listen_fd, (struct sockaddr *)&sa, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno != EAGAIN && errno != EINTR)
				LOGW("accept: %s", strerror(errno));
			return;
		}
		int slot = -1;
		for (int i = 0; i < MAX_CLIENTS; i++) {
			if (clients[i].fd < 0) {
				slot = i;
				break;
			}
		}
		if (slot < 0) {
			LOGW("too many clients, rejecting");
			close(fd);
			continue;
		}
		int one = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
		client_t *c = &clients[slot];
		memset(c, 0, sizeof *c);
		c->fd = fd;
		c->last_seen_ms = now_ms();
		char ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &sa.sin_addr, ip, sizeof ip);
		snprintf(c->peer, sizeof c->peer, "%s:%d", ip, ntohs(sa.sin_port));
		struct epoll_event ee = { .events = EPOLLIN, .data.ptr = c };
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ee) < 0) {
			close(fd);
			c->fd = -1;
			continue;
		}
		LOGI("client %s connected", c->peer);
	}
}

static void usage(void)
{
	fprintf(stderr,
		"usage: raatflector [options]\n"
		"  -b, --bind ADDR         TCP bind address for clients (default 0.0.0.0)\n"
		"  -p, --port N            TCP port for clients, 0 = ephemeral (default 9004)\n"
		"      --sood-bind ADDR    UDP bind address for LAN SOOD (default 0.0.0.0)\n"
		"      --sood-port N       UDP port for LAN SOOD (default 9003)\n"
		"      --no-multicast      do not join 239.255.90.90 (tests)\n"
		"      --core-ip IP        IPv4 address clients reply to (e.g. Core Tailscale IP)\n"
		"      --token SECRET      require shared token from clients\n"
		"  -v                      verbose logging\n"
		"  -q                      warnings and errors only\n");
}

int main(int argc, char **argv)
{
	const char *bind_addr = "0.0.0.0", *sood_bind = "0.0.0.0", *core_ip = NULL;
	int port = RAATFLECTOR_DEFAULT_PORT, sood_port = SOOD_DEFAULT_PORT;
	bool no_mcast = false;

	enum { O_SBIND = 256, O_SPORT, O_NOMCAST, O_COREIP, O_TOKEN };
	static const struct option lo[] = {
		{ "bind", required_argument, 0, 'b' },
		{ "port", required_argument, 0, 'p' },
		{ "sood-bind", required_argument, 0, O_SBIND },
		{ "sood-port", required_argument, 0, O_SPORT },
		{ "no-multicast", no_argument, 0, O_NOMCAST },
		{ "core-ip", required_argument, 0, O_COREIP },
		{ "token", required_argument, 0, O_TOKEN },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};
	int c;
	while ((c = getopt_long(argc, argv, "b:p:vqh", lo, NULL)) != -1) {
		switch (c) {
		case 'b': bind_addr = optarg; break;
		case 'p': port = atoi(optarg); break;
		case O_SBIND: sood_bind = optarg; break;
		case O_SPORT: sood_port = atoi(optarg); break;
		case O_NOMCAST: no_mcast = true; break;
		case O_COREIP: core_ip = optarg; break;
		case O_TOKEN: g_token = optarg; break;
		case 'v': log_level = 2; break;
		case 'q': log_level = 0; break;
		default: usage(); return c == 'h' ? 0 : 2;
		}
	}
	if (core_ip) {
		if (inet_pton(AF_INET, core_ip, &g_core_override) != 1) {
			LOGE("invalid --core-ip: %s", core_ip);
			return 2;
		}
		g_have_override = true;
	}

	signal(SIGPIPE, SIG_IGN);
	for (int i = 0; i < MAX_CLIENTS; i++)
		clients[i].fd = -1;

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0) {
		perror("epoll_create1");
		return 1;
	}

	/* SOOD UDP listener */
	sood_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (sood_fd < 0) {
		perror("sood socket");
		return 1;
	}
	int one = 1;
	setsockopt(sood_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	struct sockaddr_in ssa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)sood_port) };
	if (inet_pton(AF_INET, sood_bind, &ssa.sin_addr) != 1 ||
	    bind(sood_fd, (struct sockaddr *)&ssa, sizeof ssa) < 0) {
		LOGE("sood bind %s:%d: %s", sood_bind, sood_port, strerror(errno));
		return 1;
	}
	socklen_t sl = sizeof ssa;
	getsockname(sood_fd, (struct sockaddr *)&ssa, &sl);
	sood_port = ntohs(ssa.sin_port);
	if (!no_mcast) {
		join_multicast_all(sood_fd);
		nl_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
		struct sockaddr_nl snl = { .nl_family = AF_NETLINK, .nl_groups = RTMGRP_IPV4_IFADDR };
		if (nl_fd >= 0 && bind(nl_fd, (struct sockaddr *)&snl, sizeof snl) == 0) {
			struct epoll_event ee = { .events = EPOLLIN, .data.ptr = &nl_fd };
			epoll_ctl(epfd, EPOLL_CTL_ADD, nl_fd, &ee);
		} else if (nl_fd >= 0) {
			close(nl_fd);
			nl_fd = -1;
		}
	}

	/* TCP listener for remote clients */
	listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (listen_fd < 0) {
		perror("tcp socket");
		return 1;
	}
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	struct sockaddr_in lsa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
	if (inet_pton(AF_INET, bind_addr, &lsa.sin_addr) != 1 ||
	    bind(listen_fd, (struct sockaddr *)&lsa, sizeof lsa) < 0 ||
	    listen(listen_fd, 16) < 0) {
		LOGE("tcp listen %s:%d: %s", bind_addr, port, strerror(errno));
		return 1;
	}
	sl = sizeof lsa;
	getsockname(listen_fd, (struct sockaddr *)&lsa, &sl);
	port = ntohs(lsa.sin_port);

	sigset_t ss;
	sigemptyset(&ss);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGTERM);
	sigprocmask(SIG_BLOCK, &ss, NULL);
	sig_fd = signalfd(-1, &ss, SFD_NONBLOCK | SFD_CLOEXEC);

	struct epoll_event ee;
	ee = (struct epoll_event){ .events = EPOLLIN, .data.ptr = &sood_fd };
	epoll_ctl(epfd, EPOLL_CTL_ADD, sood_fd, &ee);
	ee = (struct epoll_event){ .events = EPOLLIN, .data.ptr = &listen_fd };
	epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ee);
	ee = (struct epoll_event){ .events = EPOLLIN, .data.ptr = &sig_fd };
	epoll_ctl(epfd, EPOLL_CTL_ADD, sig_fd, &ee);

	LOGI("listening tcp %s:%d, sood udp %s:%d%s%s", bind_addr, port, sood_bind, sood_port,
	     no_mcast ? "" : " (multicast " SOOD_GROUP ")", core_ip ? "" : "");
	if (core_ip)
		LOGI("core reply address override: %s", core_ip);
	printf("READY listen_port=%d sood_port=%d\n", port, sood_port);
	fflush(stdout);

	int64_t last_sweep = now_ms();
	struct epoll_event evs[64];
	bool running = true;
	while (running) {
		int n = epoll_wait(epfd, evs, 64, 5000);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		for (int i = 0; i < n; i++) {
			void *p = evs[i].data.ptr;
			if (p == &sig_fd) {
				struct signalfd_siginfo si;
				while (read(sig_fd, &si, sizeof si) == sizeof si)
					LOGI("signal %u: shutting down", si.ssi_signo);
				running = false;
			} else if (p == &sood_fd) {
				handle_sood();
			} else if (p == &listen_fd) {
				handle_accept();
			} else if (p == &nl_fd) {
				char nlbuf[4096];
				bool changed = false;
				while (recv(nl_fd, nlbuf, sizeof nlbuf, 0) > 0)
					changed = true;
				if (changed)
					join_multicast_all(sood_fd);
			} else {
				client_io((client_t *)p, evs[i].events);
			}
		}
		int64_t now = now_ms();
		if (now - last_sweep >= 10000) {
			last_sweep = now;
			for (int i = 0; i < MAX_CLIENTS; i++) {
				if (clients[i].fd < 0)
					continue;
				int64_t idle = now - clients[i].last_seen_ms;
				if (!clients[i].authed && idle > 10000) {
					client_close(&clients[i]);
				} else if (clients[i].authed && idle > 90000) {
					LOGW("client %s timed out", clients[i].peer);
					client_close(&clients[i]);
				} else if (clients[i].authed && idle > 30000) {
					client_send(&clients[i], RF_MSG_PING, NULL, 0);
				}
			}
		}
	}

	for (int i = 0; i < MAX_CLIENTS; i++)
		client_close(&clients[i]);
	if (nl_fd >= 0)
		close(nl_fd);
	close(sig_fd);
	close(listen_fd);
	close(sood_fd);
	close(epfd);
	return 0;
}
