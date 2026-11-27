// SPDX-License-Identifier: GPL-3.0-or-later
#include "sood.h"
#include "ll.h"
#include "loop.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define SOOD_GROUP "239.255.90.90"
#define SOOD_DEFAULT_PORT 9003
#define MAX_KV 32
#define DEDUP 32

static struct {
	io_watch_t w, nlw;
	ltimer_t burst;
	int burst_left;
	int port;
	bool multicast;
	char *keys[MAX_KV], *vals[MAX_KV];
	int nkv;
	struct {
		char tid[64];
		int64_t at;
	} seen[DEDUP];
	int seen_next;
} S = { .w.fd = -1, .nlw.fd = -1 };

int sood_port(void)
{
	return S.port;
}

/* Join the group on every IPv4 interface. Re-run on address changes. */
static void join_all(void)
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
		if (setsockopt(S.w.fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof mr) == 0)
			LOGD("[sood] joined %s on %s", SOOD_GROUP, i->ifa_name);
	}
	freeifaddrs(ifa);
}

static bool seen_tid(const char *tid)
{
	int64_t now = now_ms();
	for (int i = 0; i < DEDUP; i++)
		if (S.seen[i].at && now - S.seen[i].at < 10000 && !strcmp(S.seen[i].tid, tid))
			return true;
	strlcpy0(S.seen[S.seen_next].tid, tid, sizeof S.seen[0].tid);
	S.seen[S.seen_next].at = now;
	S.seen_next = (S.seen_next + 1) % DEDUP;
	return false;
}

static size_t put_kv(uint8_t *p, size_t off, size_t cap, const char *k, const char *v)
{
	size_t kl = strlen(k), vl = v ? strlen(v) : 0;
	if (kl == 0 || kl > 255 || vl > 0xFFFE || off + 1 + kl + 2 + vl > cap)
		return off;
	p[off++] = (uint8_t)kl;
	memcpy(p + off, k, kl);
	off += kl;
	uint16_t l = v ? (uint16_t)vl : 0xFFFF;
	p[off++] = (uint8_t)(l >> 8);
	p[off++] = (uint8_t)l;
	if (vl)
		memcpy(p + off, v, vl);
	return off + vl;
}

static void handle_packet(const uint8_t *p, size_t n, const struct sockaddr_in *src,
			  bool override_replyaddr)
{
	if (S.w.fd < 0 || n < 6 || memcmp(p, "SOOD", 4) || p[4] != 2 || p[5] != 'Q')
		return;
	char service[64] = "", tid[64] = "", raddr[64] = "", rport[16] = "";
	bool have_tid = false;
	size_t off = 6;
	while (off < n) {
		size_t kl = p[off++];
		if (kl == 0 || off + kl + 2 > n)
			return; /* malformed */
		const char *k = (const char *)p + off;
		off += kl;
		size_t vl = (size_t)p[off] << 8 | p[off + 1];
		off += 2;
		bool null = vl == 0xFFFF;
		if (null)
			vl = 0;
		if (off + vl > n)
			return;
		const char *v = (const char *)p + off;
		off += vl;
		char *dst = NULL;
		size_t dn = 0;
		if (kl == 10 && !memcmp(k, "service_id", 10))
			dst = service, dn = sizeof service;
		else if (kl == 4 && !memcmp(k, "_tid", 4))
			dst = tid, dn = sizeof tid, have_tid = !null;
		else if (kl == 10 && !memcmp(k, "_replyaddr", 10))
			dst = raddr, dn = sizeof raddr;
		else if (kl == 10 && !memcmp(k, "_replyport", 10))
			dst = rport, dn = sizeof rport;
		if (dst && !null && vl < dn) {
			memcpy(dst, v, vl);
			dst[vl] = 0;
		}
	}
	if (strcasecmp(service, RAAT_SERVICE_ID))
		return;
	if (have_tid && seen_tid(tid))
		return;

	struct sockaddr_in to = *src;
	if (!override_replyaddr && raddr[0] && inet_pton(AF_INET, raddr, &to.sin_addr) != 1)
		return;
	if (rport[0]) {
		long pv = strtol(rport, NULL, 10);
		if (pv <= 0 || pv > 65535)
			return;
		to.sin_port = htons((uint16_t)pv);
	}
	uint32_t a = ntohl(to.sin_addr.s_addr);
	if (a == 0 || a == 0xFFFFFFFFu || (a >> 28) == 0xE || to.sin_port == 0)
		return; /* never reply to multicast, broadcast or unspecified */

	uint8_t out[1400];
	memcpy(out, "SOOD\x02R", 6);
	size_t o = 6;
	if (have_tid)
		o = put_kv(out, o, sizeof out, "_tid", tid);
	for (int i = 0; i < S.nkv; i++)
		o = put_kv(out, o, sizeof out, S.keys[i], S.vals[i]);
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &to.sin_addr, ip, sizeof ip);
	if (sendto(S.w.fd, out, o, 0, (struct sockaddr *)&to, sizeof to) < 0)
		LOGW("[sood] reply to %s:%d: %s", ip, ntohs(to.sin_port), strerror(errno));
	else
		LOGD("[sood] answered query from %s:%d", ip, ntohs(to.sin_port));
}

/*
 * Unsolicited announce, as RoonBridge's manager does when it starts and when
 * the network interfaces change ("[raatmanager] announcing"): a 'Q' packet
 * with the info dictionary and a fresh _tid, multicast to the SOOD group on
 * every IPv4 interface. A Core that has stopped retrying an endpoint (for
 * example after it vanished without closing its connections) finds it again
 * through this; answering queries alone is not enough.
 */
static void announce(void)
{
	uint8_t out[1400];
	char tid[37];
	guid_new(tid);
	seen_tid(tid); /* our own packet may come back: don't answer it */
	memcpy(out, "SOOD\x02Q", 6);
	size_t o = put_kv(out, 6, sizeof out, "_tid", tid);
	for (int i = 0; i < S.nkv; i++)
		o = put_kv(out, o, sizeof out, S.keys[i], S.vals[i]);

	struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(SOOD_DEFAULT_PORT) };
	inet_pton(AF_INET, SOOD_GROUP, &to.sin_addr);
	struct ifaddrs *ifa, *i;
	if (getifaddrs(&ifa) < 0)
		return;
	for (i = ifa; i; i = i->ifa_next) {
		if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET || !(i->ifa_flags & IFF_UP) ||
		    !(i->ifa_flags & IFF_MULTICAST) || (i->ifa_flags & IFF_LOOPBACK))
			continue;
		struct in_addr ifaddr = ((struct sockaddr_in *)i->ifa_addr)->sin_addr;
		bool sent = false;
		if (setsockopt(S.w.fd, IPPROTO_IP, IP_MULTICAST_IF, &ifaddr, sizeof ifaddr) == 0 &&
		    sendto(S.w.fd, out, o, 0, (struct sockaddr *)&to, sizeof to) >= 0)
			sent = true;
		/* RoonBridge also sends it to every interface's subnet broadcast */
		if ((i->ifa_flags & IFF_BROADCAST) && i->ifa_broadaddr) {
			struct sockaddr_in bc = { .sin_family = AF_INET, .sin_port = htons(SOOD_DEFAULT_PORT),
						  .sin_addr = ((struct sockaddr_in *)i->ifa_broadaddr)->sin_addr };
			if (sendto(S.w.fd, out, o, 0, (struct sockaddr *)&bc, sizeof bc) >= 0)
				sent = true;
		}
		if (sent)
			LOGI("[sood] announced on %s", i->ifa_name);
		else
			LOGW("[sood] announce on %s: %s", i->ifa_name, strerror(errno));
	}
	freeifaddrs(ifa);
}

/*
 * Announce whenever an address appears (start, link up, DHCP), then again
 * with backoff (1, 3, 7, 15, 31, 63 s after) until a Core connects. One
 * packet is not enough: after a reboot with a new (random) MAC, a Core that
 * still holds the old one in its neighbour cache spends several seconds
 * probing it before it re-resolves, and every announce in that window is
 * answered into the void; the Core then waits for the next one. One-shot
 * timers only, and none once a Core is connected or the schedule ends.
 */
static const int burst_gap_ms[] = { 1000, 2000, 4000, 8000, 16000, 32000 };
#define BURST_N ((int)(sizeof burst_gap_ms / sizeof burst_gap_ms[0]))

static void burst_cb(ltimer_t *t)
{
	(void)t;
	announce();
	if (--S.burst_left > 0)
		loop_timer_start(&S.burst, burst_gap_ms[BURST_N - S.burst_left], 0);
}

static void announce_burst(void)
{
	announce();
	S.burst_left = BURST_N;
	loop_timer_start(&S.burst, burst_gap_ms[0], 0);
}

void sood_core_connected(void)
{
	if (S.multicast && loop_timer_active(&S.burst)) {
		loop_timer_stop(&S.burst);
		LOGD("[sood] a Core is connected, announcing stopped");
	}
}

static void sood_io(io_watch_t *w, uint32_t ev)
{
	(void)ev;
	uint8_t buf[2048];
	for (int i = 0; i < 64; i++) {
		struct sockaddr_in src;
		socklen_t sl = sizeof src;
		ssize_t n = recvfrom(w->fd, buf, sizeof buf, 0, (struct sockaddr *)&src, &sl);
		if (n < 0)
			return;
		handle_packet(buf, (size_t)n, &src, false);
	}
}

void sood_inject_query(const uint8_t *pkt, size_t len, const struct sockaddr_in *core_addr,
		       bool override_replyaddr)
{
	if (!pkt || !core_addr)
		return;
	handle_packet(pkt, len, core_addr, override_replyaddr);
}

void sood_announce_unicast(const struct sockaddr_in *core_addr)
{
	if (S.w.fd < 0 || !core_addr)
		return;
	uint8_t out[1400];
	char tid[37];
	guid_new(tid);
	seen_tid(tid);
	memcpy(out, "SOOD\x02Q", 6);
	size_t o = put_kv(out, 6, sizeof out, "_tid", tid);
	for (int i = 0; i < S.nkv; i++)
		o = put_kv(out, o, sizeof out, S.keys[i], S.vals[i]);
	struct sockaddr_in to = *core_addr;
	if (to.sin_port == 0)
		to.sin_port = htons(SOOD_DEFAULT_PORT);
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &to.sin_addr, ip, sizeof ip);
	if (sendto(S.w.fd, out, o, 0, (struct sockaddr *)&to, sizeof to) < 0)
		LOGW("[sood] unicast announce to %s:%d: %s", ip, ntohs(to.sin_port), strerror(errno));
	else
		LOGI("[sood] unicast announced to %s:%d", ip, ntohs(to.sin_port));
}

static void netlink_io(io_watch_t *w, uint32_t ev)
{
	(void)ev;
	char buf[8192];
	bool changed = false;
	while (recv(w->fd, buf, sizeof buf, 0) > 0)
		changed = true;
	if (changed) {
		join_all();
		announce_burst();
	}
}

int sood_start(const char *bind_addr, int port, bool join_multicast, const struct sood_kv *kv)
{
	for (S.nkv = 0; kv[S.nkv].key && S.nkv < MAX_KV; S.nkv++) {
		S.keys[S.nkv] = xstrdup(kv[S.nkv].key);
		S.vals[S.nkv] = kv[S.nkv].value ? xstrdup(kv[S.nkv].value) : NULL;
	}
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
	if (inet_pton(AF_INET, bind_addr, &sa.sin_addr) != 1 ||
	    bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
		LOGW("[sood] bind %s:%d failed: %s", bind_addr, port, strerror(errno));
		close(fd);
		return -1;
	}
	S.port = sock_local_port(fd);
	loop_io_add(&S.w, fd, EPOLLIN, sood_io, NULL);
	S.multicast = join_multicast;
	if (join_multicast) {
		join_all();
		int nl = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
		struct sockaddr_nl snl = { .nl_family = AF_NETLINK, .nl_groups = RTMGRP_IPV4_IFADDR };
		if (nl >= 0 && bind(nl, (struct sockaddr *)&snl, sizeof snl) == 0)
			loop_io_add(&S.nlw, nl, EPOLLIN, netlink_io, NULL);
		else if (nl >= 0)
			close(nl);
	}
	LOGI("[sood] listening on udp %s:%d%s", bind_addr, S.port,
	     join_multicast ? " (multicast " SOOD_GROUP ")" : "");
	if (join_multicast) {
		unsigned char off = 0;
		setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &off, sizeof off);
		setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof one);
		loop_timer_init(&S.burst, burst_cb, NULL);
		announce_burst();
	}
	return 0;
}

void sood_stop(void)
{
	int fd = S.w.fd, nl = S.nlw.fd;
	if (S.multicast)
		loop_timer_stop(&S.burst);
	loop_io_del(&S.w);
	loop_io_del(&S.nlw);
	if (fd >= 0)
		close(fd);
	if (nl >= 0)
		close(nl);
	for (int i = 0; i < S.nkv; i++) {
		free(S.keys[i]);
		free(S.vals[i]);
	}
	memset(&S, 0, sizeof S);
	S.w.fd = -1;
	S.nlw.fd = -1;
}
