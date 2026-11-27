// SPDX-License-Identifier: GPL-3.0-or-later
#ifdef ENABLE_RAATFLECTOR

#include "raatflector.h"
#include "raatflector_proto.h"
#include "loop.h"
#include "sood.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RF_RX_CAP (RAATFLECTOR_HDR_LEN + RAATFLECTOR_MAX_PAYLOAD)
#define RF_TX_CAP 2048

static struct {
	bool active;
	char host[256];
	int port;
	char *token;

	io_watch_t w;
	ltimer_t retry_t;
	ltimer_t ping_t;
	int backoff_ms;
	bool connecting;
	bool authed;

	uint8_t rx[RF_RX_CAP];
	size_t rx_n;
	uint8_t tx[RF_TX_CAP];
	size_t tx_off, tx_n;
} R = { .w.fd = -1, .retry_t.heap_idx = -1, .ping_t.heap_idx = -1 };

static void schedule_reconnect(void);
static void start_connect(void);

static void drop_conn(void)
{
	int fd = R.w.fd;
	loop_io_del(&R.w);
	if (fd >= 0)
		close(fd);
	loop_timer_stop(&R.ping_t);
	R.connecting = false;
	R.authed = false;
	R.rx_n = 0;
	R.tx_off = R.tx_n = 0;
}

static bool queue_frame(uint8_t type, const uint8_t *payload, size_t len)
{
	if (len > RAATFLECTOR_MAX_PAYLOAD || R.tx_n - R.tx_off + RAATFLECTOR_HDR_LEN + len > RF_TX_CAP)
		return false;
	if (R.tx_off > 0) {
		size_t rem = R.tx_n - R.tx_off;
		if (rem)
			memmove(R.tx, R.tx + R.tx_off, rem);
		R.tx_off = 0;
		R.tx_n = rem;
	}
	rf_put_be32(R.tx + R.tx_n, (uint32_t)len);
	R.tx[R.tx_n + 4] = type;
	if (len)
		memcpy(R.tx + R.tx_n + RAATFLECTOR_HDR_LEN, payload, len);
	R.tx_n += RAATFLECTOR_HDR_LEN + len;
	if (R.w.fd >= 0)
		loop_io_mod(&R.w, EPOLLIN | EPOLLOUT);
	return true;
}

static void send_hello(void)
{
	size_t tlen = R.token ? strlen(R.token) : 0;
	if (tlen > 1024)
		tlen = 1024;
	uint8_t buf[3 + 1024];
	buf[0] = RAATFLECTOR_PROTO_VER;
	rf_put_be16(buf + 1, (uint16_t)tlen);
	if (tlen)
		memcpy(buf + 3, R.token, tlen);
	queue_frame(RF_MSG_HELLO, buf, 3 + tlen);
}

static void ping_cb(ltimer_t *t)
{
	(void)t;
	if (R.authed)
		queue_frame(RF_MSG_PING, NULL, 0);
}

static void handle_frame(uint8_t type, const uint8_t *p, size_t len)
{
	if (type == RF_MSG_HELLO_OK) {
		R.authed = true;
		R.backoff_ms = 1000;
		LOGI("[raatflector] connected to %s:%d", R.host, R.port);
		loop_timer_start(&R.ping_t, 30000, 30000);
		if (len >= 7) {
			struct sockaddr_in core = { .sin_family = AF_INET };
			memcpy(&core.sin_addr.s_addr, p, 4);
			core.sin_port = htons(rf_get_be16(p + 4));
			if (core.sin_addr.s_addr != 0)
				sood_announce_unicast(&core);
		}
	} else if (type == RF_MSG_HELLO_ERR) {
		LOGE("[raatflector] server rejected handshake: %.*s", (int)len, (const char *)p);
		drop_conn();
		schedule_reconnect();
	} else if (type == RF_MSG_SOOD_QUERY) {
		if (len < 7)
			return;
		struct sockaddr_in core = { .sin_family = AF_INET };
		memcpy(&core.sin_addr.s_addr, p, 4);
		core.sin_port = htons(rf_get_be16(p + 4));
		uint8_t flags = p[6];
		sood_inject_query(p + 7, len - 7, &core, (flags & RF_FLAG_OVERRIDE_ADDR) != 0);
	} else if (type == RF_MSG_PING) {
		queue_frame(RF_MSG_PONG, NULL, 0);
	} else if (type == RF_MSG_PONG) {
		/* keepalive ok */
	}
}

static void rf_io(io_watch_t *w, uint32_t ev)
{
	if (ev & (EPOLLERR | EPOLLHUP)) {
		int err = 0;
		socklen_t el = sizeof err;
		getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &err, &el);
		LOGW("[raatflector] connection to %s:%d closed%s%s", R.host, R.port,
		     err ? ": " : "", err ? strerror(err) : "");
		drop_conn();
		schedule_reconnect();
		return;
	}
	if (R.connecting && (ev & EPOLLOUT)) {
		int err = 0;
		socklen_t el = sizeof err;
		if (getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err != 0) {
			LOGW("[raatflector] connect %s:%d failed: %s", R.host, R.port,
			     strerror(err ? err : errno));
			drop_conn();
			schedule_reconnect();
			return;
		}
		R.connecting = false;
		send_hello();
	}
	if (ev & EPOLLOUT) {
		while (R.tx_off < R.tx_n) {
			ssize_t n = send(w->fd, R.tx + R.tx_off, R.tx_n - R.tx_off, MSG_NOSIGNAL);
			if (n < 0) {
				if (errno == EAGAIN || errno == EINTR)
					break;
				LOGW("[raatflector] send: %s", strerror(errno));
				drop_conn();
				schedule_reconnect();
				return;
			}
			R.tx_off += (size_t)n;
		}
		if (R.tx_off == R.tx_n) {
			R.tx_off = R.tx_n = 0;
			loop_io_mod(w, EPOLLIN);
		}
	}
	if (ev & EPOLLIN) {
		for (;;) {
			ssize_t n = recv(w->fd, R.rx + R.rx_n, sizeof R.rx - R.rx_n, 0);
			if (n < 0) {
				if (errno == EAGAIN || errno == EINTR)
					break;
				LOGW("[raatflector] recv: %s", strerror(errno));
				drop_conn();
				schedule_reconnect();
				return;
			}
			if (n == 0) {
				LOGW("[raatflector] server closed connection");
				drop_conn();
				schedule_reconnect();
				return;
			}
			R.rx_n += (size_t)n;
			while (R.rx_n >= RAATFLECTOR_HDR_LEN) {
				uint32_t plen = rf_get_be32(R.rx);
				uint8_t type = R.rx[4];
				if (plen > RAATFLECTOR_MAX_PAYLOAD) {
					LOGW("[raatflector] oversized frame (%u)", plen);
					drop_conn();
					schedule_reconnect();
					return;
				}
				size_t total = RAATFLECTOR_HDR_LEN + plen;
				if (R.rx_n < total)
					break;
				handle_frame(type, R.rx + RAATFLECTOR_HDR_LEN, plen);
				if (R.w.fd < 0)
					return; /* dropped inside handle_frame */
				if (R.rx_n > total)
					memmove(R.rx, R.rx + total, R.rx_n - total);
				R.rx_n -= total;
			}
		}
	}
}

static void retry_cb(ltimer_t *t)
{
	(void)t;
	if (R.active)
		start_connect();
}

static void schedule_reconnect(void)
{
	if (!R.active)
		return;
	int wait = R.backoff_ms;
	if (R.backoff_ms < 30000) {
		R.backoff_ms *= 2;
		if (R.backoff_ms > 30000)
			R.backoff_ms = 30000;
	}
	LOGD("[raatflector] reconnecting in %d ms", wait);
	loop_timer_start(&R.retry_t, wait, 0);
}

static void start_connect(void)
{
	struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
	struct addrinfo *res = NULL;
	char pstr[16];
	snprintf(pstr, sizeof pstr, "%d", R.port);
	int rc = getaddrinfo(R.host, pstr, &hints, &res);
	if (rc != 0 || !res) {
		LOGW("[raatflector] resolve %s:%d: %s", R.host, R.port, gai_strerror(rc));
		schedule_reconnect();
		return;
	}
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		freeaddrinfo(res);
		schedule_reconnect();
		return;
	}
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);

	rc = connect(fd, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	if (rc < 0 && errno != EINPROGRESS) {
		LOGW("[raatflector] connect %s:%d: %s", R.host, R.port, strerror(errno));
		close(fd);
		schedule_reconnect();
		return;
	}
	R.connecting = (rc < 0);
	R.rx_n = 0;
	R.tx_off = R.tx_n = 0;
	loop_io_add(&R.w, fd, EPOLLIN | (R.connecting ? EPOLLOUT : 0), rf_io, NULL);
	if (!R.connecting)
		send_hello();
}

int raatflector_start(const char *server, const char *token)
{
	if (!server || !server[0])
		return -1;
	memset(&R, 0, sizeof R);
	R.w.fd = -1;
	const char *colon = strrchr(server, ':');
	if (colon && colon > server) {
		size_t hl = (size_t)(colon - server);
		if (hl >= sizeof R.host)
			hl = sizeof R.host - 1;
		memcpy(R.host, server, hl);
		R.host[hl] = 0;
		R.port = atoi(colon + 1);
		if (R.port <= 0 || R.port > 65535)
			R.port = RAATFLECTOR_DEFAULT_PORT;
	} else {
		strlcpy0(R.host, server, sizeof R.host);
		R.port = RAATFLECTOR_DEFAULT_PORT;
	}
	R.token = token && token[0] ? xstrdup(token) : NULL;
	R.active = true;
	R.backoff_ms = 1000;
	loop_timer_init(&R.retry_t, retry_cb, NULL);
	loop_timer_init(&R.ping_t, ping_cb, NULL);
	LOGI("[raatflector] client enabled, server %s:%d", R.host, R.port);
	start_connect();
	return 0;
}

void raatflector_stop(void)
{
	if (!R.active)
		return;
	R.active = false;
	loop_timer_stop(&R.retry_t);
	drop_conn();
	free(R.token);
	R.token = NULL;
}

#endif /* ENABLE_RAATFLECTOR */
