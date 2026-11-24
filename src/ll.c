#include "ll.h"
#include "loop.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LL_MAX_WQ (16u << 20) /* kill a peer that stops reading */

struct llconn {
	io_watch_t w;
	const struct llconn_ops *ops;
	void *ud;
	char tag[24];
	char peer_ip[INET_ADDRSTRLEN];
	int peer_port;
	bool open;

	uint8_t *rbuf;
	size_t rlen, rcap;

	uint8_t *wbuf;
	size_t woff, wlen, wcap;

	ltimer_t ka;
	uint32_t ka_interval, ka_timeout;
	int64_t last_rx_ms;
};

static void ll_io(io_watch_t *w, uint32_t ev);

llconn_t *ll_new(int fd, const struct llconn_ops *ops, void *ud, const char *tag)
{
	llconn_t *c = xcalloc(1, sizeof *c);
	c->ops = ops;
	c->ud = ud;
	c->open = true;
	strlcpy0(c->tag, tag, sizeof c->tag);
	struct sockaddr_in sa;
	socklen_t sl = sizeof sa;
	if (getpeername(fd, (struct sockaddr *)&sa, &sl) == 0 && sa.sin_family == AF_INET) {
		inet_ntop(AF_INET, &sa.sin_addr, c->peer_ip, sizeof c->peer_ip);
		c->peer_port = ntohs(sa.sin_port);
	}
	c->last_rx_ms = now_ms();
	loop_timer_init(&c->ka, NULL, c);
	if (loop_io_add(&c->w, fd, EPOLLIN, ll_io, c) < 0) {
		close(fd);
		free(c);
		return NULL;
	}
	LOGD("[%s] connection from %s:%d", c->tag, c->peer_ip, c->peer_port);
	return c;
}

void *ll_ud(llconn_t *c) { return c->ud; }
void ll_set_ud(llconn_t *c, void *ud) { c->ud = ud; }
bool ll_is_open(llconn_t *c) { return c && c->open; }
const char *ll_peer_ip(llconn_t *c) { return c->peer_ip; }
int ll_peer_port(llconn_t *c) { return c->peer_port; }

static void ll_finish(void *arg)
{
	llconn_t *c = arg;
	if (c->ops->on_close)
		c->ops->on_close(c);
	free(c->rbuf);
	free(c->wbuf);
	free(c);
}

void ll_close(llconn_t *c, const char *why)
{
	if (!c->open)
		return;
	c->open = false;
	LOGD("[%s] closing %s:%d: %s", c->tag, c->peer_ip, c->peer_port, why);
	loop_timer_stop(&c->ka);
	int fd = c->w.fd;
	loop_io_del(&c->w);
	if (fd >= 0)
		close(fd);
	loop_defer(ll_finish, c);
}

static void ll_flush(llconn_t *c)
{
	while (c->woff < c->wlen) {
		ssize_t n = send(c->w.fd, c->wbuf + c->woff, c->wlen - c->woff, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			ll_close(c, strerror(errno));
			return;
		}
		c->woff += (size_t)n;
	}
	if (c->woff == c->wlen) {
		c->woff = c->wlen = 0;
		loop_io_mod(&c->w, EPOLLIN);
	} else {
		loop_io_mod(&c->w, EPOLLIN | EPOLLOUT);
	}
}

static void wq_append(llconn_t *c, const void *p, size_t n)
{
	if (c->woff && c->woff == c->wlen)
		c->woff = c->wlen = 0;
	if (c->wlen + n > c->wcap) {
		if (c->woff) {
			memmove(c->wbuf, c->wbuf + c->woff, c->wlen - c->woff);
			c->wlen -= c->woff;
			c->woff = 0;
		}
		if (c->wlen + n > c->wcap) {
			size_t cap = c->wcap ? c->wcap : 4096;
			while (cap < c->wlen + n)
				cap *= 2;
			c->wbuf = xrealloc(c->wbuf, cap);
			c->wcap = cap;
		}
	}
	memcpy(c->wbuf + c->wlen, p, n);
	c->wlen += n;
}

void ll_send2(llconn_t *c, uint32_t type, const void *a, size_t alen, const void *b, size_t blen)
{
	if (!c || !c->open)
		return;
	if (c->wlen - c->woff + alen + blen > LL_MAX_WQ) {
		ll_close(c, "write queue overflow");
		return;
	}
	uint8_t hdr[8];
	be32_put(hdr, (uint32_t)(8 + alen + blen));
	be32_put(hdr + 4, type);
	wq_append(c, hdr, 8);
	if (alen)
		wq_append(c, a, alen);
	if (blen)
		wq_append(c, b, blen);
	ll_flush(c);
}

void ll_send(llconn_t *c, uint32_t type, const void *body, size_t len)
{
	ll_send2(c, type, body, len, NULL, 0);
}

void ll_respond(llconn_t *c, uint32_t rid, bool final, const char *json)
{
	if (rid == LL_NO_REPLY)
		return;
	uint8_t h[5];
	be32_put(h, rid);
	h[4] = final ? 1 : 0;
	ll_send2(c, LL_RESPONSE, h, 5, json, strlen(json));
}

static void ka_tick(ltimer_t *t)
{
	llconn_t *c = t->ud;
	if (now_ms() - c->last_rx_ms > (int64_t)c->ka_timeout) {
		LOGW("[%s] client %s:%d timed out", c->tag, c->peer_ip, c->peer_port);
		ll_close(c, "keepalive timeout");
		return;
	}
	ll_send(c, LL_KEEPALIVE, NULL, 0);
}

static void handle_frame(llconn_t *c, uint32_t type, const uint8_t *body, size_t len)
{
	switch (type) {
	case LL_KEEPALIVE:
		return;
	case LL_BEGIN_KEEPALIVE:
		if (len != 8) {
			ll_close(c, "bad LL_BEGIN_KEEPALIVE");
			return;
		}
		c->ka_interval = be32_get(body);
		c->ka_timeout = be32_get(body + 4);
		LOGD("[%s] keepalive interval=%u timeout=%u", c->tag, c->ka_interval, c->ka_timeout);
		c->ka.cb = ka_tick;
		if (c->ka_interval)
			loop_timer_start(&c->ka, c->ka_interval, c->ka_interval);
		else
			loop_timer_stop(&c->ka);
		return;
	case LL_END_KEEPALIVE:
		loop_timer_stop(&c->ka);
		return;
	default:
		c->ops->on_frame(c, type, body, len);
	}
}

static void ll_read(llconn_t *c)
{
	for (;;) {
		if (c->rcap - c->rlen < 65536) {
			size_t cap = c->rcap ? c->rcap * 2 : 65536 * 2;
			c->rbuf = xrealloc(c->rbuf, cap);
			c->rcap = cap;
		}
		ssize_t n = recv(c->w.fd, c->rbuf + c->rlen, c->rcap - c->rlen, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			ll_close(c, strerror(errno));
			return;
		}
		if (n == 0) {
			ll_close(c, "peer closed");
			return;
		}
		c->rlen += (size_t)n;
		c->last_rx_ms = now_ms();

		size_t off = 0;
		while (c->open && c->rlen - off >= 8) {
			uint32_t total = be32_get(c->rbuf + off);
			uint32_t type = be32_get(c->rbuf + off + 4);
			if (total < 8 || total - 8 > LL_MAX_BODY) {
				ll_close(c, "bad frame length");
				return;
			}
			if (c->rlen - off < total)
				break;
			handle_frame(c, type, c->rbuf + off + 8, total - 8);
			off += total;
		}
		if (!c->open)
			return;
		if (off) {
			memmove(c->rbuf, c->rbuf + off, c->rlen - off);
			c->rlen -= off;
		}
		/* Shrink after a large frame (load_script) so idle connections stay small. */
		if (c->rlen < 4096 && c->rcap > 262144) {
			c->rbuf = xrealloc(c->rbuf, 131072);
			c->rcap = 131072;
		}
	}
}

static void ll_io(io_watch_t *w, uint32_t ev)
{
	llconn_t *c = w->ud;
	if (ev & EPOLLOUT)
		ll_flush(c);
	if (c->open && (ev & (EPOLLIN | EPOLLHUP | EPOLLERR)))
		ll_read(c);
}

/* ---- listeners ---- */

int tcp_listen_fd(const char *addr, int port, int backlog)
{
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
	if (inet_pton(AF_INET, addr ? addr : "0.0.0.0", &sa.sin_addr) != 1) {
		close(fd);
		errno = EINVAL;
		return -1;
	}
	if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(fd, backlog) < 0) {
		int e = errno;
		close(fd);
		errno = e;
		return -1;
	}
	return fd;
}

int sock_local_port(int fd)
{
	struct sockaddr_in sa;
	socklen_t sl = sizeof sa;
	if (getsockname(fd, (struct sockaddr *)&sa, &sl) < 0)
		return -1;
	return ntohs(sa.sin_port);
}

int tcp_listen_range(const char *addr, int lo, int hi, int backlog, int *port_out)
{
	int fd = -1;
	for (int p = lo; lo > 0 && p <= hi && fd < 0; p++)
		fd = tcp_listen_fd(addr, p, backlog);
	if (fd < 0)
		fd = tcp_listen_fd(addr, 0, backlog);
	if (fd >= 0 && port_out)
		*port_out = sock_local_port(fd);
	return fd;
}
