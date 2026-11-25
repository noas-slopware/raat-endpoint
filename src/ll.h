// SPDX-License-Identifier: GPL-3.0-or-later
/* "LL" framing (spec 5.1): u32 BE total_len (8 + body), u32 BE type, body. */
#ifndef RAAT_LL_H
#define RAAT_LL_H

#include "common.h"

#define LL_REQUEST         0x80000001u
#define LL_RESPONSE        0x80000002u
#define LL_KEEPALIVE       0x80000003u
#define LL_BEGIN_KEEPALIVE 0x80000004u
#define LL_END_KEEPALIVE   0x80000005u
#define LL_MAX_BODY        0x400000u
#define LL_NO_REPLY        0xFFFFFFFFu

typedef struct llconn llconn_t;

struct llconn_ops {
	/* Every frame except keepalive control frames. */
	void (*on_frame)(llconn_t *c, uint32_t type, const uint8_t *body, size_t len);
	/* Called once, from a deferred task, after the socket is closed. */
	void (*on_close)(llconn_t *c);
};

llconn_t *ll_new(int fd, const struct llconn_ops *ops, void *ud, const char *tag);
void *ll_ud(llconn_t *c);
void ll_set_ud(llconn_t *c, void *ud);
bool ll_is_open(llconn_t *c);
const char *ll_peer_ip(llconn_t *c);
int ll_peer_port(llconn_t *c);

void ll_send(llconn_t *c, uint32_t type, const void *body, size_t len);
void ll_send2(llconn_t *c, uint32_t type, const void *a, size_t alen, const void *b, size_t blen);
/* 0x80000002 response; a no-op for rid 0xFFFFFFFF. */
void ll_respond(llconn_t *c, uint32_t rid, bool final, const char *json);
void ll_close(llconn_t *c, const char *why);

/* Non-blocking IPv4 TCP listener. port 0 = ephemeral. Returns fd or -1. */
int tcp_listen_fd(const char *addr, int port, int backlog);
/* Try ports lo..hi in order, then fall back to 0. */
int tcp_listen_range(const char *addr, int lo, int hi, int backlog, int *port_out);
int sock_local_port(int fd);

static inline void be32_put(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static inline uint32_t be32_get(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

#endif
