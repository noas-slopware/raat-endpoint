// SPDX-License-Identifier: GPL-3.0-or-later
/* Shared wire constants for RAATflector (L3 VPN SOOD reflector). */
#ifndef RAAT_RAATFLECTOR_PROTO_H
#define RAAT_RAATFLECTOR_PROTO_H

#include <stdint.h>

#define RAATFLECTOR_DEFAULT_PORT 9004
#define RAATFLECTOR_PROTO_VER    1
#define RAATFLECTOR_MAX_PAYLOAD  4096
#define RAATFLECTOR_HDR_LEN      5 /* 4-byte BE length + 1-byte type */

enum {
	RF_MSG_HELLO      = 0x01,
	RF_MSG_HELLO_OK   = 0x02,
	RF_MSG_HELLO_ERR  = 0x03,
	RF_MSG_SOOD_QUERY = 0x10,
	RF_MSG_PING       = 0x11,
	RF_MSG_PONG       = 0x12,
};

#define RF_FLAG_OVERRIDE_ADDR 0x01

static inline void rf_put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static inline uint16_t rf_get_be16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static inline void rf_put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static inline uint32_t rf_get_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

#endif
