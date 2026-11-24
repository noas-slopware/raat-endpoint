/* SOOD discovery responder (spec 4): answers 'Q' queries for the RAAT
 * service id with a unicast 'R'. It never sends anything unsolicited. */
#ifndef RAAT_SOOD_H
#define RAAT_SOOD_H

#include "common.h"

#define RAAT_SERVICE_ID "d7634b85-8190-470f-aa51-6cb5538dc1b9"

struct sood_kv {
	const char *key, *value;
};

/* kv: reply keys (service_id included), NULL-terminated, copied. */
int sood_start(const char *bind_addr, int port, bool join_multicast, const struct sood_kv *kv);
int sood_port(void);
void sood_stop(void);

#endif
