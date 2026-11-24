/* Single-threaded epoll event loop with a timer heap and a deferred-task queue.
 *
 * Objects that own an io_watch must be freed through loop_defer() (or after
 * loop_io_del() in a deferred task): events already fetched for the current
 * epoll batch still point at the watch, and the loop skips watches whose fd is -1. */
#ifndef RAAT_LOOP_H
#define RAAT_LOOP_H

#include "common.h"
#include <sys/epoll.h>

typedef struct io_watch io_watch_t;
typedef void (*io_cb)(io_watch_t *w, uint32_t events);

struct io_watch {
	int fd;
	uint32_t events;
	io_cb cb;
	void *ud;
};

typedef struct ltimer ltimer_t;
struct ltimer {
	int64_t due_ms;
	int64_t repeat_ms;
	void (*cb)(ltimer_t *t);
	void *ud;
	int heap_idx; /* -1 when inactive */
};

int loop_init(void);
void loop_run(void);
void loop_stop(void);
/* Run queued deferred tasks (used once more after loop_run returns). */
void loop_run_pending(void);

int loop_io_add(io_watch_t *w, int fd, uint32_t events, io_cb cb, void *ud);
int loop_io_mod(io_watch_t *w, uint32_t events);
void loop_io_del(io_watch_t *w); /* does not close the fd */

void loop_timer_init(ltimer_t *t, void (*cb)(ltimer_t *), void *ud);
void loop_timer_start(ltimer_t *t, int64_t timeout_ms, int64_t repeat_ms);
void loop_timer_stop(ltimer_t *t);
static inline bool loop_timer_active(const ltimer_t *t) { return t->heap_idx >= 0; }

/* Run fn(arg) after the current batch of events. */
void loop_defer(void (*fn)(void *), void *arg);

#endif
