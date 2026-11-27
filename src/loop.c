// SPDX-License-Identifier: GPL-3.0-or-later
#include "loop.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

static int epfd = -1;
static int wake_fd = -1;
static io_watch_t wake_w = { .fd = -1 };
static _Atomic bool stopping;

static ltimer_t **heap;
static int heap_n, heap_cap;

struct deferred {
	void (*fn)(void *);
	void *arg;
	struct deferred *next;
};
static struct deferred *dq_head, *dq_tail;

static void wake_cb(io_watch_t *w, uint32_t ev)
{
	(void)ev;
	uint64_t v;
	while (read(w->fd, &v, sizeof v) > 0)
		;
}

int loop_init(void)
{
	atomic_store(&stopping, false);
	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0)
		return -1;
	wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (wake_fd < 0) {
		close(epfd);
		epfd = -1;
		return -1;
	}
	if (loop_io_add(&wake_w, wake_fd, EPOLLIN, wake_cb, NULL) < 0) {
		close(wake_fd);
		close(epfd);
		wake_fd = epfd = -1;
		return -1;
	}
	return 0;
}

void loop_stop(void)
{
	atomic_store(&stopping, true);
	int fd = wake_fd;
	if (fd >= 0) {
		uint64_t one = 1;
		ssize_t r = write(fd, &one, sizeof one);
		(void)r;
	}
}

int loop_io_add(io_watch_t *w, int fd, uint32_t events, io_cb cb, void *ud)
{
	w->fd = fd;
	w->events = events;
	w->cb = cb;
	w->ud = ud;
	struct epoll_event ev = { .events = events, .data.ptr = w };
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		LOGE("epoll add fd %d: %s", fd, strerror(errno));
		w->fd = -1;
		return -1;
	}
	return 0;
}

int loop_io_mod(io_watch_t *w, uint32_t events)
{
	if (w->fd < 0 || w->events == events)
		return 0;
	w->events = events;
	struct epoll_event ev = { .events = events, .data.ptr = w };
	return epoll_ctl(epfd, EPOLL_CTL_MOD, w->fd, &ev);
}

void loop_io_del(io_watch_t *w)
{
	if (w->fd < 0)
		return;
	epoll_ctl(epfd, EPOLL_CTL_DEL, w->fd, NULL);
	w->fd = -1;
}

/* ---- timers: binary min-heap on due_ms ---- */

static void heap_swap(int a, int b)
{
	ltimer_t *t = heap[a];
	heap[a] = heap[b];
	heap[b] = t;
	heap[a]->heap_idx = a;
	heap[b]->heap_idx = b;
}

static void heap_up(int i)
{
	while (i > 0) {
		int p = (i - 1) / 2;
		if (heap[p]->due_ms <= heap[i]->due_ms)
			break;
		heap_swap(p, i);
		i = p;
	}
}

static void heap_down(int i)
{
	for (;;) {
		int l = 2 * i + 1, r = l + 1, m = i;
		if (l < heap_n && heap[l]->due_ms < heap[m]->due_ms)
			m = l;
		if (r < heap_n && heap[r]->due_ms < heap[m]->due_ms)
			m = r;
		if (m == i)
			break;
		heap_swap(i, m);
		i = m;
	}
}

void loop_timer_init(ltimer_t *t, void (*cb)(ltimer_t *), void *ud)
{
	memset(t, 0, sizeof *t);
	t->cb = cb;
	t->ud = ud;
	t->heap_idx = -1;
}

void loop_timer_stop(ltimer_t *t)
{
	int i = t->heap_idx;
	if (i < 0)
		return;
	t->heap_idx = -1;
	heap_n--;
	if (i != heap_n) {
		heap[i] = heap[heap_n];
		heap[i]->heap_idx = i;
		heap_up(i);
		heap_down(heap[i]->heap_idx);
	}
}

void loop_timer_start(ltimer_t *t, int64_t timeout_ms, int64_t repeat_ms)
{
	loop_timer_stop(t);
	if (timeout_ms < 0)
		timeout_ms = 0;
	t->due_ms = now_ms() + timeout_ms;
	t->repeat_ms = repeat_ms > 0 ? repeat_ms : 0;
	if (heap_n == heap_cap) {
		heap_cap = heap_cap ? heap_cap * 2 : 16;
		heap = xrealloc(heap, sizeof *heap * (size_t)heap_cap);
	}
	heap[heap_n] = t;
	t->heap_idx = heap_n++;
	heap_up(t->heap_idx);
}

static void run_timers(void)
{
	int64_t now = now_ms();
	/* Bound the work so a 0 ms repeating timer cannot starve I/O. */
	int budget = heap_n + 1;
	while (heap_n && heap[0]->due_ms <= now && budget-- > 0) {
		ltimer_t *t = heap[0];
		loop_timer_stop(t);
		if (t->repeat_ms)
			loop_timer_start(t, t->repeat_ms, t->repeat_ms);
		t->cb(t); /* may stop or free t */
	}
}

/* ---- deferred tasks ---- */

void loop_defer(void (*fn)(void *), void *arg)
{
	struct deferred *d = xmalloc(sizeof *d);
	d->fn = fn;
	d->arg = arg;
	d->next = NULL;
	if (dq_tail)
		dq_tail->next = d;
	else
		dq_head = d;
	dq_tail = d;
}

static void run_deferred(void)
{
	while (dq_head) {
		struct deferred *d = dq_head;
		dq_head = d->next;
		if (!dq_head)
			dq_tail = NULL;
		d->fn(d->arg);
		free(d);
	}
}

void loop_run(void)
{
	struct epoll_event evs[64];
	while (!atomic_load(&stopping)) {
		run_deferred();
		int timeout = -1;
		if (dq_head)
			timeout = 0;
		else if (heap_n) {
			int64_t d = heap[0]->due_ms - now_ms();
			timeout = d < 0 ? 0 : (d > 60000 ? 60000 : (int)d);
		}
		int n = epoll_wait(epfd, evs, 64, timeout);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			LOGE("epoll_wait: %s", strerror(errno));
			break;
		}
		for (int i = 0; i < n && !atomic_load(&stopping); i++) {
			io_watch_t *w = evs[i].data.ptr;
			if (w->fd >= 0)
				w->cb(w, evs[i].events);
		}
		run_deferred();
		run_timers();
	}
	run_deferred();
}

void loop_run_pending(void)
{
	run_deferred();
}

void loop_shutdown(void)
{
	run_deferred();
	loop_io_del(&wake_w);
	if (wake_fd >= 0) {
		close(wake_fd);
		wake_fd = -1;
	}
	if (epfd >= 0) {
		close(epfd);
		epfd = -1;
	}
	free(heap);
	heap = NULL;
	heap_n = heap_cap = 0;
	atomic_store(&stopping, false);
}
