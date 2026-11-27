// SPDX-License-Identifier: GPL-3.0-or-later
/* Shared helpers: logging, clocks, small utilities. */
#ifndef RAAT_COMMON_H
#define RAAT_COMMON_H

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

enum { LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_CRIT };

extern int g_log_level;

typedef void (*log_cb_t)(int level, const char *msg, void *ud);
void log_set_cb(log_cb_t cb, void *ud);

void log_msg(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void log_vmsg(int level, const char *fmt, va_list ap);

#define LOGT(...) log_msg(LOG_TRACE, __VA_ARGS__)
#define LOGD(...) log_msg(LOG_DEBUG, __VA_ARGS__)
#define LOGI(...) log_msg(LOG_INFO, __VA_ARGS__)
#define LOGW(...) log_msg(LOG_WARN, __VA_ARGS__)
#define LOGE(...) log_msg(LOG_ERROR, __VA_ARGS__)

/* Log ring served by the device server's get_log/clear_log. */
struct cJSON;
struct cJSON *log_entries_json(int64_t min_seq);
void log_clear(void);

/* CLOCK_MONOTONIC_RAW in ns: the time base of the output clock (spec 8.4). */
int64_t now_ns(void);
/* CLOCK_MONOTONIC in ms: event loop timers and keepalives. */
int64_t now_ms(void);

void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t m);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);

/* Random v4 GUID, lowercase, 36 chars + NUL. */
void guid_new(char out[37]);
/* Read a whole file; returns malloc'd NUL-terminated buffer or NULL. */
char *file_read(const char *path, size_t *len);
/* Write atomically (tmp + rename). Returns 0 on success. */
int file_write(const char *path, const char *data, size_t len);
int mkdir_p(const char *path);
/* Trim trailing whitespace in place. */
void str_rtrim(char *s);
size_t strlcpy0(char *dst, const char *src, size_t n);

#endif
