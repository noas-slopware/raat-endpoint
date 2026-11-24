#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "third_party/cjson/cJSON.h"

int g_log_level = LOG_INFO;

/* ---- log ring for get_log ---- */

#define LOG_RING 256
#define LOG_TEXT 240

static struct {
	int64_t seq;
	int level;
	int64_t time_ms;
	char text[LOG_TEXT];
} log_ring[LOG_RING];
static int64_t log_next_seq = 1;
static int64_t log_first_seq = 1;

static pthread_mutex_t log_mu = PTHREAD_MUTEX_INITIALIZER;

static const char *const level_names[] = { "trace", "debug", "info", "warning", "error", "critical" };

void log_vmsg(int level, const char *fmt, va_list ap)
{
	char buf[LOG_TEXT];
	vsnprintf(buf, sizeof buf, fmt, ap);
	if (level < 0)
		level = 0;
	if (level > LOG_CRIT)
		level = LOG_CRIT;
	pthread_mutex_lock(&log_mu);
	if (level >= LOG_DEBUG) {
		int slot = (int)(log_next_seq % LOG_RING);
		log_ring[slot].seq = log_next_seq;
		log_ring[slot].level = level;
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		log_ring[slot].time_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
		memcpy(log_ring[slot].text, buf, sizeof buf);
		log_next_seq++;
		if (log_next_seq - log_first_seq > LOG_RING)
			log_first_seq = log_next_seq - LOG_RING;
	}
	if (level >= g_log_level)
		fprintf(stderr, "[%s] %s\n", level_names[level], buf);
	pthread_mutex_unlock(&log_mu);
}

void log_msg(int level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_vmsg(level, fmt, ap);
	va_end(ap);
}

cJSON *log_entries_json(int64_t min_seq)
{
	cJSON *arr = cJSON_CreateArray();
	pthread_mutex_lock(&log_mu);
	int64_t s = min_seq > log_first_seq ? min_seq : log_first_seq;
	for (; s < log_next_seq; s++) {
		int slot = (int)(s % LOG_RING);
		cJSON *e = cJSON_CreateObject();
		cJSON_AddNumberToObject(e, "seq", (double)log_ring[slot].seq);
		cJSON_AddStringToObject(e, "level", level_names[log_ring[slot].level]);
		cJSON_AddNumberToObject(e, "time", (double)log_ring[slot].time_ms);
		cJSON_AddStringToObject(e, "text", log_ring[slot].text);
		cJSON_AddItemToArray(arr, e);
	}
	pthread_mutex_unlock(&log_mu);
	return arr;
}

void log_clear(void)
{
	pthread_mutex_lock(&log_mu);
	log_first_seq = log_next_seq;
	pthread_mutex_unlock(&log_mu);
}

/* ---- clocks ---- */

int64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ---- memory ---- */

void *xmalloc(size_t n)
{
	void *p = malloc(n ? n : 1);
	if (!p) {
		LOGE("out of memory (%zu bytes)", n);
		abort();
	}
	return p;
}

void *xcalloc(size_t n, size_t m)
{
	void *p = calloc(n ? n : 1, m ? m : 1);
	if (!p) {
		LOGE("out of memory");
		abort();
	}
	return p;
}

void *xrealloc(void *p, size_t n)
{
	void *q = realloc(p, n ? n : 1);
	if (!q) {
		LOGE("out of memory (%zu bytes)", n);
		abort();
	}
	return q;
}

char *xstrdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *d = xmalloc(n);
	memcpy(d, s, n);
	return d;
}

size_t strlcpy0(char *dst, const char *src, size_t n)
{
	size_t l = src ? strlen(src) : 0;
	if (n) {
		size_t c = l < n - 1 ? l : n - 1;
		if (c)
			memcpy(dst, src, c);
		dst[c] = 0;
	}
	return l;
}

/* ---- misc ---- */

void guid_new(char out[37])
{
	uint8_t b[16];
	size_t got = 0;
	while (got < sizeof b) {
		ssize_t r = getrandom(b + got, sizeof b - got, 0);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			abort();
		}
		got += (size_t)r;
	}
	b[6] = (b[6] & 0x0f) | 0x40;
	b[8] = (b[8] & 0x3f) | 0x80;
	snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		 b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
		 b[14], b[15]);
}

char *file_read(const char *path, size_t *len)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	size_t cap = 4096, n = 0;
	char *buf = xmalloc(cap + 1);
	for (;;) {
		if (n == cap) {
			cap *= 2;
			buf = xrealloc(buf, cap + 1);
		}
		ssize_t r = read(fd, buf + n, cap - n);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			close(fd);
			return NULL;
		}
		if (r == 0)
			break;
		n += (size_t)r;
	}
	close(fd);
	buf[n] = 0;
	if (len)
		*len = n;
	return buf;
}

int file_write(const char *path, const char *data, size_t len)
{
	char tmp[4096];
	snprintf(tmp, sizeof tmp, "%s.tmp", path);
	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return -1;
	size_t off = 0;
	while (off < len) {
		ssize_t w = write(fd, data + off, len - off);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			unlink(tmp);
			return -1;
		}
		off += (size_t)w;
	}
	if (fsync(fd) < 0 || close(fd) < 0) {
		unlink(tmp);
		return -1;
	}
	return rename(tmp, path);
}

int mkdir_p(const char *path)
{
	char buf[4096];
	strlcpy0(buf, path, sizeof buf);
	for (char *p = buf + 1; *p; p++) {
		if (*p == '/') {
			*p = 0;
			if (mkdir(buf, 0755) < 0 && errno != EEXIST)
				return -1;
			*p = '/';
		}
	}
	if (mkdir(buf, 0755) < 0 && errno != EEXIST)
		return -1;
	return 0;
}

void str_rtrim(char *s)
{
	size_t n = strlen(s);
	while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t'))
		s[--n] = 0;
}
