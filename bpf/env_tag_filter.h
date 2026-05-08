/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Environment-variable based process filter.
 *
 * When env_tag filter is enabled, agentsight only tracks processes whose
 * /proc/<pid>/environ contains a NAME=VALUE entry that exactly matches
 * the user-supplied tag (e.g. AGENTSIGHT_TAG=true). Children inherit the
 * environment automatically and so are tracked transitively via the
 * existing ppid-based propagation in should_track_process().
 */
#ifndef __ENV_TAG_FILTER_H
#define __ENV_TAG_FILTER_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* Maximum bytes we are willing to read from /proc/<pid>/environ per scan. */
#ifndef ENV_TAG_MAX_ENVIRON_BYTES
#define ENV_TAG_MAX_ENVIRON_BYTES (128 * 1024)
#endif

/* Configuration set once at startup via CLI option (e.g. "AGENTSIGHT_TAG=true").
 * Empty / NULL means the env-tag filter is disabled.
 */
struct env_tag_filter {
	bool enabled;
	char tag[128];   /* exact "KEY=VALUE" string to match */
	size_t tag_len;
};

/* Initialize the filter from a user-supplied "KEY=VALUE" string.
 * Returns true if configured (enabled), false if input is invalid/empty.
 */
static inline bool env_tag_filter_init(struct env_tag_filter *f, const char *spec)
{
	if (!f)
		return false;
	memset(f, 0, sizeof(*f));
	if (!spec || !*spec)
		return false;
	/* must contain '=' */
	if (!strchr(spec, '='))
		return false;
	size_t n = strlen(spec);
	if (n >= sizeof(f->tag))
		n = sizeof(f->tag) - 1;
	memcpy(f->tag, spec, n);
	f->tag[n] = '\0';
	f->tag_len = strlen(f->tag);
	f->enabled = true;
	return true;
}

/* Check whether /proc/<pid>/environ contains an exact NAME=VALUE entry
 * matching f->tag. Returns false on any error (process gone, perm denied).
 *
 * The environ pseudo-file is a sequence of NUL-terminated "KEY=VALUE"
 * strings. We do exact whole-entry matching to avoid substring false
 * positives.
 */
static inline bool env_tag_match_pid(const struct env_tag_filter *f, pid_t pid)
{
	if (!f || !f->enabled || f->tag_len == 0)
		return false;

	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/environ", (int)pid);

	FILE *fp = fopen(path, "rb");
	if (!fp)
		return false;

	/* Stream-read entries separated by NUL. We bound total bytes scanned. */
	char buf[1024];
	size_t bytes_read = 0;
	size_t cur = 0;
	bool match = false;

	int c;
	while ((c = fgetc(fp)) != EOF) {
		if (++bytes_read > ENV_TAG_MAX_ENVIRON_BYTES)
			break;

		if (c == '\0') {
			buf[cur] = '\0';
			if (cur == f->tag_len && memcmp(buf, f->tag, f->tag_len) == 0) {
				match = true;
				break;
			}
			cur = 0;
			continue;
		}
		if (cur < sizeof(buf) - 1)
			buf[cur++] = (char)c;
		/* if entry is too long for our local buffer, we keep consuming
		 * chars until the next NUL and then discard the entry. */
	}

	fclose(fp);
	return match;
}


/* ----------------------------------------------------------------------
 * PID admission cache (used by per-event hot paths in sslsniff/stdiocap).
 *
 * Looking up /proc/<pid>/environ on every event is expensive, so we keep
 * a tiny open-addressed hash table that remembers prior admit/reject
 * decisions. The cache is best-effort: when full or on collision we just
 * fall back to re-reading /proc, which is correct but slower.
 * ---------------------------------------------------------------------- */

#ifndef ENV_TAG_PID_CACHE_SIZE
#define ENV_TAG_PID_CACHE_SIZE 1024
#endif

struct env_tag_pid_cache_entry {
	pid_t pid;       /* 0 = empty slot */
	unsigned char admitted; /* 1 = admitted, 2 = rejected */
};

struct env_tag_pid_cache {
	struct env_tag_pid_cache_entry slots[ENV_TAG_PID_CACHE_SIZE];
};

static inline void env_tag_pid_cache_reset(struct env_tag_pid_cache *c)
{
	if (c)
		memset(c, 0, sizeof(*c));
}

static inline size_t env_tag_pid_cache_slot(pid_t pid)
{
	/* Knuth multiplicative hash, then mod table size. */
	unsigned int h = (unsigned int)pid * 2654435761u;
	return h % ENV_TAG_PID_CACHE_SIZE;
}

/* Look up cached decision for pid. Returns 1 = admitted, 0 = rejected,
 * -1 = unknown (caller must compute and then call _set).
 */
static inline int env_tag_pid_cache_get(const struct env_tag_pid_cache *c, pid_t pid)
{
	if (!c || pid <= 0)
		return -1;
	size_t s = env_tag_pid_cache_slot(pid);
	const struct env_tag_pid_cache_entry *e = &c->slots[s];
	if (e->pid != pid)
		return -1;
	return (e->admitted == 1) ? 1 : 0;
}

static inline void env_tag_pid_cache_set(struct env_tag_pid_cache *c, pid_t pid, bool admitted)
{
	if (!c || pid <= 0)
		return;
	size_t s = env_tag_pid_cache_slot(pid);
	struct env_tag_pid_cache_entry *e = &c->slots[s];
	e->pid = pid;
	e->admitted = admitted ? 1 : 2;
}

/* Convenience: check whether pid passes env-tag filter, with caching.
 * If the filter is disabled, always returns true.
 */
static inline bool env_tag_admit_pid_cached(const struct env_tag_filter *f,
                                             struct env_tag_pid_cache *cache,
                                             pid_t pid)
{
	if (!f || !f->enabled)
		return true;
	if (pid <= 0)
		return false;
	int cached = env_tag_pid_cache_get(cache, pid);
	if (cached == 1)
		return true;
	if (cached == 0)
		return false;
	bool ok = env_tag_match_pid(f, pid);
	env_tag_pid_cache_set(cache, pid, ok);
	return ok;
}

#endif /* __ENV_TAG_FILTER_H */
