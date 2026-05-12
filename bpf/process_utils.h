/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PROCESS_UTILS_H
#define __PROCESS_UTILS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

// Forward declarations for BPF types when not in test mode
#ifndef BPF_ANY
#include <bpf/libbpf.h>
typedef uint32_t __u32;
#endif

#include "process.h"

static int read_proc_comm(pid_t pid, char *comm, size_t size)
{
	char path[256];
	FILE *f;
	
	snprintf(path, sizeof(path), "/proc/%d/comm", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;
	
	if (fgets(comm, size, f)) {
		/* Remove trailing newline */
		char *newline = strchr(comm, '\n');
		if (newline)
			*newline = '\0';
	} else {
		fclose(f);
		return -1;
	}
	
	fclose(f);
	return 0;
}

static int read_proc_ppid(pid_t pid, pid_t *ppid)
{
	char path[256];
	FILE *f;
	char line[256];
	
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;
	
	if (fgets(line, sizeof(line), f)) {
		/* Parse the stat line to get ppid (4th field) */
		char *token = strtok(line, " ");
		for (int i = 0; i < 3 && token; i++) {
			token = strtok(NULL, " ");
		}
		if (token) {
			*ppid = (pid_t)strtol(token, NULL, 10);
		} else {
			fclose(f);
			return -1;
		}
	} else {
		fclose(f);
		return -1;
	}
	
	fclose(f);
	return 0;
}

static bool command_matches_filter(const char *comm, const char *filter)
{
	return strstr(comm, filter) != NULL;
}

/* Count and print processes that match the given command filters */
static int count_matching_processes(char **command_list, int command_count, bool trace_all)
{
	DIR *proc_dir;
	struct dirent *entry;
	pid_t pid, ppid;
	char comm[TASK_COMM_LEN];
	int matching_count = 0;
	
	proc_dir = opendir("/proc");
	if (!proc_dir) {
		fprintf(stderr, "Failed to open /proc directory\n");
		return -1;
	}
	
	if (trace_all) {
		printf("Tracing all processes (no filter specified)\n");
	} else {
		printf("Scanning existing processes for matching commands...\n");
	}
	
	while ((entry = readdir(proc_dir)) != NULL) {
		/* Skip non-numeric entries */
		if (strspn(entry->d_name, "0123456789") != strlen(entry->d_name))
			continue;
		
		pid = (pid_t)strtol(entry->d_name, NULL, 10);
		if (pid <= 0)
			continue;
		
		/* Read process command */
		if (read_proc_comm(pid, comm, sizeof(comm)) != 0)
			continue;
		
		/* Read parent PID */
		if (read_proc_ppid(pid, &ppid) != 0)
			continue;
		
		bool should_track = trace_all;
		
		/* If not tracing all, check if this process matches any configured filter */
		if (!trace_all && command_list && command_count > 0) {
			should_track = false;
			for (int i = 0; i < command_count; i++) {
				if (command_matches_filter(comm, command_list[i])) {
					should_track = true;
					break;
				}
			}
		}
		
		if (should_track) {
			if (!trace_all) {
				printf("  Found matching process: PID=%d, PPID=%d, COMM=%s\n", 
					pid, ppid, comm);
			}
			matching_count++;
		}
	}
	
	closedir(proc_dir);
	printf("Initially tracking %d processes\n", matching_count);
	return matching_count;
}





/*
 * json_escape_to_buf - Escape an arbitrary byte string into a JSON-safe form.
 *
 * Writes the escaped string into `out` (NUL-terminated). Returns the number
 * of bytes written (excluding the trailing NUL). On overflow, the output is
 * truncated on a safe boundary (never mid-escape) and still NUL-terminated.
 *
 * Escapes per RFC 8259: control chars 0x00..0x1F, 0x7F, double-quote, and
 * backslash. Higher bytes pass through verbatim — we deliberately do NOT
 * verify UTF-8 here because:
 *   1. The Rust consumer uses lossy_decode_line() which replaces invalid
 *      UTF-8 with U+FFFD before serde_json sees it, so the JSON parser is
 *      never fed an invalid sequence.
 *   2. Validating UTF-8 in C would require a state machine; keeping this
 *      function byte-oriented matches the mental model "escape only what
 *      JSON syntax requires".
 *
 * Usage:
 *   char esc[MAX_COMMAND_LEN * 6 + 1];
 *   json_escape_to_buf(raw, raw_len, esc, sizeof(esc));
 *   printf("\"full_command\":\"%s\"", esc);
 */
static inline size_t json_escape_to_buf(const char *src, size_t src_len,
                                        char *out, size_t out_size)
{
	if (!out || out_size == 0)
		return 0;
	size_t w = 0;
	for (size_t i = 0; i < src_len; i++) {
		unsigned char c = (unsigned char)src[i];
		/* Worst case: 6 bytes for \u00XX + trailing NUL slot. */
		if (w + 7 > out_size)
			break;
		switch (c) {
		case '"':  out[w++] = '\\'; out[w++] = '"';  break;
		case '\\': out[w++] = '\\'; out[w++] = '\\'; break;
		case '\b': out[w++] = '\\'; out[w++] = 'b';  break;
		case '\f': out[w++] = '\\'; out[w++] = 'f';  break;
		case '\n': out[w++] = '\\'; out[w++] = 'n';  break;
		case '\r': out[w++] = '\\'; out[w++] = 'r';  break;
		case '\t': out[w++] = '\\'; out[w++] = 't';  break;
		default:
			if (c < 0x20 || c == 0x7F) {
				static const char hex[] = "0123456789abcdef";
				out[w++] = '\\';
				out[w++] = 'u';
				out[w++] = '0';
				out[w++] = '0';
				out[w++] = hex[(c >> 4) & 0xF];
				out[w++] = hex[c & 0xF];
			} else {
				out[w++] = (char)c;
			}
		}
	}
	out[w] = '\0';
	return w;
}

/*
 * json_escape_cstr - convenience wrapper that takes a NUL-terminated string.
 */
static inline size_t json_escape_cstr(const char *src, char *out, size_t out_size)
{
	return json_escape_to_buf(src, src ? strlen(src) : 0, out, out_size);
}


/*
 * print_json_str_field - emit `"key":"<escaped value>"` to stdout.
 *
 * Convenience for the (very common) pattern of writing a JSON string field
 * with an arbitrary user-supplied value. The temporary escape buffer is
 * sized for the worst case (every byte expands to \u00XX = 6 chars) of
 * MAX_COMMAND_LEN bytes plus NUL.
 */
static inline void print_json_str_field(const char *key, const char *value)
{
	char esc[MAX_COMMAND_LEN * 6 + 1];
	json_escape_cstr(value ? value : "", esc, sizeof(esc));
	printf("\"%s\":\"%s\"", key, esc);
}

/*
 * postprocess_full_command - Convert raw argv bytes to a readable command string.
 *
 * BPF reads raw argv memory which contains \0 between arguments and may
 * include environment variable data past arg_end.  This function:
 *   1. Copies data to a local buffer (ringbuf consumer memory is read-only)
 *   2. Trims to actual arg_len (from e->exit_code) to remove env var leakage
 *   3. Replaces \0 separators with spaces
 *
 * Returns pointer to a static buffer (NOT thread-safe, single consumer).
 */
static const char *postprocess_full_command(const char *buf, int buf_size, unsigned int arg_len)
{
	static char cmd_buf[MAX_COMMAND_LEN];

	if (arg_len == 0 || arg_len > (unsigned int)(buf_size - 1)) {
		/* No arg_len info: just copy the first null-terminated string */
		int len = 0;
		while (len < buf_size - 1 && buf[len] != '\0')
			len++;
		if (len > 0)
			memcpy(cmd_buf, buf, len);
		cmd_buf[len] = '\0';
		return cmd_buf;
	}

	memcpy(cmd_buf, buf, arg_len);
	cmd_buf[arg_len] = '\0';

	/* Replace \0 separators between argv entries with spaces */
	for (int i = 0; i < (int)arg_len - 1; i++) {
		if (cmd_buf[i] == '\0')
			cmd_buf[i] = ' ';
	}

	return cmd_buf;
}

#endif /* __PROCESS_UTILS_H */
