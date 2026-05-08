// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! PID -> full command-line cache.
//!
//! Many event sources (`FILE_OPEN`, `BASH_READLINE`, ssl, stdio) only carry the
//! 16-byte thread name (`comm`). Callers often want the full `argv` string for
//! context. This module maintains a bounded in-process cache keyed on PID.
//!
//! Population strategy:
//!   1. Primary: `ProcessRunner` EXEC events carry `full_command` — the
//!      `CmdlineEnricher` analyzer shoves each observed value into the cache.
//!   2. Fallback: when an event references a PID we have not seen, read
//!      `/proc/<pid>/cmdline` on demand. The result (possibly empty for
//!      short-lived processes) is memoised.
//!
//! Eviction strategy:
//!   * Explicit: on EXIT events, remove the entry.
//!   * Implicit: a FIFO bound (`max_entries`) drops the oldest entry when full.
//!     We intentionally keep this simple (VecDeque + HashMap) instead of pulling
//!     in a `lru` crate dependency.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::sync::{Arc, Mutex};

/// Default upper bound on entries kept in RAM. A cmdline line is usually well
/// below 4 KiB, so 16k entries is ~< 64 MiB worst case.
const DEFAULT_MAX_ENTRIES: usize = 16_384;

/// Maximum bytes we keep per cmdline. Matches the BPF-side cap plus a small
/// margin so a userspace-resolved cmdline can surface extra args the BPF
/// truncated. Keep aligned with `MAX_COMMAND_LEN` in `bpf/process.h`.
const MAX_CMDLINE_BYTES: usize = 1024;

/// Clone-cheap shared handle.
pub type SharedPidCmdlineCache = Arc<PidCmdlineCache>;

#[derive(Debug)]
struct Inner {
    /// pid -> cmdline (already sanitised, NUL replaced with space).
    map: HashMap<u32, Arc<str>>,
    /// Insertion order for FIFO eviction.
    order: VecDeque<u32>,
    max_entries: usize,
}

#[derive(Debug)]
pub struct PidCmdlineCache {
    inner: Mutex<Inner>,
}

impl PidCmdlineCache {
    pub fn new() -> SharedPidCmdlineCache {
        Self::with_capacity(DEFAULT_MAX_ENTRIES)
    }

    pub fn with_capacity(max_entries: usize) -> SharedPidCmdlineCache {
        let cap = max_entries.max(64);
        Arc::new(Self {
            inner: Mutex::new(Inner {
                map: HashMap::with_capacity(cap.min(4096)),
                order: VecDeque::with_capacity(cap.min(4096)),
                max_entries: cap,
            }),
        })
    }

    /// Record an authoritative cmdline for `pid`. Usually called from the EXEC
    /// branch of the process event stream.
    pub fn insert(&self, pid: u32, cmdline: impl Into<String>) {
        let cleaned = sanitize_cmdline(cmdline.into());
        if cleaned.is_empty() {
            return;
        }
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // If already present just refresh the value (do not re-order — we
        // only care that the entry is present).
        let arc: Arc<str> = Arc::from(cleaned);
        if guard.map.insert(pid, arc).is_none() {
            guard.order.push_back(pid);
            let max = guard.max_entries;
            while guard.order.len() > max {
                if let Some(evict_pid) = guard.order.pop_front() {
                    guard.map.remove(&evict_pid);
                }
            }
        }
    }

    /// Lookup without triggering the `/proc` fallback.
    pub fn get_cached(&self, pid: u32) -> Option<Arc<str>> {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.map.get(&pid).cloned()
    }

    /// Resolve the cmdline, falling back to `/proc/<pid>/cmdline` on miss.
    /// Returns `None` only if the process is gone and we never observed it.
    pub fn resolve(&self, pid: u32) -> Option<Arc<str>> {
        if let Some(cached) = self.get_cached(pid) {
            return Some(cached);
        }
        let cmdline = read_proc_cmdline(pid)?;
        self.insert(pid, cmdline);
        self.get_cached(pid)
    }

    /// Drop an entry. Currently unused (FIFO handles reclamation), but kept
    /// on the public API for future explicit-eviction callers.
    #[allow(dead_code)]
    pub fn forget(&self, pid: u32) {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if guard.map.remove(&pid).is_some() {
            if let Some(pos) = guard.order.iter().position(|p| *p == pid) {
                guard.order.remove(pos);
            }
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.map.len()).unwrap_or(0)
    }
}

/// Read `/proc/<pid>/cmdline`, converting the NUL separators to spaces.
fn read_proc_cmdline(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/cmdline", pid);
    let raw = fs::read(path).ok()?;
    if raw.is_empty() {
        // Kernel threads / zombie tasks have empty cmdline. Treat as miss so
        // callers can fall back to `comm`.
        return None;
    }
    Some(bytes_to_cmdline(&raw))
}

fn bytes_to_cmdline(raw: &[u8]) -> String {
    // /proc/<pid>/cmdline is NUL-separated, with a trailing NUL.
    let trimmed = match raw.last() {
        Some(0) => &raw[..raw.len() - 1],
        _ => raw,
    };
    let mut out = String::with_capacity(trimmed.len().min(MAX_CMDLINE_BYTES));
    for &byte in trimmed.iter().take(MAX_CMDLINE_BYTES) {
        let ch = if byte == 0 { b' ' } else { byte };
        // cmdline can technically contain arbitrary bytes; push through
        // lossy decoding to stay valid UTF-8 downstream.
        out.push(ch as char);
    }
    sanitize_cmdline(out)
}

/// Replace embedded NULs with spaces, trim whitespace, cap length.
fn sanitize_cmdline(mut s: String) -> String {
    if s.contains('\0') {
        s = s.replace('\0', " ");
    }
    let trimmed = s.trim();
    if trimmed.len() > MAX_CMDLINE_BYTES {
        // Truncate on a UTF-8 char boundary.
        let mut end = MAX_CMDLINE_BYTES;
        while end > 0 && !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        return trimmed[..end].to_string();
    }
    if trimmed.len() == s.len() {
        s
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_get() {
        let cache = PidCmdlineCache::new();
        cache.insert(42, "python demo.py --flag");
        assert_eq!(cache.get_cached(42).as_deref(), Some("python demo.py --flag"));
        assert_eq!(cache.get_cached(99), None);
    }

    #[test]
    fn test_forget() {
        let cache = PidCmdlineCache::new();
        cache.insert(1, "a");
        cache.forget(1);
        assert_eq!(cache.get_cached(1), None);
    }

    #[test]
    fn test_fifo_eviction() {
        let cache = PidCmdlineCache::with_capacity(64);
        for pid in 0..200u32 {
            cache.insert(pid, format!("cmd-{}", pid));
        }
        assert!(cache.len() <= 64);
        // Newest entries must still be present.
        assert!(cache.get_cached(199).is_some());
        // Oldest entries must have been evicted.
        assert!(cache.get_cached(0).is_none());
    }

    #[test]
    fn test_bytes_to_cmdline_replaces_nuls() {
        let raw = b"python\0demo.py\0--flag\0";
        assert_eq!(bytes_to_cmdline(raw), "python demo.py --flag");
    }

    #[test]
    fn test_sanitize_embedded_nul() {
        let cache = PidCmdlineCache::new();
        cache.insert(7, "python\0demo.py");
        assert_eq!(cache.get_cached(7).as_deref(), Some("python demo.py"));
    }

    #[test]
    fn test_empty_cmdline_ignored() {
        let cache = PidCmdlineCache::new();
        cache.insert(1, "");
        cache.insert(2, "   ");
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_resolve_uses_proc_fallback_for_self() {
        let cache = PidCmdlineCache::new();
        let pid = std::process::id();
        let resolved = cache.resolve(pid);
        assert!(
            resolved.is_some(),
            "resolve() should fall back to /proc/self/cmdline"
        );
    }
}
