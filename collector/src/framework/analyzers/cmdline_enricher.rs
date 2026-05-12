// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! `CmdlineEnricher` — global analyzer that injects `full_command` into every
//! event that lacks it.
//!
//! Policy (Plan C):
//!   1. Process-runner EXEC events already carry `full_command` — we copy it
//!      into a shared [`PidCmdlineCache`].
//!   2. Process-runner EXIT events evict the PID from the cache.
//!   3. For any other event that does not already have `data.full_command`,
//!      we look the PID up in the cache. If absent we fall back to
//!      `/proc/<pid>/cmdline` via `PidCmdlineCache::resolve`.
//!   4. If resolution fails (short-lived / gone) we leave the event
//!      untouched — downstream consumers can still fall back to `comm`.
//!
//! The analyzer is intentionally placed as a *global* analyzer on
//! `AgentRunner` so it sits after every per-runner chain and sees the merged
//! event stream.

use super::Analyzer;
use crate::framework::core::{Event, SharedPidCmdlineCache};
use crate::framework::runners::EventStream;
use async_trait::async_trait;
use futures::stream::StreamExt;
use serde_json::Value;

#[derive(Debug)]
pub struct CmdlineEnricher {
    cache: SharedPidCmdlineCache,
}

impl CmdlineEnricher {
    pub fn new(cache: SharedPidCmdlineCache) -> Self {
        Self { cache }
    }

    /// Apply the enrichment policy to a single event in-place.
    fn enrich(cache: &SharedPidCmdlineCache, mut event: Event) -> Event {
        // Only process-source events are authoritative for EXEC/EXIT lifecycle.
        if event.source == "process" {
            match event_kind(&event.data) {
                Some("EXEC") => {
                    // BPF marks cmdline_truncated=true when probe_read_user
                    // failed and full_command holds only `comm`. In that case,
                    // try /proc/<pid>/cmdline as a userspace fallback before
                    // accepting the truncated value (and before polluting the
                    // shared cache).
                    if cmdline_truncated(&event.data) {
                        if let Some(real) = cache.resolve(event.pid) {
                            inject_full_command(&mut event.data, &real);
                            clear_cmdline_truncated(&mut event.data);
                            cache.insert(event.pid, real.as_ref());
                        }
                        // else: keep the comm-only value and the flag, do
                        // NOT insert into cache so trailing events fall back
                        // to /proc lookup themselves rather than re-using a
                        // poisoned value.
                    } else if let Some(cmd) = extract_full_command(&event.data) {
                        cache.insert(event.pid, cmd);
                    }
                    return event;
                }
                Some("EXIT") => {
                    // Do NOT evict on EXIT: process binaries flush pending
                    // FILE_OPEN aggregations for the PID right AFTER the EXIT
                    // event, and /proc/<pid>/cmdline is already gone by then.
                    // Rely on the FIFO bound to reclaim memory. Fall through
                    // to the generic enrichment path so EXIT events that are
                    // missing full_command (BPF truncation, admission race,
                    // etc.) can still be enriched from the cache.
                }
                _ => {}
            }
        }

        // Skip if the event already has a full_command.
        if has_full_command(&event.data) {
            return event;
        }

        if event.pid == 0 {
            return event;
        }

        if let Some(cmd) = cache.resolve(event.pid) {
            inject_full_command(&mut event.data, &cmd);
        }

        event
    }
}

fn event_kind(data: &Value) -> Option<&str> {
    data.get("event").and_then(|v| v.as_str())
}

fn cmdline_truncated(data: &Value) -> bool {
    data.get("cmdline_truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn has_full_command(data: &Value) -> bool {
    data.get("full_command")
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false)
}

fn extract_full_command(data: &Value) -> Option<String> {
    data.get("full_command")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn clear_cmdline_truncated(data: &mut Value) {
    if let Value::Object(map) = data {
        map.remove("cmdline_truncated");
    }
}

fn inject_full_command(data: &mut Value, cmd: &str) {
    if let Value::Object(map) = data {
        map.insert("full_command".to_string(), Value::String(cmd.to_string()));
    }
}

#[async_trait]
impl Analyzer for CmdlineEnricher {
    async fn process(
        &mut self,
        stream: EventStream,
    ) -> Result<EventStream, Box<dyn std::error::Error + Send + Sync>> {
        let cache = self.cache.clone();
        let enriched = stream.map(move |event| Self::enrich(&cache, event));
        Ok(Box::pin(enriched))
    }

    fn name(&self) -> &str {
        "CmdlineEnricher"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::core::PidCmdlineCache;
    use futures::stream;
    use serde_json::json;

    fn make_event(source: &str, pid: u32, data: Value) -> Event {
        Event::new_with_timestamp(0, source.to_string(), pid, "comm".to_string(), data)
    }

    #[tokio::test]
    async fn test_exec_populates_cache() {
        let cache = PidCmdlineCache::new();
        let mut enricher = CmdlineEnricher::new(cache.clone());
        let input = stream::iter(vec![make_event(
            "process",
            1234,
            json!({
                "event": "EXEC",
                "pid": 1234,
                "full_command": "python demo.py --flag",
            }),
        )]);
        let out: Vec<Event> = enricher
            .process(Box::pin(input))
            .await
            .unwrap()
            .collect()
            .await;
        assert_eq!(out.len(), 1);
        assert_eq!(
            cache.get_cached(1234).as_deref(),
            Some("python demo.py --flag")
        );
    }

    #[tokio::test]
    async fn test_injects_full_command_when_missing() {
        let cache = PidCmdlineCache::new();
        cache.insert(999, "bash -c 'sleep 1'");
        let mut enricher = CmdlineEnricher::new(cache);
        let input = stream::iter(vec![make_event(
            "process",
            999,
            json!({"event": "BASH_READLINE", "pid": 999, "command": "ls"}),
        )]);
        let events: Vec<Event> = enricher
            .process(Box::pin(input))
            .await
            .unwrap()
            .collect()
            .await;
        assert_eq!(
            events[0]
                .data
                .get("full_command")
                .and_then(|v| v.as_str())
                .unwrap(),
            "bash -c 'sleep 1'"
        );
    }

    #[tokio::test]
    async fn test_exit_keeps_cache_for_trailing_events() {
        // FILE_OPEN aggregations are flushed *after* EXIT in the BPF source;
        // we must keep the entry around so they can still be enriched.
        let cache = PidCmdlineCache::new();
        cache.insert(7, "proc-cmd");
        let mut enricher = CmdlineEnricher::new(cache.clone());
        let input = stream::iter(vec![make_event(
            "process",
            7,
            json!({"event": "EXIT", "pid": 7}),
        )]);
        let _out: Vec<Event> = enricher
            .process(Box::pin(input))
            .await
            .unwrap()
            .collect()
            .await;
        assert_eq!(cache.get_cached(7).as_deref(), Some("proc-cmd"));
    }

    #[tokio::test]
    async fn test_preserves_existing_full_command() {
        let cache = PidCmdlineCache::new();
        cache.insert(1, "cached-cmd");
        let mut enricher = CmdlineEnricher::new(cache);
        let input = stream::iter(vec![make_event(
            "ssl",
            1,
            json!({"event": "SSL_WRITE", "pid": 1, "full_command": "explicit"}),
        )]);
        let out: Vec<Event> = enricher
            .process(Box::pin(input))
            .await
            .unwrap()
            .collect()
            .await;
        assert_eq!(
            out[0].data.get("full_command").and_then(|v| v.as_str()),
            Some("explicit")
        );
    }
    #[tokio::test]
    async fn test_truncated_exec_does_not_poison_cache() {
        // When BPF marks cmdline_truncated=true and /proc lookup fails
        // (pid does not exist), the cache must NOT be populated with the
        // bare comm value, otherwise downstream FILE_OPEN events for the
        // same PID would inherit a wrong cmdline.
        let cache = PidCmdlineCache::new();
        let mut enricher = CmdlineEnricher::new(cache.clone());
        let input = stream::iter(vec![make_event(
            "process",
            999_999_999, // bogus pid, /proc lookup will fail
            json!({
                "event": "EXEC",
                "pid": 999_999_999,
                "full_command": "sh",
                "cmdline_truncated": true,
            }),
        )]);
        let _out: Vec<Event> = enricher
            .process(Box::pin(input))
            .await
            .unwrap()
            .collect()
            .await;
        assert!(
            cache.get_cached(999_999_999).is_none(),
            "truncated EXEC must not poison cache"
        );
    }

    #[tokio::test]
    async fn test_truncated_exec_falls_back_to_proc_for_self() {
        // Use the current process pid: /proc/<self>/cmdline always exists,
        // so the fallback path should both inject the real cmdline into the
        // event and seed the cache with it.
        let cache = PidCmdlineCache::new();
        let mut enricher = CmdlineEnricher::new(cache.clone());
        let my_pid = std::process::id();
        let input = stream::iter(vec![make_event(
            "process",
            my_pid,
            json!({
                "event": "EXEC",
                "pid": my_pid,
                "full_command": "agentsight",
                "cmdline_truncated": true,
            }),
        )]);
        let out: Vec<Event> = enricher
            .process(Box::pin(input))
            .await
            .unwrap()
            .collect()
            .await;
        let injected = out[0]
            .data
            .get("full_command")
            .and_then(|v| v.as_str())
            .unwrap();
        // The fallback must replace the bare comm with the real cmdline.
        assert!(
            injected.len() >= "agentsight".len(),
            "expected real cmdline (>= bare comm length), got {:?}",
            injected
        );
        assert!(
            cache.get_cached(my_pid).is_some(),
            "successful /proc fallback should seed the cache"
        );
    }

}
