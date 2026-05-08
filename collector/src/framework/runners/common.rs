// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

use crate::framework::analyzers::Analyzer;
use super::{EventStream, RunnerError};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use log::debug;
use futures::stream::Stream;
use std::pin::Pin;




/// Decode a raw line (bytes) as UTF-8 with U+FFFD replacement on invalid sequences.
/// This keeps BPF-truncated multi-byte chars from causing the entire event to drop.
fn lossy_decode_line(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).into_owned()
}

/// Try to parse a trimmed line as a JSON object. Returns None if it does not look
/// like a JSON object at all (so callers can short-circuit before invoking serde).
fn parse_json_line(trimmed: &str) -> Option<Result<serde_json::Value, serde_json::Error>> {
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        Some(serde_json::from_str(trimmed))
    } else {
        None
    }
}

/// Truncate a string for log preview, respecting char (not byte) boundaries to
/// avoid splitting multi-byte UTF-8 sequences.
fn truncate_for_log(s: &str, max_chars: usize) -> String {
    if s.chars().count() > max_chars {
        let head: String = s.chars().take(max_chars).collect();
        format!("{}...", head)
    } else {
        s.to_string()
    }
}

/// Type alias for JSON stream
pub type JsonStream = Pin<Box<dyn Stream<Item = serde_json::Value> + Send>>;

/// Common binary executor for runners - now supports streaming
pub struct BinaryExecutor {
    binary_path: String,
    additional_args: Vec<String>,
    runner_name: Option<String>,
}

impl BinaryExecutor {
    pub fn new(binary_path: String) -> Self {
        Self { 
            binary_path,
            additional_args: Vec::new(),
            runner_name: None,
        }
    }

    /// Add additional command-line arguments
    pub fn with_args(mut self, args: &[String]) -> Self {
        self.additional_args = args.to_vec();
        self
    }

    /// Set runner name for debugging purposes
    pub fn with_runner_name(mut self, name: String) -> Self {
        self.runner_name = Some(name);
        self
    }

    /// Execute binary and get raw JSON stream
    pub async fn get_json_stream(&self) -> Result<JsonStream, RunnerError> {
        // Log the actual exec command with all arguments
        if self.additional_args.is_empty() {
            log::info!("Executing binary: {}", self.binary_path);
        } else {
            log::info!("Executing binary: {} {}", self.binary_path, self.additional_args.join(" "));
        }
        
        let mut cmd = TokioCommand::new(&self.binary_path);
        cmd.stdout(Stdio::piped())
           .stderr(Stdio::piped());
        
        // Add additional arguments if any
        if !self.additional_args.is_empty() {
            cmd.args(&self.additional_args);
            debug!("Added arguments: {:?}", self.additional_args);
        }
        
        let mut child = cmd.spawn()
            .map_err(|e| Box::new(std::io::Error::new(
                std::io::ErrorKind::Other, 
                format!("Failed to start binary: {}", e)
            )) as RunnerError)?;
            
        let stdout = child.stdout.take()
            .ok_or_else(|| Box::new(std::io::Error::new(
                std::io::ErrorKind::Other, 
                "Failed to get stdout"
            )) as RunnerError)?;
        
        let stderr = child.stderr.take()
            .ok_or_else(|| Box::new(std::io::Error::new(
                std::io::ErrorKind::Other, 
                "Failed to get stderr"
            )) as RunnerError)?;
        
        if let Some(pid) = child.id() {
            debug!("Binary started with PID: Some({})", pid);
        }
        
        // Clone needed data for the stream
        let runner_name = self.runner_name.clone();
        let binary_path = self.binary_path.clone();
        
        // Spawn a task to read and log stderr
        let stderr_runner_name = runner_name.clone();
        let stderr_binary_path = binary_path.clone();
        tokio::spawn(async move {
            let mut stderr_reader = BufReader::new(stderr);
            let mut stderr_line = String::new();
            
            loop {
                stderr_line.clear();
                match stderr_reader.read_line(&mut stderr_line).await {
                    Ok(0) => {
                        // EOF reached
                        break;
                    }
                    Ok(_) => {
                        let trimmed = stderr_line.trim();
                        if !trimmed.is_empty() {
                            // Log stderr output as ERROR for visibility
                            let runner_info = stderr_runner_name.as_ref()
                                .map(|name| format!("[{}] ", name))
                                .unwrap_or_else(|| format!("[{}] ", 
                                    std::path::Path::new(&stderr_binary_path)
                                        .file_name()
                                        .and_then(|n| n.to_str())
                                        .unwrap_or("unknown")
                                ));
                            
                            // Check severity of the message
                            if trimmed.contains("Failed") || trimmed.contains("Error") || 
                               trimmed.contains("cannot") || trimmed.contains("permission denied") {
                                log::error!("{}{}", runner_info, trimmed);
                            } else if trimmed.contains("warn") || trimmed.contains("Warning") {
                                log::warn!("{}{}", runner_info, trimmed);
                            } else {
                                log::info!("{}{}", runner_info, trimmed);
                            }
                        }
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::UnexpectedEof {
                            log::warn!("Error reading stderr: {}", e);
                        }
                        break;
                    }
                }
            }
        });

        let stream = async_stream::stream! {
            let mut reader = BufReader::new(stdout);
            let mut buf: Vec<u8> = Vec::with_capacity(4096);
            let mut line_count = 0u64;

            debug!("Reading from binary stdout");

            loop {
                buf.clear();

                match reader.read_until(b'\n', &mut buf).await {
                    Ok(0) => {
                        debug!("Binary stdout closed (EOF)");
                        break;
                    }
                    Ok(_) => {
                        line_count += 1;
                        // Always lossy-decode so BPF-truncated multi-byte UTF-8
                        // chars become U+FFFD instead of dropping the event.
                        let line = lossy_decode_line(&buf);
                        let trimmed = line.trim();

                        if trimmed.is_empty() {
                            continue;
                        }

                        debug!("Line {}: {}", line_count, truncate_for_log(trimmed, 100));

                        match parse_json_line(trimmed) {
                            Some(Ok(json_value)) => {
                                debug!("Parsed JSON value");
                                yield json_value;
                            }
                            Some(Err(e)) => {
                                log::warn!(
                                    "Failed to parse JSON from line {}: {} - Line: {}",
                                    line_count,
                                    e,
                                    truncate_for_log(trimmed, 200)
                                );
                            }
                            None => {
                                if trimmed.contains("error") || trimmed.contains("warn")
                                    || trimmed.contains("failed") || trimmed.contains("Error:")
                                {
                                    log::warn!(
                                        "Possible error message from binary at line {}: {}",
                                        line_count, trimmed
                                    );
                                } else {
                                    log::warn!(
                                        "Skipping non-JSON line {} from binary: {}",
                                        line_count,
                                        truncate_for_log(trimmed, 100)
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::Interrupted {
                            log::debug!("Read interrupted, retrying...");
                            continue;
                        }
                        if e.kind() == std::io::ErrorKind::UnexpectedEof {
                            // Try to flush trailing partial line (no newline at EOF).
                            if !buf.is_empty() {
                                let line = lossy_decode_line(&buf);
                                let trimmed = line.trim();
                                if let Some(Ok(json_value)) = parse_json_line(trimmed) {
                                    log::debug!("Parsed final JSON line at EOF");
                                    yield json_value;
                                }
                            }
                            log::debug!("Reached EOF while reading");
                            break;
                        }
                        let runner_info = runner_name.as_ref()
                            .map(|name| format!("[{}] ", name))
                            .unwrap_or_else(|| format!("[{}] ",
                                std::path::Path::new(&binary_path)
                                    .file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("unknown")
                            ));
                        log::warn!(
                            "{}Error reading from binary: {} (kind: {:?})",
                            runner_info, e, e.kind()
                        );
                        break;
                    }
                }
            }

            log::info!("Terminating binary process");

            if let Err(e) = child.kill().await {
                log::warn!("Failed to kill binary process: {}", e);
            }

            match child.wait().await {
                Ok(status) => {
                    debug!("Binary process terminated with status: {}", status);
                }
                Err(e) => {
                    log::warn!("Error waiting for binary process: {}", e);
                }
            }
        };
        
                Ok(Box::pin(stream))
    }



}

/// Common analyzer processor for runners
pub struct AnalyzerProcessor;

impl AnalyzerProcessor {
    /// Process events through a chain of analyzers
    pub async fn process_through_analyzers(
        mut stream: EventStream, 
        analyzers: &mut [Box<dyn Analyzer>]
    ) -> Result<EventStream, RunnerError> {
        // Process through each analyzer in sequence
        for analyzer in analyzers.iter_mut() {
            stream = analyzer.process(stream).await?;
        }
        
        Ok(stream)
    }
}

#[cfg(test)]
mod common_helpers_tests {
    use super::{lossy_decode_line, parse_json_line, truncate_for_log};

    #[test]
    fn test_lossy_decode_truncated_chinese() {
        // "这" is E8 BF 99. Cut after 2 bytes (mid-codepoint).
        let raw = b"\xe8\xbf";
        let s = lossy_decode_line(raw);
        assert!(s.contains('\u{FFFD}'));
    }

    #[test]
    fn test_lossy_decode_keeps_full_chinese() {
        let raw = "你好".as_bytes();
        assert_eq!(lossy_decode_line(raw), "你好");
    }

    #[test]
    fn test_parse_json_with_replacement_char() {
        // U+FFFD is a valid JSON string codepoint.
        let line = "{\"cmd\":\"echo \u{FFFD}\"}";
        let r = parse_json_line(line).expect("looks like JSON");
        assert!(r.is_ok());
    }

    #[test]
    fn test_parse_json_full_chinese_intact() {
        let line = "{\"cmd\":\"echo 你好\"}";
        let r = parse_json_line(line).expect("looks like JSON");
        let v = r.unwrap();
        assert_eq!(v["cmd"], "echo 你好");
    }

    #[test]
    fn test_parse_json_non_json_returns_none() {
        assert!(parse_json_line("not json").is_none());
        assert!(parse_json_line("{not closed").is_none());
    }

    #[test]
    fn test_truncate_for_log_respects_char_boundary() {
        // 5 chinese chars, ask for 3 -> "你好世..."
        let s = "你好世界吗";
        let t = truncate_for_log(s, 3);
        assert_eq!(t, "你好世...");
        // Short string passes through.
        assert_eq!(truncate_for_log("ab", 5), "ab");
    }
}
