// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::response::{INVALID, Result};
use crate::parser::Format;
use serde_json::Value;

#[derive(Clone, Copy)]
pub(crate) struct Event<'a> {
    pub kind: &'a str,
    pub value: &'a Value,
    pub done: bool,
}

pub struct Framer {
    format: Format,
    event_limit: usize,
    event_bytes: usize,
    pub(crate) largest_event: usize,
    seen: usize,
    line: Vec<u8>,
    data: String,
    name: String,
    first: bool,
    after_cr: bool,
}

impl Framer {
    pub fn new(format: Format, event_limit: usize) -> Self {
        Self {
            format,
            event_limit,
            event_bytes: 0,
            largest_event: 0,
            seen: 0,
            line: vec![],
            data: String::new(),
            name: String::new(),
            first: true,
            after_cr: false,
        }
    }
    pub fn push(&mut self, mut chunk: &[u8], mut emit: impl FnMut(Event<'_>)) -> Result<()> {
        self.seen += chunk.len();
        if self.seen > 64 << 20 {
            return Err("too_large");
        }
        while !chunk.is_empty() {
            if self.after_cr {
                self.after_cr = false;
                if chunk[0] == b'\n' {
                    self.largest_event = self.largest_event.max(self.event_bytes);
                    if self.event_bytes > 0 {
                        self.charge(1)?;
                    }
                    chunk = &chunk[1..];
                    continue;
                }
            }
            let n = memchr::memchr2(b'\r', b'\n', chunk).unwrap_or(chunk.len());
            self.charge(n + usize::from(n < chunk.len()))?;
            self.line.extend_from_slice(&chunk[..n]);
            if n == chunk.len() {
                break;
            }
            self.after_cr = chunk[n] == b'\r';
            self.end_line(&mut emit)?;
            chunk = &chunk[n + 1..];
        }
        Ok(())
    }
    fn charge(&mut self, n: usize) -> Result<()> {
        self.event_bytes += n;
        self.largest_event = self.largest_event.max(self.event_bytes);
        if self.event_bytes > self.event_limit {
            Err("too_large")
        } else {
            Ok(())
        }
    }
    fn end_line(&mut self, emit: &mut impl FnMut(Event<'_>)) -> Result<()> {
        let mut line = std::str::from_utf8(&self.line).map_err(|_| "invalid_sse")?;
        if self.first {
            line = line.strip_prefix('\u{feff}').unwrap_or(line);
            self.first = false;
        }
        if line.is_empty() {
            self.event_bytes = 0;
            if !self.data.is_empty() {
                self.data.pop();
                let raw = self.data.trim();
                let done = raw == "[DONE]";
                let v = if done {
                    Value::Null
                } else {
                    let value: Value = serde_json::from_str(raw).map_err(|_| "invalid_json")?;
                    if !value.is_object() {
                        return Err("invalid_json");
                    }
                    value
                };
                let kind = match self.format {
                    Format::OpenaiChatCompletions => "",
                    Format::AnthropicMessages if done => return Err("invalid_json"),
                    Format::OpenaiResponses if done => "",
                    Format::AnthropicMessages | Format::OpenaiResponses => {
                        let kind = v["type"].as_str().ok_or(INVALID)?;
                        let default_event = self.format == Format::OpenaiResponses
                            && (self.name.is_empty() || self.name == "message");
                        if !default_event && kind != self.name {
                            return Err(INVALID);
                        }
                        kind
                    }
                    _ => unreachable!("LLM SSE parser requires an LLM protocol"),
                };
                emit(Event {
                    kind,
                    value: &v,
                    done,
                });
            }
            self.data.clear();
            self.name.clear();
        } else {
            let (field, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            match field {
                "event" => {
                    self.name.clear();
                    self.name.push_str(value);
                }
                "data" => {
                    self.data.push_str(value);
                    self.data.push('\n');
                }
                _ => {}
            }
        }
        self.line.clear();
        Ok(())
    }
}
