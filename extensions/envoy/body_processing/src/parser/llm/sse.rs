// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::response::{INVALID, Result};
use crate::parser::Format;
use serde_json::Value;

// Reuse ordinary frame buffers across deltas. Release outliers after dispatch.
const MAX_REUSABLE_CAPACITY: usize = 64 * 1024;

#[derive(Clone, Copy)]
pub(crate) struct Event<'a> {
    pub kind: &'a str,
    pub value: &'a Value,
    pub done: bool,
}

pub struct Framer {
    format: Format,
    seen: usize,
    line: Vec<u8>,
    data: String,
    name: String,
    first: bool,
    after_cr: bool,
}

impl Framer {
    pub fn new(format: Format) -> Self {
        Self {
            format,
            seen: 0,
            line: vec![],
            data: String::new(),
            name: String::new(),
            first: true,
            after_cr: false,
        }
    }
    pub fn push(
        &mut self,
        mut chunk: &[u8],
        mut emit: impl FnMut(Event<'_>) -> Result<()>,
    ) -> Result<()> {
        self.seen += chunk.len();
        if self.seen > 64 << 20 {
            return Err("too_large");
        }
        while !chunk.is_empty() {
            if self.after_cr {
                self.after_cr = false;
                if chunk[0] == b'\n' {
                    chunk = &chunk[1..];
                    continue;
                }
            }
            let n = memchr::memchr2(b'\r', b'\n', chunk).unwrap_or(chunk.len());
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
    fn end_line(&mut self, emit: &mut impl FnMut(Event<'_>) -> Result<()>) -> Result<()> {
        let mut line = std::str::from_utf8(&self.line).map_err(|_| "invalid_sse")?;
        if self.first {
            line = line.strip_prefix('\u{feff}').unwrap_or(line);
            self.first = false;
        }
        if line.is_empty() {
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
                })?;
            }
            self.data.clear();
            self.name.clear();
            if self.data.capacity() > MAX_REUSABLE_CAPACITY {
                self.data = String::new();
            }
            if self.name.capacity() > MAX_REUSABLE_CAPACITY {
                self.name = String::new();
            }
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
        if self.line.capacity() > MAX_REUSABLE_CAPACITY {
            self.line = Vec::new();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_releases_large_frame_buffers_and_accepts_the_next_frame() {
        let mut framer = Framer::new(Format::OpenaiChatCompletions);
        let body = format!("data: {{\"text\":\"{}\"}}\n\n", "x".repeat(4 << 20));
        let mut sizes = Vec::new();
        let mut emit = |e: Event<'_>| {
            sizes.push(e.value["text"].as_str().unwrap().len());
            Ok(())
        };
        for part in body.as_bytes().chunks(16 << 10) {
            framer.push(part, &mut emit).unwrap();
        }
        assert!(framer.line.capacity() <= MAX_REUSABLE_CAPACITY);
        assert!(framer.data.capacity() <= MAX_REUSABLE_CAPACITY);
        framer.push(b"data: {\"text\":\"ok\"}\n\n", emit).unwrap();
        assert_eq!(sizes, [4 << 20, 2]);
    }
}
