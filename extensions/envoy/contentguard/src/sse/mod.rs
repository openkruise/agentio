// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

mod anthropic;
mod chat;
mod responses;

use crate::protocol::{ANTHROPIC, CHAT, RESPONSES};
use crate::response::{INVALID, Result};
use serde_json::Value;

enum Provider {
    Chat(chat::Stream),
    Anthropic(anthropic::Stream),
    Responses(responses::Stream),
}

// Retain output independently of framing. A late usage event is still processed
// after content has been discarded, as are malformed transitions.
struct Retention {
    response_id: Option<String>,
    tools: Option<crate::tool_summary::ToolSummary>,
    limit: usize,
    room: usize,
    enabled: bool,
    truncated: bool,
    partial: bool,
    items: usize,
}
impl Retention {
    fn response_id(&mut self, id: &Value) {
        if self.response_id.is_none()
            && let Some(id) = id.as_str()
        {
            self.response_id = Some(id.into());
        }
    }
    fn retaining(&self) -> bool {
        self.enabled && !self.truncated
    }

    fn take(&mut self, n: usize) -> bool {
        if !self.retaining() {
            return false;
        }
        if n > self.room {
            self.truncated = true;
            return false;
        }
        self.room -= n;
        true
    }
    fn item(&mut self) -> Result<()> {
        self.items += 1;
        if self.items > 1024 {
            Err("too_large")
        } else {
            Ok(())
        }
    }
    fn append(&mut self, dst: &mut String, s: &str) {
        if self.take(s.len()) {
            dst.push_str(s);
        }
    }
}

pub struct Stream {
    provider: Provider,
    budget: Retention,
    event_limit: usize,
    event_bytes: usize,
    seen: usize,
    line: Vec<u8>,
    data: String,
    name: String,
    first: bool,
    after_cr: bool,
}

impl Stream {
    pub fn new(
        format: &str,
        event_limit: usize,
        room: usize,
        fields: crate::Fields,
        log_limit: usize,
    ) -> Self {
        let provider = match format {
            CHAT => Provider::Chat(Default::default()),
            ANTHROPIC => Provider::Anthropic(Default::default()),
            RESPONSES => Provider::Responses(Default::default()),
            _ => unreachable!("SSE requires an LLM format"),
        };
        Self {
            provider,
            budget: Retention {
                limit: room,
                room,
                enabled: fields.output_messages,
                response_id: None,
                tools: fields
                    .tool_calls
                    .then(|| crate::tool_summary::ToolSummary::new(log_limit)),
                truncated: false,
                partial: false,
                items: 0,
            },
            event_limit,
            event_bytes: 0,
            seen: 0,
            line: vec![],
            data: String::new(),
            name: String::new(),
            first: true,
            after_cr: false,
        }
    }
    pub fn push(&mut self, mut chunk: &[u8]) -> Result<()> {
        self.seen += chunk.len();
        if self.seen > 64 << 20 {
            return Err("too_large");
        }
        while !chunk.is_empty() {
            if self.after_cr {
                self.after_cr = false;
                if chunk[0] == b'\n' {
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
            self.end_line()?;
            chunk = &chunk[n + 1..];
        }
        Ok(())
    }
    fn charge(&mut self, n: usize) -> Result<()> {
        self.event_bytes += n;
        if self.event_bytes > self.event_limit {
            Err("too_large")
        } else {
            Ok(())
        }
    }
    fn end_line(&mut self) -> Result<()> {
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
                let retaining = self.budget.retaining();
                match &mut self.provider {
                    Provider::Chat(s) => s.add(&v, done, &mut self.budget)?,
                    Provider::Anthropic(s) => {
                        if done {
                            return Err("invalid_json");
                        }
                        s.add(&self.name, &v, raw, &mut self.budget)?;
                    }
                    Provider::Responses(s) => s.add(&self.name, &v, raw, done, &mut self.budget)?,
                }
                if self.budget.partial {
                    self.budget.enabled = false;
                }
                if retaining && !self.budget.retaining() {
                    match &mut self.provider {
                        Provider::Chat(s) => s.discard_content(),
                        Provider::Anthropic(s) => s.discard_content(),
                        Provider::Responses(s) => s.discard_content(),
                    }
                }
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
    pub fn finish(self) -> Result<(bool, Value)> {
        let keep = self.budget.retaining();
        let mut result = match self.provider {
            Provider::Chat(s) => s.finish(keep)?,
            Provider::Anthropic(s) => s.finish(keep)?,
            Provider::Responses(s) => s.finish(keep)?,
        };
        if let Some(id) = self.budget.response_id {
            result["responseId"] = id.into();
        }
        if let Some(tools) = self.budget.tools {
            tools.publish(&mut result);
        }
        if self.budget.partial {
            result["partial"] = true.into();
        }
        if self.budget.truncated {
            result["truncated"] = true.into();
        }
        Ok((self.budget.truncated, result))
    }
}

fn string(v: &Value) -> Result<&str> {
    v.as_str().ok_or(INVALID)
}
fn obj(v: &Value) -> Result<&serde_json::Map<String, Value>> {
    v.as_object().ok_or(INVALID)
}
fn unknown(v: &Value, keys: &[&str], ignore_null: bool) -> bool {
    v.as_object().is_some_and(|m| {
        m.iter()
            .any(|(k, v)| !(keys.contains(&k.as_str()) || ignore_null && v.is_null()))
    })
}
