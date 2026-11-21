// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

mod anthropic;
mod chat;
mod responses;

use crate::parser::llm::response::{INVALID, Result};
use crate::parser::llm::{ANTHROPIC, CHAT, RESPONSES};
use serde_json::Value;
use std::collections::BTreeMap;

enum Provider {
    Chat(chat::Stream),
    Anthropic(anthropic::Stream),
    Responses(responses::Stream),
}

// Retain output independently of framing. A late usage event is still processed
// after content has been discarded, as are malformed transitions.
struct Retention {
    response_id: Option<String>,
    tools: crate::parser::llm::tool_summary::ToolSummary,
    limit: usize,
    room: usize,
    // Keep visible text independently: a large tool call may exhaust message
    // retention before the assistant produces its answer.
    answer: BTreeMap<u32, String>,
    answer_bytes: usize,
    answer_overflow: bool,
    chat_assistant: bool,
    truncated: bool,
    partial: bool,
    items: usize,
}
impl Retention {
    fn visible(&mut self, index: u32, text: &str) {
        if self.answer_overflow || text.is_empty() {
            return;
        }
        if text.len() > self.limit - self.answer_bytes {
            self.answer.clear();
            self.answer_overflow = true;
            return;
        }
        self.answer_bytes += text.len();
        self.answer.entry(index).or_default().push_str(text);
    }

    fn reset_answer(&mut self) {
        self.answer.clear();
        self.answer_bytes = 0;
        self.answer_overflow = false;
    }

    fn response_id(&mut self, id: &Value) {
        if self.response_id.is_none()
            && let Some(id) = id.as_str()
        {
            self.response_id = Some(id.into());
        }
    }
    fn retaining(&self) -> bool {
        !self.partial && !self.truncated
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
}
impl Stream {
    pub fn new(format: &str, room: usize) -> Self {
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
                answer: BTreeMap::new(),
                answer_bytes: 0,
                answer_overflow: false,
                chat_assistant: true,
                response_id: None,
                tools: crate::parser::llm::tool_summary::ToolSummary::new(room),
                truncated: false,
                partial: false,
                items: 0,
            },
        }
    }

    pub fn event(&mut self, event: crate::parser::llm::sse::Event<'_>) -> Result<()> {
        let retaining = self.budget.retaining();
        match &mut self.provider {
            Provider::Chat(s) => s.add(event.value, event.done, &mut self.budget)?,
            Provider::Anthropic(s) => {
                s.add(event.kind, event.value, &mut self.budget)?;
            }
            Provider::Responses(s) => {
                s.add(event.kind, event.value, event.done, &mut self.budget)?
            }
        }
        if retaining && !self.budget.retaining() {
            match &mut self.provider {
                Provider::Chat(s) => s.discard_content(),
                Provider::Anthropic(s) => s.discard_content(),
                Provider::Responses(s) => s.discard_content(),
            }
        }
        Ok(())
    }
    pub fn finish(self) -> Result<(bool, Value)> {
        let keep = self.budget.retaining();
        let mut result = match self.provider {
            Provider::Chat(s) => s.finish(keep)?,
            Provider::Anthropic(s) => s.finish(keep)?,
            Provider::Responses(s) => s.finish(keep)?,
        };
        if !self.budget.partial && result.get("error").is_none() && !self.budget.answer_overflow {
            let text = if self.budget.chat_assistant {
                self.budget.answer.into_values().collect::<String>()
            } else {
                String::new()
            };
            result["answer"] = text.into();
        }
        if let Some(id) = self.budget.response_id {
            result["responseId"] = id.into();
        }
        self.budget.tools.publish(&mut result);
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
