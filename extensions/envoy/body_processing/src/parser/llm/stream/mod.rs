// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

mod anthropic;
mod chat;
mod responses;

use super::sse;
use crate::parser::BodyError;
use crate::parser::llm::response::Result;
use crate::parser::llm::{ANTHROPIC, CHAT, LlmView, RESPONSES};
use serde_json::Value;

/// An output keeps its wire index even when it is an alternative to the scalar answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Output {
    pub(crate) index: u32,
    pub(crate) answer_candidate: bool,
}

impl Output {
    pub(crate) fn new(protocol: &str, index: u32) -> Self {
        Self {
            index,
            answer_candidate: super::answer_candidate(protocol, index.into()),
        }
    }
}

/// Borrowed updates are delivered synchronously while decoding a complete SSE frame.
pub(crate) enum Event<'a> {
    // A provisional delta is followed by an authoritative OutputItem snapshot.
    TextDelta {
        output: Output,
        part: Option<u32>,
        text: &'a str,
        provisional: bool,
    },
    Usage(&'a Value),
    // Responses seals each output item and may replace the entire output at completion.
    OutputItem {
        output: Output,
        message: &'a Value,
    },
    ReplaceOutput,
    // Provider-specific lifecycle and content changes, including tool argument deltas.
    #[allow(dead_code)] // Available to filters interested in native tool and lifecycle events.
    Detail {
        kind: &'a str,
        value: &'a Value,
    },
    Completed {
        view: &'a LlmView,
        truncated: bool,
        answer: AnswerStatus,
    },
}
#[derive(Clone, Copy)]
pub(crate) enum AnswerStatus {
    Visible,
    Empty,
    Unavailable,
}

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
    chat_assistant: bool,
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
            Err(BodyError::TooLarge)
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
    active: Option<(Provider, Retention)>,
    trailers: Trailers,
}

// Some protocols allow a transport sentinel or keepalive after their semantic terminator.
enum Trailers {
    None,
    Done,
    Ping,
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
            active: Some((
                provider,
                Retention {
                    limit: room,
                    room,
                    chat_assistant: true,
                    response_id: None,
                    tools: crate::parser::llm::tool_summary::ToolSummary::new(room),
                    truncated: false,
                    partial: false,
                    items: 0,
                },
            )),
            trailers: Trailers::None,
        }
    }

    pub fn event(&mut self, frame: sse::Event<'_>, emit: &mut impl FnMut(Event<'_>)) -> Result<()> {
        let Some((provider, budget)) = &mut self.active else {
            return match self.trailers {
                Trailers::Done if frame.done => Ok(()),
                Trailers::Ping if frame.kind == "ping" => Ok(()),
                _ => Err(BodyError::InvalidContent),
            };
        };
        let retaining = budget.retaining();
        let terminal = match provider {
            Provider::Chat(s) => s.add(frame.value, frame.done, budget, emit)?,
            Provider::Anthropic(s) => s.add(frame.kind, frame.value, budget, emit)?,
            Provider::Responses(s) => s.add(frame.kind, frame.value, frame.done, budget, emit)?,
        };
        if let Some(trailers) = terminal {
            self.trailers = trailers;
            let (provider, budget) = self.active.take().unwrap();
            let keep = budget.retaining();
            let mut view = match provider {
                Provider::Chat(s) => s.finish(keep)?,
                Provider::Anthropic(s) => s.finish(keep)?,
                Provider::Responses(s) => s.finish(keep)?,
            };
            if let Some(id) = budget.response_id {
                view["responseId"] = id.into();
            }
            let answer = if budget.partial || view.get("error").is_some() {
                AnswerStatus::Unavailable
            } else if budget.chat_assistant {
                AnswerStatus::Visible
            } else {
                AnswerStatus::Empty
            };
            emit(Event::Completed {
                view: &LlmView {
                    document: view,
                    tool_refs: budget.tools.finish(),
                    partial: budget.partial,
                    ..Default::default()
                },
                truncated: budget.truncated,
                answer,
            });
        } else if retaining && !budget.retaining() {
            match provider {
                Provider::Chat(s) => s.discard_content(),
                Provider::Anthropic(s) => s.discard_content(),
                Provider::Responses(s) => s.discard_content(),
            }
        }
        Ok(())
    }

    /// Metadata observed before a stream ended without its protocol terminator.
    pub fn into_partial(self) -> Option<(LlmView, bool)> {
        let (provider, retention) = self.active?;
        let mut view = match provider {
            Provider::Responses(s) => s
                .view
                .unwrap_or_else(|| serde_json::json!({"format": RESPONSES})),
            Provider::Chat(s) => s.observed(),
            Provider::Anthropic(s) => s.observed(),
        };
        if let Some(id) = retention.response_id {
            view["responseId"] = id.into();
        }
        let visible = retention.chat_assistant && !retention.partial && view.get("error").is_none();
        Some((
            LlmView {
                document: view,
                tool_refs: retention.tools.finish(),
                ..Default::default()
            },
            visible,
        ))
    }
}

fn observed_view(
    format: &str,
    model: Option<String>,
    error: Option<Value>,
    reasons: impl IntoIterator<Item = String>,
) -> Value {
    let mut view = serde_json::json!({ "format": format });
    if let Some(model) = model {
        view["model"] = model.into();
    }
    if let Some(error) = error {
        view["error"] = error;
    }
    let reasons: Vec<_> = reasons.into_iter().collect();
    if !reasons.is_empty() {
        view["finishReasons"] = reasons.into();
    }
    view
}

fn string(v: &Value) -> Result<&str> {
    v.as_str().ok_or(BodyError::InvalidContent)
}
fn obj(v: &Value) -> Result<&serde_json::Map<String, Value>> {
    v.as_object().ok_or(BodyError::InvalidContent)
}
fn unknown(v: &Value, keys: &[&str], ignore_null: bool) -> bool {
    v.as_object().is_some_and(|m| {
        m.iter()
            .any(|(k, v)| !(keys.contains(&k.as_str()) || ignore_null && v.is_null()))
    })
}
