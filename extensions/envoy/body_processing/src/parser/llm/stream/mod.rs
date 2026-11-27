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
    // A message or Anthropic block. Unsealed snapshots are emitted on interruption.
    // A missing value represents a gap where no structured prefix could be retained.
    OutputItem {
        output: Output,
        part: Option<u32>,
        value: Option<&'a Value>,
        clipped: bool,
        sealed: bool,
    },
    TextGap {
        output: Output,
        part: u32,
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
    fn item(&mut self) -> Result<()> {
        self.items += 1;
        if self.items > 1024 {
            Err(BodyError::TooLarge)
        } else {
            Ok(())
        }
    }
}

// A choice or content block holds a share of the stream budget until it is sealed.
#[derive(Default)]
struct OpenContent {
    bytes: usize,
    clipped: bool,
}

impl OpenContent {
    fn take(&mut self, b: &mut Retention, bytes: usize) -> bool {
        if self.clipped || b.partial {
            return false;
        }
        if bytes > b.room {
            self.clipped = true;
            b.truncated = true;
            return false;
        }
        self.bytes += bytes;
        b.room -= bytes;
        true
    }

    fn prefix<'a>(&mut self, b: &mut Retention, text: &'a str) -> &'a str {
        let n = text.floor_char_boundary(text.len().min(b.room));
        if !self.take(b, n) {
            return "";
        }
        if n < text.len() {
            self.clipped = true;
            b.truncated = true;
        }
        &text[..n]
    }

    fn release(&mut self, b: &mut Retention) {
        b.room += std::mem::take(&mut self.bytes);
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
        let terminal = match provider {
            Provider::Chat(s) => s.add(frame.value, frame.done, budget, emit)?,
            Provider::Anthropic(s) => s.add(frame.kind, frame.value, budget, emit)?,
            Provider::Responses(s) => s.add(frame.kind, frame.value, frame.done, budget, emit)?,
        };
        if let Some(trailers) = terminal {
            self.trailers = trailers;
            let (provider, budget) = self.active.take().unwrap();
            let keep = !budget.partial;
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
        }
        Ok(())
    }

    /// Publish open text and return the metadata observed before interruption.
    pub fn into_partial(self, emit: &mut impl FnMut(Event<'_>)) -> Option<(LlmView, bool)> {
        let (provider, retention) = self.active?;
        let mut view = match provider {
            Provider::Responses(s) => s.interrupted(emit),
            Provider::Chat(s) => s.interrupted(emit),
            Provider::Anthropic(s) => s.interrupted(emit),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn open_sse_items_share_room_and_sealed_items_release_it() {
        for protocol in [CHAT, ANTHROPIC] {
            let mut stream = Stream::new(protocol, 1024);
            let mut sealed = Vec::new();
            let mut push = |kind: &str, frame: Value| {
                stream
                    .event(
                        sse::Event {
                            kind,
                            value: &frame,
                            done: false,
                        },
                        &mut |event| {
                            if let Event::OutputItem {
                                output,
                                part,
                                value: Some(item),
                                clipped,
                                sealed: true,
                            } = event
                            {
                                let value = if part.is_some() {
                                    &item["text"]
                                } else {
                                    &item["content"][0]["text"]
                                };
                                sealed.push((
                                    part.unwrap_or(output.index),
                                    value.as_str().unwrap().len(),
                                    clipped,
                                ));
                            }
                        },
                    )
                    .unwrap();
            };
            if protocol == ANTHROPIC {
                push(
                    "message_start",
                    json!({"message":{"model":"m","content":[]}}),
                );
            }
            let value = "x".repeat(700);
            for (index, close) in [
                (0, false),
                (1, false),
                (1, true),
                (0, true),
                (2, false),
                (2, true),
            ] {
                match (protocol, close) {
                    (CHAT, false) => push(
                        "",
                        json!({"model":"m","choices":[{"index":index,"delta":{"content":value}}]}),
                    ),
                    (CHAT, true) => push(
                        "",
                        json!({"model":"m","choices":[{"index":index,"delta":{},"finish_reason":"stop"}]}),
                    ),
                    (_, false) => push(
                        "content_block_start",
                        json!({"index":index,"content_block":{"type":"text","text":value}}),
                    ),
                    (_, true) => push("content_block_stop", json!({"index":index})),
                }
            }
            assert_eq!(sealed.len(), 3);
            assert_eq!(sealed[0].0, 1);
            assert!((1..=324).contains(&sealed[0].1));
            assert!(sealed[0].2);
            assert_eq!(sealed[1], (0, 700, false));
            assert_eq!(sealed[2], (2, 700, false));
        }
    }
}
