// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{
    json_capture::JsonCapture,
    llm::{self, Fields, response::Result, tool_summary::ToolSummary},
};
use serde_json::{Value, json};

// Root keys and metadata keep a separate budget from message and tool items.
const ROOT_FIELD_LIMIT: usize = 1 << 20;

pub(crate) enum Event {
    BeginMessages,
    BeginTools {
        legacy: bool,
    },
    NullTools,
    Message {
        message: Result<Value>,
        question: Option<String>,
        references: Value,
    },
    Tool {
        definition: Result<Value>,
        legacy: bool,
    },
    System(Value),
    OmittedMessage(Value),
    OmittedTool,
}

#[derive(Clone, Copy)]
enum State {
    Root,
    Key(bool),
    Colon,
    Value,
    Item(bool),
    AfterItem,
    AfterValue,
    NonObject,
    Done,
}

struct Fragment {
    capture: JsonCapture,
    depth: usize,
    quoted: bool,
    escaped: bool,
    started: bool,
}
impl Fragment {
    fn new(message: bool, limit: usize) -> Self {
        Self {
            capture: if message {
                JsonCapture::message_fragment(limit)
            } else {
                JsonCapture::new(limit)
            },
            depth: 0,
            quoted: false,
            escaped: false,
            started: false,
        }
    }

    // Return the number of bytes in this fragment, leaving its separator for
    // the object/array grammar. The actual JSON value is decoded once.
    fn feed(&mut self, input: &[u8]) -> Result<(usize, bool)> {
        let mut i = 0;
        let mut done = false;
        while i < input.len() {
            if self.quoted {
                if self.escaped {
                    self.escaped = false;
                    i += 1;
                    continue;
                }
                i += memchr::memchr2(b'"', b'\\', &input[i..]).unwrap_or(input.len() - i);
                if i == input.len() {
                    break;
                }
                let ch = input[i];
                i += 1;
                if ch == b'\\' {
                    self.escaped = true;
                } else {
                    self.quoted = false;
                    if self.depth == 0 {
                        done = true;
                        break;
                    }
                }
            } else {
                let ch = input[i];
                if self.started
                    && self.depth == 0
                    && (ch.is_ascii_whitespace() || matches!(ch, b',' | b']' | b'}'))
                {
                    done = true;
                    break;
                }
                self.started = true;
                match ch {
                    b'"' => self.quoted = true,
                    b'{' | b'[' => {
                        self.depth += 1;
                        if self.depth > 128 {
                            return Err("invalid_json");
                        }
                    }
                    b'}' | b']' => {
                        self.depth = self.depth.checked_sub(1).ok_or("invalid_json")?;
                        if self.depth == 0 {
                            i += 1;
                            done = true;
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
        }
        self.capture
            .push(&input[..i], "json", false, Fields::default());
        Ok((i, done))
    }
}

pub(crate) struct Request {
    max_item_size: usize,
    format: &'static str,
    state: State,
    key: String,
    fragment: Option<Fragment>,
    metadata: Value,
}

impl Request {
    pub(crate) fn new(format: &'static str, max_item_size: usize) -> Self {
        Self {
            format,
            max_item_size,
            state: State::Root,
            key: String::new(),
            fragment: None,
            metadata: json!({}),
        }
    }

    pub(crate) fn push(
        &mut self,
        mut input: &[u8],
        mut emit: impl FnMut(Event, bool),
    ) -> Result<()> {
        while !input.is_empty() {
            if let Some(f) = &mut self.fragment {
                let (n, done) = f.feed(input)?;
                input = &input[n..];
                if done {
                    let fragment = self.fragment.take().unwrap();
                    let exhausted = fragment.capture.exhausted();
                    let (clipped, mut value) = fragment.capture.finish_fragment()?;
                    match self.state {
                        State::NonObject => return Err("invalid_content"),
                        State::Key(_) => {
                            let Value::String(key) = value else {
                                return Err("invalid_json");
                            };
                            self.key = key;
                            self.state = State::Colon;
                        }
                        State::Item(_) => {
                            if exhausted {
                                let event = match self.key.as_str() {
                                    "messages" | "input" => {
                                        Event::OmittedMessage(value["retainedText"].take())
                                    }
                                    _ => Event::OmittedTool,
                                };
                                emit(event, true);
                            } else {
                                self.item(value, clipped, &mut emit);
                            }

                            self.state = State::AfterItem;
                        }
                        State::Value => {
                            self.value(value, clipped, &mut emit)?;
                            self.state = State::AfterValue;
                        }
                        _ => unreachable!(),
                    }
                }
                continue;
            }
            let ch = input[0];
            if matches!(ch, b' ' | b'\t' | b'\n' | b'\r') {
                input = &input[1..];
                continue;
            }
            self.state = match (self.state, ch) {
                (State::Root, b'{') => State::Key(true),
                (State::Root, _) => {
                    self.state = State::NonObject;
                    self.fragment = Some(Fragment::new(false, ROOT_FIELD_LIMIT));
                    continue;
                }

                (State::Key(true) | State::AfterValue, b'}') => State::Done,
                (State::Key(_), b'"') => {
                    self.fragment = Some(Fragment::new(false, ROOT_FIELD_LIMIT));
                    continue;
                }
                (State::Colon, b':') => State::Value,
                (State::Value, b'[') if self.collection().is_some() => {
                    let key = self.collection().unwrap();
                    self.metadata[key] = json!([]);
                    let event = match key {
                        "tools" | "functions" => Event::BeginTools {
                            legacy: key == "functions",
                        },
                        _ => Event::BeginMessages,
                    };
                    emit(event, false);
                    State::Item(true)
                }
                (State::Item(true) | State::AfterItem, b']') => State::AfterValue,
                (State::Value | State::Item(_), _) if !matches!(ch, b',' | b'}' | b']') => {
                    let message = matches!(self.state, State::Item(_))
                        && matches!(self.key.as_str(), "messages" | "input");
                    let item = matches!(self.state, State::Item(_))
                        || matches!(
                            (self.format, self.key.as_str()),
                            (llm::RESPONSES, "instructions" | "input") | (llm::ANTHROPIC, "system")
                        );
                    let limit = if item {
                        self.max_item_size
                    } else {
                        ROOT_FIELD_LIMIT
                    };
                    self.fragment = Some(Fragment::new(message, limit));
                    continue;
                }
                (State::AfterItem, b',') => State::Item(false),
                (State::AfterValue, b',') => State::Key(false),
                _ => return Err("invalid_json"),
            };
            input = &input[1..];
        }
        Ok(())
    }

    fn collection(&self) -> Option<&'static str> {
        match (self.format, self.key.as_str()) {
            (llm::CHAT | llm::ANTHROPIC, "messages") => Some("messages"),
            (llm::RESPONSES, "input") => Some("input"),
            (_, "tools") => Some("tools"),
            (llm::CHAT, "functions") => Some("functions"),
            _ => None,
        }
    }

    fn item(&self, v: Value, clipped: bool, emit: &mut impl FnMut(Event, bool)) {
        match self.key.as_str() {
            "tools" => emit(
                Event::Tool {
                    definition: llm::tool_definition(&v, self.format),
                    legacy: false,
                },
                clipped,
            ),
            "functions" => emit(
                Event::Tool {
                    definition: Ok(v),
                    legacy: true,
                },
                clipped,
            ),
            _ => {
                let message = if self.format == llm::RESPONSES {
                    llm::responses_item(&v)
                } else {
                    llm::chat_message(&v, self.format)
                };
                let question = llm::user_question(&v, self.format);
                let mut summary = ToolSummary::new(self.max_item_size);
                summary.request_item(self.format, 0, &v);
                let mut references = Value::Null;
                summary.publish(&mut references);
                emit(
                    Event::Message {
                        message,
                        question,
                        references,
                    },
                    clipped,
                );
            }
        }
    }

    fn value(
        &mut self,
        value: Value,
        clipped: bool,
        emit: &mut impl FnMut(Event, bool),
    ) -> Result<()> {
        match self.key.as_str() {
            "input" if self.format == llm::RESPONSES && value.is_string() => {
                emit(Event::BeginMessages, false);
                let text = value.as_str().unwrap();
                emit(
                    Event::Message {
                        message: Ok(json!({"role":"user","content":llm::plain(text)})),
                        question: (!text.is_empty()).then(|| text.to_owned()),
                        references: Value::Null,
                    },
                    clipped,
                );
                self.metadata["input"] = json!([]);
            }
            "system" if self.format == llm::ANTHROPIC => emit(
                Event::System(llm::blocks(&value, self.format).into()),
                clipped,
            ),
            "instructions" if self.format == llm::RESPONSES => {
                if let Some(s) = llm::optional_string(&value)? {
                    emit(Event::System(llm::plain(s).into()), clipped)
                }
            }
            "tools" if !value.is_null() => emit(
                Event::Tool {
                    definition: Err("invalid_content"),
                    legacy: false,
                },
                false,
            ),
            "tools" => emit(Event::NullTools, false),
            "model"
            | "messages"
            | "input"
            | "status"
            | "stop_reason"
            | "stream"
            | "max_tokens"
            | "max_completion_tokens"
            | "max_output_tokens"
            | "conversation"
            | "previous_response_id" => {
                self.metadata[&self.key] = value;
            }
            _ => {}
        }
        Ok(())
    }
    pub(crate) fn finish(self) -> Result<Value> {
        if !matches!(self.state, State::Done) {
            return Err("invalid_json");
        }
        llm::document(self.format, &self.metadata, false, Fields::default())
    }
}
