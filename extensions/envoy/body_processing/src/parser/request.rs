// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{
    json_capture::JsonCapture,
    llm::{self, Fields, response::Result, tool_summary::ToolSummary},
};
use serde_json::{Value, json};

// Root keys and metadata keep a separate budget from message and tool items.
const ROOT_FIELD_LIMIT: usize = 1 << 20;

pub(crate) enum ItemEvent {
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

/// Synchronous notifications from one pass over the decoded request JSON.
/// Offsets index the decompressed JSON for gzip requests. An unfinished or
/// invalid model string can emit data without a matching end notification.
pub(crate) trait RequestEvents {
    fn item(&mut self, item: ItemEvent, clipped: bool);

    /// Byte offset just after the opening quote of a top-level model string.
    fn model_start(&mut self, _start: usize) {}

    /// Borrowed JSON string contents, including escapes, without the quotes.
    fn model_data(&mut self, _bytes: &[u8]) {}

    /// Range excludes the quotes. A clipped value has no complete decoded string.
    fn model_end(&mut self, _range: std::ops::Range<usize>, _value: Option<&str>) {}
}

#[derive(Clone, Copy)]
enum State {
    Root,
    Key(bool),
    Colon,
    Value,
    Model { start: usize },
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
    bytes_seen: usize,
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
            bytes_seen: 0,
            max_item_size,
            state: State::Root,
            key: String::new(),
            fragment: None,
            metadata: json!({}),
        }
    }

    pub(crate) fn push(&mut self, mut input: &[u8], events: &mut impl RequestEvents) -> Result<()> {
        self.bytes_seen += input.len();
        while !input.is_empty() {
            let offset = self.bytes_seen - input.len();
            if let Some(f) = &mut self.fragment {
                let (n, done) = f.feed(input)?;
                if let State::Model { start } = self.state {
                    // feed includes each quote exactly once, even across input slices.
                    let from = usize::from(offset < start);
                    let to = n - usize::from(done);
                    if from < to {
                        events.model_data(&input[from..to]);
                    }
                }
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
                                        ItemEvent::OmittedMessage(value["retainedText"].take())
                                    }
                                    _ => ItemEvent::OmittedTool,
                                };
                                events.item(event, true);
                            } else {
                                self.item(value, clipped, events);
                            }

                            self.state = State::AfterItem;
                        }
                        State::Model { start } => {
                            let end = offset + n - 1;
                            let decoded = if clipped { None } else { value.as_str() };
                            events.model_end(start..end, decoded);
                            self.metadata["model"] = value;
                            self.state = State::AfterValue;
                        }
                        State::Value => {
                            self.value(value, clipped, events)?;
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
                (State::Value, b'"') if self.key == "model" => {
                    let start = offset + 1;
                    events.model_start(start);
                    self.state = State::Model { start };
                    self.fragment = Some(Fragment::new(false, ROOT_FIELD_LIMIT));
                    continue;
                }
                (State::Value, b'[') if self.collection().is_some() => {
                    let key = self.collection().unwrap();
                    self.metadata[key] = json!([]);
                    let event = match key {
                        "tools" | "functions" => ItemEvent::BeginTools {
                            legacy: key == "functions",
                        },
                        _ => ItemEvent::BeginMessages,
                    };
                    events.item(event, false);
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

    fn item(&self, v: Value, clipped: bool, events: &mut impl RequestEvents) {
        match self.key.as_str() {
            "tools" => events.item(
                ItemEvent::Tool {
                    definition: llm::tool_definition(&v, self.format),
                    legacy: false,
                },
                clipped,
            ),
            "functions" => events.item(
                ItemEvent::Tool {
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
                events.item(
                    ItemEvent::Message {
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
        events: &mut impl RequestEvents,
    ) -> Result<()> {
        match self.key.as_str() {
            "input" if self.format == llm::RESPONSES && value.is_string() => {
                events.item(ItemEvent::BeginMessages, false);
                let text = value.as_str().unwrap();
                events.item(
                    ItemEvent::Message {
                        message: Ok(json!({"role":"user","content":llm::plain(text)})),
                        question: (!text.is_empty()).then(|| text.to_owned()),
                        references: Value::Null,
                    },
                    clipped,
                );
                self.metadata["input"] = json!([]);
            }
            "system" if self.format == llm::ANTHROPIC => events.item(
                ItemEvent::System(llm::blocks(&value, self.format).into()),
                clipped,
            ),
            "instructions" if self.format == llm::RESPONSES => {
                if let Some(s) = llm::optional_string(&value)? {
                    events.item(ItemEvent::System(llm::plain(s).into()), clipped)
                }
            }
            "tools" if !value.is_null() => events.item(
                ItemEvent::Tool {
                    definition: Err("invalid_content"),
                    legacy: false,
                },
                false,
            ),
            "tools" => events.item(ItemEvent::NullTools, false),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Range;

    #[derive(Debug, Default, PartialEq)]
    struct Model {
        start: usize,
        raw: Vec<u8>,
        end: Option<(Range<usize>, Option<String>)>,
    }

    #[derive(Default)]
    struct Models(Vec<Model>);

    impl RequestEvents for Models {
        fn item(&mut self, _: ItemEvent, _: bool) {}

        fn model_start(&mut self, start: usize) {
            self.0.push(Model {
                start,
                ..Model::default()
            });
        }

        fn model_data(&mut self, bytes: &[u8]) {
            assert!(!bytes.is_empty());
            let model = self.0.last_mut().unwrap();
            assert!(model.end.is_none());
            model.raw.extend_from_slice(bytes);
        }

        fn model_end(&mut self, range: Range<usize>, value: Option<&str>) {
            let model = self.0.last_mut().unwrap();
            assert_eq!(range, model.start..model.start + model.raw.len());
            assert!(
                model
                    .end
                    .replace((range, value.map(str::to_owned)))
                    .is_none()
            );
        }
    }

    #[test]
    fn model_events_arrive_before_the_next_chunk_or_request_end() {
        let mut request = Request::new(llm::CHAT, 1024);
        let mut models = Models::default();
        let prefix = br#"{"model":""#;
        request.push(prefix, &mut models).unwrap();
        let start = prefix.len();
        assert_eq!(
            models.0,
            [Model {
                start,
                ..Model::default()
            }]
        );

        request.push(b"bench-", &mut models).unwrap();
        assert_eq!(models.0[0].raw, b"bench-");
        assert!(models.0[0].end.is_none());

        request.push(br#"alias""#, &mut models).unwrap();
        let range = start..start + b"bench-alias".len();
        assert_eq!(models.0[0].end, Some((range, Some("bench-alias".into()))));
        request.push(br#","messages":[]}"#, &mut models).unwrap();
        assert!(request.finish().is_ok());
    }

    #[test]
    fn model_ranges_follow_json_quoting_and_only_top_level_strings() {
        let body = r#"{"messages":[{"model":"nested"}],"model":null,"model":{},"mo\u0064el":"水\"x\\\u0061","model":""}"#.as_bytes();
        let raw = r#"水\"x\\\u0061"#.as_bytes();
        let first = body.windows(raw.len()).position(|v| v == raw).unwrap();
        let empty = body.len() - 2;
        for size in 1..=body.len() {
            let mut request = Request::new(llm::CHAT, 1024);
            let mut models = Models::default();
            for chunk in body.chunks(size) {
                request.push(chunk, &mut models).unwrap();
            }
            let [a, b] = models.0.as_slice() else {
                panic!("expected two model strings")
            };
            assert_eq!(a.raw, raw);
            assert_eq!(
                a.end,
                Some((first..first + raw.len(), Some("水\"x\\a".into())))
            );
            assert!(b.raw.is_empty());
            assert_eq!(b.end, Some((empty..empty, Some(String::new()))));
        }
    }

    #[test]
    fn clipped_or_unfinished_models_do_not_publish_a_complete_value() {
        let raw = vec![b'x'; ROOT_FIELD_LIMIT + 1];
        let mut request = Request::new(llm::RESPONSES, 1024);
        let mut models = Models::default();
        let prefix = br#"{"model":""#;
        request.push(prefix, &mut models).unwrap();
        for chunk in raw.chunks(8192) {
            request.push(chunk, &mut models).unwrap();
        }
        request.push(br#""}"#, &mut models).unwrap();
        assert_eq!(models.0[0].raw, raw);
        assert_eq!(
            models.0[0].end,
            Some((prefix.len()..prefix.len() + raw.len(), None))
        );

        for (suffix, invalid) in [(b"open".as_slice(), false), (br#"bad\q""#.as_slice(), true)] {
            let mut request = Request::new(llm::CHAT, 1024);
            let mut models = Models::default();
            request.push(prefix, &mut models).unwrap();
            assert_eq!(request.push(suffix, &mut models).is_err(), invalid);
            assert!(models.0[0].end.is_none());
            assert!(request.finish().is_err());
        }
    }
}
