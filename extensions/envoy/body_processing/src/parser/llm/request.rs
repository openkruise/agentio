// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Event, Fields, LlmView, ToolReferences,
    json_capture::{CaptureLoss, JsonCapture},
    response::Result,
    tool_summary::ToolSummary,
};
use crate::parser::{BodyError, llm};
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
        question_clipped: bool,
        text_clipped: bool,
        references: ToolReferences,
    },
    Tool {
        definition: Result<Value>,
        legacy: bool,
    },
    System(Value),
    OmittedSystem,
    OmittedMessage {
        text: Value,
        question: Option<String>,
        has_question: bool,
        text_clipped: bool,
        references_clipped: bool,
    },
    OmittedTool {
        legacy: bool,
    },
}

fn emit_item(emit: &mut impl FnMut(Event<'_>), item: ItemEvent, clipped: bool) {
    emit(Event::RequestItem {
        item: &item,
        clipped,
    });
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
    boundary: super::json_boundary::ValueBoundary,
}

impl Fragment {
    fn new(message_format: Option<&'static str>, limit: usize) -> Self {
        Self {
            capture: if let Some(format) = message_format {
                JsonCapture::message_fragment(limit, format)
            } else {
                JsonCapture::new(limit)
            },
            boundary: Default::default(),
        }
    }

    fn feed(&mut self, input: &[u8]) -> Result<(usize, bool)> {
        let (n, done) = self.boundary.feed(input)?;
        self.capture
            .push(&input[..n], "json", false, Fields::default());
        Ok((n, done))
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
    partial: bool,
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
            partial: false,
        }
    }

    pub(crate) fn push(
        &mut self,
        mut input: &[u8],
        events: &mut impl FnMut(Event<'_>),
    ) -> Result<()> {
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
                        events(Event::ModelData(&input[from..to]));
                    }
                }
                input = &input[n..];
                if done {
                    let fragment = self.fragment.take().unwrap();
                    let has_question = fragment.capture.has_user_text(self.format);
                    let (loss, mut value) = fragment.capture.finish_fragment()?;
                    self.partial |= loss.exhausted;
                    let clipped = loss.document;
                    match self.state {
                        State::NonObject => return Err(BodyError::InvalidContent),
                        State::Key(_) => {
                            let Value::String(key) = value else {
                                return Err(BodyError::InvalidJson);
                            };
                            self.key = key;
                            self.state = State::Colon;
                        }
                        State::Item(_) => {
                            if loss.exhausted {
                                let event = match self.key.as_str() {
                                    "messages" | "input" => ItemEvent::OmittedMessage {
                                        text: value["retainedText"].take(),
                                        question: value["question"].as_str().map(str::to_owned),
                                        has_question,
                                        text_clipped: loss.preview,
                                        references_clipped: loss.references,
                                    },
                                    _ => ItemEvent::OmittedTool {
                                        legacy: self.key == "functions",
                                    },
                                };
                                emit_item(events, event, true);
                            } else {
                                self.item(value, loss, has_question, events);
                            }

                            self.state = State::AfterItem;
                        }
                        State::Model { start } => {
                            let end = offset + n - 1;
                            let decoded = if clipped { None } else { value.as_str() };
                            events(Event::ModelEnd {
                                range: start..end,
                                value: decoded,
                            });
                            self.metadata["model"] = value;
                            self.state = State::AfterValue;
                        }
                        State::Value => {
                            if loss.exhausted
                                && matches!(
                                    (self.format, self.key.as_str()),
                                    (llm::ANTHROPIC, "system") | (llm::RESPONSES, "instructions")
                                )
                            {
                                emit_item(events, ItemEvent::OmittedSystem, true);
                            } else {
                                self.value(value, clipped, events)?;
                            }
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
                    self.fragment = Some(Fragment::new(None, ROOT_FIELD_LIMIT));
                    continue;
                }

                (State::Key(true) | State::AfterValue, b'}') => State::Done,
                (State::Key(_), b'"') => {
                    self.fragment = Some(Fragment::new(None, ROOT_FIELD_LIMIT));
                    continue;
                }
                (State::Colon, b':') => State::Value,
                (State::Value, b'"') if self.key == "model" => {
                    let start = offset + 1;
                    events(Event::ModelStart(start));
                    self.state = State::Model { start };
                    self.fragment = Some(Fragment::new(None, ROOT_FIELD_LIMIT));
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
                    emit_item(events, event, false);
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
                    self.fragment = Some(Fragment::new(message.then_some(self.format), limit));
                    continue;
                }
                (State::AfterItem, b',') => State::Item(false),
                (State::AfterValue, b',') => State::Key(false),
                _ => return Err(BodyError::InvalidJson),
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

    fn item(
        &self,
        v: Value,
        loss: CaptureLoss,
        has_question: bool,
        events: &mut impl FnMut(Event<'_>),
    ) {
        let clipped = loss.document;
        match self.key.as_str() {
            "tools" => emit_item(
                events,
                ItemEvent::Tool {
                    definition: llm::tool_definition(&v, self.format),
                    legacy: false,
                },
                clipped,
            ),
            "functions" => emit_item(
                events,
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
                let mut question = llm::user_question(&v, self.format);
                if let (Some(text), Some(n)) = (&mut question, loss.question_prefix_bytes) {
                    text.truncate(n);
                }
                let references = if loss.references {
                    ToolReferences {
                        truncated: true,
                        ..Default::default()
                    }
                } else {
                    let mut summary = ToolSummary::new(self.max_item_size);
                    summary.request_item(self.format, 0, &v);
                    summary.finish()
                };
                emit_item(
                    events,
                    ItemEvent::Message {
                        message,
                        question,
                        question_clipped: loss.text && has_question,
                        text_clipped: loss.text,
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
        events: &mut impl FnMut(Event<'_>),
    ) -> Result<()> {
        match self.key.as_str() {
            "input" if self.format == llm::RESPONSES && value.is_string() => {
                emit_item(events, ItemEvent::BeginMessages, false);
                let text = value.as_str().unwrap();
                emit_item(
                    events,
                    ItemEvent::Message {
                        message: Ok(json!({"role":"user","content":llm::plain(text)})),
                        question: (!text.is_empty()).then(|| text.to_owned()),
                        question_clipped: clipped,
                        text_clipped: clipped,
                        references: ToolReferences::default(),
                    },
                    clipped,
                );
                self.metadata["input"] = json!([]);
            }
            "system" if self.format == llm::ANTHROPIC => emit_item(
                events,
                ItemEvent::System(llm::blocks(&value, self.format).into()),
                clipped,
            ),
            "instructions" if self.format == llm::RESPONSES => {
                if let Some(s) = llm::optional_string(&value)? {
                    emit_item(events, ItemEvent::System(llm::plain(s).into()), clipped)
                }
            }
            "tools" if !value.is_null() => emit_item(
                events,
                ItemEvent::Tool {
                    definition: Err(BodyError::InvalidContent),
                    legacy: false,
                },
                false,
            ),
            "tools" => emit_item(events, ItemEvent::NullTools, false),
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
    pub(crate) fn finish(self) -> Result<LlmView> {
        if !matches!(self.state, State::Done) {
            return Err(BodyError::InvalidJson);
        }
        Ok(LlmView {
            document: llm::document(self.format, &self.metadata, false, Fields::default())?,
            partial: self.partial,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Range;

    #[test]
    fn request_events_normalize_images_across_protocols() {
        let url = "https://example.test/cat.png";
        let remote = json!({"type":"image","source":"url","url":url});
        let inline =
            json!({"type":"image","source":"base64","mediaType":"image/png","data":"YQ=="});
        for (protocol, key, parts, expected) in [
            (
                llm::CHAT,
                "messages",
                json!([{"type":"image_url","image_url":{"url":url,"detail":"low"}}]),
                json!([{"type":"image","source":"url","url":url,"detail":"low"}]),
            ),
            (
                llm::RESPONSES,
                "input",
                json!([{"type":"input_image","file_id":"file-42","detail":"high"},
                       {"type":"input_image","image_url":url},
                       {"type":"input_image","image_url":"data:image/png;base64,YQ=="}]),
                json!([{"type":"image","source":"file","fileId":"file-42","detail":"high"}, remote, inline]),
            ),
            (
                llm::ANTHROPIC,
                "messages",
                json!([{"type":"image","source":{"type":"url","url":url}},
                       {"type":"image","source":{"type":"base64","media_type":"image/png","data":"YQ=="}}]),
                json!([remote, inline]),
            ),
        ] {
            let body = json!({"model":"test",(key):[{"role":"user","content":parts}]}).to_string();
            let mut parser = Request::new(protocol, 4096);
            let mut messages = Vec::new();
            for chunk in body.as_bytes().chunks(7) {
                parser
                    .push(chunk, &mut |event| {
                        if let Event::RequestItem {
                            item: ItemEvent::Message { message, .. },
                            ..
                        } = event
                        {
                            messages.push(message.as_ref().unwrap().clone());
                        }
                    })
                    .unwrap();
            }
            parser.finish().unwrap();
            assert_eq!(
                messages,
                [json!({"role":"user","content":expected})],
                "{protocol}"
            );
        }
    }

    #[derive(Debug, Default, PartialEq)]
    struct Model {
        start: usize,
        raw: Vec<u8>,
        end: Option<(Range<usize>, Option<String>)>,
    }

    #[derive(Default)]
    struct Models(Vec<Model>);

    impl Models {
        fn observe(&mut self, event: Event<'_>) {
            match event {
                Event::RequestItem { .. } | Event::Response(_) => (),
                Event::ModelStart(start) => self.model_start(start),
                Event::ModelData(bytes) => self.model_data(bytes),
                Event::ModelEnd { range, value } => self.model_end(range, value),
            }
        }

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
        request.push(prefix, &mut |e| models.observe(e)).unwrap();
        let start = prefix.len();
        assert_eq!(
            models.0,
            [Model {
                start,
                ..Model::default()
            }]
        );

        request.push(b"bench-", &mut |e| models.observe(e)).unwrap();
        assert_eq!(models.0[0].raw, b"bench-");
        assert!(models.0[0].end.is_none());

        request
            .push(br#"alias""#, &mut |e| models.observe(e))
            .unwrap();
        let range = start..start + b"bench-alias".len();
        assert_eq!(models.0[0].end, Some((range, Some("bench-alias".into()))));
        request
            .push(br#","messages":[]}"#, &mut |e| models.observe(e))
            .unwrap();
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
                request.push(chunk, &mut |e| models.observe(e)).unwrap();
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
        request.push(prefix, &mut |e| models.observe(e)).unwrap();
        for chunk in raw.chunks(8192) {
            request.push(chunk, &mut |e| models.observe(e)).unwrap();
        }
        request.push(br#""}"#, &mut |e| models.observe(e)).unwrap();
        assert_eq!(models.0[0].raw, raw);
        assert_eq!(
            models.0[0].end,
            Some((prefix.len()..prefix.len() + raw.len(), None))
        );

        for (suffix, invalid) in [(b"open".as_slice(), false), (br#"bad\q""#.as_slice(), true)] {
            let mut request = Request::new(llm::CHAT, 1024);
            let mut models = Models::default();
            request.push(prefix, &mut |e| models.observe(e)).unwrap();
            assert_eq!(
                request.push(suffix, &mut |e| models.observe(e)).is_err(),
                invalid
            );
            assert!(models.0[0].end.is_none());
            assert!(request.finish().is_err());
        }
    }
}
