// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::limit::{array_size_with, bounded_value, json_bytes, string_prefix};
use crate::parser::{encoded_len, llm::Fields, request::ItemEvent};
use serde_json::{Map, Value, json};

#[derive(Default)]
pub(crate) struct Projection {
    view: Value,
    error: Option<&'static str>,
    messages_size: usize,
    tools: Definitions,
    functions: Definitions,
    refs_size: usize,
    text: TextPreview,
    messages_full: bool,
    clipped: bool,
    question_clipped: bool,
}

#[derive(Default)]
struct Definitions {
    value: Option<Value>,
    bytes: usize,
    full: bool,
}

#[derive(Default)]
pub(super) struct TextPreview {
    items: Vec<Value>,
    bytes: usize,
    pub(super) clipped: bool,
}

impl TextPreview {
    pub(super) fn push(&mut self, text: &str, limit: usize) {
        if self.clipped || text.is_empty() {
            return;
        }
        let overhead = if self.items.is_empty() { 4 } else { 3 };
        let prefix = string_prefix(text, limit.saturating_sub(self.bytes + overhead));
        self.clipped = prefix.len() < text.len();
        if !prefix.is_empty() {
            let value = Value::from(prefix);
            self.bytes = array_size_with(self.bytes, &value, limit).unwrap();
            self.items.push(value);
        }
    }

    pub(super) fn publish(self, view: &mut Value) -> bool {
        if !self.items.is_empty() {
            view["retainedText"] = self.items.into();
        }
        self.clipped
    }
}

impl Definitions {
    fn start(&mut self, value: Value) {
        *self = Self {
            value: Some(value),
            ..Self::default()
        };
    }
    fn push(&mut self, definition: &Value, room: usize) {
        if self.full {
            return;
        }
        let Some(next) = array_size_with(self.bytes, definition, room) else {
            self.full = true;
            return;
        };
        self.bytes = next;
        self.value
            .as_mut()
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(definition.clone());
    }
}

impl Projection {
    pub(crate) fn observe(
        &mut self,
        event: &ItemEvent,
        clipped: bool,
        fields: Fields,
        room: usize,
    ) {
        match event {
            ItemEvent::BeginMessages => {
                self.messages_full = false;
                self.question_clipped = false;
                self.messages_size = 0;
                self.refs_size = 0;
                self.text = TextPreview::default();
                if let Some(v) = self.view.as_object_mut() {
                    for key in ["question", "toolCalls", "toolCallsTruncated"] {
                        v.remove(key);
                    }
                }
                if fields.input_messages {
                    self.view["inputMessages"] = json!([]);
                }
            }
            ItemEvent::NullTools if fields.tools => self.tools.start(Value::Null),
            ItemEvent::BeginTools { legacy } if fields.tools => {
                let group = if *legacy {
                    &mut self.functions
                } else {
                    &mut self.tools
                };
                group.start(json!([]));
            }
            ItemEvent::Message {
                message,
                question,
                question_clipped,
                text_clipped,
                references,
            } => {
                if fields.question {
                    self.question(question.as_deref(), *question_clipped, room);
                }
                if fields.tool_call_refs {
                    self.references(references, room);
                }
                if fields.input_messages || fields.retained_text {
                    let item = match message {
                        Ok(item) => item,
                        Err(e) => {
                            self.error = Some(e);
                            return;
                        }
                    };
                    if fields.retained_text {
                        self.clipped |= *text_clipped;
                        for block in item["content"].as_array().into_iter().flatten() {
                            if block["type"] == "text"
                                && let Some(s) = block["text"].as_str()
                            {
                                self.text.push(s, room);
                            }
                        }
                    }
                    self.clipped |= fields.input_messages && clipped;
                    if fields.input_messages && !self.messages_full {
                        let mut logged = item.clone();
                        super::format::message(&mut logged);
                        let size =
                            array_size_with(self.messages_size, &logged, room).or_else(|| {
                                self.clipped = true;
                                fit_inline_media(
                                    &item["content"],
                                    &mut logged,
                                    self.messages_size,
                                    room,
                                )
                            });
                        if let Some(next) = size {
                            self.messages_size = next;
                            self.view["inputMessages"]
                                .as_array_mut()
                                .unwrap()
                                .push(logged);
                        } else {
                            self.close_messages();
                        }
                    }
                }
            }
            ItemEvent::OmittedMessage {
                text,
                question,
                has_question,
                text_clipped,
                references_clipped,
            } => {
                if fields.question && *has_question {
                    self.question(
                        question.as_deref(),
                        *text_clipped || question.is_none(),
                        room,
                    );
                }
                if fields.tool_call_refs && *references_clipped {
                    self.view["toolCallsTruncated"] = true.into();
                }
                if fields.input_messages {
                    self.close_messages();
                }
                if fields.retained_text {
                    for s in text
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                    {
                        self.text.push(s, room);
                    }
                    self.clipped |= *text_clipped;
                }
            }
            ItemEvent::OmittedTool { legacy } if fields.tools => {
                let group = if *legacy {
                    &mut self.functions
                } else {
                    &mut self.tools
                };
                group.full = true;
                self.clipped = true;
            }
            ItemEvent::Tool { definition, legacy } if fields.tools => match definition {
                Ok(tool) => {
                    let group = if *legacy {
                        &mut self.functions
                    } else {
                        &mut self.tools
                    };
                    group.push(tool, room);
                    self.clipped |= clipped || group.full;
                }
                Err(status) => self.error = Some(status),
            },
            ItemEvent::System(system) if fields.instructions => {
                let mut parts = system.clone();
                super::format::project_parts(&mut parts);
                let (value, shortened) = bounded_value(&parts, room);
                self.clipped |= clipped || shortened;
                if let Some(value) = value {
                    self.view["systemInstructions"] = value;
                } else if let Some(view) = self.view.as_object_mut() {
                    view.remove("systemInstructions");
                }
            }
            ItemEvent::OmittedSystem if fields.instructions => {
                self.clipped = true;
                if let Some(view) = self.view.as_object_mut() {
                    view.remove("systemInstructions");
                }
            }
            _ => {}
        }
    }

    fn close_messages(&mut self) {
        self.messages_full = true;
        self.clipped = true;
        if self.messages_size == 0 {
            self.view.as_object_mut().unwrap().remove("inputMessages");
        }
    }

    fn question(&mut self, question: Option<&str>, clipped: bool, room: usize) {
        if let Some(text) = question {
            let prefix = string_prefix(text, room);
            self.question_clipped = clipped || prefix.len() != text.len();
            self.view["question"] = prefix.into();
        } else if clipped {
            self.question_clipped = true;
            if let Some(view) = self.view.as_object_mut() {
                view.remove("question");
            }
        }
    }

    fn references(&mut self, refs: &Value, limit: usize) {
        if self.view["toolCallsTruncated"] == true {
            return;
        }
        for entry in refs["toolCalls"].as_array().into_iter().flatten() {
            let Some(next) = array_size_with(self.refs_size, entry, limit) else {
                self.view["toolCallsTruncated"] = true.into();
                return;
            };
            self.refs_size = next;
            if self.view["toolCalls"].is_null() {
                self.view["toolCalls"] = json!([]);
            }
            self.view["toolCalls"]
                .as_array_mut()
                .unwrap()
                .push(entry.clone());
        }
        if refs["toolCallsTruncated"] == true {
            self.view["toolCallsTruncated"] = true.into();
        }
    }
    pub(crate) fn finish(self, metadata: &Value) -> Result<(bool, Value), &'static str> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let mut result = metadata.clone();
        if let Value::Object(fields) = self.view {
            result.as_object_mut().unwrap().extend(fields);
        }
        // Chat treats legacy functions as additional definitions after tools,
        // regardless of their order on the wire.
        if let Some(tools) = self.tools.value
            && (!self.tools.full || self.tools.bytes > 0)
        {
            result["tools"] = tools;
        }
        if !self.tools.full
            && let Some(Value::Array(functions)) = self.functions.value
            && (!self.functions.full || !functions.is_empty())
        {
            if result["tools"].is_null() {
                result["tools"] = json!([]);
            }
            result["tools"].as_array_mut().unwrap().extend(functions);
        }
        let text_clipped = self.text.publish(&mut result);
        Ok((
            self.clipped || self.question_clipped || text_clipped,
            result,
        ))
    }
}

// Reserve the text and descriptors of this message before spending the remaining
// field budget on complete attachments in their original order.
fn fit_inline_media(
    content: &Value,
    message: &mut Value,
    used: usize,
    limit: usize,
) -> Option<usize> {
    let mut costs = Vec::new();
    visit_inline_media(content, message.get_mut("parts")?, &mut |media, part| {
        let full = json_bytes(part, limit);
        media.set_retained(part, false);
        let cost = full.map(|bytes| bytes.saturating_sub(encoded_len(part)));
        if cost == Some(0) {
            // A short file can be smaller than its omission marker.
            media.set_retained(part, true);
        }
        costs.push(cost);
    });
    if costs.is_empty() {
        return None;
    }
    let mut size = array_size_with(used, message, limit)?;
    if size < limit {
        let mut costs = costs.into_iter();
        visit_inline_media(content, &mut message["parts"], &mut |media, part| {
            if let Some(cost) = costs.next().unwrap()
                && cost > 0
                && cost <= limit - size
            {
                media.set_retained(part, true);
                size += cost;
            }
        });
    }
    Some(size)
}

enum InlineMedia<'a> {
    Image(&'a Value),
    Attachment {
        data: &'a Value,
        locations: &'a Map<String, Value>,
    },
}

impl InlineMedia<'_> {
    fn set_retained(&self, part: &mut Value, keep: bool) {
        match *self {
            Self::Image(data) => {
                if keep {
                    part["content"] = data.clone();
                } else {
                    part.as_object_mut().unwrap().remove("content");
                }
            }
            Self::Attachment { data, locations } => {
                for (path, prefix) in locations {
                    *part["data"].pointer_mut(path).unwrap() = if keep {
                        data.pointer(path).unwrap().clone()
                    } else {
                        format!("{}[omitted]", prefix.as_str().unwrap()).into()
                    };
                }
            }
        }
    }
}

// Normalization and formatting preserve part order, including nested tool results.
fn visit_inline_media(
    content: &Value,
    parts: &mut Value,
    visit: &mut impl FnMut(InlineMedia<'_>, &mut Value),
) {
    for (block, part) in content
        .as_array()
        .into_iter()
        .flatten()
        .zip(parts.as_array_mut().into_iter().flatten())
    {
        match block["type"].as_str() {
            Some("image") if block["source"] == "base64" => {
                if let Some(data) = block.get("data") {
                    visit(InlineMedia::Image(data), part);
                }
            }
            Some("tool_result") => {
                visit_inline_media(&block["content"], &mut part["response"], visit);
            }
            Some("attachment") => {
                if let Some(locations) = block["inlineData"].as_object() {
                    visit(
                        InlineMedia::Attachment {
                            data: &block["data"],
                            locations,
                        },
                        part,
                    );
                }
            }
            _ => {}
        }
    }
}

pub(crate) fn response_view(value: &Value, fields: Fields, limit: usize) -> Value {
    let mut view = serde_json::Map::new();
    for (k, v) in value.as_object().unwrap() {
        let keep = match k.as_str() {
            "outputMessagesError" => false,
            "answer" => fields.answer,
            "usage" => fields.usage,
            "truncated" => {
                fields.output_messages || (fields.answer && value.get("answer").is_none())
            }
            "outputMessages" => fields.output_messages,
            "toolCalls" | "toolCallsTruncated" => fields.tool_call_refs,
            "retainedText" => false,
            _ => true,
        };
        if keep {
            if k == "toolCalls" {
                let (value, clipped) = bounded_value(v, limit);
                if let Some(value) = value {
                    view.insert(k.clone(), value);
                }
                if clipped {
                    view.insert("toolCallsTruncated".into(), true.into());
                }
            } else {
                view.insert(k.clone(), v.clone());
            }
        }
    }
    Value::Object(view)
}

pub(super) fn response_text(value: &Value, limit: usize) -> TextPreview {
    let mut text = TextPreview::default();
    if let Some(parts) = value["retainedText"].as_array() {
        for part in parts.iter().filter_map(Value::as_str) {
            text.push(part, limit);
        }
    } else {
        for message in value["outputMessages"].as_array().into_iter().flatten() {
            for part in crate::parser::llm::answer_parts(message) {
                text.push(part, limit);
            }
        }
    }
    text
}
