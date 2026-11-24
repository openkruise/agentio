// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::limit::{array_size_with, bounded_value, json_bytes, string_prefix};
use crate::parser::{
    BodyError, encoded_len,
    llm::{Fields, LlmView, ToolReferences},
    request::ItemEvent,
};
use serde_json::{Map, Value, json};

#[derive(Default)]
pub(crate) struct Projection {
    view: Value,
    error: Option<BodyError>,
    messages_size: usize,
    tools: Definitions,
    functions: Definitions,
    references: ToolProjection,
    text: TextPreview,
    messages_full: bool,
    clipped: bool,
    question_clipped: bool,
}

#[derive(Default)]
struct ToolProjection {
    refs: ToolReferences,
    bytes: usize,
}

impl ToolProjection {
    fn observe(&mut self, refs: &ToolReferences, limit: usize) {
        if self.refs.truncated {
            return;
        }
        for entry in &refs.entries {
            let Some(next) = array_size_with(self.bytes, entry, limit) else {
                self.refs.truncated = true;
                return;
            };
            self.bytes = next;
            self.refs.entries.push(entry.clone());
        }
        self.refs.truncated = refs.truncated;
    }
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
                self.references = ToolProjection::default();
                self.text = TextPreview::default();
                if let Some(v) = self.view.as_object_mut() {
                    v.remove("question");
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
                    self.references.observe(references, room);
                }
                if fields.input_messages || fields.retained_text {
                    let item = match message {
                        Ok(item) => item,
                        Err(e) => {
                            self.error = Some(*e);
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
                    self.references.refs.truncated = true;
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
                Err(reason) => self.error = Some(*reason),
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

    pub(crate) fn finish(self, metadata: &LlmView) -> Result<(bool, LlmView), BodyError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let mut result = metadata.document.clone();
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
            LlmView {
                document: result,
                tool_refs: self.references.refs,
                partial: metadata.partial,
                ..Default::default()
            },
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

pub(crate) fn response_view(source: &LlmView, fields: Fields, limit: usize) -> LlmView {
    let value = &source.document;
    let mut view = serde_json::Map::new();
    for (k, v) in value.as_object().unwrap() {
        let keep = match k.as_str() {
            "answer" => fields.answer,
            "usage" => fields.usage,
            "outputMessages" => fields.output_messages,
            "retainedText" => false,
            _ => true,
        };
        if keep {
            view.insert(k.clone(), v.clone());
        }
    }
    let mut references = ToolProjection::default();
    if fields.tool_call_refs {
        references.observe(&source.tool_refs, limit);
    }
    LlmView {
        document: Value::Object(view),
        tool_refs: references.refs,
        partial: source.partial,
        ..Default::default()
    }
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
