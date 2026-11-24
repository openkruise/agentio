// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{
    limit::{array_size_with, bounded_value, string_prefix},
    messages::{Messages, format_parts},
};
use crate::chain::Side;
use crate::parser::{
    BodyError,
    llm::ItemEvent,
    llm::{Fields, LlmView, ToolReferences},
};
use serde_json::{Value, json};

#[derive(Default)]
pub(crate) struct Projection {
    view: Value,
    error: Option<BodyError>,
    messages: Option<Messages>,
    tools: Definitions,
    functions: Definitions,
    references: ToolProjection,
    text: TextPreview,
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
                self.question_clipped = false;
                self.references = ToolProjection::default();
                self.text = TextPreview::default();
                if let Some(v) = self.view.as_object_mut() {
                    v.remove("question");
                }
                if fields.input_messages {
                    self.messages = Some(Messages::new(room));
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
                    if let Some(messages) = &mut self.messages {
                        messages.push(item, Side::Request);
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
                if let Some(messages) = &mut self.messages {
                    messages.omit();
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
                let parts = format_parts(system);
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

    pub(crate) fn finish(mut self, metadata: &LlmView) -> Result<(bool, LlmView), BodyError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let mut result = metadata.document.clone();
        if let Value::Object(fields) = self.view {
            result.as_object_mut().unwrap().extend(fields);
        }
        if let Some(messages) = self.messages {
            let (value, clipped) = messages.finish();
            self.clipped |= clipped;
            if let Some(value) = value {
                result["inputMessages"] = value;
            }
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

pub(crate) fn response_view(source: &LlmView, fields: Fields, limit: usize) -> (LlmView, bool) {
    let value = &source.document;
    let mut messages_clipped = false;
    let mut view = serde_json::Map::new();
    for (k, v) in value.as_object().unwrap() {
        let keep = match k.as_str() {
            "answer" => fields.answer,
            "usage" => fields.usage,
            "outputMessages" | "retainedText" => false,
            _ => true,
        };
        if keep {
            view.insert(k.clone(), v.clone());
        }
    }
    if fields.output_messages
        && let Some(items) = value.get("outputMessages")
    {
        let (messages, clipped) =
            Messages::project(items.as_array().unwrap(), limit, Side::Response);
        messages_clipped = clipped;
        if let Some(messages) = messages {
            view.insert("outputMessages".into(), messages);
        }
    }
    let mut references = ToolProjection::default();
    if fields.tool_call_refs {
        references.observe(&source.tool_refs, limit);
    }
    (
        LlmView {
            document: Value::Object(view),
            tool_refs: references.refs,
            partial: source.partial,
            ..Default::default()
        },
        messages_clipped,
    )
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
