// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::parser::{encoded_len, llm::Fields, request::ItemEvent};
use serde_json::{Value, json};

#[derive(Default)]
pub(crate) struct Projection {
    view: Value,
    error: Option<&'static str>,
    messages_size: usize,
    tools: Definitions,
    functions: Definitions,
    refs_size: usize,
    text_size: usize,
    retained_text: Vec<Value>,
    messages_full: bool,
    clipped: bool,
}

#[derive(Default)]
struct Definitions {
    value: Option<Value>,
    bytes: usize,
    full: bool,
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
        let cost = encoded_len(definition) + 1;
        if cost > room - self.bytes {
            self.full = true;
            return;
        }
        self.bytes += cost;
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
        log_limit: usize,
    ) {
        match event {
            ItemEvent::BeginMessages => {
                self.messages_full = false;
                self.messages_size = 0;
                self.refs_size = 0;
                self.text_size = 0;
                self.retained_text.clear();
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
                references,
            } => {
                if fields.question
                    && let Some(text) = question
                {
                    self.clipped |= clipped || text.len() > room;
                    self.view["question"] =
                        text[..text.floor_char_boundary(text.len().min(room))].into();
                }
                if fields.tool_call_refs {
                    self.references(references, log_limit);
                }
                if fields.input_messages {
                    self.clipped |= clipped;
                    let item = match message {
                        Ok(item) => item,
                        Err(e) => {
                            self.error = Some(e);
                            return;
                        }
                    };
                    let mut item = item.clone();
                    if encoded_len(&item) > room {
                        super::capture::shrink(&mut item, room / 4);
                        self.clipped = true;
                    }
                    for block in item["content"].as_array().into_iter().flatten() {
                        if block["type"] == "text"
                            && let Some(s) = block["text"].as_str()
                        {
                            self.retain_text(s, room);
                        }
                    }
                    if !self.messages_full {
                        let cost = encoded_len(&item) + 1;
                        if self.messages_size + cost > room {
                            self.messages_full = true;
                            self.clipped = true;
                            self.view.as_object_mut().unwrap().remove("inputMessages");
                        } else {
                            self.messages_size += cost;
                            self.view["inputMessages"]
                                .as_array_mut()
                                .unwrap()
                                .push(item);
                        }
                    }
                }
            }
            ItemEvent::OmittedMessage(text) => {
                self.clipped |= fields.input_messages || fields.question || fields.tool_call_refs;
                if fields.question
                    && let Some(view) = self.view.as_object_mut()
                {
                    view.remove("question");
                }
                if fields.input_messages {
                    self.messages_full = true;
                    self.view.as_object_mut().unwrap().remove("inputMessages");
                    for s in text
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                    {
                        self.retain_text(s, room);
                    }
                }
            }
            ItemEvent::OmittedTool => self.clipped |= fields.tools,
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
            ItemEvent::System(system) if fields.input_messages || fields.instructions => {
                self.clipped |= clipped;
                if encoded_len(system) <= room {
                    self.view["systemInstructions"] = system.clone()
                } else {
                    self.clipped = true
                }
            }
            _ => {}
        }
    }

    fn retain_text(&mut self, s: &str, room: usize) {
        let left = (room / 2).saturating_sub(self.text_size + 4);
        let n = s.floor_char_boundary(s.len().min(left));
        if n > 0 {
            self.retained_text.push(s[..n].into());
            self.text_size += n + 4;
        }
    }

    fn references(&mut self, refs: &Value, limit: usize) {
        if self.view["toolCallsTruncated"] == true {
            return;
        }
        if let Some(entries) = refs["toolCalls"].as_array() {
            for entry in entries {
                self.refs_size += reference_size(entry);
                if self.refs_size > limit
                    || self.view["toolCalls"]
                        .as_array()
                        .is_some_and(|v| v.len() >= 1024)
                {
                    self.view["toolCallsTruncated"] = true.into();
                    self.view.as_object_mut().unwrap().remove("toolCalls");
                    return;
                }
                if self.view["toolCalls"].is_null() {
                    self.view["toolCalls"] = json!([])
                }
                self.view["toolCalls"]
                    .as_array_mut()
                    .unwrap()
                    .push(entry.clone());
            }
        }
        if self.refs_size > limit || refs["toolCallsTruncated"] == true {
            self.view["toolCallsTruncated"] = true.into();
            self.view.as_object_mut().unwrap().remove("toolCalls");
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
        if let Some(tools) = self.tools.value {
            result["tools"] = tools;
        }
        if let Some(Value::Array(functions)) = self.functions.value {
            if result["tools"].is_null() {
                result["tools"] = json!([]);
            }
            result["tools"].as_array_mut().unwrap().extend(functions);
        }
        if self.messages_full && !self.retained_text.is_empty() {
            result["retainedText"] = self.retained_text.into();
        }
        Ok((self.clipped, result))
    }
}

fn reference_size(entry: &Value) -> usize {
    ["id", "name"]
        .iter()
        .filter_map(|k| entry[*k].as_str())
        .map(str::len)
        .sum()
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
            "retainedText" => fields.output_messages,
            _ => true,
        };
        if keep {
            if k == "toolCalls"
                && v.as_array()
                    .is_some_and(|a| a.iter().map(reference_size).sum::<usize>() > limit)
            {
                view.insert("toolCallsTruncated".into(), true.into());
            } else {
                view.insert(k.clone(), v.clone());
            }
        }
    }
    Value::Object(view)
}
