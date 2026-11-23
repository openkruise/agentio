// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{ANTHROPIC, CHAT, RESPONSES, ToolKind, anthropic_tool, responses_tool};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Serialize)]
struct Reference {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

// Streamed Chat names arrive as fragments; Responses instead sends item snapshots.
// Track positions so parallel calls keep their protocol order across callbacks.
pub(crate) struct ToolSummary {
    limit: usize,
    entries: BTreeMap<(usize, usize), Reference>,
    bytes: usize,
    truncated: bool,
}

impl ToolSummary {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            bytes: 0,
            truncated: false,
            limit,
        }
    }

    fn record(
        &mut self,
        position: (usize, usize),
        kind: &'static str,
        id: &Value,
        name: &Value,
        delta: bool,
    ) {
        let (id, name) = (id.as_str(), name.as_str());
        if self.truncated || (id.is_none() && name.is_none()) {
            return;
        }
        let previous = self.entries.get(&position);
        let old_id = previous
            .and_then(|p| p.id.as_deref())
            .unwrap_or_default()
            .len();
        let old_name = previous
            .and_then(|p| p.name.as_deref())
            .unwrap_or_default()
            .len();
        if let Some(id) = id {
            self.bytes = self.bytes - old_id + id.len();
        }
        if let Some(name) = name {
            self.bytes = self.bytes + name.len() - if delta { 0 } else { old_name };
        }
        if self.bytes > self.limit || (previous.is_none() && self.entries.len() >= 1024) {
            self.entries.clear();
            self.truncated = true;
            return;
        }
        let entry = self.entries.entry(position).or_insert(Reference {
            kind,
            id: None,
            name: None,
        });
        if let Some(id) = id
            && entry.id.as_deref() != Some(id)
        {
            entry.id = Some(id.into());
        }
        if let Some(name) = name {
            if delta {
                entry.name.get_or_insert_default().push_str(name);
            } else {
                entry.name = Some(name.into());
            }
        }
    }

    pub(crate) fn chat_delta(&mut self, choice: usize, slot: usize, id: &Value, name: &Value) {
        self.record((choice, slot), "call", id, name, true);
    }

    fn chat(&mut self, index: usize, message: &Value) {
        if matches!(message["role"].as_str(), Some("tool" | "function")) {
            self.record(
                (index, 0),
                "result",
                &message["tool_call_id"],
                &message["name"],
                false,
            );
            return;
        }
        for (i, call) in message["tool_calls"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            self.record(
                (index, i),
                "call",
                &call["id"],
                &call[if call["type"] == "custom" {
                    "custom"
                } else {
                    "function"
                }]["name"],
                false,
            );
        }
        if message["function_call"].is_object() {
            self.record(
                (index, usize::MAX),
                "call",
                &Value::Null,
                &message["function_call"]["name"],
                false,
            );
        }
    }

    pub(crate) fn anthropic(&mut self, position: (usize, usize), block: &Value) {
        match block["type"].as_str().and_then(anthropic_tool) {
            Some(ToolKind::Call) => {
                self.record(position, "call", &block["id"], &block["name"], false)
            }
            Some(ToolKind::Result) => self.record(
                position,
                "result",
                &block["tool_use_id"],
                &Value::Null,
                false,
            ),
            _ => (),
        }
    }

    pub(crate) fn responses(&mut self, index: usize, item: &Value) {
        match item["type"].as_str().and_then(responses_tool) {
            Some(ToolKind::Call) => {
                self.record((index, 0), "call", &item["call_id"], &item["name"], false)
            }
            Some(ToolKind::Result) => {
                self.record((index, 0), "result", &item["call_id"], &Value::Null, false)
            }
            _ => (),
        }
    }

    pub(crate) fn request_item(&mut self, format: &str, i: usize, item: &Value) {
        match format {
            CHAT => self.chat(i, item),
            ANTHROPIC => {
                for (j, block) in item["content"].as_array().into_iter().flatten().enumerate() {
                    self.anthropic((i, j), block);
                }
            }
            RESPONSES => self.responses(i, item),
            _ => unreachable!(),
        }
    }

    pub(crate) fn document(&mut self, format: &str, doc: &Value, response: bool) {
        // The terminal Responses snapshot replaces earlier item observations.
        self.entries.clear();
        self.bytes = 0;
        self.truncated = false;
        let key = match (format, response) {
            (CHAT, true) => "choices",
            (ANTHROPIC, true) => "content",
            (RESPONSES, true) => "output",
            (RESPONSES, false) => "input",
            _ => "messages",
        };
        for (i, item) in doc[key].as_array().into_iter().flatten().enumerate() {
            match format {
                CHAT if response => self.chat(
                    item["index"].as_u64().unwrap_or(i as u64) as usize,
                    &item["message"],
                ),
                ANTHROPIC if response => self.anthropic((0, i), item),
                RESPONSES if response => self.responses(i, item),
                _ if !response => self.request_item(format, i, item),
                _ => unreachable!(),
            }
        }
    }

    pub(crate) fn publish(self, view: &mut Value) {
        if self.truncated {
            view["toolCallsTruncated"] = true.into();
        } else if !self.entries.is_empty() {
            view["toolCalls"] =
                serde_json::to_value(self.entries.into_values().collect::<Vec<_>>()).unwrap();
        }
    }
}
