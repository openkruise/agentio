// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use envoy_proxy_dynamic_modules_rust_sdk::EnvoyHttpFilter;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

#[derive(Default, Deserialize)]
#[serde(transparent)]
pub struct AttributeSources(BTreeMap<String, Source>);

#[derive(Default, Clone, Copy, Deserialize, serde::Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Schema {
    #[default]
    Agentio,
    Genai,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum Source {
    RequestHeader(String),
    FilterState(String),
}

impl AttributeSources {
    pub fn validate(&self) -> Result<(), &'static str> {
        for (name, source) in &self.0 {
            if name.is_empty() {
                return Err("attribute name must be non-empty");
            }
            match source {
                Source::RequestHeader(h)
                    if h.is_empty()
                        || !h.bytes().all(|b| {
                            b.is_ascii_lowercase()
                                || b.is_ascii_digit()
                                || b"!#$%&'*+-.^_`|~".contains(&b)
                        }) =>
                {
                    return Err("requestHeader must be a lowercase HTTP header name");
                }
                Source::FilterState(k) if k.is_empty() => return Err("filterState needs a key"),
                _ => (),
            }
        }
        Ok(())
    }

    pub fn snapshot(&self, envoy: &impl EnvoyHttpFilter, limit: usize) -> Attributes {
        let mut attrs = Attributes::default();
        let mut remaining = limit;
        for (name, source) in &self.0 {
            let value = match source {
                Source::RequestHeader(k) => envoy.get_request_header_value(k),
                Source::FilterState(k) => envoy.get_filter_state_typed(k.as_bytes()),
            };
            if let Some(buf) = value {
                if name.len() + buf.as_slice().len() > remaining {
                    attrs.truncated = true;
                    continue;
                }
                let text = String::from_utf8_lossy(buf.as_slice());
                remaining = remaining.saturating_sub(name.len() + text.len());
                attrs
                    .values
                    .insert(name.clone(), Value::String(text.into_owned()));
            }
        }
        attrs
    }
}

#[derive(Default)]
pub struct Attributes {
    pub values: Map<String, Value>,
    pub truncated: bool,
}

fn messages(value: &mut Value) {
    for msg in value
        .as_array_mut()
        .into_iter()
        .flatten()
        .filter_map(Value::as_object_mut)
    {
        if let Some(mut parts) = msg.remove("content") {
            for part in parts
                .as_array_mut()
                .into_iter()
                .flatten()
                .filter_map(Value::as_object_mut)
            {
                match part.get("type").and_then(Value::as_str) {
                    Some("text") => {
                        if let Some(text) = part.remove("text") {
                            part.insert("content".into(), text);
                        }
                    }
                    Some("tool_result") => {
                        part.insert("type".into(), "tool_call_response".into());
                        if let Some(id) = part.remove("toolCallId") {
                            part.insert("id".into(), id);
                        }
                        if let Some(content) = part.remove("content") {
                            part.insert("response".into(), content);
                        }
                    }
                    _ => (),
                }
            }
            msg.insert("parts".into(), parts);
        }
        if let Some(reason) = msg.remove("finishReason") {
            msg.insert("finish_reason".into(), reason);
        }
    }
}

// Move normalized fields into the audit attributes so prompt/response text is
// serialized once. Keep unmapped provider details in the bounded content field.
pub fn project(
    view: &mut Value,
    attrs: &mut Map<String, Value>,
    response: bool,
    schema: Schema,
    include_errors: bool,
) {
    let Some(doc) = view.as_object_mut() else {
        return;
    };
    for (key, attr) in [
        ("responseId", "gen_ai.response.id"),
        ("previousResponseId", "gen_ai.request.previous_response.id"),
        ("requestStream", "gen_ai.request.stream"),
        ("maxTokens", "gen_ai.request.max_tokens"),
        ("finishReasons", "gen_ai.response.finish_reasons"),
        ("conversationId", "gen_ai.conversation.id"),
    ] {
        if let Some(value) = doc.remove(key) {
            attrs.insert(attr.into(), value);
        }
    }
    if let Some(error) = doc.get("error") {
        if let Some(code) = error["code"].as_str() {
            attrs.insert("agentio.response.error_code".into(), code.into());
        }
        if let Some(kind) = error["type"]
            .as_str()
            .filter(|s| *s != "error")
            .or_else(|| error["code"].as_str())
        {
            attrs.insert("error.type".into(), kind.into());
        }
    }
    if !include_errors {
        doc.remove("error");
    }
    if schema == Schema::Agentio {
        return;
    }
    attrs.insert("gen_ai.operation.name".into(), "chat".into());
    for (key, field) in [
        (
            "model",
            if response {
                "gen_ai.response.model"
            } else {
                "gen_ai.request.model"
            },
        ),
        ("inputMessages", "gen_ai.input.messages"),
        ("outputMessages", "gen_ai.output.messages"),
        ("tools", "gen_ai.tool.definitions"),
    ] {
        if let Some(mut v) = doc.remove(key) {
            if key.ends_with("Messages") {
                messages(&mut v);
            } else if key == "tools" {
                for tool in v
                    .as_array_mut()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_object_mut)
                {
                    tool.entry("type").or_insert("function".into());
                }
            }
            attrs.insert(field.into(), v);
        }
    }
    if let Some(Value::Object(usage)) = doc.remove("usage") {
        for (key, value) in usage {
            let field = match key.as_str() {
                "inputTokens" => "gen_ai.usage.input_tokens",
                "outputTokens" => "gen_ai.usage.output_tokens",
                "cachedInputTokens" => "gen_ai.usage.cache_read.input_tokens",
                "cacheCreationInputTokens" => "gen_ai.usage.cache_creation.input_tokens",
                "reasoningTokens" => "gen_ai.usage.reasoning.output_tokens",
                "totalTokens" => "agentio.usage.total_tokens",
                _ => continue,
            };
            attrs.insert(field.into(), value);
        }
    }
}
