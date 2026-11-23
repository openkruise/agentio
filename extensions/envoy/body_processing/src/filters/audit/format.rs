// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use serde_json::{Map, Value, json};

pub(super) const METADATA: &[(&str, &str)] = &[
    ("responseId", "gen_ai.response.id"),
    ("previousResponseId", "gen_ai.request.previous_response.id"),
    ("requestStream", "gen_ai.request.stream"),
    ("maxTokens", "gen_ai.request.max_tokens"),
    ("finishReasons", "gen_ai.response.finish_reasons"),
    ("conversationId", "gen_ai.conversation.id"),
    ("question", "llm.question"),
    ("answer", "llm.answer"),
    ("status", "llm.status"),
    ("incompleteReason", "llm.incompleteReason"),
    ("partial", "llm.partial"),
    ("truncated", "llm.truncated"),
    ("toolCallsTruncated", "llm.toolCallsTruncated"),
    ("retainedText", "llm.retainedText"),
];

pub(super) const USAGE: &[(&str, &str)] = &[
    ("inputTokens", "gen_ai.usage.input_tokens"),
    ("outputTokens", "gen_ai.usage.output_tokens"),
    ("cachedInputTokens", "gen_ai.usage.cache_read.input_tokens"),
    (
        "cacheCreationInputTokens",
        "gen_ai.usage.cache_write.input_tokens",
    ),
    ("reasoningTokens", "gen_ai.usage.reasoning.output_tokens"),
    ("totalTokens", "agentio.usage.total_tokens"),
];

fn project_image(block: &mut Map<String, Value>) {
    let (kind, from, to) = match block.remove("source").as_ref().and_then(Value::as_str) {
        Some("file") => ("file", "fileId", "file_id"),
        Some("url") => ("uri", "url", "uri"),
        Some("base64") => ("blob", "data", "content"),
        _ => unreachable!("unknown normalized image source"),
    };
    block.insert("type".into(), kind.into());
    block.insert("modality".into(), "image".into());
    if let Some(value) = block.remove(from) {
        block.insert(to.into(), value);
    }
    if let Some(mime) = block.remove("mediaType") {
        block.insert("mime_type".into(), mime);
    }
}

pub(super) fn project_parts(parts: &mut Value) {
    for part in parts.as_array_mut().into_iter().flatten() {
        let Some(block) = part.as_object_mut() else {
            continue;
        };
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(text) = block.remove("text") {
                    block.insert("content".into(), text);
                }
            }
            Some("tool_result") => {
                block.insert("type".into(), "tool_call_response".into());
                if let Some(id) = block.remove("toolCallId") {
                    block.insert("id".into(), id);
                }
                if let Some(mut response) = block.remove("content") {
                    project_parts(&mut response);
                    block.insert("response".into(), response);
                }
            }
            Some("tool_call") if block.get("server") == Some(&Value::Bool(true)) => {
                block.remove("server");
                block.insert("type".into(), "server_tool_call".into());
                let mut details = block.remove("arguments").unwrap_or_default();
                if !details.is_object() || details.get("type").is_some() {
                    details = json!({"arguments":details});
                }
                details["type"] = block["name"].clone();
                block.insert("server_tool_call".into(), details);
            }
            Some("image") => project_image(block),
            Some("attachment") => {
                block.insert("type".into(), "provider_content".into());
                block.remove("kind");
                block.remove("inlineData");
            }
            _ => (),
        }
    }
}

pub(super) fn message(value: &mut Value) {
    if let Some(msg) = value.as_object_mut() {
        if let Some(mut parts) = msg.remove("content") {
            project_parts(&mut parts);
            msg.insert("parts".into(), parts);
        }
        if let Some(reason) = msg.remove("finishReason") {
            msg.insert("finish_reason".into(), reason);
        }
    }
}

// Project the normalized document onto literal keys in the JSON log record.
pub(crate) fn project(
    view: &mut Value,
    attrs: &mut Map<String, Value>,
    response: bool,
    include_errors: bool,
) {
    let Some(doc) = view.as_object_mut() else {
        return;
    };
    for &(key, attr) in METADATA {
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
    if include_errors && let Some(error) = doc.remove("error") {
        attrs.insert("llm.error".into(), error);
    }
    if let Some(mut instructions) = doc.remove("systemInstructions") {
        project_parts(&mut instructions);
        attrs.insert("gen_ai.system_instructions".into(), instructions);
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
                for item in v.as_array_mut().into_iter().flatten() {
                    message(item);
                }
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
    if let Some(Value::Object(mut usage)) = doc.remove("usage") {
        for &(key, field) in USAGE {
            if let Some(value) = usage.remove(key) {
                attrs.insert(field.into(), value);
            }
        }
    }
}
