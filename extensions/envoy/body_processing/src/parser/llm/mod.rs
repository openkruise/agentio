// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

pub(super) mod attachment;
mod image;
mod input;
mod json_capture;
mod protocol;
mod request;
pub(crate) mod response;
pub(crate) mod sse;
pub(crate) mod stream;
pub(super) mod tool_summary;
pub(crate) use input::{Event, Outcome, Parser};
pub(crate) use json_capture::CaptureLoss;
pub(crate) use protocol::{Protocol, ProtocolSelection};
pub(crate) use request::ItemEvent;
pub(crate) use tool_summary::ToolReferences;

use crate::parser::BodyError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const CHAT: &str = "openai-chat-completions";
pub const RESPONSES: &str = "openai-responses";
pub const ANTHROPIC: &str = "anthropic-messages";
type Parsed = Result<Value, BodyError>;

/// Normalized protocol fields and the parser's observations about their completeness.
#[derive(Clone, Default)]
pub(crate) struct LlmView {
    pub document: Value,
    pub tool_refs: ToolReferences,
    pub partial: bool,
    pub output_messages_error: Option<BodyError>,
}

impl From<Value> for LlmView {
    fn from(document: Value) -> Self {
        Self {
            document,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Fields {
    pub(crate) input_messages: bool,
    pub(crate) output_messages: bool,
    pub(crate) tools: bool,
    pub(crate) instructions: bool,
    pub(crate) error: bool,
    pub(crate) tool_call_refs: bool,
    pub(crate) question: bool,
    pub(crate) answer: bool,
    pub(crate) retained_text: bool,
    pub(crate) usage: bool,
}

impl Fields {
    pub(crate) const ALL: Self = Self {
        input_messages: true,
        output_messages: true,
        tools: true,
        instructions: true,
        error: true,
        tool_call_refs: true,
        question: true,
        answer: true,
        retained_text: true,
        usage: true,
    };
}
#[cfg(test)]
impl Fields {
    pub(crate) fn fixture_default() -> Self {
        Self::DEFAULT
    }
    pub(crate) const DEFAULT: Self = Self {
        input_messages: true,
        output_messages: true,
        tools: true,
        instructions: true,
        error: true,
        tool_call_refs: false,
        question: false,
        answer: false,
        retained_text: false,
        usage: true,
    };
}

pub(super) fn optional_string(v: &Value) -> Result<Option<&str>, BodyError> {
    if v.is_null() {
        Ok(None)
    } else {
        v.as_str().map(Some).ok_or(BodyError::InvalidContent)
    }
}

fn message(role: &str, content: Vec<Value>) -> Value {
    let mut message = json!({"role": role});
    // Putting content inside json! would copy every normalized block.
    message["content"] = Value::Array(content);
    message
}

fn text_block(s: &str) -> Value {
    json!({"type":"text", "text":s})
}

pub(super) fn plain(s: &str) -> Vec<Value> {
    if s.is_empty() {
        vec![]
    } else {
        vec![text_block(s)]
    }
}

fn provider(v: &Value, format: &str) -> Value {
    json!({"type":"provider_content","format":format,"data":v})
}

pub(crate) fn tool_call(id: &Value, name: &Value, arguments: &Value) -> Value {
    let decoded = arguments
        .as_str()
        .and_then(|s| serde_json::from_str::<Value>(s).ok());
    json!({"type":"tool_call","id":id,"name":name,"arguments":decoded.as_ref().unwrap_or(arguments)})
}

fn tool_result(id: &Value, content: Vec<Value>, error: bool) -> Value {
    json!({"type":"tool_result","toolCallId":id,"content":content,"isError":error})
}

#[derive(Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ToolKind {
    Call,
    Result,
}

pub(super) fn anthropic_tool(kind: &str) -> Option<ToolKind> {
    match kind {
        "tool_use" | "server_tool_use" | "mcp_tool_use" => Some(ToolKind::Call),
        "tool_result" => Some(ToolKind::Result),
        k if k.ends_with("_tool_result") => Some(ToolKind::Result),
        _ => None,
    }
}

pub(super) fn responses_tool(kind: &str) -> Option<ToolKind> {
    match kind {
        "function_call" | "custom_tool_call" | "computer_call" => Some(ToolKind::Call),
        "function_call_output" | "custom_tool_call_output" | "computer_call_output" => {
            Some(ToolKind::Result)
        }
        _ => None,
    }
}

pub(crate) fn blocks(v: &Value, format: &str) -> Vec<Value> {
    if v.is_null() {
        return vec![];
    }
    if let Some(text) = v.as_str() {
        return plain(text);
    }
    let Some(items) = v.as_array() else {
        return vec![attachment::content_part(v, format)];
    };
    let mut result = Vec::new();
    for item in items {
        let block = match item["type"].as_str() {
            Some("text") if item["text"].is_string() => {
                if item["text"] == "" {
                    continue;
                }
                item.clone()
            }
            Some(kind)
                if format == ANTHROPIC
                    && anthropic_tool(kind) == Some(ToolKind::Call)
                    && optional_string(&item["id"]).is_ok()
                    && optional_string(&item["name"]).is_ok() =>
            {
                let mut call = tool_call(&item["id"], &item["name"], &item["input"]);
                if item["type"] == "server_tool_use" {
                    call["server"] = true.into();
                }
                if let Some(server) = item.get("server_name") {
                    call["server_name"] = server.clone();
                }
                call
            }
            Some(kind)
                if format == ANTHROPIC
                    && anthropic_tool(kind) == Some(ToolKind::Result)
                    && optional_string(&item["tool_use_id"]).is_ok() =>
            {
                tool_result(
                    &item["tool_use_id"],
                    blocks(&item["content"], format),
                    item["is_error"] == true
                        || item["content"]["type"]
                            .as_str()
                            .is_some_and(|kind| kind.ends_with("_tool_result_error")),
                )
            }
            _ => attachment::content_part(item, format),
        };
        result.push(block);
    }
    result
}

pub(crate) fn chat_message(v: &Value, format: &str) -> Parsed {
    let role = v["role"].as_str().ok_or(BodyError::InvalidContent)?;
    let mut content = blocks(&v["content"], format);
    if format == CHAT {
        optional_string(&v["tool_call_id"])?;
        if matches!(role, "tool" | "function") {
            let mut result = tool_result(&v["tool_call_id"], content, false);
            if let Some(name) = v["name"].as_str() {
                result["name"] = name.into();
            }
            content = vec![result];
        }
        if let Some(calls) = v["tool_calls"].as_array() {
            for call in calls {
                if !call.is_object() {
                    return Err(BodyError::InvalidContent);
                }
                let f = &call["function"];
                if f.is_object() {
                    optional_string(&call["id"])?;
                    optional_string(&call["type"])?;
                    optional_string(&f["name"])?;
                    if !call["index"].is_null() {
                        response::index(&call["index"])?;
                    }
                    content.push(tool_call(&call["id"], &f["name"], &f["arguments"]));
                } else {
                    content.push(provider(call, format));
                }
            }
        }
        let f = &v["function_call"];
        if f.is_object() {
            optional_string(&f["name"])?;
            content.push(tool_call(&Value::Null, &f["name"], &f["arguments"]));
        }
        if let Some(s) = v["refusal"].as_str().filter(|s| !s.is_empty()) {
            content.push(json!({"type":"refusal","text":s}));
        }
        for key in ["annotations", "audio"] {
            if !v[key].is_null() {
                content.push(provider(&json!({(key): &v[key]}), format));
            }
        }
    }
    Ok(message(role, content))
}

fn responses_text_key(part: &Value) -> Option<&'static str> {
    match part["type"].as_str()? {
        "input_text" | "output_text" => Some("text"),
        "refusal" if part["refusal"].is_null() => Some("text"),
        "refusal" => Some("refusal"),
        _ => None,
    }
}

fn responses_blocks(v: &Value) -> Result<Vec<Value>, BodyError> {
    if let Some(s) = v.as_str() {
        return Ok(plain(s));
    }
    v.as_array()
        .ok_or(BodyError::InvalidContent)?
        .iter()
        .map(|item| {
            if !item.is_object() {
                return Err(BodyError::InvalidContent);
            }
            if let Some(key) = responses_text_key(item) {
                optional_string(&item["text"])?;
                optional_string(&item["refusal"])?;
                let text = item[key].as_str().ok_or(BodyError::InvalidContent)?;
                let mut b = item.clone();
                b.as_object_mut().unwrap().remove(key);
                b["type"] = if item["type"] == "refusal" {
                    "refusal"
                } else {
                    "text"
                }
                .into();
                b["text"] = text.into();
                Ok(b)
            } else {
                Ok(attachment::content_part(item, RESPONSES))
            }
        })
        .collect()
}

pub(crate) fn responses_item(item: &Value) -> Parsed {
    let kind = optional_string(&item["type"])?;
    if !item.is_object() {
        return Err(BodyError::InvalidContent);
    }
    let tool = kind.and_then(responses_tool);
    if tool.is_none() && !matches!(kind, None | Some("message")) {
        return Ok(message("assistant", vec![provider(item, RESPONSES)]));
    }
    for key in ["id", "role", "call_id", "name", "arguments"] {
        optional_string(&item[key])?;
    }
    Ok(match tool {
        Some(ToolKind::Call) if kind == Some("computer_call") => {
            message("assistant", vec![provider(item, RESPONSES)])
        }
        Some(ToolKind::Call) => {
            let custom = kind == Some("custom_tool_call");
            let input_key = if custom { "input" } else { "arguments" };
            for key in ["call_id", "name", input_key] {
                item[key].as_str().ok_or(BodyError::InvalidContent)?;
            }
            let mut call = if custom {
                json!({"type":"tool_call","id":item["call_id"],"name":item["name"],"arguments":item[input_key]})
            } else {
                tool_call(&item["call_id"], &item["name"], &item[input_key])
            };
            if let Some(namespace) = item["namespace"].as_str() {
                call["namespace"] = namespace.into();
            }
            message("assistant", vec![call])
        }
        Some(ToolKind::Result) => {
            item["call_id"].as_str().ok_or(BodyError::InvalidContent)?;
            message(
                "tool",
                vec![tool_result(
                    &item["call_id"],
                    if kind == Some("computer_call_output") {
                        vec![attachment::content_part(&item["output"], RESPONSES)]
                    } else {
                        responses_blocks(&item["output"])?
                    },
                    false,
                )],
            )
        }
        _ => message(
            item["role"].as_str().ok_or(BodyError::InvalidContent)?,
            responses_blocks(&item["content"])?,
        ),
    })
}

fn tools(v: &Value, format: &str) -> Parsed {
    if v.is_null() {
        return Ok(Value::Null);
    }
    let mut definitions = Vec::new();
    for item in v.as_array().ok_or(BodyError::InvalidContent)? {
        definitions.push(tool_definition(item, format)?);
    }
    Ok(Value::Array(definitions))
}

pub(super) fn tool_definition(item: &Value, format: &str) -> Parsed {
    let source = match format {
        CHAT if item["function"].is_object() => &item["function"],
        ANTHROPIC if item.is_object() && (item["type"].is_null() || item["type"] == "custom") => {
            item
        }
        RESPONSES if item["type"] == "function" => item,
        _ => {
            return Ok(provider(item, format));
        }
    };
    let schema = if format == ANTHROPIC {
        "input_schema"
    } else {
        "parameters"
    };
    Ok(json!({
        "name": optional_string(&source["name"])?,
        "description": optional_string(&source["description"])?,
        "parameters": &source[schema],
    }))
}

// Select immediate user text parts only. A tool_result can itself contain text.
fn question(doc: &Value, format: &str) -> Option<String> {
    let input = if format == RESPONSES {
        &doc["input"]
    } else {
        &doc["messages"]
    };
    if let Some(text) = input.as_str() {
        return (!text.is_empty()).then(|| text.to_owned());
    }
    input
        .as_array()?
        .iter()
        .rev()
        .find_map(|message| user_question(message, format))
}

pub(super) fn user_question(message: &Value, format: &str) -> Option<String> {
    question_prefix(message, format, &[])
}

// A scalar projection ends at the first shortened component, even when another
// text block follows it. The structured messages can still retain later parts.
#[derive(Default)]
struct TextPrefix<'a> {
    text: String,
    ended: bool,
    cuts: &'a [&'a Value],
}

impl TextPrefix<'_> {
    fn push(&mut self, value: &Value) {
        if !self.ended
            && let Some(s) = value.as_str()
        {
            self.text.push_str(s);
            // Distinct blocks can contain identical text. Only the clipped
            // member of the decoded document terminates this projection.
            self.ended = self.cuts.iter().any(|v| std::ptr::eq(*v, value));
        }
    }

    fn content(&mut self, value: &Value, format: &str) {
        if value.is_string() {
            self.push(value);
        }
        for part in value.as_array().into_iter().flatten() {
            let key = if format == RESPONSES {
                responses_text_key(part)
            } else {
                (part["type"] == "text").then_some("text")
            };
            if let Some(key) = key {
                self.push(&part[key]);
            }
        }
    }
}

pub(super) fn question_prefix(message: &Value, format: &str, cuts: &[&Value]) -> Option<String> {
    let text_type = if format == RESPONSES {
        "input_text"
    } else {
        "text"
    };

    if message["role"] != "user"
        || (format == RESPONSES && !message["type"].is_null() && message["type"] != "message")
    {
        return None;
    }
    let content = &message["content"];
    let mut prefix = TextPrefix {
        cuts,
        ..Default::default()
    };
    if content.is_string() {
        prefix.push(content);
    } else {
        for part in content
            .as_array()?
            .iter()
            .filter(|p| p["type"] == text_type)
        {
            prefix.push(&part["text"]);
        }
    }
    (!prefix.text.is_empty()).then_some(prefix.text)
}

// Chat exposes alternatives as choices. Its scalar answer uses choice zero;
// Responses and Anthropic can contribute assistant text from every output.
pub(super) fn answer_candidate(protocol: &str, index: u64) -> bool {
    protocol != CHAT || index == 0
}

pub(super) fn answer_prefix(doc: &Value, format: &str, cuts: &[&Value]) -> String {
    let mut prefix = TextPrefix {
        cuts,
        ..Default::default()
    };
    match format {
        CHAT => {
            // The normalized answer is choice zero, with refusal following content.
            for choice in doc["choices"].as_array().into_iter().flatten().filter(|c| {
                response::index(&c["index"]).is_ok_and(|i| answer_candidate(format, i.into()))
            }) {
                let m = &choice["message"];
                if m["role"] == "assistant" {
                    prefix.content(&m["content"], format);
                    prefix.push(&m["refusal"]);
                }
            }
        }
        ANTHROPIC => prefix.content(&doc["content"], format),
        RESPONSES => {
            for m in doc["output"].as_array().into_iter().flatten() {
                if m["role"] == "assistant" && (m["type"].is_null() || m["type"] == "message") {
                    prefix.content(&m["content"], format);
                }
            }
        }
        _ => {}
    }
    prefix.text
}

// Consume only top-level visible blocks from a normalized assistant message.
pub(crate) fn answer_parts(message: &Value) -> impl Iterator<Item = &str> {
    message["content"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(move |part| {
            message["role"] == "assistant"
                && matches!(part["type"].as_str(), Some("text" | "refusal"))
        })
        .filter_map(|part| part["text"].as_str())
}

fn llm(v: &Value, format: &str, fields: Fields) -> Parsed {
    if !v.is_object() {
        return Err(BodyError::InvalidContent);
    }
    let mut view = json!({"format":format});
    optional_string(&v["model"])?;
    let mut messages = vec![];
    if format == RESPONSES {
        optional_string(&v["status"])?;
        if let Some(s) = optional_string(&v["instructions"])?
            && fields.input_messages
        {
            view["systemInstructions"] = plain(s).into();
        }
        match &v["input"] {
            Value::String(s) => {
                if fields.input_messages {
                    messages.push(message("user", plain(s)));
                }
            }
            Value::Array(items) => {
                if fields.input_messages {
                    for item in items {
                        messages.push(responses_item(item)?);
                    }
                }
            }
            Value::Null => (),
            _ => return Err(BodyError::InvalidContent),
        }
    } else {
        if format == ANTHROPIC {
            v["model"].as_str().ok_or(BodyError::InvalidContent)?;
            optional_string(&v["stop_reason"])?;
        }
        if format == ANTHROPIC && fields.input_messages && !v["system"].is_null() {
            view["systemInstructions"] = blocks(&v["system"], format).into();
        }
        let values = v["messages"].as_array().ok_or(BodyError::InvalidContent)?;
        if fields.input_messages {
            for m in values {
                messages.push(chat_message(m, format)?);
            }
        }
    }
    if fields.question
        && let Some(text) = question(v, format)
    {
        view["question"] = text.into();
    }
    if fields.input_messages {
        view["inputMessages"] = Value::Array(messages);
    }
    if fields.tools
        && let Some(t) = v.get("tools")
    {
        view["tools"] = tools(t, format)?;
    }
    if fields.tools
        && format == CHAT
        && let Some(legacy) = v["functions"].as_array()
    {
        let definitions = view
            .as_object_mut()
            .unwrap()
            .entry("tools")
            .or_insert_with(|| json!([]));
        if definitions.is_null() {
            *definitions = json!([]);
        }
        definitions
            .as_array_mut()
            .ok_or(BodyError::InvalidContent)?
            .extend(legacy.iter().cloned());
    }
    Ok(view)
}

pub(crate) fn document(format: &str, doc: &Value, response: bool, fields: Fields) -> Parsed {
    if format == "json" {
        return Ok(doc.clone());
    }
    let mut view = if response {
        response::normalize(format, doc, fields.output_messages || fields.answer)?
    } else {
        llm(doc, format, fields)?
    };
    if response {
        if let Some(id) = doc["id"].as_str() {
            view["responseId"] = id.into();
        }
        let mut reasons = Vec::new();
        if format == CHAT {
            for (i, c) in doc["choices"].as_array().into_iter().flatten().enumerate() {
                if let Some(reason) = c["finish_reason"].as_str() {
                    reasons.push((c["index"].as_u64().unwrap_or(i as u64), reason));
                }
            }
            reasons.sort_by_key(|(i, _)| *i);
        } else if format == ANTHROPIC
            && let Some(reason) = doc["stop_reason"].as_str()
        {
            reasons.push((0, reason));
        }
        if !reasons.is_empty() {
            view["finishReasons"] = reasons.into_iter().map(|(_, s)| Value::from(s)).collect();
        }
    } else {
        request_metadata(format, doc, &mut view);
    }
    Ok(view)
}

pub(super) fn request_metadata(format: &str, doc: &Value, view: &mut Value) {
    if let Some(model) = doc["model"].as_str() {
        view["model"] = model.into();
    }
    if let Some(stream) = doc["stream"].as_bool() {
        view["requestStream"] = stream.into();
    }
    let max_tokens = match format {
        CHAT => doc["max_completion_tokens"]
            .as_u64()
            .or_else(|| doc["max_tokens"].as_u64()),
        RESPONSES => doc["max_output_tokens"].as_u64(),
        _ => doc["max_tokens"].as_u64(),
    };
    if let Some(n) = max_tokens {
        view["maxTokens"] = n.into();
    }
    if format == RESPONSES {
        if let Some(id) = doc["conversation"]
            .as_str()
            .or_else(|| doc["conversation"]["id"].as_str())
        {
            view["conversationId"] = id.into();
        }
        if let Some(id) = doc["previous_response_id"].as_str() {
            view["previousResponseId"] = id.into();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_provider_extensions_and_tool_arguments() {
        let input = json!({"model":"m","tools":null,"messages":[{"role":"assistant","content":[
            {"type":"text","text":"hi","citations":[1]},
            {"type":"server_tool_use","name":"lookup","input":{"q":"hi"}},
            {"type":"image","source":{"type":"vendor_asset","id":"asset-1"}}
        ]}]});
        let view = document(ANTHROPIC, &input, false, Fields::DEFAULT).unwrap();
        let blocks = &view["inputMessages"][0]["content"];
        assert_eq!(blocks[0], input["messages"][0]["content"][0]);
        assert_eq!(
            blocks[1],
            json!({"type":"tool_call","server":true,"id":null,"name":"lookup","arguments":{"q":"hi"}})
        );
        assert_eq!(
            blocks[2],
            provider(&input["messages"][0]["content"][2], ANTHROPIC)
        );
        assert_eq!(view.get("tools"), Some(&Value::Null));
        let input = json!({"model":"m","messages":[{"role":"assistant","tool_calls":[
            {"id":"c","function":{"name":"lookup","arguments":"{bad"}}
        ]},{"role":"tool","tool_call_id":"c","content":"result"}]});
        let view = document(CHAT, &input, false, Fields::DEFAULT).unwrap();
        let msgs = &view["inputMessages"];
        assert_eq!(msgs[0]["content"][0]["arguments"], "{bad");
        assert_eq!(
            msgs[1]["content"][0],
            json!({"type":"tool_result","toolCallId":"c","content":[{"type":"text","text":"result"}],"isError":false})
        );
    }
}
