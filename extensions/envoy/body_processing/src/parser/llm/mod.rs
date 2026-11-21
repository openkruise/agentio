// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod response;
pub(crate) mod sse;
pub(crate) mod stream;
pub(super) mod tool_summary;

use serde::Deserialize;
use serde_json::{Value, json};

pub const CHAT: &str = "openai-chat-completions";
pub const RESPONSES: &str = "openai-responses";
pub const ANTHROPIC: &str = "anthropic-messages";
const INVALID: &str = "invalid_content";
type Parsed = Result<Value, &'static str>;

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Fields {
    pub(crate) input_messages: bool,
    pub(crate) output_messages: bool,
    pub(crate) tools: bool,
    pub(crate) tool_call_refs: bool,
    pub(crate) question: bool,
    pub(crate) answer: bool,
}

impl Fields {
    pub(crate) const ALL: Self = Self {
        input_messages: true,
        output_messages: true,
        tools: true,
        tool_call_refs: true,
        question: true,
        answer: true,
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
        tool_call_refs: false,
        question: false,
        answer: false,
    };
}

pub(super) fn optional_string(v: &Value) -> Result<Option<&str>, &'static str> {
    if v.is_null() {
        Ok(None)
    } else {
        v.as_str().map(Some).ok_or(INVALID)
    }
}

fn message(role: &str, content: Vec<Value>) -> Value {
    json!({"role": role, "content": content})
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

#[derive(Clone, Copy, PartialEq)]
enum ToolKind {
    Call,
    Result,
}

fn anthropic_tool(kind: &str) -> Option<ToolKind> {
    match kind {
        "tool_use" | "server_tool_use" | "mcp_tool_use" => Some(ToolKind::Call),
        "tool_result" => Some(ToolKind::Result),
        k if k.ends_with("_tool_result") => Some(ToolKind::Result),
        _ => None,
    }
}

fn responses_tool(kind: &str) -> Option<ToolKind> {
    match kind {
        "function_call" | "custom_tool_call" => Some(ToolKind::Call),
        "function_call_output" | "custom_tool_call_output" => Some(ToolKind::Result),
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
        return vec![provider(v, format)];
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
            _ => provider(item, format),
        };
        result.push(block);
    }
    result
}

pub(crate) fn chat_message(v: &Value, format: &str) -> Parsed {
    let role = v["role"].as_str().ok_or(INVALID)?;
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
                    return Err(INVALID);
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

fn responses_blocks(v: &Value) -> Result<Vec<Value>, &'static str> {
    if let Some(s) = v.as_str() {
        return Ok(plain(s));
    }
    v.as_array()
        .ok_or(INVALID)?
        .iter()
        .map(|item| {
            if !item.is_object() {
                return Err(INVALID);
            }
            let refusal = item["type"] == "refusal";
            if refusal || matches!(item["type"].as_str(), Some("input_text" | "output_text")) {
                optional_string(&item["text"])?;
                optional_string(&item["refusal"])?;
                let key = if refusal && !item["refusal"].is_null() {
                    "refusal"
                } else {
                    "text"
                };
                let text = item[key].as_str().ok_or(INVALID)?;
                let mut b = item.clone();
                b.as_object_mut().unwrap().remove(key);
                b["type"] = if refusal { "refusal" } else { "text" }.into();
                b["text"] = text.into();
                Ok(b)
            } else {
                Ok(provider(item, RESPONSES))
            }
        })
        .collect()
}

pub(crate) fn responses_item(item: &Value) -> Parsed {
    let kind = optional_string(&item["type"])?;
    if !item.is_object() {
        return Err(INVALID);
    }
    let tool = kind.and_then(responses_tool);
    if tool.is_none() && !matches!(kind, None | Some("message")) {
        return Ok(message("assistant", vec![provider(item, RESPONSES)]));
    }
    for key in ["id", "role", "call_id", "name", "arguments"] {
        optional_string(&item[key])?;
    }
    Ok(match tool {
        Some(ToolKind::Call) => {
            let custom = kind == Some("custom_tool_call");
            let input_key = if custom { "input" } else { "arguments" };
            for key in ["call_id", "name", input_key] {
                item[key].as_str().ok_or(INVALID)?;
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
            item["call_id"].as_str().ok_or(INVALID)?;
            message(
                "tool",
                vec![tool_result(
                    &item["call_id"],
                    responses_blocks(&item["output"])?,
                    false,
                )],
            )
        }
        _ => message(
            item["role"].as_str().ok_or(INVALID)?,
            responses_blocks(&item["content"])?,
        ),
    })
}

fn tools(v: &Value, format: &str) -> Parsed {
    if v.is_null() {
        return Ok(Value::Null);
    }
    let mut definitions = Vec::new();
    for item in v.as_array().ok_or(INVALID)? {
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
    let text = if let Some(s) = content.as_str() {
        s.to_owned()
    } else {
        content
            .as_array()?
            .iter()
            .filter(|p| p["type"] == text_type)
            .filter_map(|p| p["text"].as_str())
            .collect()
    };
    (!text.is_empty()).then_some(text)
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
        return Err(INVALID);
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
            _ => return Err(INVALID),
        }
    } else {
        if format == ANTHROPIC {
            v["model"].as_str().ok_or(INVALID)?;
            optional_string(&v["stop_reason"])?;
        }
        if format == ANTHROPIC && fields.input_messages && !v["system"].is_null() {
            view["systemInstructions"] = blocks(&v["system"], format).into();
        }
        let values = v["messages"].as_array().ok_or(INVALID)?;
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
            .ok_or(INVALID)?
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
            {"type":"image","source":{"type":"url","url":"https://example.test"}}
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
