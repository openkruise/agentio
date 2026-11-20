// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use serde_json::{Value, json};

pub const CHAT: &str = "openai-chat-completions";
pub const RESPONSES: &str = "openai-responses";
pub const ANTHROPIC: &str = "anthropic-messages";
const INVALID: &str = "invalid_content";
type Parsed = Result<Value, &'static str>;

// Count the JSON bytes charged by EPE's encoding/json, including HTML escaping,
// without allocating another serialized copy of a retained message.
pub(crate) fn encoded_len<T: serde::Serialize + ?Sized>(value: &T) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            self.0 += 5 * bytes
                .iter()
                .filter(|b| matches!(b, b'<' | b'>' | b'&'))
                .count();
            self.0 += 3 * bytes
                .windows(3)
                .filter(|w| matches!(*w, [0xe2, 0x80, 0xa8 | 0xa9]))
                .count();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).expect("serializable protocol content");
    counter.0
}

fn optional_string(v: &Value) -> Result<Option<&str>, &'static str> {
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

fn plain(s: &str) -> Vec<Value> {
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
            Some("tool_use" | "server_tool_use")
                if format == ANTHROPIC
                    && optional_string(&item["id"]).is_ok()
                    && optional_string(&item["name"]).is_ok() =>
            {
                let mut call = tool_call(&item["id"], &item["name"], &item["input"]);
                if item["type"] == "server_tool_use" {
                    call["server"] = true.into();
                }
                call
            }
            Some("tool_result") if optional_string(&item["tool_use_id"]).is_ok() => tool_result(
                &item["tool_use_id"],
                blocks(&item["content"], format),
                item["is_error"] == true,
            ),
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
        if role == "tool" {
            content = vec![tool_result(&v["tool_call_id"], content, false)];
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
                        crate::response::index(&call["index"])?;
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
                let key = if refusal { "refusal" } else { "text" };
                let text = item[key].as_str().ok_or(INVALID)?;
                let mut b = item.clone();
                b.as_object_mut().unwrap().remove(key);
                b["type"] = key.into();
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
    if !matches!(
        kind,
        None | Some("message" | "function_call" | "function_call_output")
    ) {
        return Ok(message("assistant", vec![provider(item, RESPONSES)]));
    }
    for key in ["id", "role", "call_id", "name", "arguments"] {
        optional_string(&item[key])?;
    }
    Ok(match kind {
        Some("function_call") => {
            for key in ["call_id", "name", "arguments"] {
                item[key].as_str().ok_or(INVALID)?;
            }
            message(
                "assistant",
                vec![tool_call(
                    &item["call_id"],
                    &item["name"],
                    &item["arguments"],
                )],
            )
        }
        Some("function_call_output") => {
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
        let source = match format {
            CHAT if item["function"].is_object() => &item["function"],
            ANTHROPIC
                if item.is_object() && (item["type"].is_null() || item["type"] == "custom") =>
            {
                item
            }
            RESPONSES if item["type"] == "function" => item,
            _ => {
                definitions.push(provider(item, format));
                continue;
            }
        };
        let schema = if format == ANTHROPIC {
            "input_schema"
        } else {
            "parameters"
        };
        definitions.push(json!({
            "name": optional_string(&source["name"])?,
            "description": optional_string(&source["description"])?,
            "parameters": &source[schema],
        }));
    }
    Ok(Value::Array(definitions))
}

fn llm(v: &Value, format: &str, fields: crate::Fields) -> Parsed {
    if !v.is_object() {
        return Err(INVALID);
    }
    let mut view = json!({"format":format});
    if let Some(model) = optional_string(&v["model"])? {
        view["model"] = model.into();
    }
    let mut messages = vec![];
    if format == RESPONSES {
        optional_string(&v["status"])?;
        if let Some(s) = optional_string(&v["instructions"])?
            && fields.input_messages
        {
            messages.push(message("system", plain(s)));
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
        v["model"].as_str().ok_or(INVALID)?;
        if format == ANTHROPIC {
            optional_string(&v["stop_reason"])?;
        }
        if fields.input_messages && !v["system"].is_null() {
            messages.push(message("system", blocks(&v["system"], format)));
        }
        let values = v["messages"].as_array().ok_or(INVALID)?;
        if fields.input_messages {
            for m in values {
                messages.push(chat_message(m, format)?);
            }
        }
    }
    if fields.input_messages {
        view["inputMessages"] = Value::Array(messages);
    }
    if fields.tools
        && let Some(t) = v.get("tools")
    {
        view["tools"] = tools(t, format)?;
    }
    Ok(view)
}

pub fn parse(
    format: &str,
    body: &[u8],
    response: bool,
    fields: crate::Fields,
    schema: crate::audit::Schema,
) -> Parsed {
    let doc = serde_json::from_slice(body).map_err(|_| "invalid_json")?;
    if format == "json" {
        Ok(doc)
    } else if response {
        crate::response::normalize(format, &doc, fields.output_messages)
    } else {
        let mut view = llm(&doc, format, fields)?;
        if schema == crate::audit::Schema::Genai
            && format == RESPONSES
            && let Some(id) = doc["conversation"]
                .as_str()
                .or_else(|| doc["conversation"]["id"].as_str())
        {
            view["conversationId"] = id.into();
        }
        Ok(view)
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
        let view = parse(
            ANTHROPIC,
            input.to_string().as_bytes(),
            false,
            crate::Fields::ALL,
            Default::default(),
        )
        .unwrap();
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
        let view = parse(
            CHAT,
            input.to_string().as_bytes(),
            false,
            crate::Fields::ALL,
            Default::default(),
        )
        .unwrap();
        let msgs = &view["inputMessages"];
        assert_eq!(msgs[0]["content"][0]["arguments"], "{bad");
        assert_eq!(
            msgs[1]["content"][0],
            json!({"type":"tool_result","toolCallId":"c","content":[{"type":"text","text":"result"}],"isError":false})
        );
    }
}
