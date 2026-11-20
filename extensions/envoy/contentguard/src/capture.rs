// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::audit::{self, Attributes, Schema};
use crate::{
    Direction, Fields, Format, json_capture::JsonCapture, multipart::Multipart, protocol, sse,
};
use serde::Serialize;
use serde_json::{Map, Value};

enum Body {
    Json(JsonCapture, &'static str),
    Multipart(Multipart),
    Stream(Box<sse::Stream>),
    Text(Vec<u8>),
    Unavailable(&'static str),
}

pub struct Capture {
    schema: Schema,
    body: Body,
    record: Record,
    content_budget: usize,
    line_limit: usize,
    settings: Direction,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(rename = "requestID")]
    id: String,
    direction: &'static str,
    path: String,
    status: &'static str,
    bytes_seen: usize,
    #[serde(skip_serializing_if = "Map::is_empty")]
    attributes: Map<String, Value>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    attributes_truncated: bool,
    content: Value,
}

fn format(path: &str) -> &'static str {
    match path.trim_end_matches('/').rsplit('/').next() {
        Some("completions") => protocol::CHAT,
        Some("responses") => protocol::RESPONSES,
        Some("messages") => protocol::ANTHROPIC,
        _ => "json",
    }
}

fn prefix(s: &str, limit: usize) -> &str {
    &s[..s.floor_char_boundary(limit.min(s.len()))]
}

impl Capture {
    pub fn new(
        direction: &'static str,
        path: &str,
        id: &str,
        media: &str,
        encoding: &str,
        settings: Direction,
        (schema, attrs): (Schema, &Attributes),
    ) -> Self {
        let limit = settings.max_log_bytes;
        let path = path.split('?').next().unwrap_or(path);
        let mut record = Record {
            kind: "content",
            id: prefix(id, 128).to_owned(),
            direction,
            path: prefix(path, 256).to_owned(),
            status: "complete",
            bytes_seen: 0,
            attributes: Map::new(),
            attributes_truncated: attrs.truncated,
            content: Value::Null,
        };
        // Reserve room for the longest status, byte count and newline. HTTP
        // header strings can expand when escaped into JSON.
        let mut envelope = serde_json::to_vec(&record).unwrap().len();
        if envelope + 128 >= limit {
            record.path.clear();
            envelope = serde_json::to_vec(&record).unwrap().len();
        }
        if !attrs.values.is_empty() {
            // Reserve the attributes object, truncation flag, and the longest
            // status and byte count before charging each escaped key/value.
            let mut remaining = limit.saturating_sub(envelope + 112);
            for (key, value) in &attrs.values {
                let cost = serde_json::to_vec(key).unwrap().len()
                    + serde_json::to_vec(value).unwrap().len()
                    + 2;
                if cost > remaining {
                    record.attributes_truncated = true;
                    continue;
                }
                remaining -= cost;
                record.attributes.insert(key.clone(), value.clone());
            }
            envelope = serde_json::to_vec(&record).unwrap().len();
        }
        let room = limit.saturating_sub(envelope + 64);
        let codec = match settings.format {
            Format::Auto => format(path),
            Format::Text => "text",
            Format::Json => "json",
            Format::OpenaiChatCompletions => protocol::CHAT,
            Format::OpenaiResponses => protocol::RESPONSES,
            Format::AnthropicMessages => protocol::ANTHROPIC,
        };
        let auto = settings.format == Format::Auto;
        let llm = !matches!(codec, "json" | "text");
        let encoding = encoding.trim();
        let body = if !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity") {
            Body::Unavailable("unsupported_encoding")
        } else if let Ok(m) = media.parse::<mime::Mime>() {
            let essence = m.essence_str();
            let stream = direction == "response" && llm && essence == "text/event-stream";
            if codec != "text"
                && m.type_() == mime::APPLICATION
                && (essence == "application/json" || m.suffix() == Some(mime::JSON))
            {
                Body::Json(
                    JsonCapture::new(settings.max_capture_bytes.unwrap_or(room)),
                    codec,
                )
            } else if auto && essence == "multipart/form-data" {
                m.get_param("boundary")
                    .and_then(|b| Multipart::new(b.as_str(), room))
                    .map_or(Body::Unavailable("invalid_multipart"), Body::Multipart)
            } else if stream
                || (auto && m.type_() == mime::TEXT && !(llm && essence == "text/event-stream"))
                || (codec == "text" && essence == "text/plain")
            {
                if m.get_param("charset").is_some_and(|v| {
                    !v.as_str().is_empty() && !v.as_str().eq_ignore_ascii_case("utf-8")
                }) {
                    Body::Unavailable("unsupported_encoding")
                } else if stream {
                    Body::Stream(Box::new(sse::Stream::new(
                        codec,
                        settings.max_capture_bytes.unwrap_or(64 << 10),
                        settings
                            .max_content_bytes
                            .or(settings.max_capture_bytes)
                            .unwrap_or(room),
                        settings.fields.unwrap_or(Fields::DEFAULT),
                        schema,
                        limit,
                    )))
                } else {
                    Body::Text(vec![])
                }
            } else {
                Body::Unavailable("unsupported_media_type")
            }
        } else {
            Body::Unavailable("unsupported_media_type")
        };
        Self {
            schema,
            record,
            body,
            content_budget: room,
            line_limit: limit,
            settings,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.record.bytes_seen += chunk.len();
        if matches!(self.body, Body::Json(..) | Body::Text(_))
            && self
                .settings
                .max_capture_bytes
                .is_some_and(|limit| self.record.bytes_seen > limit)
        {
            self.body = Body::Unavailable("too_large");
        }
        match &mut self.body {
            Body::Stream(stream) => {
                if let Err(code) = stream.push(chunk) {
                    self.body = Body::Unavailable(code);
                }
            }
            Body::Text(buf) => {
                let n = chunk.len().min(
                    self.settings
                        .max_capture_bytes
                        .unwrap_or(self.content_budget)
                        .saturating_sub(buf.len()),
                );
                buf.extend_from_slice(&chunk[..n]);
            }
            Body::Json(c, _) => c.push(chunk),
            Body::Multipart(c) => {
                if let Err(e) = c.push(chunk) {
                    self.body = Body::Unavailable(e);
                }
            }
            Body::Unavailable(_) => {}
        }
    }

    pub fn missing_buffer(&mut self, size: usize) {
        self.body = Body::Unavailable("capture_error");
        self.record.bytes_seen += size;
    }

    pub fn encode(mut self, complete: bool) -> (&'static [u8], Vec<u8>) {
        let stream = matches!(&self.body, Body::Stream(_));
        let llm = stream || matches!(&self.body,Body::Json(_,format) if *format!="json");
        let result = match self.body {
            _ if !complete => Err("incomplete"),
            Body::Unavailable("unsupported_media_type")
                if self.record.bytes_seen == 0 && self.settings.format == Format::Auto =>
            {
                Ok((false, Value::Null))
            }
            Body::Unavailable(e) => Err(e),
            Body::Json(c, f) => c.finish(
                f,
                self.record.direction == "response",
                self.settings.fields.unwrap_or(Fields::DEFAULT),
                self.schema,
                self.line_limit,
            ),
            Body::Stream(stream) => stream.finish(),
            Body::Multipart(c) => c.finish(),
            Body::Text(buf) => {
                let clipped = self.record.bytes_seen > buf.len();
                match std::str::from_utf8(&buf) {
                    Ok(text) => Ok((clipped, Value::from(text))),
                    Err(e) if clipped && e.error_len().is_none() => Ok((
                        true,
                        Value::from(std::str::from_utf8(&buf[..e.valid_up_to()]).unwrap()),
                    )),
                    Err(_) => Err("invalid_text"),
                }
            }
        };
        match result {
            Ok((mut clipped, mut v)) => {
                if llm {
                    clipped |= v["toolCallsTruncated"] == true;
                    if self.settings.fields.is_some_and(|f| f.tool_calls)
                        && let Some(summary) =
                            v.as_object_mut().and_then(|doc| doc.remove("toolCalls"))
                    {
                        self.record
                            .attributes
                            .insert("agentio.tool.calls".into(), summary);
                    }
                    if let Some(limit) = self
                        .settings
                        .max_content_bytes
                        .or(self.settings.max_capture_bytes)
                        .or_else(|| stream.then_some(self.content_budget))
                        && bound_content(&mut v, limit)
                    {
                        clipped = true;
                    }
                    if v["partial"] == true {
                        self.record.status = "partial";
                    }
                }
                if llm && self.schema == Schema::Genai {
                    audit::project(
                        &mut v,
                        &mut self.record.attributes,
                        self.record.direction == "response",
                    );
                }
                self.record.content = v;
                if clipped {
                    self.record.status = "truncated";
                }
            }
            Err(e) => self.record.status = e,
        }
        let mut line = serde_json::to_vec(&self.record).expect("record contains only JSON values");
        if line.len() >= self.line_limit {
            // Escaping and protocol normalization can enlarge the retained document.
            // Discard large binary leaves first, then shorten oversized text.
            self.record.status = "truncated";
            shrink(&mut self.record.content, self.content_budget / 4);
            if self.schema == Schema::Genai {
                for key in [
                    "gen_ai.input.messages",
                    "gen_ai.output.messages",
                    "gen_ai.tool.definitions",
                ] {
                    if let Some(v) = self.record.attributes.get_mut(key) {
                        shrink(v, self.content_budget / 4);
                    }
                }
            }
            line.clear();
            serde_json::to_writer(&mut line, &self.record).unwrap();
            if line.len() >= self.line_limit {
                self.record.content = Value::Null;
                if self.schema == Schema::Genai {
                    for key in [
                        "gen_ai.input.messages",
                        "gen_ai.output.messages",
                        "gen_ai.tool.definitions",
                    ] {
                        self.record.attributes.remove(key);
                    }
                }
                line.clear();
                serde_json::to_writer(&mut line, &self.record).unwrap();
            }
        }
        if line.len() >= self.line_limit
            && self
                .record
                .attributes
                .remove("agentio.tool.calls")
                .is_some()
        {
            self.record.attributes_truncated = true;
            line.clear();
            serde_json::to_writer(&mut line, &self.record).unwrap();
        }
        if line.len() >= self.line_limit {
            self.record.attributes.clear();
            self.record.attributes_truncated = true;
            line.clear();
            serde_json::to_writer(&mut line, &self.record).unwrap();
        }
        let key: &[u8] = if self.record.direction == "request" {
            b"agentio.contentguard.request"
        } else {
            b"agentio.contentguard.response"
        };
        (key, line)
    }
}

// The normalized messages and tool definitions share one retention budget.
fn bound_content(view: &mut Value, limit: usize) -> bool {
    let keys = ["inputMessages", "outputMessages", "tools", "retainedText"];
    let bytes: usize = keys
        .iter()
        .filter_map(|k| view.get(k))
        .map(protocol::encoded_len)
        .sum();
    if bytes <= limit {
        return false;
    }
    let map = view.as_object_mut().expect("LLM view is an object");
    for k in keys {
        map.remove(k);
    }
    view["truncated"] = true.into();
    true
}

fn shrink(v: &mut Value, cap: usize) {
    match v {
        Value::String(s) if s.len() > cap => {
            s.truncate(s.floor_char_boundary(cap));
        }
        Value::Array(a) => a.iter_mut().for_each(|child| shrink(child, cap)),
        Value::Object(m) => {
            for (key, child) in m {
                if child.as_str().is_some_and(|s| {
                    s.len() > cap
                        && (s.starts_with("data:")
                            || matches!(
                                key.as_str(),
                                "data" | "file_data" | "bytes" | "image_url" | "url" | "base64"
                            ))
                }) {
                    *child = Value::from("[omitted]");
                } else {
                    shrink(child, cap);
                }
            }
        }
        _ => {}
    }
}
