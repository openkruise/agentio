// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Attributes, Direction,
    projection::{Projection, response_view},
};
use crate::AuditRecords;
use crate::parser::body::{Content, Decoded, HttpCapture, ParsedBody};
use crate::parser::request::Event;
use serde::Serialize;
use serde_json::{Map, Value};

pub struct AuditContext<'a> {
    pub chain: &'a str,
    pub filter_index: usize,
    pub attributes: &'a Attributes,
}

pub struct Capture {
    filter_index: usize,
    record: Record,
    content_budget: usize,
    line_limit: usize,
    projection: Projection,
    pub(crate) settings: Direction,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    #[serde(rename = "type")]
    kind: &'static str,
    chain: String,
    #[serde(rename = "requestID")]
    id: String,
    direction: &'static str,
    path: String,
    capture_status: &'static str,
    bytes_seen: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded_bytes: Option<usize>,
    #[serde(rename = "llm.protocol", skip_serializing_if = "Option::is_none")]
    protocol: Option<&'static str>,
    #[serde(flatten)]
    attributes: Map<String, Value>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    attributes_truncated: bool,
}

fn prefix(s: &str, limit: usize) -> &str {
    &s[..s.floor_char_boundary(limit.min(s.len()))]
}

impl Capture {
    pub(crate) fn start(
        direction: &'static str,
        path: &str,
        id: &str,
        settings: Direction,
        context: AuditContext<'_>,
    ) -> Self {
        let AuditContext {
            chain,
            filter_index,
            attributes: attrs,
        } = context;
        let limit = settings.max_log_bytes;
        let path = path.split('?').next().unwrap_or(path);
        let mut record = Record {
            kind: "content",
            chain: chain.to_owned(),
            id: prefix(id, 128).to_owned(),
            direction,
            path: prefix(path, 256).to_owned(),
            capture_status: "complete",
            bytes_seen: 0,
            decoded_bytes: None,
            attributes: Map::new(),
            attributes_truncated: attrs.truncated,
            protocol: settings.format.protocol(),
        };
        // Reserve room for the longest status, byte count and newline. HTTP
        // header strings can expand when escaped into JSON.
        let mut envelope = serde_json::to_vec(&record).unwrap().len();
        if envelope + 128 >= limit {
            record.path.clear();
            if serde_json::to_vec(&record).unwrap().len() + 128 >= limit {
                record.id.clear();
            }
            envelope = serde_json::to_vec(&record).unwrap().len();
        }
        if !attrs.values.is_empty() {
            // Reserve room for the truncation flag and the longest
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
        Self {
            filter_index,
            record,
            content_budget: room,
            line_limit: limit,
            projection: Projection::default(),
            settings,
        }
    }

    pub(crate) fn document_room(&self) -> usize {
        self.settings
            .max_capture_bytes
            .unwrap_or(self.content_budget)
    }

    pub(crate) fn http_capture(&self, media: Option<&mime::Mime>, encoding: &str) -> HttpCapture {
        HttpCapture::new(
            self.settings.format,
            self.document_room(),
            self.settings.max_capture_bytes,
            media,
            encoding,
        )
    }
    pub(crate) fn observe(&mut self, event: &Event, clipped: bool, size: usize) {
        if self
            .settings
            .max_capture_bytes
            .is_none_or(|limit| size <= limit)
        {
            self.projection.observe(
                event,
                clipped,
                self.settings.fields,
                self.content_budget,
                self.line_limit,
            );
        }
    }
    pub(crate) fn project(
        &mut self,
        source: Result<&(bool, Value), &'static str>,
        request: bool,
        event_size: Option<usize>,
        size: usize,
    ) -> Decoded {
        let limit_exceeded = match event_size {
            Some(n) => n > self.settings.max_capture_bytes.unwrap_or(64 << 10),
            None => self.settings.max_capture_bytes.is_some_and(|n| size > n),
        };
        if limit_exceeded {
            return Err("too_large");
        }
        let (clipped, view) = source?;
        if (self.settings.fields.output_messages || self.settings.fields.answer)
            && view["outputMessagesError"].is_string()
        {
            return Err("invalid_content");
        }
        let (truncated, value) = if request {
            std::mem::take(&mut self.projection).finish(view)?
        } else {
            (
                *clipped
                    && (self.settings.fields.output_messages
                        || (self.settings.fields.answer && view.get("answer").is_none())),
                response_view(view, self.settings.fields, self.line_limit),
            )
        };
        Ok(ParsedBody {
            truncated,
            content: Content::Llm {
                value,
                streamed: event_size.is_some(),
            },
        })
    }
    pub(crate) fn finish(
        mut self,
        bytes_seen: usize,
        decoded_bytes: Option<usize>,
        body: Decoded,
        records: &mut AuditRecords,
    ) {
        self.record.bytes_seen = bytes_seen;
        self.record.decoded_bytes = decoded_bytes;
        records.record_audit(self.filter_index, self.record.direction, self.encode(body));
    }

    fn encode(mut self, result: Decoded) -> Vec<u8> {
        match result {
            Ok(ParsedBody {
                truncated: mut clipped,
                content,
            }) => {
                match content {
                    Content::Llm {
                        value: mut v,
                        streamed: stream,
                    } => {
                        clipped |= v["toolCallsTruncated"] == true;
                        if self.settings.fields.tool_call_refs
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
                            self.record.capture_status = "partial";
                        }
                        super::format::project(
                            &mut v,
                            &mut self.record.attributes,
                            self.record.direction == "response",
                            self.settings.fields.output_messages,
                        );
                    }
                    Content::Http(value) => {
                        self.record.attributes.insert("http.body".into(), value);
                    }
                    Content::Empty => (),
                }
                if clipped {
                    self.record.capture_status = "truncated";
                }
            }
            Err(e) => self.record.capture_status = e,
        }
        let mut line = serde_json::to_vec(&self.record).expect("record contains only JSON values");
        if line.len() >= self.line_limit {
            // Escaping and protocol normalization can enlarge the retained document.
            // Discard large binary leaves first, then shorten oversized text.
            self.record.capture_status = "truncated";
            const BODY_FIELDS: &[&str] = &[
                "http.body",
                "llm.question",
                "llm.answer",
                "llm.error",
                "llm.retainedText",
                "gen_ai.system_instructions",
                "gen_ai.input.messages",
                "gen_ai.output.messages",
                "gen_ai.tool.definitions",
            ];
            for &key in BODY_FIELDS {
                if let Some(v) = self.record.attributes.get_mut(key) {
                    shrink(v, self.content_budget / 4);
                }
            }
            line.clear();
            serde_json::to_writer(&mut line, &self.record).unwrap();
            if line.len() >= self.line_limit {
                for &key in BODY_FIELDS {
                    self.record.attributes.remove(key);
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
        line
    }
}

// The normalized messages and tool definitions share one retention budget.
fn bound_content(view: &mut Value, limit: usize) -> bool {
    let keys = [
        "systemInstructions",
        "inputMessages",
        "outputMessages",
        "question",
        "answer",
        "tools",
        "retainedText",
    ];
    let bytes: usize = keys
        .iter()
        .filter_map(|k| view.get(k))
        .map(crate::parser::encoded_len)
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

pub(super) fn shrink(v: &mut Value, cap: usize) {
    match v {
        Value::String(s) if s.len() > cap => {
            s.truncate(s.floor_char_boundary(cap));
        }
        Value::Array(a) => a.iter_mut().for_each(|child| shrink(child, cap)),
        Value::Object(m) => {
            if m.get("type").and_then(Value::as_str) == Some("blob")
                && m.get("content")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.len() > cap)
            {
                m.remove("content");
            }
            for (key, child) in m {
                if child.as_str().is_some_and(|s| {
                    s.len() > cap
                        && matches!(
                            key.as_str(),
                            "data" | "file_data" | "bytes" | "image_url" | "url" | "base64"
                        )
                }) {
                    let mime = child
                        .as_str()
                        .and_then(|s| s.strip_prefix("data:"))
                        .and_then(|s| s.get(..s.len().min(128)))
                        .and_then(|s| s.split_once(";base64,"))
                        .map(|(mime, _)| mime);
                    *child = match mime {
                        Some(mime) => format!("data:{mime};base64,[omitted]").into(),
                        None => "[omitted]".into(),
                    };
                } else {
                    shrink(child, cap);
                }
            }
        }
        _ => {}
    }
}
