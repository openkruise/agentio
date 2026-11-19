// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::{json_capture::JsonCapture, multipart::Multipart, protocol};
use serde::Serialize;
use serde_json::Value;

enum Body {
    Json(JsonCapture, &'static str),
    Multipart(Multipart),
    Text(Vec<u8>),
    Unavailable(&'static str),
}

pub struct Capture {
    body: Body,
    record: Record,
    content_budget: usize,
    line_limit: usize,
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
        limit: usize,
    ) -> Self {
        let path = path.split('?').next().unwrap_or(path);
        let mut record = Record {
            kind: "content",
            id: prefix(id, 128).to_owned(),
            direction,
            path: prefix(path, 256).to_owned(),
            status: "complete",
            bytes_seen: 0,
            content: Value::Null,
        };
        // Reserve room for the longest status, byte count and newline. HTTP
        // header strings can expand when escaped into JSON.
        if serde_json::to_vec(&record).unwrap().len() + 128 >= limit {
            record.path.clear();
        }
        let room = limit.saturating_sub(serde_json::to_vec(&record).unwrap().len() + 64);
        let body = if !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity") {
            Body::Unavailable("unsupported_encoding")
        } else if let Ok(m) = media.parse::<mime::Mime>() {
            if m == mime::APPLICATION_JSON
                || m.essence_str() == "application/json"
                || m.suffix() == Some(mime::JSON)
            {
                let codec = if direction == "request" {
                    format(path)
                } else {
                    "json"
                };
                Body::Json(JsonCapture::new(room), codec)
            } else if m.essence_str() == "multipart/form-data" {
                m.get_param("boundary")
                    .and_then(|b| Multipart::new(b.as_str(), room))
                    .map_or(Body::Unavailable("invalid_multipart"), Body::Multipart)
            } else if m.type_() == mime::TEXT {
                if m.get_param("charset")
                    .is_some_and(|v| !v.as_str().eq_ignore_ascii_case("utf-8"))
                {
                    Body::Unavailable("unsupported_encoding")
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
            record,
            body,
            content_budget: room,
            line_limit: limit,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.record.bytes_seen += chunk.len();
        match &mut self.body {
            Body::Text(buf) => {
                let n = chunk
                    .len()
                    .min(self.content_budget.saturating_sub(buf.len()));
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
        let result = match self.body {
            _ if !complete => Err("incomplete"),
            _ if self.record.bytes_seen == 0 => Ok((false, Value::Null)),
            Body::Unavailable(e) => Err(e),
            Body::Json(c, f) => c.finish(f),
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
            Ok((clipped, v)) => {
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
            line.clear();
            serde_json::to_writer(&mut line, &self.record).unwrap();
            if line.len() >= self.line_limit {
                self.record.content = Value::Null;
                line.clear();
                serde_json::to_writer(&mut line, &self.record).unwrap();
            }
        }
        let key: &[u8] = if self.record.direction == "request" {
            b"agentio.contentguard.request"
        } else {
            b"agentio.contentguard.response"
        };
        (key, line)
    }
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
