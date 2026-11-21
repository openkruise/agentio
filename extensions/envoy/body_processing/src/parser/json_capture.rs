// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::llm::tool_summary::ToolSummary;
use crate::parser::llm::{self, Fields};
use serde_json::{Value, json};

use memchr::memchr2;

// Keep a bounded JSON document for the existing protocol decoders. Scan quoted
// strings across body slices without ever copying their discarded suffix.
struct Scanner {
    doc: Vec<u8>,
    token: Vec<u8>,
    token_limit: usize,
    quoted: bool,
    escaped: bool,
    overflow: bool,
    path: Vec<Slot>,
    too_deep: bool,
    message_fragment: bool,
    text: Vec<String>,
    text_room: usize,
    format: &'static str,
    fields: Fields,
    response: bool,
    metadata: Value,
    scalar: Vec<u8>,
    reading_scalar: bool,
    selected_loss: bool,
    limit: usize,
    media_room: usize,
    exhausted: bool,
}

// One entry for each open container. Only keys needed by the projection are
// interned, so input key length and the number of siblings do not grow the path.
#[derive(Clone, Copy, PartialEq)]
enum Slot {
    Key,
    Field(&'static [u8]),
    Element,
}

use Slot::{Element, Field, Key};

const KEYS: &[&[u8]] = &[
    b"messages",
    b"input",
    b"instructions",
    b"system",
    b"choices",
    b"message",
    b"output",
    b"content",
    b"text",
    b"refusal",
    b"prompt",
    b"output_text",
    b"tools",
    b"functions",
    b"url",
    b"data",
    b"image_url",
    b"file_data",
    b"bytes",
    b"image",
    b"b64_json",
    b"model",
    b"stream",
    b"max_tokens",
    b"max_completion_tokens",
    b"max_output_tokens",
    b"conversation",
    b"id",
    b"previous_response_id",
];

fn field_name(raw: &[u8]) -> &'static [u8] {
    // Enough for the longest recognized key written entirely as Unicode escapes.
    if raw.len() > 128 {
        return b"";
    }
    let decoded;
    let name = if raw.contains(&b'\\') {
        decoded = decode_string(raw);
        decoded.as_deref().map(str::as_bytes).unwrap_or_default()
    } else {
        raw
    };
    KEYS.iter()
        .copied()
        .find(|key| *key == name)
        .unwrap_or_default()
}

fn decode_string(raw: &[u8]) -> Option<String> {
    let mut quoted = Vec::with_capacity(raw.len() + 2);
    quoted.push(b'"');
    quoted.extend_from_slice(raw);
    quoted.push(b'"');
    serde_json::from_slice(&quoted).ok()
}

fn message_text(path: &[Slot]) -> bool {
    matches!(
        path,
        [Field(b"content")] | [Field(b"content"), Element, Field(b"text" | b"refusal")]
    )
}

fn media_key(token: &[u8]) -> bool {
    matches!(
        token,
        b"url" | b"data" | b"image_url" | b"file_data" | b"bytes" | b"image" | b"b64_json"
    )
}

// Return a prefix ending on a complete UTF-8 character and JSON escape.
// Decoding only runs when clipping a string, never for each body chunk.
fn close_prefix(token: &[u8]) -> Vec<u8> {
    let mut candidate = Vec::with_capacity(token.len() + 2);
    candidate.push(b'"');
    candidate.extend_from_slice(token);
    candidate.push(b'"');
    for _ in 0..=12 {
        if serde_json::from_slice::<String>(&candidate).is_ok() {
            return candidate;
        }
        if candidate.len() <= 2 {
            break;
        }
        candidate.pop();
        *candidate.last_mut().unwrap() = b'"';
    }
    b"\"\"".to_vec()
}

impl Scanner {
    pub fn new(limit: usize, format: &'static str, response: bool, fields: Fields) -> Self {
        Self {
            doc: vec![],
            token: vec![],
            token_limit: 0,
            quoted: false,
            escaped: false,
            overflow: false,
            path: Vec::new(),
            too_deep: false,
            message_fragment: false,
            format,
            response,
            fields,
            metadata: json!({}),
            scalar: vec![],
            reading_scalar: false,
            selected_loss: false,
            text: vec![],
            text_room: limit / 2,
            limit,
            media_room: limit / 4,
            exhausted: false,
        }
    }

    fn selected_text(&self) -> bool {
        let path = self.path.as_slice();
        if self.message_fragment {
            return message_text(path);
        }
        if self.format == "json" {
            return matches!(
                path.last(),
                Some(Field(
                    b"text"
                        | b"content"
                        | b"input"
                        | b"instructions"
                        | b"system"
                        | b"prompt"
                        | b"output_text"
                ))
            );
        }
        if self.response && !self.fields.output_messages
            || !self.response && !self.fields.input_messages
        {
            return false;
        }
        match (self.format, self.response, path) {
            (llm::CHAT, true, [Field(b"choices"), Element, Field(b"message"), rest @ ..]) => {
                message_text(rest) || rest == [Field(b"refusal")]
            }
            (llm::ANTHROPIC, true, [Field(b"content"), Element, Field(b"text")]) => true,
            (llm::RESPONSES, true, [Field(b"output"), Element, rest @ ..]) => message_text(rest),
            (llm::CHAT | llm::ANTHROPIC, false, [Field(b"messages"), Element, rest @ ..]) => {
                message_text(rest)
            }
            (
                llm::ANTHROPIC,
                false,
                [Field(b"system")] | [Field(b"system"), Element, Field(b"text")],
            ) => true,
            (llm::RESPONSES, false, [Field(b"input" | b"instructions")]) => true,
            (llm::RESPONSES, false, [Field(b"input"), Element, rest @ ..]) => message_text(rest),
            _ => false,
        }
    }

    fn metadata_key(&self) -> Option<&'static str> {
        if self.response || self.format == "json" {
            return None;
        }
        match self.path.as_slice() {
            [
                Field(
                    key @ (b"model"
                    | b"stream"
                    | b"max_tokens"
                    | b"max_completion_tokens"
                    | b"max_output_tokens"
                    | b"conversation"
                    | b"previous_response_id"),
                ),
            ] => std::str::from_utf8(key).ok(),
            [Field(b"conversation"), Field(b"id")] => Some("conversation"),
            _ => None,
        }
    }

    fn selected_root(&self) -> bool {
        if self.response || self.format == "json" {
            return true;
        }
        match self.path.first() {
            Some(Field(b"input" | b"messages")) => {
                self.fields.input_messages || self.fields.question || self.fields.tool_call_refs
            }
            Some(Field(b"system" | b"instructions")) => self.fields.input_messages,
            Some(Field(b"tools" | b"functions")) => self.fields.tools,
            _ => self.metadata_key().is_some(),
        }
    }

    fn token_limit(&self) -> usize {
        let doc_room = if self.exhausted {
            0
        } else {
            self.limit.saturating_sub(self.doc.len() + 2)
        };
        let fallback_room = if self.path.last() == Some(&Key) {
            128
        } else if self.selected_text() {
            self.text_room
        } else if self.metadata_key().is_some() {
            self.limit
        } else {
            0
        };
        doc_room.max(fallback_room)
    }

    fn append_token(&mut self, data: &[u8]) {
        let take = data
            .len()
            .min(self.token_limit.saturating_sub(self.token.len()));
        self.token.extend_from_slice(&data[..take]);
        self.overflow |= take < data.len();
    }

    fn close_string(&mut self) {
        let key = self.path.last() == Some(&Key);
        if self.selected_text() && self.text_room > 4 && !self.token.is_empty() {
            let n = self.token.len().min(self.text_room - 4);
            let raw = close_prefix(&self.token[..n]);
            if let Ok(text) = serde_json::from_slice::<String>(&raw) {
                self.text_room -= n + 4;
                self.text.push(text);
            }
        }
        if !self.overflow
            && let Some(name) = self.metadata_key()
            && let Some(value) = decode_string(&self.token)
        {
            self.metadata[name] = value.into();
        }
        let media = matches!(self.path.last(), Some(Field(name)) if media_key(name));
        // A shortened key can alias a real protocol field. Switch to the path
        // projection rather than decoding a document with a fabricated key.
        if key
            && (self.overflow || self.token.len() + 2 > self.limit.saturating_sub(self.doc.len()))
        {
            self.exhausted = true;
        }
        if !self.exhausted {
            if self.overflow
                || self.token.len() + 2 > self.limit.saturating_sub(self.doc.len())
                || (media && self.token.len() > self.media_room)
            {
                self.selected_loss |= self.selected_root();
                if media {
                    // Keep the MIME type of inline images when their base64 payload is skipped.
                    let header = self
                        .token
                        .strip_prefix(b"data:")
                        .and_then(|s| s.split(|&c| c == b',').next());
                    if let Some(header) = header.filter(|h| {
                        h.len() <= 128
                            && h.ends_with(b";base64")
                            && h.iter()
                                .all(|b| b.is_ascii_alphanumeric() || b"/.+-;".contains(b))
                    }) {
                        self.doc.extend_from_slice(br#""data:"#);
                        self.doc.extend_from_slice(header);
                        self.doc.extend_from_slice(br#",[omitted]""#);
                    } else {
                        self.doc.extend_from_slice(br#""[omitted]""#);
                    }
                } else {
                    let prefix = &self.token[..self.token.len() / 2];
                    self.doc.extend_from_slice(&close_prefix(prefix));
                }
            } else {
                if media {
                    self.media_room -= self.token.len();
                }
                self.doc.push(b'"');
                self.doc.extend_from_slice(&self.token);
                self.doc.push(b'"');
            }
        }
        self.quoted = false;
        if key {
            *self.path.last_mut().unwrap() = Field(if self.overflow {
                b""
            } else {
                field_name(&self.token)
            });
        }
        self.token.clear();
        self.overflow = false;
    }

    pub fn push(&mut self, mut chunk: &[u8]) {
        while !chunk.is_empty() && !self.too_deep {
            if self.quoted {
                if self.escaped {
                    self.append_token(&chunk[..1]);
                    self.escaped = false;
                    chunk = &chunk[1..];
                    continue;
                }
                let n = memchr2(b'"', b'\\', chunk).unwrap_or(chunk.len());
                self.append_token(&chunk[..n]);
                chunk = &chunk[n..];
                if let Some((&ch, rest)) = chunk.split_first() {
                    if ch == b'"' {
                        self.close_string();
                    } else {
                        self.append_token(&chunk[..1]);
                        self.escaped = true;
                    }
                    chunk = rest;
                }
            } else {
                let ch = chunk[0];
                chunk = &chunk[1..];
                if self.reading_scalar {
                    if ch.is_ascii_whitespace() || matches!(ch, b',' | b'}') {
                        if self.scalar.len() <= 32
                            && let Some(key) = self.metadata_key()
                            && let Ok(value) = serde_json::from_slice::<Value>(&self.scalar)
                        {
                            self.metadata[key] = value;
                        }
                        self.reading_scalar = false;
                        self.scalar.clear();
                    } else if self.scalar.len() <= 32 {
                        self.scalar.push(ch);
                    }
                }
                if matches!(ch, b' ' | b'\t' | b'\n' | b'\r') {
                    if !self.exhausted && self.doc.last() != Some(&b' ') {
                        self.doc.push(b' ');
                    }
                    continue;
                }
                if ch == b'"' {
                    self.quoted = true;
                    self.token_limit = self.token_limit();
                } else {
                    if !self.exhausted {
                        self.doc.push(ch);
                    }
                    match ch {
                        b'{' | b'[' if self.path.len() == 128 => self.too_deep = true,
                        b'{' => self.path.push(Key),
                        b'[' => self.path.push(Element),
                        b'}' | b']' => {
                            self.path.pop();
                        }
                        b',' => {
                            if let Some(slot @ Field(_)) = self.path.last_mut() {
                                *slot = Key;
                            }
                        }
                        b'0'..=b'9' | b't' | b'f'
                            if !self.reading_scalar && self.metadata_key().is_some() =>
                        {
                            self.reading_scalar = true;
                            self.scalar.push(ch);
                        }
                        _ => {}
                    }
                }
            }
            if self.doc.len() > self.limit {
                self.exhausted = true;
            }
        }
    }

    fn finish(self, log_limit: usize) -> Result<Value, &'static str> {
        let format = self.format;
        if self.quoted || self.too_deep || !self.path.is_empty() {
            return Err("invalid_json");
        }
        if self.exhausted {
            let mut view = serde_json::json!({"format":format});
            if !self.response && format != "json" {
                llm::request_metadata(format, &self.metadata, &mut view);
            }
            if !self.text.is_empty() {
                view["retainedText"] = self.text.into();
            }
            return Ok(view);
        }
        parse(format, &self.doc, self.response, self.fields, log_limit)
    }
}

// Small documents take the ordinary protocol path unchanged. Once the budget
// is crossed, replay only the bounded prefix into the scanner and continue.
pub struct JsonCapture {
    limit: usize,
    prefix: Vec<u8>,
    scanner: Option<Box<Scanner>>,
    message_fragment: bool,
}

impl JsonCapture {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            prefix: vec![],
            scanner: None,
            message_fragment: false,
        }
    }
    pub(super) fn message_fragment(limit: usize) -> Self {
        Self {
            message_fragment: true,
            ..Self::new(limit)
        }
    }

    pub(super) fn exhausted(&self) -> bool {
        self.scanner.as_ref().is_some_and(|s| s.exhausted)
    }

    pub fn push(&mut self, chunk: &[u8], format: &'static str, response: bool, fields: Fields) {
        if let Some(s) = &mut self.scanner {
            s.push(chunk);
            return;
        }
        if chunk.len() <= self.limit - self.prefix.len() {
            self.prefix.extend_from_slice(chunk);
            return;
        }
        let mut s = Scanner::new(self.limit, format, response, fields);
        s.message_fragment = self.message_fragment;
        s.push(&std::mem::take(&mut self.prefix));
        s.push(chunk);
        self.scanner = Some(Box::new(s));
    }
    pub(super) fn finish_fragment(self) -> Result<(bool, Value), &'static str> {
        let limit = self.limit;
        self.finish("json", false, Fields::default(), limit)
    }

    pub fn finish(
        self,
        format: &str,
        response: bool,
        fields: Fields,
        log_limit: usize,
    ) -> Result<(bool, serde_json::Value), &'static str> {
        if let Some(s) = self.scanner {
            let clipped = s.exhausted || s.selected_loss;
            s.finish(log_limit).map(|v| (clipped, v))
        } else {
            parse(format, &self.prefix, response, fields, log_limit).map(|v| (false, v))
        }
    }
}

fn parse(
    format: &str,
    body: &[u8],
    response: bool,
    fields: Fields,
    log_limit: usize,
) -> Result<Value, &'static str> {
    let doc = serde_json::from_slice(body).map_err(|_| "invalid_json")?;
    if format == "json" {
        return Ok(doc);
    }
    project_document(format, &doc, response, fields, log_limit)
}

pub(super) fn project_document(
    format: &str,
    doc: &Value,
    response: bool,
    fields: Fields,
    log_limit: usize,
) -> Result<Value, &'static str> {
    let mut view = match llm::document(format, doc, response, fields) {
        Ok(view) => view,
        Err(status) if response => {
            // A malformed optional message must not discard valid metadata for
            // an audit which only asks for usage or tool references.
            let mut metadata = llm::document(format, doc, true, Fields::default())?;
            metadata["outputMessagesError"] = status.into();
            metadata
        }
        Err(status) => return Err(status),
    };
    if response && let Some(messages) = view["outputMessages"].as_array() {
        let answer: String = messages
            .iter()
            .filter(|message| format != llm::CHAT || message["index"] == 0)
            .flat_map(llm::answer_parts)
            .collect();
        view["answer"] = answer.into();
    }
    if format != "json" && fields.tool_call_refs {
        let mut calls = ToolSummary::new(log_limit);
        calls.document(format, doc, response);
        calls.publish(&mut view);
    }
    Ok(view)
}
