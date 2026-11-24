// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::llm::tool_summary::ToolSummary;
use crate::parser::BodyError;
use crate::parser::llm::{self, Fields, LlmView};
use serde_json::{Value, json};

use memchr::memchr2;

#[derive(Clone, Copy, Default)]
pub(crate) struct CaptureLoss {
    pub document: bool,
    pub exhausted: bool,
    pub text: bool,
    pub references: bool,
    pub preview: bool,
    pub answer: bool,
    pub error: bool,
    pub finish_reasons: bool,
    pub question_prefix_bytes: Option<usize>,
}

// An omitted item can replace the last question only if it actually carried
// user text. Object members may arrive in any order, including role after content.
#[derive(Default)]
struct MessageShape {
    user: bool,
    tool_role: bool,
    tool_item: bool,
    tool_block: bool,
    chat_call: bool,
    non_message: bool,
    visible_text: bool,
    block_text: bool,
    block_type: bool,
    preview_type: bool,
    // A block's type can follow its text. Restore this cursor for non-text blocks.
    preview_start: (usize, usize, bool, bool),
    question_parts: Vec<usize>,
    block_question: Option<usize>,
}

impl MessageShape {
    fn tool_output(&self, format: Option<&str>) -> bool {
        format == Some(llm::CHAT) && self.tool_role
            || format == Some(llm::RESPONSES) && self.non_message
    }

    fn has_tools(&self, format: &str) -> bool {
        match format {
            llm::CHAT => self.tool_role || self.chat_call,
            llm::ANTHROPIC => self.tool_block,
            llm::RESPONSES => self.tool_item,
            _ => false,
        }
    }
}

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
    array_indices: Vec<usize>,
    shortened_text: Vec<String>,
    too_deep: bool,
    message_format: Option<&'static str>,
    shape: MessageShape,
    text: Vec<String>,
    text_room: usize,
    format: &'static str,
    fields: Fields,
    response: bool,
    metadata: Value,
    choice: ChoiceMetadata,
    finish_reasons: Vec<(u64, String)>,
    reason_bytes: usize,
    scalar: Vec<u8>,
    reading_scalar: bool,
    loss: CaptureLoss,
    limit: usize,
    media_room: usize,
    exhausted: bool,
}

// Chat permits index to follow message. Attribute text loss after the complete choice.
#[derive(Default)]
struct ChoiceMetadata {
    index: Option<u64>,
    reason: Option<String>,
    text_clipped: bool,
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
    b"file_url",
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
    b"role",
    b"type",
    b"name",
    b"call_id",
    b"tool_use_id",
    b"tool_call_id",
    b"status",
    b"stop_reason",
    b"incomplete_details",
    b"reason",
    b"usage",
    b"prompt_tokens",
    b"completion_tokens",
    b"input_tokens",
    b"output_tokens",
    b"total_tokens",
    b"cache_read_input_tokens",
    b"cache_creation_input_tokens",
    b"prompt_tokens_details",
    b"completion_tokens_details",
    b"input_tokens_details",
    b"output_tokens_details",
    b"cached_tokens",
    b"reasoning_tokens",
    b"cache_write_tokens",
    b"function",
    b"custom",
    b"function_call",
    b"tool_calls",
    b"finish_reason",
    b"index",
    b"error",
    b"code",
    b"param",
];

// Each ASCII byte of a recognized key can be written as a six-byte JSON Unicode escape.
const MAX_ENCODED_KEY_BYTES: usize = {
    let mut longest = 0;
    let mut keys = KEYS;
    while let [key, rest @ ..] = keys {
        if key.len() > longest {
            longest = key.len();
        }
        keys = rest;
    }
    longest * 6
};

fn field_name(raw: &[u8]) -> &'static [u8] {
    if raw.len() > MAX_ENCODED_KEY_BYTES {
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
            array_indices: vec![],
            shortened_text: vec![],
            too_deep: false,
            message_format: None,
            shape: MessageShape::default(),
            format,
            response,
            fields,
            metadata: json!({}),
            choice: ChoiceMetadata::default(),
            finish_reasons: vec![],
            reason_bytes: 0,
            scalar: vec![],
            reading_scalar: false,
            loss: CaptureLoss::default(),
            text: vec![],
            text_room: limit / 2,
            limit,
            media_room: limit / 4,
            exhausted: false,
        }
    }

    fn selected_text(&self) -> bool {
        let path = self.path.as_slice();
        if self.message_format.is_some() {
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
        match (self.format, path) {
            (llm::CHAT, [Field(b"choices"), Element, Field(b"message"), rest @ ..]) => {
                message_text(rest) || rest == [Field(b"refusal")]
            }
            (llm::ANTHROPIC, [Field(b"content"), Element, Field(b"text")]) => true,
            (llm::RESPONSES, [Field(b"output"), Element, rest @ ..]) => message_text(rest),
            _ => false,
        }
    }

    // Only fixed, protocol-defined scalar paths are retained outside the
    // compact document. Large provider extensions cannot displace these values.
    fn response_metadata(&self) -> bool {
        self.response
            && matches!(
                self.path.as_slice(),
                [Field(b"id" | b"model" | b"status" | b"stop_reason")]
                    | [
                        Field(b"error"),
                        Field(b"type" | b"code" | b"message" | b"param")
                    ]
                    | [
                        Field(b"choices"),
                        Element,
                        Field(b"finish_reason" | b"index")
                    ]
                    | [Field(b"incomplete_details"), Field(b"reason")]
                    | [
                        Field(b"usage"),
                        Field(
                            b"prompt_tokens"
                                | b"completion_tokens"
                                | b"input_tokens"
                                | b"output_tokens"
                                | b"total_tokens"
                                | b"cache_read_input_tokens"
                                | b"cache_creation_input_tokens"
                        )
                    ]
                    | [
                        Field(b"usage"),
                        Field(
                            b"prompt_tokens_details"
                                | b"completion_tokens_details"
                                | b"input_tokens_details"
                                | b"output_tokens_details"
                        ),
                        Field(b"cached_tokens" | b"reasoning_tokens" | b"cache_write_tokens")
                    ]
            )
    }

    fn save_metadata(&mut self, value: Value) {
        match self.path.as_slice() {
            [Field(b"choices"), Element, Field(b"index")] => {
                self.choice.index = value.as_u64();
                return;
            }
            [Field(b"choices"), Element, Field(b"finish_reason")] => {
                self.choice.reason = value.as_str().map(str::to_owned);
                return;
            }
            _ => {}
        }
        let mut target = &mut self.metadata;
        for slot in &self.path {
            let Field(key) = slot else { unreachable!() };
            target = &mut target[std::str::from_utf8(key).unwrap()];
        }
        *target = value;
    }

    fn tool_identity(&self) -> bool {
        let path = self.path.as_slice();
        let (format, path) = match (self.message_format, self.format, path) {
            (Some(format), _, path) => (format, path),
            (_, llm::CHAT, [Field(b"choices"), Element, Field(b"message"), rest @ ..]) => {
                (llm::CHAT, rest)
            }
            (_, llm::ANTHROPIC, path) => (llm::ANTHROPIC, path),
            (_, llm::RESPONSES, [Field(b"output"), Element, rest @ ..]) => (llm::RESPONSES, rest),
            _ => return false,
        };
        match format {
            llm::CHAT => matches!(
                path,
                [Field(b"tool_call_id" | b"name" | b"role")]
                    | [Field(b"function_call"), Field(b"name")]
                    | [Field(b"tool_calls"), Element, Field(b"id" | b"type")]
                    | [
                        Field(b"tool_calls"),
                        Element,
                        Field(b"function" | b"custom"),
                        Field(b"name")
                    ]
            ),
            llm::ANTHROPIC => matches!(
                path,
                [
                    Field(b"content"),
                    Element,
                    Field(b"id" | b"name" | b"type" | b"tool_use_id")
                ]
            ),
            llm::RESPONSES => matches!(path, [Field(b"call_id" | b"name" | b"type")]),
            _ => false,
        }
    }

    fn token_limit(&self) -> usize {
        let doc_room = if self.exhausted {
            0
        } else {
            self.limit.saturating_sub(self.doc.len() + 2)
        };
        let fallback_room = if self.path.last() == Some(&Key) {
            MAX_ENCODED_KEY_BYTES
        } else if self.response_metadata() {
            self.limit
        } else if self.message_format.is_some()
            && matches!(
                self.path.as_slice(),
                [Field(b"role" | b"type")] | [Field(b"content"), Element, Field(b"type")]
            )
        {
            32
        } else if self.selected_text() {
            self.text_room
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
        let selected_text = self.selected_text();
        let nonempty = self.overflow || !self.token.is_empty();
        if let Some(format) = self.message_format {
            match self.path.as_slice() {
                [Field(b"role")] => {
                    let role = decode_string(&self.token);
                    self.shape.user = role.as_deref() == Some("user");
                    self.shape.tool_role = matches!(role.as_deref(), Some("tool" | "function"));
                }
                [Field(b"type")] => {
                    let kind = decode_string(&self.token);
                    self.shape.non_message = kind.as_deref() != Some("message");
                    self.shape.tool_item = kind.as_deref().and_then(llm::responses_tool).is_some();
                }
                [Field(b"content")] => self.shape.visible_text |= nonempty,
                [Field(b"content"), Element, Field(b"type")] => {
                    let kind = decode_string(&self.token);
                    self.shape.preview_type = if format == llm::RESPONSES {
                        matches!(kind.as_deref(), Some("input_text" | "output_text"))
                    } else {
                        kind.as_deref() == Some("text")
                    };
                    self.shape.block_type = kind.as_deref()
                        == Some(if format == llm::RESPONSES {
                            "input_text"
                        } else {
                            "text"
                        });
                    self.shape.tool_block |=
                        kind.as_deref().and_then(llm::anthropic_tool).is_some();
                }
                [Field(b"content"), Element, Field(b"text")] => self.shape.block_text = nonempty,
                _ => {}
            }
        }
        if selected_text && nonempty && !self.loss.preview {
            let n = self.token.len().min(self.text_room.saturating_sub(4));
            self.loss.preview |= self.overflow || n < self.token.len();
            if n > 0 {
                let raw = close_prefix(&self.token[..n]);
                let text: String = serde_json::from_slice(&raw).unwrap();
                self.text_room -= n + 4;
                if self.message_format.is_some() && self.path == [Field(b"content")] {
                    self.shape.question_parts.push(self.text.len());
                } else if self.message_format.is_some()
                    && self.path == [Field(b"content"), Element, Field(b"text")]
                {
                    self.shape.block_question = Some(self.text.len());
                }
                self.text.push(text);
            }
        }
        if !self.overflow
            && self.response_metadata()
            && let Some(value) = decode_string(&self.token)
        {
            self.save_metadata(value.into());
        }
        if self.overflow && self.path.first() == Some(&Field(b"error")) {
            self.loss.error = true;
        }
        if self.response
            && self.path == [Field(b"error"), Key]
            && !matches!(&self.token[..], b"type" | b"code" | b"message" | b"param")
        {
            self.loss.error = true;
        }
        let media = matches!(self.path.last(), Some(Field(name)) if media_key(name))
            || (self.path.last() == Some(&Field(b"file_url")) && self.token.starts_with(b"data:"));
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
                self.loss.document = true;
                self.loss.text |= selected_text;
                if self.format == llm::CHAT {
                    self.choice.text_clipped |= selected_text;
                } else {
                    self.loss.answer |= selected_text;
                }
                self.loss.references |= self.tool_identity();
                if media {
                    self.doc.push(b'"');
                    self.doc
                        .extend_from_slice(llm::attachment::data_uri_prefix(&self.token));
                    self.doc.extend_from_slice(br#"[omitted]""#);
                } else {
                    if selected_text && (self.response || self.message_format.is_some()) {
                        let mut indices = self.array_indices.iter();
                        let mut pointer = String::new();
                        for slot in &self.path {
                            pointer.push('/');
                            match slot {
                                Field(key) => pointer.push_str(std::str::from_utf8(key).unwrap()),
                                Element => pointer.push_str(&indices.next().unwrap().to_string()),
                                Key => unreachable!(),
                            }
                        }
                        self.shortened_text.push(pointer);
                    }
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
                            && let Ok(value) = serde_json::from_slice::<Value>(&self.scalar)
                        {
                            self.save_metadata(value);
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
                        b'{' => {
                            if self.response && self.path == [Field(b"error")] {
                                self.metadata["error"] = json!({});
                            }
                            if self.response
                                && self.path.first() == Some(&Field(b"error"))
                                && self.path.len() > 1
                            {
                                self.loss.error = true;
                            }
                            if self.message_format.is_some() {
                                match self.path.as_slice() {
                                    [Field(b"content"), Element] => {
                                        self.shape.preview_start = (
                                            self.text.len(),
                                            self.text_room,
                                            self.loss.preview,
                                            self.loss.text,
                                        )
                                    }
                                    [Field(b"tool_calls"), Element] | [Field(b"function_call")] => {
                                        self.shape.chat_call = true
                                    }
                                    _ => {}
                                }
                            }
                            self.path.push(Key);
                        }
                        b'[' => {
                            self.path.push(Element);
                            self.array_indices.push(0);
                        }
                        b'}' | b']' => {
                            if self.path.pop() == Some(Element) {
                                self.array_indices.pop();
                            }
                            if ch == b'}'
                                && self.message_format.is_some()
                                && self.path == [Field(b"content"), Element]
                            {
                                if !self.shape.preview_type {
                                    let (len, room, clipped, text_clipped) =
                                        self.shape.preview_start;
                                    self.text.truncate(len);
                                    self.text_room = room;
                                    self.loss.preview = clipped;
                                    self.loss.text = text_clipped;
                                }
                                if let Some(index) = self.shape.block_question.take()
                                    && self.shape.block_type
                                {
                                    self.shape.question_parts.push(index);
                                }
                                self.shape.visible_text |=
                                    self.shape.block_type && self.shape.block_text;
                                self.shape.block_type = false;
                                self.shape.preview_type = false;
                                self.shape.block_text = false;
                            }
                            if ch == b'}'
                                && self.format == llm::CHAT
                                && self.path == [Field(b"choices"), Element]
                            {
                                let choice = std::mem::take(&mut self.choice);
                                self.loss.answer |= choice.text_clipped
                                    && choice
                                        .index
                                        .is_some_and(|i| llm::answer_candidate(self.format, i));
                                if let Some(reason) = choice.reason {
                                    self.reason_bytes += reason.len() + 3;
                                    if self.reason_bytes <= self.limit {
                                        self.finish_reasons.push((
                                            choice
                                                .index
                                                .unwrap_or(self.finish_reasons.len() as u64),
                                            reason,
                                        ));
                                    } else {
                                        self.loss.finish_reasons = true;
                                    }
                                }
                            }
                        }
                        b',' => {
                            if let Some(slot @ Field(_)) = self.path.last_mut() {
                                *slot = Key;
                            } else if self.path.last() == Some(&Element) {
                                *self.array_indices.last_mut().unwrap() += 1;
                            }
                        }
                        b'0'..=b'9' | b'-' | b't' | b'f' | b'n'
                            if !self.reading_scalar && self.response_metadata() =>
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

    fn finish(mut self, log_limit: usize, loss: &mut CaptureLoss) -> Result<LlmView, BodyError> {
        let format = self.format;
        if self.quoted || self.too_deep || !self.path.is_empty() {
            return Err(BodyError::InvalidJson);
        }
        if self.exhausted {
            let mut view = serde_json::json!({"format":format});
            if self.response {
                view = llm::response::metadata(format, &self.metadata)?;
                if let Some(id) = self.metadata.get_mut("id").filter(|v| v.is_string()) {
                    view["responseId"] = id.take();
                }
                if let Some(reason) = self
                    .metadata
                    .get_mut("stop_reason")
                    .filter(|v| v.is_string())
                {
                    view["finishReasons"] = json!([reason.take()]);
                } else if !self.finish_reasons.is_empty() {
                    self.finish_reasons.sort_by_key(|(index, _)| *index);
                    view["finishReasons"] = self
                        .finish_reasons
                        .into_iter()
                        .map(|(_, reason)| Value::from(reason))
                        .collect();
                }
            }
            if self.shape.user
                && self.shape.visible_text
                && !self.shape.tool_output(self.message_format)
            {
                let question: String = self
                    .shape
                    .question_parts
                    .iter()
                    .map(|&i| self.text[i].as_str())
                    .collect();
                if !question.is_empty() {
                    view["question"] = question.into();
                }
            }
            if !self.shape.tool_output(self.message_format) && !self.text.is_empty() {
                view["retainedText"] = self.text.into();
            }
            return Ok(LlmView {
                document: view,
                partial: self.response,
                ..Default::default()
            });
        }
        let doc: Value = serde_json::from_slice(&self.doc).map_err(|_| BodyError::InvalidJson)?;
        let cuts: Vec<_> = self
            .shortened_text
            .iter()
            .filter_map(|p| doc.pointer(p))
            .collect();
        if let Some(protocol) = self.message_format {
            if !cuts.is_empty() {
                loss.question_prefix_bytes =
                    Some(llm::question_prefix(&doc, protocol, &cuts).map_or(0, |s| s.len()));
            }
            return Ok(doc.into());
        }
        if format == "json" {
            return Ok(doc.into());
        }
        project_document(format, &doc, self.response, self.fields, log_limit, &cuts)
    }
}

// Small documents take the ordinary protocol path unchanged. Once the budget
// is crossed, replay only the bounded prefix into the scanner and continue.
pub struct JsonCapture {
    limit: usize,
    prefix: Vec<u8>,
    scanner: Option<Box<Scanner>>,
    message_format: Option<&'static str>,
}

impl JsonCapture {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            prefix: vec![],
            scanner: None,
            message_format: None,
        }
    }
    pub(super) fn message_fragment(limit: usize, format: &'static str) -> Self {
        Self {
            message_format: Some(format),
            ..Self::new(limit)
        }
    }

    pub(super) fn has_user_text(&self, format: &str) -> bool {
        self.scanner.as_ref().is_some_and(|s| {
            s.shape.user
                && s.shape.visible_text
                && (format != llm::RESPONSES || !s.shape.non_message)
        })
    }

    fn loss(&self) -> CaptureLoss {
        self.scanner
            .as_ref()
            .map_or_else(CaptureLoss::default, |s| CaptureLoss {
                document: s.exhausted || s.loss.document,
                references: self.message_format.map_or(s.loss.references, |format| {
                    (s.loss.references || s.exhausted) && s.shape.has_tools(format)
                }),
                preview: s.loss.preview && !s.shape.tool_output(self.message_format),
                text: s.loss.text && !s.shape.tool_output(self.message_format),
                exhausted: s.exhausted,
                ..s.loss
            })
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
        s.message_format = self.message_format;
        s.push(&std::mem::take(&mut self.prefix));
        s.push(chunk);
        self.scanner = Some(Box::new(s));
    }
    pub(super) fn finish_fragment(self) -> Result<(CaptureLoss, Value), BodyError> {
        let limit = self.limit;
        self.finish("json", false, Fields::default(), limit)
            .map(|(loss, view)| (loss, view.document))
    }

    pub fn finish(
        self,
        format: &str,
        response: bool,
        fields: Fields,
        log_limit: usize,
    ) -> Result<(CaptureLoss, LlmView), BodyError> {
        let mut loss = self.loss();
        if let Some(s) = self.scanner {
            let view = s.finish(log_limit, &mut loss)?;
            Ok((loss, view))
        } else {
            parse(format, &self.prefix, response, fields, log_limit).map(|v| (loss, v))
        }
    }
}

fn parse(
    format: &str,
    body: &[u8],
    response: bool,
    fields: Fields,
    log_limit: usize,
) -> Result<LlmView, BodyError> {
    let doc: Value = serde_json::from_slice(body).map_err(|_| BodyError::InvalidJson)?;
    if format == "json" {
        return Ok(doc.into());
    }
    project_document(format, &doc, response, fields, log_limit, &[])
}

fn project_document(
    format: &str,
    doc: &Value,
    response: bool,
    fields: Fields,
    log_limit: usize,
    cuts: &[&Value],
) -> Result<LlmView, BodyError> {
    let mut view = match llm::document(format, doc, response, fields) {
        Ok(value) => LlmView::from(value),
        Err(status) if response => {
            // A malformed optional message must not discard valid metadata for
            // an audit which only asks for usage or tool references.
            LlmView {
                document: llm::document(format, doc, true, Fields::default())?,
                output_messages_error: Some(status),
                ..Default::default()
            }
        }
        Err(status) => return Err(status),
    };
    if response && view.document["outputMessages"].is_array() {
        view.document["answer"] = llm::answer_prefix(doc, format, cuts).into();
    }
    if format != "json" && fields.tool_call_refs {
        let mut calls = ToolSummary::new(log_limit);
        calls.document(format, doc, response);
        view.tool_refs = calls.finish();
    }
    Ok(view)
}
