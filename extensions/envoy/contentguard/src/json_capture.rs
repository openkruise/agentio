// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use memchr::memchr2;

// Keep a bounded JSON document for the existing protocol decoders. Scan quoted
// strings across body slices without ever copying their discarded suffix.
struct Scanner {
    doc: Vec<u8>,
    token: Vec<u8>,
    quoted: bool,
    escaped: bool,
    overflow: bool,
    text_value: bool,
    last_key_text: bool,
    text: Vec<String>,
    text_room: usize,
    media_value: bool,
    last_key_media: bool,
    limit: usize,
    clipped: bool,
    media_room: usize,
    exhausted: bool,
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
    pub fn new(limit: usize) -> Self {
        Self {
            doc: vec![],
            token: vec![],
            quoted: false,
            escaped: false,
            overflow: false,
            text_value: false,
            last_key_text: false,
            text: vec![],
            text_room: limit / 2,
            media_value: false,
            last_key_media: false,
            limit,
            clipped: false,
            media_room: limit / 4,
            exhausted: false,
        }
    }

    fn append_token(&mut self, data: &[u8]) {
        let room = self
            .limit
            .saturating_sub(self.doc.len() + self.token.len() + 2);
        let room = if self.exhausted {
            let bound = if self.text_value { self.text_room } else { 32 };
            bound.saturating_sub(self.token.len())
        } else {
            room
        };
        let take = room.min(data.len());
        self.token.extend_from_slice(&data[..take]);
        self.overflow |= take < data.len();
    }

    fn close_string(&mut self) {
        // Save a bounded text projection even if repeated block descriptors
        // eventually exhaust the structural budget of the normalized document.
        self.last_key_text = !self.overflow
            && matches!(
                self.token.as_slice(),
                b"text"
                    | b"content"
                    | b"input"
                    | b"instructions"
                    | b"system"
                    | b"prompt"
                    | b"output_text"
            );
        if self.text_value && self.text_room > 4 && !self.token.is_empty() {
            let n = self.token.len().min(self.text_room - 4);
            let raw = close_prefix(&self.token[..n]);
            if let Ok(text) = serde_json::from_slice::<String>(&raw) {
                self.text_room -= n + 4;
                self.text.push(text);
            }
        }
        self.text_value = false;
        self.last_key_media = !self.overflow && media_key(&self.token);
        let media = self.media_value || self.token.starts_with(b"data:");
        if !self.exhausted {
            if self.overflow || (media && self.token.len() > self.media_room) {
                self.clipped = true;
                if media {
                    self.doc.extend_from_slice(br#""[omitted]""#);
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
        self.media_value = false;
        self.token.clear();
        self.overflow = false;
    }

    pub fn push(&mut self, mut chunk: &[u8]) {
        while !chunk.is_empty() {
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
                if matches!(ch, b' ' | b'\t' | b'\n' | b'\r') {
                    if !self.exhausted && self.doc.last() != Some(&b' ') {
                        self.doc.push(b' ');
                    }
                    continue;
                }
                if ch == b'"' {
                    self.quoted = true;
                } else {
                    if !self.exhausted {
                        self.doc.push(ch);
                    }
                    self.text_value = ch == b':' && self.last_key_text;
                    self.last_key_text = false;
                    self.media_value = ch == b':' && self.last_key_media;
                    self.last_key_media = false;
                }
            }
            if self.doc.len() > self.limit {
                self.exhausted = true;
                self.clipped = true;
            }
        }
    }

    pub fn finish(
        self,
        format: &str,
        response: bool,
        fields: crate::Fields,
    ) -> Result<serde_json::Value, &'static str> {
        if self.quoted {
            return Err("invalid_json");
        }
        if self.exhausted {
            let mut view = serde_json::json!({"format":format});
            // The fallback text projection has no field paths. Only expose it
            // when all potential source fields were selected.
            if format == "json"
                || (response && fields.output_messages)
                || (!response && fields.input_messages && fields.tools)
            {
                view["retainedText"] = self.text.into();
            }
            return Ok(view);
        }
        super::protocol::parse(format, &self.doc, response, fields)
    }
}

// Small documents take the ordinary protocol path unchanged. Once the budget
// is crossed, replay only the bounded prefix into the scanner and continue.
pub struct JsonCapture {
    limit: usize,
    prefix: Vec<u8>,
    scanner: Option<Scanner>,
}

impl JsonCapture {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            prefix: vec![],
            scanner: None,
        }
    }
    pub fn push(&mut self, chunk: &[u8]) {
        if let Some(s) = &mut self.scanner {
            s.push(chunk);
            return;
        }
        if chunk.len() <= self.limit - self.prefix.len() {
            self.prefix.extend_from_slice(chunk);
            return;
        }
        let mut s = Scanner::new(self.limit);
        s.push(&std::mem::take(&mut self.prefix));
        s.push(chunk);
        self.scanner = Some(s);
    }
    pub fn finish(
        self,
        format: &str,
        response: bool,
        fields: crate::Fields,
    ) -> Result<(bool, serde_json::Value), &'static str> {
        if let Some(s) = self.scanner {
            let clipped = s.clipped;
            s.finish(format, response, fields).map(|v| (clipped, v))
        } else {
            super::protocol::parse(format, &self.prefix, response, fields).map(|v| (false, v))
        }
    }
}
