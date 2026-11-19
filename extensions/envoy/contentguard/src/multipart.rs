// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use base64::{Engine, engine::general_purpose::STANDARD};
use memchr::memmem;
use serde_json::{Value, json};

const HEADER_LIMIT: usize = 8192;

enum State {
    First,
    Headers,
    Data,
    End,
}

struct Part {
    name: String,
    filename: Option<String>,
    media: Option<String>,
    data: Vec<u8>,
    bytes: usize,
}

impl Part {
    fn from_headers(bytes: &[u8]) -> Option<Self> {
        let mut disposition = None;
        let mut media = None;
        for line in std::str::from_utf8(bytes).ok()?.split("\r\n") {
            let (key, value) = line.split_once(':')?;
            if key.eq_ignore_ascii_case("content-disposition") {
                // Parse MIME parameters, including quoted field names and filenames.
                disposition = format!("multipart/{}", value.trim())
                    .parse::<mime::Mime>()
                    .ok();
            } else if key.eq_ignore_ascii_case("content-type") {
                media = Some(value.trim().to_owned());
            }
        }
        let disp = disposition?;
        Some(Self {
            name: disp.get_param("name")?.as_str().to_owned(),
            filename: disp.get_param("filename").map(|f| f.as_str().to_owned()),
            media,
            data: vec![],
            bytes: 0,
        })
    }

    fn append(&mut self, data: &[u8], room: usize) {
        self.bytes += data.len();
        // A file either fits in base64 or is omitted entirely. Release its
        // provisional storage immediately so subsequent fields get the budget.
        if self.filename.is_some() && self.bytes.div_ceil(3).saturating_mul(4) > room {
            self.data = Vec::new();
        } else {
            let take = data.len().min(room.saturating_sub(self.data.len()));
            self.data.extend_from_slice(&data[..take]);
        }
    }
}

pub struct Multipart {
    delimiter: Vec<u8>,
    pending: Vec<u8>,
    state: State,
    part: Option<Part>,
    fields: Vec<Value>,
    remaining: usize,
    clipped: bool,
}

impl Multipart {
    pub fn new(boundary: &str, limit: usize) -> Option<Self> {
        if boundary.is_empty() || boundary.len() > 70 {
            return None;
        }
        Some(Self {
            delimiter: format!("\r\n--{boundary}").into_bytes(),
            pending: vec![],
            state: State::First,
            part: None,
            fields: vec![],
            remaining: limit,
            clipped: false,
        })
    }

    fn end_part(&mut self) {
        let part = self.part.take().unwrap();
        let mut field = json!({"name":part.name, "bytes":part.bytes});
        if let Some(media) = part.media {
            field["contentType"] = media.into();
        }
        let partial = part.data.len() != part.bytes;
        if let Some(filename) = part.filename {
            field["filename"] = filename.into();
            if partial {
                field["omitted"] = true.into();
            } else {
                field["base64"] = STANDARD.encode(&part.data).into();
            }
        } else {
            field["text"] = String::from_utf8_lossy(&part.data).into_owned().into();
            if partial {
                field["truncated"] = true.into();
            }
        }
        self.clipped |= partial;
        let size = field.to_string().len() + 1;
        if size <= self.remaining {
            self.remaining -= size;
            self.fields.push(field);
        } else {
            self.clipped = true;
        }
    }

    pub fn push(&mut self, data: &[u8]) -> Result<(), &'static str> {
        // Bound temporary scratch even if Envoy delivers a single very large slice.
        for chunk in data.chunks(8192) {
            if matches!(self.state, State::End) {
                break;
            }
            self.pending.extend_from_slice(chunk);
            let mut pos = 0;
            loop {
                let buf = &self.pending[pos..];
                match self.state {
                    State::First => {
                        let initial = &self.delimiter[2..];
                        if buf.len() < initial.len() + 2 {
                            break;
                        }
                        if !buf.starts_with(initial) {
                            return Err("invalid_multipart");
                        }
                        pos += initial.len();
                        match &self.pending[pos..pos + 2] {
                            b"--" => self.state = State::End,
                            b"\r\n" => self.state = State::Headers,
                            _ => return Err("invalid_multipart"),
                        }
                        pos += 2;
                    }
                    State::Headers => {
                        let Some(n) = memmem::find(buf, b"\r\n\r\n") else {
                            if buf.len() > HEADER_LIMIT + 3 {
                                return Err("multipart_headers_too_large");
                            }
                            break;
                        };
                        if n > HEADER_LIMIT {
                            return Err("multipart_headers_too_large");
                        }
                        self.part = Some(Part::from_headers(&buf[..n]).ok_or("invalid_multipart")?);
                        pos += n + 4;
                        self.state = State::Data;
                    }
                    State::Data => {
                        let found = memmem::find(buf, &self.delimiter);
                        let n = found
                            .unwrap_or_else(|| buf.len().saturating_sub(self.delimiter.len() - 1));
                        let room = self.remaining.saturating_sub(160);
                        self.part.as_mut().unwrap().append(&buf[..n], room);
                        pos += n;
                        if found.is_none() || self.pending.len() - pos < self.delimiter.len() + 2 {
                            break;
                        }
                        let suffix = pos + self.delimiter.len();
                        let next = match &self.pending[suffix..suffix + 2] {
                            b"--" => State::End,
                            b"\r\n" => State::Headers,
                            _ => {
                                self.part
                                    .as_mut()
                                    .unwrap()
                                    .append(&self.pending[pos..pos + 1], room);
                                pos += 1;
                                continue;
                            }
                        };
                        self.end_part();
                        self.state = next;
                        pos = suffix + 2;
                    }
                    State::End => {
                        pos = self.pending.len();
                        break;
                    }
                }
            }
            self.pending.drain(..pos);
        }
        Ok(())
    }

    pub fn finish(self) -> Result<(bool, Value), &'static str> {
        if !matches!(self.state, State::End) {
            return Err("invalid_multipart");
        }
        Ok((self.clipped, json!({"parts":self.fields})))
    }
}
