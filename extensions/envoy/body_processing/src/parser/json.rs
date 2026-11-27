// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::BodyError;
use serde_json::Value;

/// Keep small JSON verbatim. On overflow, replay the prefix once into the
/// caller's streaming scanner and feed all remaining chunks to that scanner.
pub(super) enum Buffer<S> {
    Raw(Vec<u8>),
    Scanning(Box<S>),
}

pub(super) trait Scan {
    fn push(&mut self, chunk: &[u8]);
}

impl<S: Scan> Buffer<S> {
    pub(super) fn push(&mut self, chunk: &[u8], limit: usize, start: impl FnOnce() -> S) {
        match self {
            Self::Raw(prefix) if chunk.len() <= limit - prefix.len() => {
                prefix.extend_from_slice(chunk)
            }
            Self::Raw(prefix) => {
                let mut scanner = Box::new(start());
                scanner.push(&std::mem::take(prefix));
                scanner.push(chunk);
                *self = Self::Scanning(scanner);
            }
            Self::Scanning(scanner) => scanner.push(chunk),
        }
    }
}

/// Find the closing quote of an open JSON string, carrying a trailing escape
/// across chunks. The returned offset excludes the closing quote.
pub(super) fn string_end(input: &[u8], escaped: &mut bool) -> Option<usize> {
    let mut pos = 0;
    while pos < input.len() {
        if *escaped {
            *escaped = false;
            pos += 1;
        } else {
            pos += memchr::memchr2(b'"', b'\\', &input[pos..])?;
            if input[pos] == b'"' {
                return Some(pos);
            }
            *escaped = true;
            pos += 1;
        }
    }
    None
}

// Return a prefix ending on a complete UTF-8 character and JSON escape.
// Decoding only runs when clipping a string, never for each body chunk.
pub(super) fn close_prefix(token: &[u8]) -> Vec<u8> {
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

pub(super) struct JsonCapture {
    input: Buffer<Compact>,
    limit: usize,
}

impl JsonCapture {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            input: Buffer::Raw(Vec::new()),
            limit,
        }
    }

    pub(super) fn push(&mut self, chunk: &[u8]) {
        self.input.push(chunk, self.limit, || Compact {
            limit: self.limit,
            ..Default::default()
        });
    }

    pub(super) fn finish(self) -> Result<(bool, Value), BodyError> {
        let (clipped, bytes) = match self.input {
            Buffer::Raw(bytes) => (false, bytes),
            Buffer::Scanning(scan) => {
                if scan.string_start.is_some() || !scan.closers.is_empty() || scan.invalid {
                    return Err(BodyError::InvalidJson);
                }
                if scan.exhausted {
                    // Preserve the HTTP capture's marker when the JSON structure cannot fit.
                    return Ok((true, serde_json::json!({"format": "json"})));
                }
                (scan.clipped, scan.document)
            }
        };
        let value = serde_json::from_slice(&bytes).map_err(|_| BodyError::InvalidJson)?;
        Ok((clipped, value))
    }
}

// Preserve JSON structure and shorten long string values without interpreting
// field names. A shortened key would invent a different document.
#[derive(Default)]
struct Compact {
    document: Vec<u8>,
    limit: usize,
    closers: Vec<u8>,
    string_start: Option<usize>,
    escaped: bool,
    short_string: bool,
    clipped: bool,
    exhausted: bool,
    invalid: bool,
}

impl Scan for Compact {
    fn push(&mut self, mut input: &[u8]) {
        while !input.is_empty() && !self.invalid {
            if let Some(start) = self.string_start {
                let end = string_end(input, &mut self.escaped);
                let n = end.unwrap_or(input.len());
                if !self.exhausted {
                    let take = n.min(self.limit.saturating_sub(self.document.len() + 1));
                    self.document.extend_from_slice(&input[..take]);
                    self.short_string |= take < n;
                    if end.is_some() {
                        if self.short_string {
                            let retained = &self.document[start + 1..];
                            let prefix = close_prefix(&retained[..retained.len() / 2]);
                            self.document.truncate(start);
                            self.document.extend_from_slice(&prefix);
                            self.clipped = true;
                        } else {
                            self.document.push(b'"');
                        }
                        self.exhausted |= self.document.len() > self.limit;
                    }
                }
                let Some(end) = end else { return };
                self.string_start = None;
                input = &input[end + 1..];
                continue;
            }

            let ch = input[0];
            input = &input[1..];
            if matches!(ch, b' ' | b'\t' | b'\n' | b'\r') {
                if !self.exhausted && self.document.last() != Some(&b' ') {
                    self.document.push(b' ');
                }
            } else {
                match ch {
                    b'[' | b'{' => {
                        if self.closers.len() == 128 {
                            self.invalid = true;
                            return;
                        }
                        self.closers.push(if ch == b'[' { b']' } else { b'}' });
                    }
                    b']' | b'}' if self.closers.pop() != Some(ch) => {
                        self.invalid = true;
                        return;
                    }
                    b'"' => self.string_start = Some(self.document.len()),
                    b':' if self.short_string => self.exhausted = true,
                    _ => {}
                }
                self.short_string = false;
                if !self.exhausted {
                    self.document.push(ch);
                }
            }
            self.exhausted |= self.document.len() > self.limit;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compaction_keeps_keys_intact_or_reports_the_document_as_truncated() {
        let truncated = Ok((true, serde_json::json!({"format":"json"})));
        for (wire, limit, expected) in [
            (r#"{"long-name":"v"}"#, 8, truncated.clone()),
            (r#""""#, 1, truncated),
            (r#"{"long-name":["v"}"#, 8, Err(BodyError::InvalidJson)),
            (
                r#"{"long-name":"unterminated"#,
                8,
                Err(BodyError::InvalidJson),
            ),
        ] {
            for chunk_size in [1, wire.len()] {
                let mut capture = JsonCapture::new(limit);
                for chunk in wire.as_bytes().chunks(chunk_size) {
                    capture.push(chunk);
                }
                assert_eq!(capture.finish(), expected);
            }
        }
    }
}
