// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{
    ANTHROPIC, CHAT, CaptureLoss, Fields, LlmView, RESPONSES, ToolReferences, answer_parts,
    json_boundary::ValueBoundary,
    json_capture::JsonCapture,
    response::Result,
    stream::{Event, Output},
};
use crate::parser::{BodyError, json::string_end};
use serde_json::Value;
use std::{collections::BTreeMap, io};

fn collection(format: &str) -> &'static str {
    match format {
        CHAT => "choices",
        ANTHROPIC => "content",
        RESPONSES => "output",
        _ => unreachable!(),
    }
}

/// Use the protocol decoder for one element at a time, including its existing
/// paths for preserving text, tool references and metadata during compaction.
pub(super) struct ItemCapture {
    format: &'static str,
    json: JsonCapture,
}

impl ItemCapture {
    pub(super) fn new(format: &'static str, limit: usize) -> Self {
        let prefix: &[u8] = match format {
            CHAT => br#"{"model":"_","choices":["#,
            ANTHROPIC => br#"{"model":"_","content":["#,
            RESPONSES => br#"{"model":"_","output":["#,
            _ => unreachable!(),
        };
        // The synthetic envelope consumes none of the actual item's allowance.
        let mut this = Self {
            format,
            json: JsonCapture::new(limit + prefix.len() + 2),
        };
        this.push(prefix);
        this
    }

    fn push(&mut self, bytes: &[u8]) {
        self.json.push(bytes, self.format, true, Fields::ALL);
    }

    pub(super) fn finish(mut self) -> Result<(CaptureLoss, LlmView)> {
        self.push(b"]}");
        self.json.finish(self.format, true, Fields::ALL)
    }
}

impl io::Write for ItemCapture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.push(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn emit_item(
    format: &'static str,
    position: u32,
    view: &mut LlmView,
    loss: CaptureLoss,
    emit: &mut impl FnMut(Event<'_>),
) -> u32 {
    let has_text = view.document["retainedText"]
        .as_array()
        .is_some_and(|v| !v.is_empty());
    let answer_bytes = view.document["answer"].as_str().map(str::len);
    let message = view
        .document
        .get_mut("outputMessages")
        .and_then(|v| v.as_array_mut())
        .and_then(|items| items.first_mut());
    let index = if format == CHAT {
        message
            .as_deref()
            .and_then(|m| m["index"].as_u64())
            .map_or(loss.choice_index.unwrap_or(position), |i| i as u32)
    } else if format == ANTHROPIC {
        0
    } else {
        position
    };
    let output = Output::new(format, index);
    let block = (format == ANTHROPIC).then_some(position);
    if let Some(m) = message {
        m["index"] = index.into();
        let mut remaining = if loss.answer && output.answer_candidate {
            answer_bytes.unwrap_or(0)
        } else {
            usize::MAX
        };
        let mut last = block.unwrap_or(0);
        for (i, text) in answer_parts(m).enumerate() {
            let part = block.unwrap_or(i as u32);
            let keep = text.floor_char_boundary(text.len().min(remaining));
            emit(Event::TextDelta {
                output,
                part: Some(part),
                text: &text[..keep],
                provisional: false,
            });
            last = part;
            remaining -= keep;
            if keep < text.len() {
                break;
            }
        }
        if loss.answer || !output.answer_candidate && loss.text {
            emit(Event::TextGap { output, part: last });
        }
        let value = if block.is_some() {
            m["content"].get(0)
        } else {
            Some(&*m)
        };
        emit(Event::OutputItem {
            output,
            part: block,
            value,
            clipped: loss.document,
            sealed: true,
        });
    } else {
        if loss.answer || loss.exhausted && (has_text || loss.preview) {
            emit(Event::TextGap {
                output,
                part: block.unwrap_or(0),
            });
        }
        emit(Event::OutputItem {
            output,
            part: block,
            value: None,
            clipped: true,
            sealed: true,
        });
    }
    index
}

enum Array {
    Outside,
    Next { first: bool },
    Item(Box<(ValueBoundary, ItemCapture)>),
    Separator,
}

/// Route the top-level output array to per-item captures. The outer JSON
/// decoder receives the original metadata document with an empty output array.
pub(crate) struct Document {
    format: &'static str,
    limit: usize,
    metadata: JsonCapture,
    array: Array,
    depth: usize,
    quoted: bool,
    escaped: bool,
    key: Vec<u8>,
    key_overflow: bool,
    matched: bool,
    colon: bool,
    seen_collection: bool,
    items: u32,
    reasons: BTreeMap<u32, Value>,
    reason_bytes: usize,
    refs: CollectedRefs,
    error: Option<BodyError>,
    partial: bool,
    reasons_clipped: bool,
}

#[derive(Default)]
struct CollectedRefs {
    by_item: BTreeMap<u32, ToolReferences>,
    bytes: usize,
    count: usize,
    clipped: bool,
}

impl CollectedRefs {
    fn add(&mut self, index: u32, refs: ToolReferences, limit: usize, lost: bool) {
        if self.clipped {
            return;
        }
        self.bytes += refs
            .entries
            .iter()
            .map(|r| r.identity_bytes())
            .sum::<usize>();
        self.count += refs.entries.len();
        if refs.truncated || lost || self.bytes > limit || self.count > 1024 {
            self.by_item.clear();
            self.clipped = true;
        } else if !refs.entries.is_empty() {
            self.by_item.insert(index, refs);
        }
    }
    fn finish(self) -> ToolReferences {
        ToolReferences {
            entries: self.by_item.into_values().flat_map(|v| v.entries).collect(),
            truncated: self.clipped,
        }
    }
}

impl Document {
    pub(super) fn new(format: &'static str, limit: usize) -> Self {
        Self {
            format,
            limit,
            metadata: JsonCapture::new(limit),
            array: Array::Outside,
            depth: 0,
            quoted: false,
            escaped: false,
            key: vec![],
            key_overflow: false,
            matched: false,
            colon: false,
            seen_collection: false,
            items: 0,
            reasons: BTreeMap::new(),
            reason_bytes: 0,
            refs: Default::default(),
            error: None,
            partial: false,
            reasons_clipped: false,
        }
    }

    pub(super) fn push(
        &mut self,
        mut input: &[u8],
        emit: &mut impl FnMut(Event<'_>),
    ) -> Result<()> {
        while !input.is_empty() {
            match &mut self.array {
                Array::Outside => {
                    let n = self.metadata_slice(input);
                    self.metadata
                        .push(&input[..n], self.format, true, Fields::ALL);
                    input = &input[n..];
                    if !matches!(self.array, Array::Outside) {
                        self.seen_collection = true;
                        self.items = 0;
                        self.reasons.clear();
                        self.reason_bytes = 0;
                        self.reasons_clipped = false;
                        self.refs = Default::default();
                        self.error = None;
                        self.partial = false;
                        emit(Event::ReplaceOutput);
                    }
                }
                Array::Item(item) => {
                    let (n, done) = item.0.feed(input)?;
                    item.1.push(&input[..n]);
                    input = &input[n..];
                    if done {
                        let Array::Item(item) =
                            std::mem::replace(&mut self.array, Array::Separator)
                        else {
                            unreachable!()
                        };
                        let (loss, mut view) = item.1.finish()?;
                        let i = emit_item(self.format, self.items, &mut view, loss, emit);
                        self.error = self.error.or(view.output_messages_error);
                        self.partial |= loss.exhausted && self.format == CHAT;
                        self.refs.add(
                            i,
                            view.tool_refs,
                            self.limit,
                            loss.references || loss.exhausted,
                        );
                        if let Some(reason) = view.document["finishReasons"].get(0) {
                            self.reason_bytes += reason.as_str().unwrap().len() + 3;
                            if self.reason_bytes <= self.limit {
                                self.reasons.insert(i, reason.clone());
                            } else {
                                self.reasons_clipped = true;
                            }
                        }
                        self.items = self.items.checked_add(1).ok_or(BodyError::TooLarge)?;
                    }
                }
                state => {
                    let byte = input[0];
                    if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                        input = &input[1..];
                        continue;
                    }
                    match (&*state, byte) {
                        (Array::Next { first: true } | Array::Separator, b']') => {
                            self.metadata.push(b"]", self.format, true, Fields::ALL);
                            self.array = Array::Outside;
                        }
                        (Array::Separator, b',') => self.array = Array::Next { first: false },
                        (Array::Next { .. }, b',' | b']' | b'}') => {
                            return Err(BodyError::InvalidJson);
                        }
                        (Array::Next { .. }, _) => {
                            self.array = Array::Item(Box::new((
                                ValueBoundary::default(),
                                ItemCapture::new(self.format, self.limit),
                            )));
                            continue;
                        }
                        _ => return Err(BodyError::InvalidJson),
                    }
                    input = &input[1..];
                }
            }
        }
        Ok(())
    }

    // Find a root collection key across callback boundaries. The outer decoder
    // validates the surrounding JSON syntax and handles all other members.
    fn metadata_slice(&mut self, bytes: &[u8]) -> usize {
        let mut pos = 0;
        while pos < bytes.len() {
            if self.quoted {
                let tail = &bytes[pos..];
                let end = string_end(tail, &mut self.escaped);
                let n = end.unwrap_or(tail.len());
                if self.depth == 1 && !self.key_overflow {
                    if self.key.len() + n <= 48 {
                        self.key.extend_from_slice(&tail[..n]);
                    } else {
                        self.key_overflow = true;
                    }
                }
                pos += n;
                if end.is_none() {
                    return pos;
                }
                pos += 1;
                self.quoted = false;
                if self.depth == 1 && !self.key_overflow {
                    let wanted = collection(self.format);
                    self.matched = if self.key.contains(&b'\\') {
                        self.key.push(b'"');
                        serde_json::from_slice::<String>(&self.key).is_ok_and(|s| s == wanted)
                    } else {
                        self.key[1..] == *wanted.as_bytes()
                    };
                }
                continue;
            }
            let ch = bytes[pos];
            pos += 1;
            if ch.is_ascii_whitespace() {
                continue;
            }
            if ch == b'[' && self.depth == 1 && self.colon {
                self.colon = false;
                self.matched = false;
                self.array = Array::Next { first: true };
                return pos;
            }
            self.colon = ch == b':' && self.matched;
            self.matched = false;
            match ch {
                b'"' => {
                    self.quoted = true;
                    self.escaped = false;
                    self.key.clear();
                    self.key.push(b'"');
                    self.key_overflow = false;
                }
                b'[' | b'{' => self.depth += 1,
                b']' | b'}' => self.depth = self.depth.saturating_sub(1),
                _ => {}
            }
        }
        pos
    }

    pub(super) fn finish(self) -> Result<(CaptureLoss, LlmView)> {
        if !matches!(self.array, Array::Outside) {
            return Err(BodyError::InvalidJson);
        }
        let (mut loss, mut view) = self.metadata.finish(self.format, true, Fields::ALL)?;
        if loss.exhausted
            && self.seen_collection
            && (self.format == RESPONSES || view.document.get("error").is_none())
        {
            view.document["outputMessages"] = serde_json::json!([]);
        }
        // All output was accounted for by the item events. Metadata compaction
        // is tracked independently of those already delivered fields.
        loss.document = false;
        if !self.reasons.is_empty() {
            view.document["finishReasons"] = self.reasons.into_values().collect::<Vec<_>>().into();
        }
        loss.finish_reasons |= self.reasons_clipped;
        view.tool_refs = self.refs.finish();
        view.output_messages_error = view.output_messages_error.or(self.error);
        view.partial |= self.partial;
        Ok((loss, view))
    }
}
