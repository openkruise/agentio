// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::limit::{json_bytes, string_prefix};
use crate::{chain::Side, parser::encoded_len};
use serde::{Serialize, Serializer, ser::SerializeMap};
use serde_json::Value;
use std::collections::BTreeMap;

/// One audit field. A missing part closes the prefix, while omitting an inline
/// payload can leave room for the rest of the message and subsequent messages.
pub(super) struct Messages {
    items: Vec<Value>,
    bytes: usize,
    limit: usize,
    closed: bool,
    clipped: bool,
}

impl Messages {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            items: Vec::new(),
            bytes: 2, // []
            limit,
            closed: limit < 2,
            clipped: limit < 2,
        }
    }

    pub(super) fn omit(&mut self) {
        self.closed = true;
        self.clipped = true;
    }

    #[cfg(test)]
    pub(super) fn project(items: &[Value], limit: usize, side: Side) -> (Option<Value>, bool) {
        let mut messages = Self::new(limit);
        for item in items {
            messages.push(item, side);
            if messages.closed {
                break;
            }
        }
        messages.finish()
    }

    pub(super) fn push(&mut self, message: &Value, side: Side) {
        let reserve_media = matches!(side, Side::Request);
        if self.closed {
            return;
        }
        let comma = usize::from(!self.items.is_empty());
        let Some(room) = self.limit.checked_sub(self.bytes + comma) else {
            self.omit();
            return;
        };
        let empty = Value::Array(Vec::new());
        let mut envelope: BTreeMap<_, _> = message
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect();
        let content = envelope.remove("content").unwrap().as_array().unwrap();
        envelope.insert("parts", &empty);
        if let Some(reason) = envelope.remove("finishReason") {
            envelope.insert("finish_reason", reason);
        }
        let Some(mut size) = json_bytes(&envelope, room) else {
            self.omit();
            return;
        };
        let mut parts = Vec::new();
        for block in content {
            let separator = usize::from(!parts.is_empty());
            let fitted = (room - size)
                .checked_sub(separator)
                .and_then(|space| Part::new(block, reserve_media).fit(space));
            let Some((part, bytes, clipped)) = fitted else {
                self.omit();
                break;
            };
            parts.push(part);
            size += separator + bytes;
            if clipped {
                self.omit();
                break;
            }
        }
        if self.closed && parts.is_empty() {
            return;
        }
        if reserve_media {
            let mut free = room - size;
            self.clipped |= restore_media(content, &mut parts, &mut free);
            size = room - free;
        }
        let mut logged = serde_json::to_value(envelope).unwrap();
        logged["parts"] = parts.into();
        self.items.push(logged);
        self.bytes += comma + size;
    }

    pub(super) fn finish(self) -> (Option<Value>, bool) {
        let value = (!self.closed || !self.items.is_empty()).then(|| self.items.into());
        (value, self.clipped)
    }
}

/// Sealed outputs may arrive out of order. Keep their formatted, bounded prefix
/// in protocol order. An Anthropic output is one message assembled from blocks.
#[derive(Default)]
pub(super) struct ResponseMessages {
    entries: BTreeMap<u32, (Value, usize)>,
    used: usize, // entry bytes plus one separator per entry
    cut: Option<u32>,
    blocks: bool,
}

impl ResponseMessages {
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(super) fn cut(&mut self, index: u32) {
        self.cut = Some(self.cut.map_or(index, |old| old.min(index)));
        while self
            .entries
            .last_key_value()
            .is_some_and(|(&key, _)| key > index)
        {
            let (_, (_, size)) = self.entries.pop_last().unwrap();
            self.used -= size + 1;
        }
    }

    pub(super) fn message(&mut self, index: u32, message: &Value, limit: usize) {
        self.insert(index, limit, |room| {
            let mut one = Messages::new(room + 2);
            one.push(message, Side::Response);
            (one.items.pop(), one.clipped)
        });
    }

    pub(super) fn block(&mut self, index: u32, block: &Value, limit: usize) {
        self.blocks = true;
        self.insert(index, limit, |room| {
            match Part::new(block, false).fit(room) {
                Some((part, _, clipped)) => (Some(part), clipped),
                None => (None, true),
            }
        });
    }

    fn insert(
        &mut self,
        index: u32,
        limit: usize,
        fit: impl FnOnce(usize) -> (Option<Value>, bool),
    ) {
        if self.cut.is_some_and(|cut| index > cut) {
            return;
        }
        let later = if self
            .entries
            .last_key_value()
            .is_some_and(|(&last, _)| last >= index)
        {
            let later = self.entries.split_off(&index);
            self.used -= later.values().map(|(_, size)| size + 1).sum::<usize>();
            later
        } else {
            BTreeMap::new()
        };
        let room = limit.saturating_sub(self.used + 2);
        let (value, clipped) = fit(room);
        if let Some(value) = value {
            let size = encoded_len(&value);
            self.entries.insert(index, (value, size));
            self.used += size + 1;
        }
        if clipped {
            self.cut = Some(index);
            return;
        }
        for (key, (mut value, size)) in later {
            if key == index {
                continue;
            }
            let room = limit.saturating_sub(self.used + 2);
            if size <= room {
                self.entries.insert(key, (value, size));
                self.used += size + 1;
            } else {
                let retained = if self.blocks {
                    trim_part(&mut value, room)
                } else {
                    trim_message(&mut value, room)
                };
                if retained {
                    let size = encoded_len(&value);
                    self.entries.insert(key, (value, size));
                    self.used += size + 1;
                }
                self.cut = Some(key);
                break;
            }
        }
    }

    pub(super) fn finish(
        self,
        anthropic: bool,
        reason: Option<&Value>,
        limit: usize,
    ) -> (Option<Value>, bool) {
        let mut clipped = self.cut.is_some();
        let entries: Vec<_> = self.entries.into_values().map(|(v, _)| v).collect();
        if !anthropic {
            let value = (limit >= 2 && (!clipped || !entries.is_empty())).then(|| entries.into());
            return (value, clipped || limit < 2);
        }
        if entries.is_empty() && clipped {
            return (None, true);
        }
        let mut message = serde_json::json!({"role":"assistant","index":0,"parts":entries});
        if let Some(reason) = reason {
            message["finish_reason"] = reason.clone();
        }
        let room = limit.saturating_sub(2);
        if json_bytes(&message, room).is_none() {
            if !trim_message(&mut message, room) {
                return (None, true);
            }
            clipped = true;
        }
        (Some(Value::Array(vec![message])), clipped)
    }
}

// Trim an already formatted suffix displaced by an earlier index or by the
// finish reason on an Anthropic message. Opaque parts stay atomic.
fn trim_part(part: &mut Value, room: usize) -> bool {
    let key = match part["type"].as_str() {
        Some("text") => "content",
        Some("refusal") => "text",
        _ => return false,
    };
    let text = part[key].take();
    let Some(text) = text.as_str() else {
        return false;
    };
    part[key] = "".into();
    let Some(overhead) = json_bytes(part, room) else {
        return false;
    };
    let prefix = string_prefix(text, room - overhead);
    if prefix.is_empty() {
        return false;
    }
    part[key] = prefix.into();
    true
}

fn trim_message(message: &mut Value, room: usize) -> bool {
    let parts = message["parts"].as_array_mut().unwrap();
    let full = std::mem::take(parts);
    let Some(mut used) = json_bytes(message, room) else {
        return false;
    };
    let parts = message["parts"].as_array_mut().unwrap();
    let empty = full.is_empty();
    for mut part in full {
        let available = room.saturating_sub(used + usize::from(!parts.is_empty()));
        if let Some(size) = json_bytes(&part, available) {
            used += size + usize::from(!parts.is_empty());
            parts.push(part);
        } else {
            if trim_part(&mut part, available) {
                parts.push(part);
            }
            break;
        }
    }
    empty || !parts.is_empty()
}

/// A borrowed view of one normalized content block in its audit JSON shape.
/// The same serializer measures and emits the value, including provider fields.
#[derive(Clone, Copy)]
struct Part<'a> {
    block: &'a Value,
    text: Option<&'a str>,
    reserve_media: bool,
}

impl<'a> Part<'a> {
    fn new(block: &'a Value, reserve_media: bool) -> Self {
        Self {
            block,
            text: None,
            reserve_media,
        }
    }

    fn fit(self, room: usize) -> Option<(Value, usize, bool)> {
        let text = match self.block["type"].as_str() {
            Some("text" | "refusal") => self.block["text"].as_str(),
            _ => None,
        };
        // In-budget values need one size check. For long text the raw byte
        // length alone can rule out the full value before scanning for escapes.
        if text.is_none_or(|s| s.len() <= room)
            && let Some(size) = json_bytes(&self, room)
        {
            return Some((serde_json::to_value(self).unwrap(), size, false));
        }

        let text = text?;
        let overhead = json_bytes(
            &Self {
                text: Some(""),
                ..self
            },
            room,
        )?;
        let prefix = string_prefix(text, room - overhead);
        if prefix.is_empty() {
            return None;
        }
        let part = Self {
            text: Some(prefix),
            ..self
        };
        Some((
            serde_json::to_value(part).unwrap(),
            overhead + encoded_len(&prefix) - 2,
            true,
        ))
    }
}

struct Parts<'a>(&'a [Value], bool);

impl Serialize for Parts<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|block| Part::new(block, self.1)))
    }
}

pub(super) fn format_parts(parts: &Value) -> Value {
    serde_json::to_value(Parts(parts.as_array().unwrap(), false)).unwrap()
}

impl Serialize for Part<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let block = self.block;
        let Some(fields) = block.as_object() else {
            return block.serialize(serializer);
        };
        let mut out = serializer.serialize_map(None)?;
        let skip: &[&str] = match block["type"].as_str() {
            Some(kind @ ("text" | "refusal")) if block["text"].is_string() => {
                let text = self.text.unwrap_or_else(|| block["text"].as_str().unwrap());
                if kind == "text" {
                    out.serialize_entry("content", text)?;
                    &["text", "content"]
                } else {
                    out.serialize_entry("text", text)?;
                    &["text"]
                }
            }
            Some("tool_result") => {
                out.serialize_entry("type", "tool_call_response")?;
                out.serialize_entry("id", &block["toolCallId"])?;
                let children = block["content"].as_array().unwrap();
                out.serialize_entry("response", &Parts(children, self.reserve_media))?;
                &["type", "toolCallId", "content", "id", "response"]
            }
            Some("tool_call") if block["server"] == true => {
                out.serialize_entry("type", "server_tool_call")?;
                out.serialize_entry("server_tool_call", &ServerTool(block))?;
                &["type", "server", "arguments", "server_tool_call"]
            }
            Some("image") => {
                let (kind, from, to) = match block["source"].as_str() {
                    Some("file") => ("file", "fileId", "file_id"),
                    Some("url") => ("uri", "url", "uri"),
                    Some("base64") => ("blob", "data", "content"),
                    _ => unreachable!("unknown normalized image source"),
                };
                out.serialize_entry("type", kind)?;
                out.serialize_entry("modality", "image")?;
                if !(self.reserve_media && kind == "blob")
                    && let Some(value) = block.get(from)
                {
                    out.serialize_entry(to, value)?;
                }
                if let Some(mime) = block.get("mediaType") {
                    out.serialize_entry("mime_type", mime)?;
                }
                for (k, v) in fields {
                    if !matches!(k.as_str(), "type" | "source" | "modality" | "mediaType")
                        && k != from
                    {
                        out.serialize_entry(k, v)?;
                    }
                }
                return out.end();
            }
            Some("attachment") => {
                out.serialize_entry("type", "provider_content")?;
                if self.reserve_media
                    && let Some(locations) = block["inlineData"].as_object()
                {
                    let data = &block["data"];
                    let payloads: Vec<_> = locations
                        .iter()
                        .map(|(path, prefix)| {
                            (data.pointer(path).unwrap(), prefix.as_str().unwrap())
                        })
                        .collect();
                    // For short payloads the original can be smaller than "[omitted]".
                    if omission_saves_bytes(&payloads) {
                        out.serialize_entry("data", &OmittedData(data, &payloads))?;
                    } else {
                        out.serialize_entry("data", data)?;
                    }
                    &["type", "kind", "inlineData", "data"]
                } else {
                    &["type", "kind", "inlineData"]
                }
            }
            _ => &[],
        };
        for (k, v) in fields {
            if !skip.contains(&k.as_str()) {
                out.serialize_entry(k, v)?;
            }
        }
        out.end()
    }
}

struct ServerTool<'a>(&'a Value);

impl Serialize for ServerTool<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut out = serializer.serialize_map(None)?;
        let arguments = &self.0["arguments"];
        if let Some(fields) = arguments.as_object().filter(|m| !m.contains_key("type")) {
            for (k, v) in fields {
                out.serialize_entry(k, v)?;
            }
        } else {
            out.serialize_entry("arguments", arguments)?;
        }
        out.serialize_entry("type", &self.0["name"])?;
        out.end()
    }
}

const OMITTED: &str = "[omitted]";

fn omission_saves_bytes(payloads: &[(&Value, &str)]) -> bool {
    let mut marker_bytes = OMITTED.len() * payloads.len();
    for &(value, prefix) in payloads {
        let suffix = &value.as_str().unwrap()[prefix.len()..];
        if suffix.len() > marker_bytes {
            return true;
        }
        let Some(left) = marker_bytes.checked_sub(encoded_len(&suffix) - 2) else {
            return true;
        };
        marker_bytes = left;
    }
    false
}

// Only the scalar nodes identified by the parser's inlineData pointers change.
// Walk the borrowed provider value so an omitted payload is never copied.
struct OmittedData<'a>(&'a Value, &'a [(&'a Value, &'a str)]);
impl Serialize for OmittedData<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let Some((_, prefix)) = self.1.iter().find(|(node, _)| std::ptr::eq(*node, self.0)) {
            return serializer.collect_str(&format_args!("{prefix}{OMITTED}"));
        }
        match self.0 {
            Value::Object(fields) => {
                serializer.collect_map(fields.iter().map(|(k, v)| (k, Self(v, self.1))))
            }
            Value::Array(items) => serializer.collect_seq(items.iter().map(|v| Self(v, self.1))),
            v => v.serialize(serializer),
        }
    }
}

/// Spend the remaining message budget on complete payloads in source order.
fn restore_media(content: &[Value], parts: &mut [Value], room: &mut usize) -> bool {
    let mut clipped = false;
    for (block, part) in content.iter().zip(parts) {
        let payload_bytes: usize = match block["type"].as_str() {
            Some("image") if block["source"] == "base64" => {
                let Some(data) = block["data"].as_str() else {
                    continue;
                };
                data.len()
            }
            Some("attachment") => {
                let Some(locations) = block["inlineData"].as_object() else {
                    continue;
                };
                locations
                    .keys()
                    .map(|path| block["data"].pointer(path).unwrap().as_str().unwrap().len())
                    .sum()
            }
            Some("tool_result") => {
                clipped |= restore_media(
                    block["content"].as_array().unwrap(),
                    part["response"].as_array_mut().unwrap(),
                    room,
                );
                continue;
            }
            _ => continue,
        };
        let minimum = encoded_len(part);
        let available = minimum.saturating_add(*room);
        // The payload alone can rule out a multi-MiB attachment before scanning it for JSON escapes.
        if payload_bytes > available {
            clipped = true;
            continue;
        }
        let full = Part::new(block, false);
        if let Some(size) = json_bytes(&full, available) {
            if size > minimum {
                *part = serde_json::to_value(full).unwrap();
                *room -= size - minimum;
            }
        } else {
            clipped = true;
        }
    }
    clipped
}
