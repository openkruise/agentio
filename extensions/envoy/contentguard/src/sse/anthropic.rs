// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{Retention, obj, string, unknown};
use crate::{
    protocol::{ANTHROPIC, blocks},
    response::{INVALID, Result, anthropic_totals, index, usage_counts},
};
use serde_json::{Value, json};

#[derive(Default)]
pub(super) struct Stream {
    model: Option<String>,
    blocks: Vec<Block>,
    stop: Option<String>,
    usage: Option<Value>,
    error: Option<Value>,
    done: bool,
}

struct Block {
    kind: String,
    source: Value,
    input: String,
    closed: bool,
}

impl Stream {
    pub(super) fn add(
        &mut self,
        event: &str,
        v: &Value,
        raw: &str,
        b: &mut Retention,
    ) -> Result<()> {
        let kind = string(&v["type"])?;
        if kind != event {
            return Err(INVALID);
        }
        if kind == "ping" {
            return Ok(());
        }
        if self.done {
            return Err(INVALID);
        }
        match kind {
            "error" => {
                obj(&v["error"])?;
                self.error = Some(v["error"].clone());
                self.done = true;
            }
            "message_start" => {
                let m = &v["message"];
                if self.model.is_some() || !m["content"].as_array().is_some_and(Vec::is_empty) {
                    return Err(INVALID);
                }
                b.response_id(&m["id"]);
                self.model = Some(string(&m["model"])?.into());
                self.merge_usage(&m["usage"]);
            }
            _ if self.model.is_none() => return Err(INVALID),
            "content_block_start" => {
                if index(&v["index"])? as usize != self.blocks.len() {
                    return Err(INVALID);
                }
                let source = &v["content_block"];
                let kind = string(&source["type"])?;
                if kind.len() > 128 {
                    return Err(INVALID);
                }
                b.item()?;
                #[derive(serde::Deserialize)]
                struct Start<'a> {
                    #[serde(borrow)]
                    content_block: &'a serde_json::value::RawValue,
                }
                let kept = if b.retaining()
                    && b.take(
                        serde_json::from_str::<Start>(raw)
                            .map_err(|_| INVALID)?
                            .content_block
                            .get()
                            .len(),
                    ) {
                    source.clone()
                } else {
                    Value::Null
                };
                if let Some(tools) = &mut b.tools {
                    tools.anthropic((0, self.blocks.len()), source);
                }
                self.blocks.push(Block {
                    kind: kind.into(),
                    source: kept,
                    input: String::new(),
                    closed: false,
                });
            }
            "content_block_delta" | "content_block_stop" => {
                let block = self
                    .blocks
                    .get_mut(index(&v["index"])? as usize)
                    .ok_or(INVALID)?;
                if block.closed {
                    return Err(INVALID);
                }
                if kind == "content_block_stop" {
                    block.closed = true;
                    if !block.input.is_empty() && b.retaining() {
                        let input: Value =
                            serde_json::from_str(&block.input).map_err(|_| INVALID)?;
                        obj(&input)?;
                        block.source["input"] = input;
                    }
                    block.input.clear();
                } else {
                    block.delta(&v["delta"], b)?;
                }
            }
            "message_delta" => {
                let delta = &v["delta"];
                obj(delta)?;
                if self.blocks.iter().any(|s| !s.closed) {
                    return Err(INVALID);
                }
                if let Some(s) = delta.get("stop_reason") {
                    self.stop = if s.is_null() {
                        None
                    } else {
                        let reason = string(s)?;
                        if reason.len() > 256 {
                            return Err(INVALID);
                        }
                        Some(reason.into())
                    };
                }
                if let Some(u) = v.get("usage") {
                    obj(u)?;
                    self.merge_usage(u);
                }
                b.partial |= unknown(delta, &["stop_reason", "stop_sequence"], false);
            }
            "message_stop" => self.done = true,
            _ => b.partial = true,
        }
        Ok(())
    }

    fn merge_usage(&mut self, raw: &Value) {
        if raw.is_object() {
            let latest = usage_counts(ANTHROPIC, raw);
            let target = self.usage.get_or_insert_with(|| json!({}));
            for (key, value) in latest.as_object().unwrap() {
                target[key] = value.clone();
            }
        }
    }

    pub(super) fn discard_content(&mut self) {
        for block in &mut self.blocks {
            block.source = Value::Null;
            block.input = String::new();
        }
    }

    pub(super) fn finish(self, keep: bool) -> Result<Value> {
        if !self.done {
            return Err("incomplete_stream");
        }
        if let Some(e) = self.error {
            return Ok(json!({"format":ANTHROPIC,"error":e}));
        }
        let reason = self.stop.ok_or("incomplete_stream")?;
        if self.blocks.iter().any(|b| !b.closed) {
            return Err("incomplete_stream");
        }
        let mut view = json!({"format":ANTHROPIC,"model":self.model.ok_or("incomplete_stream")?});
        if let Some(mut counts) = self.usage {
            anthropic_totals(&mut counts);
            view["usage"] = counts;
        }
        view["finishReasons"] = json!([reason]);
        if keep {
            let raw = Value::Array(self.blocks.into_iter().map(|b| b.source).collect());
            view["outputMessages"] = json!([{"role":"assistant","index":0,"finishReason":reason,"content":blocks(&raw,ANTHROPIC)}]);
        }
        Ok(view)
    }
}
impl Block {
    fn delta(&mut self, delta: &Value, b: &mut Retention) -> Result<()> {
        obj(delta)?;
        let (expected, field) = match delta["type"].as_str() {
            Some("text_delta") => ("text", "text"),
            Some("thinking_delta") => ("thinking", "thinking"),
            Some("signature_delta") => ("thinking", "signature"),
            Some("input_json_delta") => {
                if !matches!(self.kind.as_str(), "tool_use" | "server_tool_use") {
                    return Err(INVALID);
                }
                b.append(&mut self.input, string(&delta["partial_json"])?);
                return Ok(());
            }
            Some("citations_delta") => {
                if self.kind != "text" {
                    return Err(INVALID);
                }
                let citation = &delta["citation"];
                obj(citation)?;
                if b.retaining() && b.take(crate::protocol::encoded_len(citation)) {
                    if self.source["citations"].is_null() {
                        self.source["citations"] = json!([]);
                    }
                    self.source["citations"]
                        .as_array_mut()
                        .ok_or(INVALID)?
                        .push(citation.clone());
                }
                return Ok(());
            }
            _ => {
                b.partial = true;
                return Ok(());
            }
        };
        if self.kind != expected {
            return Err(INVALID);
        }
        let part = string(&delta[field])?;
        if b.take(part.len()) {
            if self.source[field].is_null() {
                self.source[field] = "".into();
            }
            if let Value::String(text) = &mut self.source[field] {
                text.push_str(part);
            } else {
                return Err(INVALID);
            }
        }
        Ok(())
    }
}
