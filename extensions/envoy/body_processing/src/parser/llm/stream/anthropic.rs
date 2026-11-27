// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{Event, OpenContent, Output, Retention, Trailers, obj, string};
use crate::parser::BodyError;
use crate::parser::llm::{
    ANTHROPIC, ToolKind, anthropic_tool, blocks,
    response::{Result, anthropic_totals, index, usage_counts},
};
use serde_json::{Value, json};

#[derive(Default)]
pub(super) struct Stream {
    model: Option<String>,
    blocks: Vec<Block>,
    stop: Option<String>,
    usage: Option<Value>,
    error: Option<Value>,
}

struct Block {
    work: OpenContent,
    kind: String,
    source: Value,
    input: String,
    closed: bool,
}

impl Stream {
    pub(super) fn add(
        &mut self,
        kind: &str,
        v: &Value,
        b: &mut Retention,
        emit: &mut impl FnMut(Event<'_>),
    ) -> Result<Option<Trailers>> {
        if kind == "ping" {
            return Ok(None);
        }
        match kind {
            "error" => {
                obj(&v["error"])?;
                self.error = Some(v["error"].clone());
            }
            "message_start" => {
                let m = &v["message"];
                if self.model.is_some() || !m["content"].as_array().is_some_and(Vec::is_empty) {
                    return Err(BodyError::InvalidContent);
                }
                b.response_id(&m["id"]);
                self.model = Some(string(&m["model"])?.into());
                self.merge_usage(&m["usage"], emit);
            }
            _ if self.model.is_none() => return Err(BodyError::InvalidContent),
            "content_block_start" => {
                if index(&v["index"])? as usize != self.blocks.len() {
                    return Err(BodyError::InvalidContent);
                }
                let source = &v["content_block"];
                let kind = string(&source["type"])?;
                if kind.len() > 128 {
                    return Err(BodyError::InvalidContent);
                }
                b.item()?;
                if kind == "text"
                    && let Some(text) = source["text"].as_str()
                {
                    emit(Event::TextDelta {
                        provisional: false,
                        output: Output::new(ANTHROPIC, 0),
                        part: Some(self.blocks.len() as u32),
                        text,
                    });
                }
                let mut work = OpenContent::default();
                let kept = if kind == "text"
                    && source.as_object().is_some_and(|o| o.len() == 2)
                    && source["text"].is_string()
                {
                    let envelope = json!({"type":"text","text":""});
                    if work.take(b, crate::parser::encoded_len(&envelope)) {
                        json!({"type":"text","text":work.prefix(b,source["text"].as_str().unwrap())})
                    } else {
                        Value::Null
                    }
                } else if work.take(b, crate::parser::encoded_len(source)) {
                    source.clone()
                } else {
                    Value::Null
                };
                b.tools.anthropic((0, self.blocks.len()), source);
                self.blocks.push(Block {
                    work,
                    kind: kind.into(),
                    source: kept,
                    input: String::new(),
                    closed: false,
                });
            }
            "content_block_delta" | "content_block_stop" => {
                let i = index(&v["index"])?;
                let block = self
                    .blocks
                    .get_mut(i as usize)
                    .ok_or(BodyError::InvalidContent)?;
                if block.closed {
                    return Err(BodyError::InvalidContent);
                }
                if kind == "content_block_stop" {
                    block.closed = true;
                    if !block.input.is_empty() && !block.work.clipped && !b.partial {
                        let input: Value = serde_json::from_str(&block.input)
                            .map_err(|_| BodyError::InvalidContent)?;
                        obj(&input)?;
                        block.source["input"] = input;
                    }
                    block.input = String::new();
                    let source = block.source.take();
                    let parts = if source.is_null() || (block.work.clipped && block.kind != "text")
                    {
                        vec![]
                    } else {
                        blocks(&Value::Array(vec![source]), ANTHROPIC)
                    };
                    emit(Event::OutputItem {
                        output: Output::new(ANTHROPIC, 0),
                        part: Some(i),
                        value: parts.first(),
                        clipped: block.work.clipped,
                        sealed: true,
                    });
                    block.work.release(b);
                } else {
                    block.delta(&v["delta"], b)?;
                    if v["delta"]["type"] == "text_delta" {
                        emit(Event::TextDelta {
                            provisional: false,
                            output: Output::new(ANTHROPIC, 0),
                            part: Some(i),
                            text: string(&v["delta"]["text"])?,
                        });
                    }
                }
            }
            "message_delta" => {
                let delta = &v["delta"];
                obj(delta)?;
                if self.blocks.iter().any(|s| !s.closed) {
                    return Err(BodyError::InvalidContent);
                }
                if let Some(s) = delta.get("stop_reason") {
                    self.stop = if s.is_null() {
                        None
                    } else {
                        let reason = string(s)?;
                        if reason.len() > 256 {
                            return Err(BodyError::InvalidContent);
                        }
                        Some(reason.into())
                    };
                }
                if let Some(u) = v.get("usage") {
                    obj(u)?;
                    self.merge_usage(u, emit);
                }
            }
            "message_stop" => {}
            _ => b.partial = true,
        }
        if kind != "content_block_delta" || v["delta"]["type"] != "text_delta" {
            emit(Event::Detail { kind, value: v });
        }
        Ok(matches!(kind, "message_stop" | "error").then_some(Trailers::Ping))
    }

    fn merge_usage(&mut self, raw: &Value, emit: &mut impl FnMut(Event<'_>)) {
        if raw.is_object() {
            let latest = usage_counts(ANTHROPIC, raw);
            let target = self.usage.get_or_insert_with(|| json!({}));
            for (key, value) in latest.as_object().unwrap() {
                target[key] = value.clone();
            }
            // Totals include cached tokens. Keep the unadjusted counters for later patches.
            let mut snapshot = target.clone();
            anthropic_totals(&mut snapshot);
            emit(Event::Usage(&snapshot));
        }
    }

    pub(super) fn observed(self) -> Value {
        super::observed_view(ANTHROPIC, self.model, self.error, self.stop)
    }

    pub(super) fn interrupted(self, emit: &mut impl FnMut(Event<'_>)) -> Value {
        for (index, block) in self.blocks.iter().enumerate() {
            if block.closed || block.kind != "text" {
                continue;
            }
            let value = block.source["text"]
                .as_str()
                .filter(|text| !text.is_empty())
                .map(|_| &block.source);
            if value.is_some() || block.work.clipped {
                emit(Event::OutputItem {
                    output: Output::new(ANTHROPIC, 0),
                    part: Some(index as u32),
                    value,
                    clipped: block.work.clipped,
                    sealed: false,
                });
            }
        }
        self.observed()
    }

    pub(super) fn finish(self, keep: bool) -> Result<Value> {
        if self.error.is_some() {
            return Ok(self.observed());
        }
        let reason = self.stop.ok_or(BodyError::IncompleteStream)?;
        if self.blocks.iter().any(|b| !b.closed) {
            return Err(BodyError::IncompleteStream);
        }
        let mut view =
            json!({"format":ANTHROPIC,"model":self.model.ok_or(BodyError::IncompleteStream)?});
        view["finishReasons"] = json!([reason]);
        if keep {
            view["outputMessages"] = json!([]);
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
                if anthropic_tool(&self.kind) != Some(ToolKind::Call) {
                    return Err(BodyError::InvalidContent);
                }
                let part = string(&delta["partial_json"])?;
                if self.work.take(b, part.len()) {
                    self.input.push_str(part);
                }
                return Ok(());
            }
            Some("citations_delta") => {
                if self.kind != "text" {
                    return Err(BodyError::InvalidContent);
                }
                let citation = &delta["citation"];
                obj(citation)?;
                if self.work.take(b, crate::parser::encoded_len(citation)) {
                    if self.source["citations"].is_null() {
                        self.source["citations"] = json!([]);
                    }
                    self.source["citations"]
                        .as_array_mut()
                        .ok_or(BodyError::InvalidContent)?
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
            return Err(BodyError::InvalidContent);
        }
        let part = string(&delta[field])?;
        let part = if expected == "text" {
            self.work.prefix(b, part)
        } else if self.work.take(b, part.len()) {
            part
        } else {
            ""
        };
        if !part.is_empty() {
            if self.source[field].is_null() {
                self.source[field] = "".into();
            }
            if let Value::String(text) = &mut self.source[field] {
                text.push_str(part);
            } else {
                return Err(BodyError::InvalidContent);
            }
        }
        Ok(())
    }
}
