// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{Event, OpenContent, Output, Retention, Trailers, obj, string, unknown};
use crate::parser::BodyError;
use crate::parser::llm::{
    CHAT,
    response::{Result, index, usage},
    tool_call,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Stream {
    model: Option<String>,
    error: Option<Value>,
    choices: BTreeMap<u32, Choice>,
}
#[derive(Default)]
struct Choice {
    work: OpenContent,
    text_clipped: bool,
    tool_cut: Option<u32>,
    legacy_clipped: bool,
    role: Option<String>,
    text: String,
    refusal: String,
    finish: Option<String>,
    tools: BTreeMap<u32, Tool>,
    legacy: Option<Function>,
}
#[derive(Default)]
struct Tool {
    id: Option<String>,
    kind: Option<String>,
    function: Option<Function>,
}
#[derive(Default)]
struct Function {
    name: Option<String>,
    arguments: Option<String>,
}

impl Function {
    fn add(&mut self, v: &Value, b: &mut Retention, work: &mut OpenContent) -> Result<()> {
        obj(v)?;
        b.partial |= unknown(v, &["name", "arguments"], false);
        for (key, dst) in [("name", &mut self.name), ("arguments", &mut self.arguments)] {
            if let Some(raw) = v.get(key).filter(|value| !value.is_null()) {
                let part = string(raw)?;
                if work.take(b, part.len()) {
                    dst.get_or_insert_default().push_str(part);
                }
            }
        }
        Ok(())
    }
    fn block(self, id: Option<String>) -> Value {
        tool_call(
            &Value::from(id),
            &Value::from(self.name),
            &Value::from(self.arguments),
        )
    }
}

impl Stream {
    pub(super) fn add(
        &mut self,
        v: &Value,
        done: bool,
        b: &mut Retention,
        emit: &mut impl FnMut(Event<'_>),
    ) -> Result<Option<Trailers>> {
        if done {
            return Ok(Some(Trailers::None));
        }
        b.response_id(&v["id"]);
        if let Some(e) = v.get("error").filter(|v| !v.is_null()) {
            emit(Event::Detail {
                kind: "error",
                value: e,
            });
            self.error = Some(e.clone());
            return Ok(Some(Trailers::Done));
        }
        let model = string(&v["model"])?;
        if self
            .model
            .as_ref()
            .is_some_and(|m| !m.is_empty() && m != model)
        {
            return Err(BodyError::InvalidContent);
        }
        if self.model.as_deref().is_none_or(str::is_empty) {
            self.model = Some(model.into());
            emit(Event::Detail {
                kind: "chat.completion.chunk",
                value: v,
            });
        }
        if !v["usage"].is_null() {
            emit(Event::Usage(&usage(CHAT, &v["usage"])));
        }
        for row in v["choices"].as_array().ok_or(BodyError::InvalidContent)? {
            let i = index(&row["index"])?;
            let output = Output::new(CHAT, i);
            if !self.choices.contains_key(&i) {
                b.item()?;
            }
            let c = self.choices.entry(i).or_default();
            if c.finish.is_some() {
                return Err(BodyError::InvalidContent);
            }
            let d = &row["delta"];
            obj(d)?;
            b.partial |= unknown(
                d,
                &["role", "content", "refusal", "function_call", "tool_calls"],
                true,
            );
            if !row["finish_reason"].is_null()
                || d.as_object().unwrap().iter().any(|(key, value)| {
                    !value.is_null() && !matches!(key.as_str(), "content" | "refusal")
                })
            {
                emit(Event::Detail {
                    kind: "choice",
                    value: row,
                });
            }
            if !d["role"].is_null() {
                let role = string(&d["role"])?;
                if role.len() > 64 {
                    return Err(BodyError::InvalidContent);
                }
                c.role = Some(role.into());
                if output.answer_candidate {
                    b.chat_assistant = role == "assistant";
                }
            }
            for (k, dst) in [("content", &mut c.text), ("refusal", &mut c.refusal)] {
                if !d[k].is_null() {
                    let part = string(&d[k])?;
                    emit(Event::TextDelta {
                        provisional: false,
                        output,
                        part: Some(u32::from(k == "refusal")),
                        text: part,
                    });
                    let prefix = c.work.prefix(b, part);
                    dst.push_str(prefix);
                    c.text_clipped |= k == "content" && prefix.len() < part.len();
                }
            }
            if !d["tool_calls"].is_null() {
                for t in d["tool_calls"]
                    .as_array()
                    .ok_or(BodyError::InvalidContent)?
                {
                    let idx = index(&t["index"])?;
                    b.partial |= unknown(t, &["id", "index", "type", "function"], true)
                        || (!t["type"].is_null() && t["type"] != "function");
                    for key in ["id", "type"] {
                        if !t[key].is_null() {
                            string(&t[key])?;
                        }
                    }
                    b.tools
                        .chat_delta(i as usize, idx as usize, &t["id"], &t["function"]["name"]);
                    if c.work.clipped || b.partial {
                        c.tool_cut = Some(c.tool_cut.map_or(idx, |cut| cut.min(idx)));
                        if let Some(f) = t.get("function").filter(|v| !v.is_null()) {
                            Function::default().add(f, b, &mut c.work)?;
                        }
                        continue;
                    }
                    if !c.tools.contains_key(&idx) {
                        b.item()?;
                    }
                    let target = c.tools.entry(idx).or_default();
                    for (k, dst) in [("id", &mut target.id), ("type", &mut target.kind)] {
                        if !t[k].is_null() {
                            let s = string(&t[k])?;
                            if dst.as_ref().is_some_and(|old| old != s) {
                                return Err(BodyError::InvalidContent);
                            }
                            if dst.is_none() && c.work.take(b, crate::parser::encoded_len(s)) {
                                *dst = Some(s.into());
                            }
                        }
                    }
                    if let Some(f) = t.get("function").filter(|v| !v.is_null()) {
                        target
                            .function
                            .get_or_insert_default()
                            .add(f, b, &mut c.work)?;
                    }
                    if c.work.clipped {
                        c.tool_cut = Some(c.tool_cut.map_or(idx, |cut| cut.min(idx)));
                    }
                }
            }
            if !d["function_call"].is_null() {
                b.tools.chat_delta(
                    i as usize,
                    usize::MAX,
                    &Value::Null,
                    &d["function_call"]["name"],
                );
                c.legacy
                    .get_or_insert_default()
                    .add(&d["function_call"], b, &mut c.work)?;
                c.legacy_clipped |= c.work.clipped;
            }
            if !row["finish_reason"].is_null() {
                let f = string(&row["finish_reason"])?;
                if f.len() > 256 {
                    return Err(BodyError::InvalidContent);
                }
                let mut sealed = std::mem::take(c);
                sealed.work.release(b);
                let clipped = sealed.work.clipped;
                let m = sealed.message(i, Some(f));
                emit(Event::OutputItem {
                    output,
                    part: None,
                    value: (!clipped || m["content"].as_array().is_some_and(|v| !v.is_empty()))
                        .then_some(&m),
                    clipped,
                    sealed: true,
                });
                c.finish = Some(f.into());
            }
        }
        Ok(None)
    }
    pub(super) fn observed(self) -> Value {
        let reasons = self.choices.into_values().filter_map(|c| c.finish);
        super::observed_view(CHAT, self.model, self.error, reasons)
    }

    pub(super) fn interrupted(mut self, emit: &mut impl FnMut(Event<'_>)) -> Value {
        for (&index, choice) in &mut self.choices {
            if choice.finish.is_some() {
                continue;
            }
            let choice = std::mem::take(choice);
            let clipped = choice.work.clipped;
            let message = choice.message(index, None);
            let value = (!message["content"].as_array().unwrap().is_empty()).then_some(&message);
            if value.is_some() || clipped {
                emit(Event::OutputItem {
                    output: Output::new(CHAT, index),
                    part: None,
                    value,
                    clipped,
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
        if self.choices.is_empty() || self.model.as_deref().is_none_or(str::is_empty) {
            return Err(BodyError::InvalidContent);
        }
        let mut v = json!({"format":CHAT,"model":self.model});
        let mut reasons = vec![];
        for c in self.choices.into_values() {
            reasons.push(c.finish.ok_or(BodyError::IncompleteStream)?);
        }
        if !reasons.is_empty() {
            v["finishReasons"] = reasons.into();
        }
        if keep {
            v["outputMessages"] = json!([]);
        }
        Ok(v)
    }
}

impl Choice {
    fn message(self, index: u32, reason: Option<&str>) -> Value {
        let mut blocks = vec![];
        if !self.text.is_empty() {
            blocks.push(json!({"type":"text","text":self.text}));
        }
        for (idx, t) in self.tools {
            if reason.is_none() || self.text_clipped || self.tool_cut.is_some_and(|cut| idx >= cut)
            {
                break;
            }
            if let Some(f) = t.function {
                blocks.push(f.block(t.id));
            } else {
                let mut raw = json!({});
                if let Some(id) = t.id {
                    raw["id"] = id.into();
                }
                if let Some(kind) = t.kind {
                    raw["type"] = kind.into();
                }
                blocks.push(json!({"type":"provider_content","format":CHAT,"data":raw}));
            }
        }
        if reason.is_some()
            && !self.text_clipped
            && self.tool_cut.is_none()
            && !self.legacy_clipped
            && let Some(f) = self.legacy
        {
            blocks.push(f.block(None));
        }
        if !self.text_clipped
            && self.tool_cut.is_none()
            && !self.legacy_clipped
            && !self.refusal.is_empty()
        {
            blocks.push(json!({"type":"refusal","text":self.refusal}));
        }
        let mut message = json!({"index":index,"role":self.role.as_deref().unwrap_or("assistant"),"content":blocks});
        if let Some(reason) = reason {
            message["finishReason"] = reason.into();
        }
        message
    }
}
