// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{Retention, obj, string, unknown};
use crate::{
    protocol::{CHAT, tool_call},
    response::{INVALID, Result, index, usage},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Stream {
    model: Option<String>,
    usage: Option<Value>,
    error: Option<Value>,
    done: bool,
    choices: BTreeMap<u32, Choice>,
}
#[derive(Default)]
struct Choice {
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
    fn add(&mut self, v: &Value, b: &mut Retention) -> Result<()> {
        obj(v)?;
        b.partial |= unknown(v, &["name", "arguments"], false);
        for (key, dst) in [("name", &mut self.name), ("arguments", &mut self.arguments)] {
            if let Some(raw) = v.get(key) {
                let part = string(raw)?;
                if b.take(part.len()) {
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
    pub(super) fn add(&mut self, v: &Value, done: bool, b: &mut Retention) -> Result<()> {
        if done && (!self.done || self.error.is_some()) {
            self.done = true;
            return Ok(());
        }
        if self.done {
            return Err(INVALID);
        }
        b.response_id(&v["id"]);
        if let Some(e) = v.get("error") {
            self.error = (!e.is_null()).then(|| e.clone());
            self.done = true;
            return Ok(());
        }
        let model = string(&v["model"])?;
        if self
            .model
            .as_ref()
            .is_some_and(|m| !m.is_empty() && m != model)
        {
            return Err(INVALID);
        }
        if self.model.as_deref().is_none_or(str::is_empty) {
            self.model = Some(model.into());
        }
        if !v["usage"].is_null() {
            self.usage = Some(usage(CHAT, &v["usage"]));
        }
        for row in v["choices"].as_array().ok_or(INVALID)? {
            let i = index(&row["index"])?;
            if !self.choices.contains_key(&i) {
                b.item()?;
            }
            let c = self.choices.entry(i).or_default();
            if c.finish.is_some() {
                return Err(INVALID);
            }
            let d = &row["delta"];
            obj(d)?;
            b.partial |= unknown(
                d,
                &["role", "content", "refusal", "function_call", "tool_calls"],
                true,
            );
            if !d["role"].is_null() {
                let role = string(&d["role"])?;
                if role.len() > 64 {
                    return Err(INVALID);
                }
                c.role = Some(role.into());
            }
            for (k, dst) in [("content", &mut c.text), ("refusal", &mut c.refusal)] {
                if !d[k].is_null() {
                    b.append(dst, string(&d[k])?);
                }
            }
            if !d["tool_calls"].is_null() {
                for t in d["tool_calls"].as_array().ok_or(INVALID)? {
                    let idx = index(&t["index"])?;
                    b.partial |= unknown(t, &["id", "index", "type", "function"], true)
                        || (!t["type"].is_null() && t["type"] != "function");
                    for key in ["id", "type"] {
                        if !t[key].is_null() {
                            string(&t[key])?;
                        }
                    }
                    if let Some(tools) = &mut b.tools {
                        tools.chat_delta(
                            i as usize,
                            idx as usize,
                            &t["id"],
                            &t["function"]["name"],
                        );
                    }
                    if !b.retaining() {
                        if let Some(f) = t.get("function") {
                            Function::default().add(f, b)?;
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
                                return Err(INVALID);
                            }
                            if dst.is_none() && b.take(crate::protocol::encoded_len(s)) {
                                *dst = Some(s.into());
                            }
                        }
                    }
                    if let Some(f) = t.get("function") {
                        target.function.get_or_insert_default().add(f, b)?;
                    }
                }
            }
            if !d["function_call"].is_null() {
                if let Some(tools) = &mut b.tools {
                    tools.chat_delta(
                        i as usize,
                        usize::MAX,
                        &Value::Null,
                        &d["function_call"]["name"],
                    );
                }
                c.legacy
                    .get_or_insert_default()
                    .add(&d["function_call"], b)?;
            }
            if !row["finish_reason"].is_null() {
                let f = string(&row["finish_reason"])?;
                if f.len() > 256 {
                    return Err(INVALID);
                }
                c.finish = Some(f.into());
            }
        }
        Ok(())
    }
    pub(super) fn discard_content(&mut self) {
        for choice in self.choices.values_mut() {
            choice.text = String::new();
            choice.refusal = String::new();
            choice.tools.clear();
            choice.legacy = None;
        }
    }

    pub(super) fn finish(self, keep: bool) -> Result<Value> {
        if !self.done {
            return Err("incomplete_stream");
        }
        if let Some(error) = self.error {
            return Ok(json!({"format":CHAT,"error":error}));
        }
        if self.choices.is_empty() || self.model.as_deref().is_none_or(str::is_empty) {
            return Err(INVALID);
        }
        let mut v = json!({"format":CHAT,"model":self.model});
        if let Some(usage) = self.usage {
            v["usage"] = usage;
        }
        let mut reasons = vec![];
        let mut out = vec![];
        for (i, c) in self.choices {
            let reason = c.finish.ok_or("incomplete_stream")?;
            reasons.push(reason.clone());
            if !keep {
                continue;
            }
            let mut blocks = vec![];
            if !c.text.is_empty() {
                blocks.push(json!({"type":"text","text":c.text}));
            }
            for t in c.tools.into_values() {
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
            if let Some(f) = c.legacy {
                blocks.push(f.block(None));
            }
            if !c.refusal.is_empty() {
                blocks.push(json!({"type":"refusal","text":c.refusal}));
            }
            out.push(json!({"index":i,"role":c.role.as_deref().unwrap_or("assistant"),"content":blocks,"finishReason":reason}));
        }
        if !reasons.is_empty() {
            v["finishReasons"] = reasons.into();
        }
        if keep {
            v["outputMessages"] = out.into();
        }
        Ok(v)
    }
}
