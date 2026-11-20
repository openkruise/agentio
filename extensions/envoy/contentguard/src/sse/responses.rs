// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{Retention, string};
use crate::{
    protocol::{RESPONSES, responses_item},
    response::{INVALID, Result, index, metadata},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Stream {
    view: Option<Value>,
    items: BTreeMap<u32, Item>,
    terminal: Option<Vec<Value>>,
    done: bool,
}
struct Item {
    id: String,
    closed: bool,
    message: Option<Value>,
}
impl Stream {
    pub(super) fn add(
        &mut self,
        event: &str,
        v: &Value,
        raw: &str,
        done: bool,
        b: &mut Retention,
    ) -> Result<()> {
        if done {
            return if self.done {
                Ok(())
            } else {
                Err("invalid_json")
            };
        }
        if self.done {
            return Err(INVALID);
        }
        let kind = string(&v["type"])?;
        if !event.is_empty() && event != "message" && event != kind {
            return Err(INVALID);
        }
        match kind {
            "error" => {
                string(&v["message"])?;
                self.view.get_or_insert_with(|| json!({"format":RESPONSES}))["error"] = v.clone();
                self.done = true;
            }
            "response.created"
            | "response.in_progress"
            | "response.queued"
            | "response.completed"
            | "response.failed"
            | "response.incomplete" => {
                let doc = &v["response"];
                b.response_id(&doc["id"]);
                let model = string(&doc["model"])?;
                let status = string(&doc["status"])?;
                if kind != "response.created" && kind.strip_prefix("response.") != Some(status) {
                    return Err(INVALID);
                }
                let mut m = metadata(RESPONSES, doc)?;
                if let Some(old) = self.view.as_ref() {
                    if old["model"].as_str().is_some_and(|s| s != model) {
                        return Err(INVALID);
                    }
                    for (key, wire) in [
                        ("usage", "usage"),
                        ("error", "error"),
                        ("incompleteReason", "incomplete_details"),
                    ] {
                        if let Some(prev) = old.get(key)
                            && (doc.get(wire).is_none() || (key == "usage" && doc[wire].is_null()))
                        {
                            m[key] = prev.clone();
                        }
                    }
                }
                self.view = Some(m);
                self.done = matches!(status, "completed" | "failed" | "incomplete")
                    && kind != "response.created";
                if self.done && !doc["output"].is_null() {
                    let out = doc["output"].as_array().ok_or(INVALID)?;
                    if out.len() > 1024 {
                        return Err("too_large");
                    }
                    if !out.is_empty() {
                        if let Some(tools) = &mut b.tools {
                            tools.document(RESPONSES, doc, true);
                        }
                        self.items.clear();
                        b.room = b.limit;
                        #[derive(serde::Deserialize)]
                        struct Envelope<'a> {
                            #[serde(borrow)]
                            response: Output<'a>,
                        }
                        #[derive(serde::Deserialize)]
                        struct Output<'a> {
                            #[serde(borrow)]
                            output: &'a serde_json::value::RawValue,
                        }
                        if b.retaining()
                            && b.take(
                                serde_json::from_str::<Envelope>(raw)
                                    .map_err(|_| INVALID)?
                                    .response
                                    .output
                                    .get()
                                    .len(),
                            )
                        {
                            self.terminal =
                                Some(out.iter().map(responses_item).collect::<Result<_>>()?);
                        }
                    }
                }
            }
            "response.output_item.added" | "response.output_item.done" => {
                let i = index(&v["output_index"])?;
                let item = &v["item"];
                let id = string(&item["id"])?;
                if id.len() > 1024 {
                    return Err(INVALID);
                }
                let closed = kind.ends_with(".done");
                if self
                    .items
                    .get(&i)
                    .is_some_and(|old| old.id != id || old.closed || !closed)
                {
                    return Err(INVALID);
                }
                if !self.items.contains_key(&i) {
                    b.item()?;
                }
                let message = if closed {
                    let m = responses_item(item)?;
                    #[derive(serde::Deserialize)]
                    struct Snapshot<'a> {
                        #[serde(borrow)]
                        item: &'a serde_json::value::RawValue,
                    }
                    (b.retaining()
                        && b.take(
                            serde_json::from_str::<Snapshot>(raw)
                                .map_err(|_| INVALID)?
                                .item
                                .get()
                                .len(),
                        ))
                    .then_some(m)
                } else {
                    None
                };
                if let Some(tools) = &mut b.tools {
                    tools.responses(i as usize, item);
                }
                self.items.insert(
                    i,
                    Item {
                        id: id.into(),
                        closed,
                        message,
                    },
                );
            }
            "response.output_text.delta"
            | "response.refusal.delta"
            | "response.function_call_arguments.delta"
            | "response.output_text.done"
            | "response.refusal.done"
            | "response.function_call_arguments.done"
            | "response.content_part.added"
            | "response.content_part.done"
            | "response.output_text.annotation.added"
            | "response.reasoning_summary_part.added"
            | "response.reasoning_summary_part.done"
            | "response.reasoning_summary_text.delta"
            | "response.reasoning_summary_text.done" => {
                let item = self.items.get(&index(&v["output_index"])?).ok_or(INVALID)?;
                if item.closed || string(&v["item_id"])? != item.id {
                    return Err(INVALID);
                }
                if matches!(
                    kind,
                    "response.output_text.delta"
                        | "response.refusal.delta"
                        | "response.function_call_arguments.delta"
                ) {
                    string(&v["delta"])?;
                }
            }
            _ => b.partial = true,
        }
        Ok(())
    }

    pub(super) fn discard_content(&mut self) {
        self.terminal = None;
        for item in self.items.values_mut() {
            item.message = None;
        }
    }

    pub(super) fn finish(self, keep: bool) -> Result<Value> {
        if !self.done {
            return Err("incomplete_stream");
        }
        let mut view = self.view.ok_or(INVALID)?;
        let mut messages = vec![];
        if let Some(output) = self.terminal {
            messages = output;
        } else if view.get("error").is_none() {
            for (i, (index, item)) in self.items.into_iter().enumerate() {
                if index as usize != i || !item.closed {
                    return Err("incomplete_stream");
                }
                if let Some(m) = item.message {
                    messages.push(m);
                }
            }
        }
        if keep {
            for (i, m) in messages.iter_mut().enumerate() {
                m["index"] = i.into();
            }
            view["outputMessages"] = messages.into();
        }
        Ok(view)
    }
}
