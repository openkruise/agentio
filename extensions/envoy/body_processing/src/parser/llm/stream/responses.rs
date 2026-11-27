// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{Event, Output, Retention, Trailers, string};
use crate::parser::BodyError;
use crate::parser::llm::{
    RESPONSES, answer_parts,
    json_response::{ItemCapture, emit_item},
    response::{Result, index, metadata},
    responses_item,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, btree_map::Entry};

#[derive(Default)]
pub(super) struct Stream {
    view: Option<Value>,
    items: BTreeMap<u32, Item>,
    authoritative: bool,
}
#[derive(Default)]
struct Item {
    id: String,
    closed: bool,
    text: BTreeMap<(u32, bool), String>,
    text_bytes: usize,
    text_cut: Option<(u32, bool)>,
}
impl Stream {
    pub(super) fn add(
        &mut self,
        kind: &str,
        v: &Value,
        done: bool,
        b: &mut Retention,
        emit: &mut impl FnMut(Event<'_>),
    ) -> Result<Option<Trailers>> {
        if done {
            return Err(BodyError::InvalidJson);
        }
        let mut terminal = false;
        match kind {
            "error" => {
                string(&v["message"])?;
                self.view.get_or_insert_with(|| json!({"format":RESPONSES}))["error"] = v.clone();
                terminal = true;
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
                    return Err(BodyError::InvalidContent);
                }
                let mut m = metadata(RESPONSES, doc)?;
                if let Some(usage) = m.as_object_mut().unwrap().remove("usage") {
                    emit(Event::Usage(&usage));
                }
                if let Some(old) = self.view.as_ref() {
                    if old["model"].as_str().is_some_and(|s| s != model) {
                        return Err(BodyError::InvalidContent);
                    }
                    for (key, wire) in [
                        ("error", "error"),
                        ("incompleteReason", "incomplete_details"),
                    ] {
                        if let Some(prev) = old.get(key)
                            && doc.get(wire).is_none()
                        {
                            m[key] = prev.clone();
                        }
                    }
                }
                self.view = Some(m);
                terminal = matches!(status, "completed" | "failed" | "incomplete")
                    && kind != "response.created";
                if terminal && !doc["output"].is_null() {
                    let out = doc["output"].as_array().ok_or(BodyError::InvalidContent)?;
                    if out.len() > 1024 {
                        return Err(BodyError::TooLarge);
                    }
                    if !out.is_empty() {
                        b.tools.document(RESPONSES, doc, true);
                        self.items.clear();
                        b.room = b.limit;
                        b.truncated = false;
                        b.partial = false;
                        emit(Event::ReplaceOutput);
                        for (index, item) in out.iter().enumerate() {
                            sealed(index as u32, item, b, emit)?;
                        }
                        self.authoritative = true;
                    }
                }
            }
            "response.output_item.added" | "response.output_item.done" => {
                let i = index(&v["output_index"])?;
                let item = &v["item"];
                let id = string(&item["id"])?;
                if id.len() > 1024 {
                    return Err(BodyError::InvalidContent);
                }
                let closed = kind.ends_with(".done");
                if self
                    .items
                    .get(&i)
                    .is_some_and(|old| old.id != id || old.closed || !closed)
                {
                    return Err(BodyError::InvalidContent);
                }
                if !self.items.contains_key(&i) {
                    b.item()?;
                }
                let previous = self.items.insert(
                    i,
                    Item {
                        id: id.into(),
                        closed,
                        ..Default::default()
                    },
                );
                if let Some(previous) = previous {
                    b.room += previous.text_bytes;
                }
                if closed {
                    sealed(i, item, b, emit)?;
                }
                b.tools.responses(i as usize, item);
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
                let output = index(&v["output_index"])?;
                let item = self
                    .items
                    .get_mut(&output)
                    .ok_or(BodyError::InvalidContent)?;
                if item.closed || string(&v["item_id"])? != item.id {
                    return Err(BodyError::InvalidContent);
                }
                match kind {
                    "response.output_text.delta" | "response.refusal.delta" => {
                        let part = v.get("content_index").map(index).transpose()?;
                        let text = string(&v["delta"])?;
                        if !b.partial {
                            item.retain_text(
                                part.unwrap_or_default(),
                                kind == "response.refusal.delta",
                                text,
                                &mut b.room,
                            );
                        }
                        emit(Event::TextDelta {
                            provisional: true,
                            output: Output::new(RESPONSES, output),
                            part,
                            text,
                        });
                        return Ok(None);
                    }
                    "response.function_call_arguments.delta" => {
                        string(&v["delta"])?;
                    }
                    _ => {}
                }
            }
            _ => b.partial = true,
        }
        emit(Event::Detail { kind, value: v });
        Ok(terminal.then_some(Trailers::Done))
    }

    pub(super) fn interrupted(self, emit: &mut impl FnMut(Event<'_>)) -> Value {
        for (index, item) in self.items {
            if item.text.is_empty() && item.text_cut.is_none() {
                continue;
            }
            let content: Vec<_> = item
                .text
                .into_iter()
                .take_while(|(part, _)| item.text_cut.is_none_or(|cut| *part <= cut))
                .map(|((_, refusal), text)| {
                    let mut block = json!({"type": if refusal { "refusal" } else { "text" }});
                    block["text"] = text.into();
                    block
                })
                .collect();
            let value = (!content.is_empty()).then(|| {
                let mut message = json!({"index":index,"role":"assistant"});
                message["content"] = content.into();
                message
            });
            emit(Event::OutputItem {
                output: Output::new(RESPONSES, index),
                part: None,
                value: value.as_ref(),
                clipped: item.text_cut.is_some(),
                sealed: false,
            });
        }
        self.view.unwrap_or_else(|| json!({"format": RESPONSES}))
    }

    pub(super) fn finish(self, keep: bool) -> Result<Value> {
        let mut view = self.view.ok_or(BodyError::InvalidContent)?;
        if !self.authoritative && view.get("error").is_none() {
            for (i, (index, item)) in self.items.into_iter().enumerate() {
                if index as usize != i || !item.closed {
                    return Err(BodyError::IncompleteStream);
                }
            }
        }
        if keep {
            view["outputMessages"] = json!([]);
        }
        Ok(view)
    }
}

impl Item {
    fn retain_text(&mut self, part: u32, refusal: bool, text: &str, room: &mut usize) {
        if text.is_empty() {
            return;
        }
        let key = (part, refusal);
        if let Some(cut) = &mut self.text_cut {
            *cut = (*cut).min(key);
            return;
        }
        // Charge each part for its envelope as well as its text.
        let entry = self.text.entry(key);
        let overhead = if matches!(&entry, Entry::Vacant(_)) {
            r#"{"type":"refusal","text":""},"#.len()
        } else {
            0
        };
        let keep = text.floor_char_boundary(text.len().min(room.saturating_sub(overhead)));
        if keep > 0 {
            entry.or_default().push_str(&text[..keep]);
            self.text_bytes += overhead + keep;
            *room -= overhead + keep;
        }
        if keep < text.len() {
            self.text_cut = Some(key);
        }
    }
}

fn sealed(i: u32, item: &Value, b: &mut Retention, emit: &mut impl FnMut(Event<'_>)) -> Result<()> {
    let output = Output::new(RESPONSES, i);
    if crate::parser::encoded_len(item) > b.limit {
        let mut capture = ItemCapture::new(RESPONSES, b.limit);
        serde_json::to_writer(&mut capture, item).unwrap();
        let (loss, mut view) = capture.finish()?;
        if let Some(reason) = view.output_messages_error {
            return Err(reason);
        }
        emit_item(RESPONSES, i, &mut view, loss, emit);
    } else {
        let mut message = responses_item(item)?;
        message["index"] = i.into();
        for (part, text) in answer_parts(&message).enumerate() {
            emit(Event::TextDelta {
                output,
                part: Some(part as u32),
                text,
                provisional: false,
            });
        }
        emit(Event::OutputItem {
            output,
            part: None,
            value: Some(&message),
            clipped: false,
            sealed: true,
        });
    }
    Ok(())
}
