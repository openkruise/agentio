// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Attributes, Direction,
    projection::{Projection, response_view},
};
use crate::FilterOutput;
use crate::parser::body::{Content, Decoded, ParsedBody};
use crate::parser::request::ItemEvent;

use serde_json::{Map, Value};

pub struct AuditContext<'a> {
    pub chain: &'a str,
    pub filter_index: usize,
    pub attributes: &'a Attributes,
}

pub struct Capture {
    template: std::sync::Arc<super::template::Template>,
    context: Map<String, Value>,
    filter_index: usize,
    record: Record,
    content_budget: usize,
    line_limit: usize,
    projection: Projection,
    sse: Option<Box<super::sse::Projection>>,
    pub(crate) settings: Direction,
}

struct Record {
    chain: String,
    id: String,
    direction: &'static str,
    path: String,
    capture_status: &'static str,
    bytes_seen: usize,
    decoded_bytes: Option<usize>,
    protocol: Option<&'static str>,
    attributes: Map<String, Value>,
    attributes_truncated: bool,
}

fn prefix(s: &str, limit: usize) -> &str {
    &s[..s.floor_char_boundary(limit.min(s.len()))]
}

impl Capture {
    pub(super) fn with_template(
        direction: &'static str,
        path: &str,
        id: &str,
        settings: Direction,
        context: AuditContext<'_>,
        template: std::sync::Arc<super::template::Template>,
    ) -> Self {
        let AuditContext {
            chain,
            filter_index,
            attributes: attrs,
        } = context;
        let limit = settings.max_log_bytes;
        let path = path.split('?').next().unwrap_or(path);
        let mut record = Record {
            chain: chain.to_owned(),
            id: prefix(id, 128).to_owned(),
            direction,
            path: prefix(path, 256).to_owned(),
            capture_status: "complete",
            bytes_seen: 0,
            decoded_bytes: None,
            attributes: Map::new(),
            attributes_truncated: attrs.truncated,
            protocol: settings.format.protocol(),
        };
        let mut remaining = limit;
        let mut context = Map::new();
        for (key, value) in &attrs.values {
            let cost = serde_json::to_vec(key).unwrap().len()
                + serde_json::to_vec(value).unwrap().len()
                + 2;
            if cost > remaining {
                record.attributes_truncated = true;
            } else {
                remaining -= cost;
                context.insert(key.clone(), value.clone());
            }
        }
        // Keep space for JSON delimiters. The renderer charges escaped keys/values exactly.
        let room = remaining.saturating_sub(32);
        Self {
            context,
            template,
            filter_index,
            record,
            content_budget: room,
            line_limit: limit,
            projection: Projection::default(),
            sse: None,
            settings,
        }
    }

    #[cfg(test)]
    pub(crate) fn start(
        direction: &'static str,
        path: &str,
        id: &str,
        mut settings: Direction,
        context: AuditContext<'_>,
    ) -> Self {
        settings.fields.usage = true; // The fixture template exposes all usage counters.
        let template = std::sync::Arc::new(super::template::Template::fixture(
            &context.attributes.values,
        ));
        Self::with_template(direction, path, id, settings, context, template)
    }
    #[cfg(test)]
    pub(crate) fn document_room(&self) -> usize {
        self.settings
            .max_capture_bytes
            .unwrap_or(self.content_budget)
    }

    pub(crate) fn observe(&mut self, event: &ItemEvent, clipped: bool, size: usize) {
        if self
            .settings
            .max_capture_bytes
            .is_none_or(|limit| size <= limit)
        {
            self.projection.observe(
                event,
                clipped,
                self.settings.fields,
                self.content_budget,
                self.line_limit,
            );
        }
    }
    pub(crate) fn project(
        &mut self,
        source: Result<&(bool, Value), &'static str>,
        request: bool,
        size: usize,
    ) -> Decoded {
        if self.settings.max_capture_bytes.is_some_and(|n| size > n) {
            return Err("too_large");
        }
        let (clipped, view) = source?;
        if (self.settings.fields.output_messages || self.settings.fields.answer)
            && view["outputMessagesError"].is_string()
        {
            return Err("invalid_content");
        }
        let (mut truncated, mut value) = if request {
            std::mem::take(&mut self.projection).finish(view)?
        } else {
            (
                *clipped
                    && (self.settings.fields.output_messages
                        || (self.settings.fields.answer && view.get("answer").is_none())),
                response_view(view, self.settings.fields, self.line_limit),
            )
        };
        if let Some(limit) = self
            .settings
            .max_content_bytes
            .or(self.settings.max_capture_bytes)
        {
            truncated |= bound_content(&mut value, limit);
        }
        Ok(ParsedBody {
            truncated,
            content: Content::Llm(value),
        })
    }
    pub(crate) fn finish(
        mut self,
        bytes_seen: usize,
        decoded_bytes: Option<usize>,
        body: Decoded,
        records: &mut FilterOutput,
    ) {
        self.record.bytes_seen = bytes_seen;
        self.record.decoded_bytes = decoded_bytes;
        records.record_audit(self.filter_index, self.record.direction, self.encode(body));
    }

    fn encode(mut self, result: Decoded) -> Vec<u8> {
        match result {
            Ok(ParsedBody {
                truncated: mut clipped,
                content,
            }) => {
                match content {
                    Content::Llm(mut v) => {
                        clipped |= v["toolCallsTruncated"] == true;
                        if self.settings.fields.tool_call_refs
                            && let Some(summary) =
                                v.as_object_mut().and_then(|doc| doc.remove("toolCalls"))
                        {
                            self.record
                                .attributes
                                .insert("agentio.tool.calls".into(), summary);
                        }
                        if v["partial"] == true {
                            self.record.capture_status = "partial";
                        }
                        super::format::project(
                            &mut v,
                            &mut self.record.attributes,
                            self.record.direction == "response",
                            self.settings.fields.output_messages || self.settings.fields.error,
                        );
                    }
                    Content::Http(value) => {
                        self.record.attributes.insert("http.body".into(), value);
                    }
                    Content::Empty => (),
                }
                if clipped {
                    self.record.capture_status = "truncated";
                }
            }
            Err(e) => self.record.capture_status = e,
        }
        let r = self.record;
        let mut fields = r.attributes;
        fields.insert("chain".into(), r.chain.into());
        fields.insert("direction".into(), r.direction.into());
        fields.insert("requestID".into(), r.id.into());
        fields.insert("path".into(), r.path.into());
        fields.insert("bytesSeen".into(), r.bytes_seen.into());
        if let Some(n) = r.decoded_bytes {
            fields.insert("decodedBytes".into(), n.into());
        }
        if let Some(protocol) = r.protocol {
            fields.insert("llm.protocol".into(), protocol.into());
        }
        if r.attributes_truncated {
            fields.insert("attributesTruncated".into(), true.into());
        }
        let status = if r.attributes_truncated && r.capture_status == "complete" {
            "truncated"
        } else {
            r.capture_status
        };
        self.template
            .render(&fields, &self.context, r.direction, status, self.line_limit)
    }
}

// The normalized messages and tool definitions share one retention budget.
pub(super) fn bound_content(view: &mut Value, limit: usize) -> bool {
    let keys = [
        "systemInstructions",
        "inputMessages",
        "outputMessages",
        "question",
        "answer",
        "tools",
        "retainedText",
    ];
    let bytes: usize = keys
        .iter()
        .filter_map(|k| view.get(k))
        .map(crate::parser::encoded_len)
        .sum();
    if bytes <= limit {
        return false;
    }
    let map = view.as_object_mut().expect("LLM view is an object");
    for k in keys {
        map.remove(k);
    }
    view["truncated"] = true.into();
    true
}

pub(super) fn shrink(v: &mut Value, cap: usize) {
    match v {
        Value::String(s) if s.len() > cap => {
            s.truncate(s.floor_char_boundary(cap));
        }
        Value::Array(a) => a.iter_mut().for_each(|child| shrink(child, cap)),
        Value::Object(m) => {
            if m.get("type").and_then(Value::as_str) == Some("blob")
                && m.get("content")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.len() > cap)
            {
                m.remove("content");
            }
            for (key, child) in m {
                if child.as_str().is_some_and(|s| {
                    s.len() > cap
                        && matches!(
                            key.as_str(),
                            "data" | "file_data" | "bytes" | "image_url" | "url" | "base64"
                        )
                }) {
                    let mime = child
                        .as_str()
                        .and_then(|s| s.strip_prefix("data:"))
                        .and_then(|s| s.get(..s.len().min(128)))
                        .and_then(|s| s.split_once(";base64,"))
                        .map(|(mime, _)| mime);
                    *child = match mime {
                        Some(mime) => format!("data:{mime};base64,[omitted]").into(),
                        None => "[omitted]".into(),
                    };
                } else {
                    shrink(child, cap);
                }
            }
        }
        _ => {}
    }
}

impl crate::filters::BodyFilter for Capture {
    fn on_event(
        &mut self,
        event: &crate::parser::BodyEvent<'_>,
        bytes_seen: usize,
    ) -> crate::filters::Decision {
        use crate::parser::BodyEvent;
        match event {
            BodyEvent::LlmItem { item, clipped } => self.observe(item, *clipped, bytes_seen),
            BodyEvent::LlmResponse(event) => self.sse.get_or_insert_with(Default::default).observe(
                event,
                self.settings,
                self.content_budget,
            ),
            _ => {}
        }
        crate::filters::Decision::Continue
    }
    fn on_end(
        mut self: Box<Self>,
        end: &crate::filters::BodyEnd,
        output: &mut FilterOutput,
    ) -> crate::filters::Decision {
        use crate::filters::BodyResult;
        let body = match &end.result {
            BodyResult::Incomplete => Err("incomplete"),
            BodyResult::Llm(view) => self.project(
                view.as_ref().map_err(|e| *e),
                self.record.direction == "request",
                end.decoded_bytes.unwrap_or(end.bytes_seen),
            ),
            BodyResult::Sse { largest_event, .. }
                if *largest_event > self.settings.max_capture_bytes.unwrap_or(64 << 10) =>
            {
                Err("too_large")
            }
            BodyResult::Sse { status: Err(e), .. } => Err(*e),
            BodyResult::Sse { status: Ok(()), .. } => Ok(self.sse.take().unwrap().finish()),
            BodyResult::Http(result) => result.clone(),
        };
        self.finish(end.bytes_seen, end.decoded_bytes, body, output);
        crate::filters::Decision::Continue
    }
}
