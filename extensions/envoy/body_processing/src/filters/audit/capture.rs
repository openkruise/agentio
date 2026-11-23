// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{
    projection::{Projection, response_text, response_view},
    template::{BodyFields, Template},
};
use crate::{
    FilterOutput,
    chain::Side,
    filters::{BodyEnd, BodyFilter, BodyInterest, BodyResult, Decision},
    parser::{
        BodyEvent,
        body::{Content, ParsedBody},
    },
};
use serde_json::{Map, Value};
use std::sync::Arc;

#[cfg(test)]
use {super::Attributes, crate::parser::Format};

#[cfg(test)]
pub(crate) struct AuditContext<'a> {
    pub chain: &'a str,
    pub filter_index: usize,
    pub attributes: &'a Attributes,
}

#[derive(Default)]
struct BodyCapture {
    request: Projection,
    sse: super::sse::Projection,
}

pub(crate) struct Capture {
    template: Arc<Template>,
    filter_index: usize,
    direction: Side,
    #[cfg(test)]
    fixture_fields: Map<String, Value>,
    views: Vec<BodyCapture>,
    body: Map<String, Value>,
    clipped: bool,
    partial: bool,
    #[cfg(test)]
    pub(crate) format: Format,
}

impl Capture {
    pub(super) fn new(
        direction: Side,
        filter_index: usize,
        template: Arc<Template>,
        context_clipped: bool,
    ) -> Self {
        Self {
            filter_index,
            direction,
            #[cfg(test)]
            fixture_fields: Map::new(),
            views: (0..template.body.len())
                .map(|_| BodyCapture::default())
                .collect(),
            template,
            body: Map::new(),
            clipped: matches!(direction, Side::Request) && context_clipped,
            partial: false,
            #[cfg(test)]
            format: Format::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn start(
        direction: &'static str,
        path: &str,
        id: &str,
        mut settings: super::Direction,
        context: AuditContext<'_>,
    ) -> Self {
        settings.fields.usage = true;
        settings.fields.instructions |= settings.fields.input_messages;
        settings.fields.retained_text |= settings.fields.input_messages;
        let template = Arc::new(Template::fixture(settings.fields, settings.field_bytes));
        let mut attrs = Attributes::default();
        for (alias, value) in &context.attributes.values {
            attrs.insert(alias, value.as_str().unwrap(), settings.field_bytes);
        }
        attrs.truncated |= context.attributes.truncated;
        attrs.insert("requestID", id, settings.field_bytes);
        if attrs.truncated {
            attrs
                .values
                .insert("attributesTruncated".into(), true.into());
        }
        attrs.insert("chain", context.chain, settings.field_bytes);
        attrs.insert("direction", direction, settings.field_bytes);
        attrs.insert(
            "path",
            path.split('?').next().unwrap(),
            settings.field_bytes,
        );
        if let Some(protocol) = settings.format.protocol() {
            attrs.insert("llm.protocol", protocol, settings.field_bytes);
        }
        let side = match direction {
            "request" => Side::Request,
            "response" => Side::Response,
            _ => unreachable!(),
        };
        let mut capture = Self::new(side, context.filter_index, template, attrs.truncated);
        capture.format = settings.format;
        capture.fixture_fields = attrs.values;
        capture
    }
    #[cfg(test)]
    pub(crate) fn document_room(&self) -> usize {
        self.template.body[0].limit
    }

    fn finish(mut self, end: &BodyEnd, error: Option<&'static str>, output: &mut FilterOutput) {
        let row = output.audit(self.filter_index);
        #[cfg(test)]
        row.append(&mut self.fixture_fields);
        if error.is_none() || matches!(end.result, BodyResult::InterruptedSse { .. }) {
            row.append(&mut self.body);
        }
        for name in &self.template.wire_bytes {
            row.insert(name.clone(), end.bytes_seen.into());
        }
        if let Some(n) = end.decoded_bytes {
            for name in &self.template.decoded_bytes {
                row.insert(name.clone(), n.into());
            }
        }
        let status = error.unwrap_or(if self.clipped {
            "truncated"
        } else if self.partial {
            "partial"
        } else {
            "complete"
        });
        for key in &self.template.status {
            row.insert(key.clone(), status.into());
        }
    }
}

impl BodyFields {
    fn publish(&self, body: ParsedBody, response: bool, output: &mut Map<String, Value>) -> bool {
        let mut clipped = body.truncated;
        let mut attrs = Map::new();
        match body.content {
            Content::Llm(mut value) => {
                clipped |= value["toolCallsTruncated"] == true;
                if self.fields.tool_call_refs
                    && let Some(summary) = value.as_object_mut().and_then(|v| v.remove("toolCalls"))
                {
                    attrs.insert("agentio.tool.calls".into(), summary);
                }
                super::format::project(
                    &mut value,
                    &mut attrs,
                    response,
                    self.fields.output_messages || self.fields.error,
                );
            }
            Content::Http(v) => {
                attrs.insert("http.body".into(), v);
            }
            Content::Empty => {}
        }
        for col in &self.columns {
            if let Some(value) = attrs.get(col.key) {
                clipped |= col.project(value, output);
            }
        }
        clipped
    }
}

impl BodyFilter for Capture {
    fn interest(&self) -> BodyInterest {
        BodyInterest {
            events: !self.template.body.is_empty() || !self.template.status.is_empty(),
            decoded_bytes: !self.template.decoded_bytes.is_empty(),
        }
    }

    fn on_event(&mut self, event: &BodyEvent<'_>, _: usize) -> Decision {
        if let BodyEvent::LlmResponse(crate::parser::llm::stream::Event::Completed {
            view, ..
        }) = event
        {
            self.partial = view["partial"] == true;
        }
        for (group, state) in self.template.body.iter().zip(&mut self.views) {
            match event {
                BodyEvent::LlmItem { item, clipped } => {
                    state
                        .request
                        .observe(item, *clipped, group.fields, group.limit)
                }
                BodyEvent::LlmResponse(event) => {
                    if let Some(body) = state.sse.observe(event, group.fields, group.limit) {
                        self.clipped |= group.publish(body, true, &mut self.body);
                    }
                }
                _ => {}
            }
        }
        Decision::Continue
    }

    fn on_end(mut self: Box<Self>, end: &BodyEnd, output: &mut FilterOutput) -> Decision {
        let mut error = None;
        match &end.result {
            BodyResult::Failed(e) | BodyResult::Llm(Err(e)) | BodyResult::Http(Err(e)) => {
                error = Some(*e)
            }
            BodyResult::Counts | BodyResult::Sse => {}
            BodyResult::InterruptedSse { reason, partial } => {
                if let Some((view, visible)) = partial {
                    for (group, state) in self.template.body.iter().zip(&mut self.views) {
                        let body = state
                            .sse
                            .interrupted(view, *visible, group.fields, group.limit);
                        group.publish(body, true, &mut self.body);
                    }
                }
                error = Some(*reason);
            }
            BodyResult::Llm(Ok((loss, view))) => {
                self.partial = view["partial"] == true;
                let request = matches!(self.direction, Side::Request);
                for (group, state) in self.template.body.iter().zip(&mut self.views) {
                    if (group.fields.output_messages
                        || group.fields.answer
                        || group.fields.retained_text)
                        && view["outputMessagesError"].is_string()
                    {
                        error = Some("invalid_content");
                        break;
                    }
                    let result = if request {
                        std::mem::take(&mut state.request).finish(view)
                    } else {
                        let mut result = response_view(view, group.fields, group.limit);
                        let mut clipped = group.fields.output_messages && loss.document
                            || group.fields.answer && (loss.answer || loss.exhausted)
                            || group.fields.error && loss.exhausted && loss.error
                            || loss.finish_reasons
                                && group
                                    .columns
                                    .iter()
                                    .any(|c| c.key == "gen_ai.response.finish_reasons");
                        if group.fields.tool_call_refs && (loss.references || loss.exhausted) {
                            result.as_object_mut().unwrap().remove("toolCalls");
                            result["toolCallsTruncated"] = true.into();
                        }
                        if group.fields.retained_text {
                            clipped |= response_text(view, group.limit).publish(&mut result);
                            clipped |= if loss.exhausted {
                                loss.preview
                            } else {
                                loss.text
                            };
                        }
                        Ok((clipped, result))
                    };
                    match result {
                        Ok((truncated, v)) => {
                            self.clipped |= group.publish(
                                ParsedBody {
                                    truncated,
                                    content: Content::Llm(v),
                                },
                                !request,
                                &mut self.body,
                            )
                        }
                        Err(e) => {
                            error = Some(e);
                            break;
                        }
                    }
                }
            }
            BodyResult::Http(Ok(body)) => {
                for group in &self.template.body {
                    self.clipped |= group.publish(
                        body.clone(),
                        matches!(self.direction, Side::Response),
                        &mut self.body,
                    );
                }
            }
        }
        self.finish(end, error, output);
        Decision::Continue
    }
}
