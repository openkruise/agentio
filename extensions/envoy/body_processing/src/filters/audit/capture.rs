// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{projection::Projection, template::Template};
use crate::{
    FilterOutput,
    chain::Side,
    filters::{BodyEnd, BodyFilter, BodyInterest, BodyResult, Decision},
    parser::{
        BodyError, BodyEvent,
        body::{Content, ParsedBody},
        llm,
    },
};
use serde::Serialize;
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

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CaptureStatus {
    Complete,
    Partial,
    Truncated,
    #[serde(untagged)]
    Failed(BodyError),
}

impl CaptureStatus {
    pub(super) fn write(self, row: &mut Map<String, Value>, aliases: &[String]) {
        for alias in aliases {
            row.insert(alias.clone(), serde_json::json!(self));
        }
    }
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
        let template = Arc::new(Template::fixture(
            side,
            settings.fields,
            settings.field_bytes,
        ));
        let mut capture = Self::new(side, context.filter_index, template, attrs.truncated);
        capture.format = settings.format;
        capture.fixture_fields = attrs.values;
        capture
    }
    #[cfg(test)]
    pub(crate) fn document_room(&self) -> usize {
        self.template.body[0].limit
    }

    fn finish(mut self, end: &BodyEnd, error: Option<BodyError>, output: &mut FilterOutput) {
        let row = output.audit(self.filter_index);
        #[cfg(test)]
        row.append(&mut self.fixture_fields);
        if error.is_none()
            || matches!(
                end.result,
                BodyResult::Llm(llm::Outcome::InterruptedSse { .. })
            )
        {
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
        let status = match error {
            Some(reason) => CaptureStatus::Failed(reason),
            None if self.clipped => CaptureStatus::Truncated,
            None if self.partial => CaptureStatus::Partial,
            None => CaptureStatus::Complete,
        };
        status.write(row, &self.template.status);
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
        let BodyEvent::Llm(event) = event;
        if let llm::Event::Response(llm::stream::Event::Completed { view, .. }) = event {
            self.partial = view.partial;
        }
        for (group, state) in self.template.body.iter().zip(&mut self.views) {
            match event {
                llm::Event::RequestItem { item, clipped } => {
                    state
                        .request
                        .observe(item, *clipped, group.fields, group.limit)
                }
                llm::Event::Response(event) => {
                    if let Some(body) = state.sse.observe(event, group.fields, group.limit) {
                        self.clipped |= group.publish(body, &mut self.body);
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
            BodyResult::Failed(e) => error = Some(*e),
            BodyResult::Counts | BodyResult::Llm(llm::Outcome::Sse) => {}
            BodyResult::Llm(llm::Outcome::InterruptedSse { reason, partial }) => {
                if let Some((view, visible)) = partial {
                    for (group, state) in self.template.body.iter().zip(&mut self.views) {
                        let body = state
                            .sse
                            .interrupted(view, *visible, group.fields, group.limit);
                        group.publish(body, &mut self.body);
                    }
                }
                error = Some(*reason);
            }
            BodyResult::Llm(llm::Outcome::Document { loss, view }) => {
                self.partial = view.partial;
                let request = matches!(self.direction, Side::Request);
                for (group, state) in self.template.body.iter().zip(&mut self.views) {
                    if (group.fields.output_messages
                        || group.fields.answer
                        || group.fields.retained_text)
                        && let Some(reason) = view.output_messages_error
                    {
                        error = Some(reason);
                        break;
                    }
                    let result = if request {
                        std::mem::take(&mut state.request).finish(view)
                    } else {
                        let status = if view.document.get("outputMessages").is_some() {
                            llm::stream::AnswerStatus::Visible
                        } else {
                            llm::stream::AnswerStatus::Unavailable
                        };
                        let event = llm::stream::Event::Completed {
                            view,
                            truncated: loss.document,
                            answer: status,
                        };
                        let body = state
                            .sse
                            .observe(&event, group.fields, group.limit)
                            .unwrap();
                        let Content::Llm(mut result) = body.content else {
                            unreachable!()
                        };
                        if group.fields.tool_call_refs && loss.references {
                            result.tool_refs.entries.clear();
                            result.tool_refs.truncated = true;
                        }
                        Ok((
                            body.truncated
                                || group.fields.error && loss.error
                                || group.finish_reasons && loss.finish_reasons,
                            result,
                        ))
                    };
                    match result {
                        Ok((truncated, v)) => {
                            self.clipped |= group.publish(
                                ParsedBody {
                                    truncated,
                                    content: Content::Llm(v),
                                },
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
            BodyResult::Http(body) => {
                for group in &self.template.body {
                    self.clipped |= group.publish(body.clone(), &mut self.body);
                }
            }
        }
        self.finish(end, error, output);
        Decision::Continue
    }
}
