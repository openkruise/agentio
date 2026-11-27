// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{
    format::Field,
    messages::{Messages, format_parts},
    template::{BodyFields, Template},
};
use crate::{
    chain::Side,
    parser::{
        body::{Content, ParsedBody},
        llm::Fields,
    },
};
use serde_json::{Map, Value};

// Output aliases used by the EPE parity fixtures.
fn body_fields(side: Side, fields: Fields, limit: usize) -> BodyFields {
    let model = match side {
        Side::Request => "gen_ai.request.model",
        Side::Response => "gen_ai.response.model",
    };
    let mut group = BodyFields {
        limit,
        fields,
        finish_reasons: true,
        columns: [
            (Field::HttpBody, "http.body"),
            (Field::ToolRefs, "agentio.tool.calls"),
            (Field::Partial, "llm.partial"),
            (Field::ToolRefsTruncated, "llm.toolCallsTruncated"),
            (Field::ErrorType, "error.type"),
            (Field::ErrorCode, "agentio.response.error_code"),
            (Field::Operation, "gen_ai.operation.name"),
            (Field::Model, model),
            (Field::Instructions, "gen_ai.system_instructions"),
            (Field::InputMessages, "gen_ai.input.messages"),
            (Field::OutputMessages, "gen_ai.output.messages"),
            (Field::Tools, "gen_ai.tool.definitions"),
            (Field::ResponseId, "gen_ai.response.id"),
            (
                Field::PreviousResponseId,
                "gen_ai.request.previous_response.id",
            ),
            (Field::Stream, "gen_ai.request.stream"),
            (Field::MaxTokens, "gen_ai.request.max_tokens"),
            (Field::FinishReasons, "gen_ai.response.finish_reasons"),
            (Field::ConversationId, "gen_ai.conversation.id"),
            (Field::Question, "llm.question"),
            (Field::Answer, "llm.answer"),
            (Field::Status, "llm.status"),
            (Field::IncompleteReason, "llm.incompleteReason"),
            (Field::Truncated, "llm.truncated"),
            (Field::RetainedText, "llm.retainedText"),
            (Field::Usage("inputTokens"), "gen_ai.usage.input_tokens"),
            (Field::Usage("outputTokens"), "gen_ai.usage.output_tokens"),
            (
                Field::Usage("cachedInputTokens"),
                "gen_ai.usage.cache_read.input_tokens",
            ),
            (
                Field::Usage("cacheCreationInputTokens"),
                "gen_ai.usage.cache_write.input_tokens",
            ),
            (
                Field::Usage("reasoningTokens"),
                "gen_ai.usage.reasoning.output_tokens",
            ),
            (Field::Usage("totalTokens"), "agentio.usage.total_tokens"),
        ]
        .into_iter()
        .map(|(field, alias)| (field, vec![alias.to_owned()]))
        .collect(),
    };
    if fields.output_messages || fields.error {
        group.columns.insert(Field::Error, vec!["llm.error".into()]);
    }
    group
}

impl Template {
    pub(super) fn fixture(side: Side, fields: Fields, limit: usize) -> Self {
        Self {
            body: vec![body_fields(side, fields, limit)],
            wire_bytes: vec!["bytesSeen".into()],
            decoded_bytes: vec!["decodedBytes".into()],
            status: vec!["captureStatus".into()],
        }
    }
}

pub(crate) fn expected_fields(document: &Value, side: Side) -> Map<String, Value> {
    let mut row = Map::new();
    let mut document = document.clone();
    for key in ["inputMessages", "outputMessages"] {
        if let Some(value) = document.get_mut(key) {
            *value = Messages::project(value.as_array().unwrap(), usize::MAX, side)
                .0
                .unwrap();
        }
    }
    if let Some(parts) = document.get_mut("systemInstructions") {
        *parts = format_parts(parts);
    }
    let body = ParsedBody {
        truncated: false,
        content: Content::Llm(document.into()),
    };
    body_fields(side, Fields::ALL, usize::MAX).publish(body, &mut row);
    row
}
