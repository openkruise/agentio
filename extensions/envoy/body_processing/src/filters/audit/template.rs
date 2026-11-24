// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Audit, Source,
    limit::{DEFAULT_FIELD_BYTES, MAX_FIELD_BYTES, bounded_value},
};
use crate::{chain::Side, parser::llm::Fields};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Copy)]
enum Field {
    Question,
    Tools,
    Messages,
    Answer,
    FinishReasons,
    Usage,
    ToolRefs,
    Instructions,
    Error,
    RetainedText,
    Metadata,
    Scalar,
}

impl Field {
    fn resolve(name: &str) -> Result<(Side, Self, &'static str), String> {
        use Side::{Request, Response};
        Ok(match name {
            "llm.question" => (Request, Self::Question, "llm.question"),
            "llm.toolDefinitions" => (Request, Self::Tools, "gen_ai.tool.definitions"),
            "llm.systemInstructions" => (Request, Self::Instructions, "gen_ai.system_instructions"),
            "llm.request.model" => (Request, Self::Metadata, "gen_ai.request.model"),
            "llm.response.model" => (Response, Self::Metadata, "gen_ai.response.model"),
            "llm.request.messages" => (Request, Self::Messages, "gen_ai.input.messages"),
            "llm.response.messages" => (Response, Self::Messages, "gen_ai.output.messages"),
            "llm.request.toolCallRefs" => (Request, Self::ToolRefs, "agentio.tool.calls"),
            "llm.response.toolCallRefs" => (Response, Self::ToolRefs, "agentio.tool.calls"),
            "llm.request.retainedText" => (Request, Self::RetainedText, "llm.retainedText"),
            "llm.response.retainedText" => (Response, Self::RetainedText, "llm.retainedText"),
            "llm.stream" => (Request, Self::Scalar, "gen_ai.request.stream"),
            "llm.maxTokens" => (Request, Self::Scalar, "gen_ai.request.max_tokens"),
            "llm.conversationId" => (Request, Self::Metadata, "gen_ai.conversation.id"),
            "llm.previousResponseId" => (
                Request,
                Self::Metadata,
                "gen_ai.request.previous_response.id",
            ),
            "llm.answer" => (Response, Self::Answer, "llm.answer"),
            "llm.error" => (Response, Self::Error, "llm.error"),
            "llm.responseId" => (Response, Self::Metadata, "gen_ai.response.id"),
            "llm.finishReasons" => (
                Response,
                Self::FinishReasons,
                "gen_ai.response.finish_reasons",
            ),
            "llm.status" => (Response, Self::Metadata, "llm.status"),
            "llm.incompleteReason" => (Response, Self::Metadata, "llm.incompleteReason"),
            "llm.errorType" => (Response, Self::Metadata, "error.type"),
            "llm.errorCode" => (Response, Self::Metadata, "agentio.response.error_code"),
            "llm.model" | "llm.messages" | "llm.toolCallRefs" | "llm.retainedText" => {
                let field = &name[4..];
                return Err(format!(
                    "ambiguous {name}; use llm.request.{field} or llm.response.{field}"
                ));
            }
            _ => {
                let key = name
                    .strip_prefix("llm.usage.")
                    .and_then(|n| projected_key(super::format::USAGE, n))
                    .ok_or_else(|| format!("unknown LLM event field {name:?}"))?;
                (Response, Self::Usage, key)
            }
        })
    }

    fn retain(self, side: Side, group: &mut BodyFields) {
        let fields = &mut group.fields;
        match self {
            Self::Question => fields.question = true,
            Self::Tools => fields.tools = true,
            Self::Messages => match side {
                Side::Request => fields.input_messages = true,
                Side::Response => fields.output_messages = true,
            },
            Self::RetainedText => fields.retained_text = true,
            Self::Instructions => fields.instructions = true,
            Self::Error => fields.error = true,
            Self::Answer => fields.answer = true,
            Self::FinishReasons => group.finish_reasons = true,
            Self::Usage => fields.usage = true,
            Self::ToolRefs => fields.tool_call_refs = true,
            Self::Metadata | Self::Scalar => {}
        }
    }
}

fn projected_key(fields: &'static [(&str, &str)], name: &str) -> Option<&'static str> {
    fields
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, out)| *out)
}

/// Compile one Envoy-style command per typed JSON value when the configuration loads.
struct Command<'a> {
    name: &'a str,
    argument: Option<&'a str>,
    limit: Option<usize>,
}

impl<'a> Command<'a> {
    fn parse(expression: &'a str) -> Result<Self, &'static str> {
        let inner = expression
            .strip_prefix('%')
            .and_then(|s| s.strip_suffix('%'))
            .ok_or("expected a single %COMMAND% or %COMMAND(argument)%")?;
        let (name, argument, suffix) = if let Some((name, rest)) = inner.split_once('(') {
            let (arg, suffix) = rest.split_once(')').ok_or("missing closing parenthesis")?;
            (name, Some(arg), suffix)
        } else {
            let i = inner.find(':').unwrap_or(inner.len());
            (&inner[..i], None, &inner[i..])
        };
        let limit = if suffix.is_empty() {
            None
        } else {
            let n = suffix
                .strip_prefix(':')
                .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|n| (1..=MAX_FIELD_BYTES).contains(n))
                .ok_or("field limit must be a byte count between 1 and 1048576")?;
            Some(n)
        };
        Ok(Self {
            name,
            argument,
            limit,
        })
    }
}

pub(super) struct Column {
    pub alias: String,
    pub key: &'static str,
    pub limit: usize,
}

impl Column {
    pub fn project(&self, value: &Value, output: &mut Map<String, Value>) -> bool {
        let (value, clipped) = bounded_value(value, self.limit);
        if let Some(value) = value {
            output.insert(self.alias.clone(), value);
        }
        clipped
    }
}

// Fields with the same retention limit can use the same audit projection. Each
// source (messages, question, tools, etc.) has its own counter in that projection.
pub(super) struct BodyFields {
    pub limit: usize,
    pub fields: Fields,
    pub finish_reasons: bool,
    pub columns: Vec<Column>,
}

#[derive(Default)]
pub(crate) struct Template {
    pub(super) body: Vec<BodyFields>,
    pub(super) wire_bytes: Vec<String>,
    pub(super) decoded_bytes: Vec<String>,
    pub(super) status: Vec<String>,
}

impl Template {
    fn event(&mut self, field: Field, side: Side, key: &'static str, name: &str, limit: usize) {
        let column = Column {
            alias: name.into(),
            key,
            limit,
        };
        let index = match self.body.iter().position(|p| p.limit == limit) {
            Some(i) => i,
            None => {
                self.body.push(BodyFields {
                    limit,
                    fields: Fields::default(),
                    finish_reasons: false,
                    columns: Vec::new(),
                });
                self.body.len() - 1
            }
        };
        let group = &mut self.body[index];
        field.retain(side, group);
        group.columns.push(column);
    }

    #[cfg(test)]
    pub(super) fn fixture(fields: Fields, limit: usize) -> Self {
        let col = |key: &'static str| Column {
            alias: key.into(),
            key,
            limit,
        };
        let body_keys = [
            "http.body",
            "llm.error",
            "agentio.tool.calls",
            "llm.partial",
            "llm.toolCallsTruncated",
            "error.type",
            "agentio.response.error_code",
            "gen_ai.operation.name",
            "gen_ai.request.model",
            "gen_ai.response.model",
            "gen_ai.system_instructions",
            "gen_ai.input.messages",
            "gen_ai.output.messages",
            "gen_ai.tool.definitions",
        ];
        Self {
            body: vec![BodyFields {
                fields,
                finish_reasons: true,
                limit,
                columns: body_keys
                    .into_iter()
                    .chain(
                        super::format::METADATA
                            .iter()
                            .chain(super::format::USAGE)
                            .map(|(_, key)| *key),
                    )
                    .map(col)
                    .collect(),
            }],
            wire_bytes: vec!["bytesSeen".into()],
            decoded_bytes: vec!["decodedBytes".into()],
            status: vec!["captureStatus".into()],
        }
    }
}

impl Audit {
    pub(crate) fn compile(expressions: BTreeMap<String, String>) -> Result<Self, String> {
        let mut request = None;
        let mut response = None;
        let mut context = BTreeMap::new();
        for (alias, expression) in expressions {
            if alias.is_empty() {
                return Err("empty log field name".into());
            }
            let command =
                Command::parse(&expression).map_err(|e| format!("field {alias:?}: {e}"))?;
            let limit = command.limit.unwrap_or(DEFAULT_FIELD_BYTES);
            let source = match (command.name, command.argument) {
                ("CHAIN", None) => Source::Chain,
                ("PATH", None) => Source::Path,
                ("EVENT", Some("llm.protocol")) => Source::Protocol,
                ("EVENT", Some("llm.operation")) => Source::Operation,
                ("EVENT", Some(name)) => {
                    let (side, field, key) =
                        Field::resolve(name).map_err(|e| format!("field {alias:?}: {e}"))?;
                    if command.limit.is_some() && matches!(field, Field::Scalar | Field::Usage) {
                        return Err(format!(
                            "field {alias:?}: {name} is a scalar and does not take a byte limit"
                        ));
                    }
                    let template = match side {
                        Side::Request => &mut request,
                        Side::Response => &mut response,
                    };
                    template
                        .get_or_insert_with(Template::default)
                        .event(field, side, key, &alias, limit);
                    continue;
                }
                (name @ ("CAPTURE_STATUS" | "BYTES_SEEN" | "DECODED_BYTES"), side) => {
                    if command.limit.is_some() {
                        return Err(format!(
                            "field {alias:?}: {name} does not take a byte limit"
                        ));
                    }
                    let template = match side {
                        Some("request") => &mut request,
                        Some("response") => &mut response,
                        _ => {
                            return Err(format!(
                                "field {alias:?}: use %{name}(request)% or %{name}(response)%"
                            ));
                        }
                    }
                    .get_or_insert_with(Template::default);
                    match name {
                        "BYTES_SEEN" => template.wire_bytes.push(alias),
                        "DECODED_BYTES" => template.decoded_bytes.push(alias),
                        _ => template.status.push(alias),
                    }
                    continue;
                }
                (name, Some(args)) => Source::parse(name, args, command.limit)
                    .map_err(|e| format!("field {alias:?}: {name}: {e}"))?,
                _ => {
                    return Err(format!(
                        "field {alias:?}: unsupported audit expression {expression:?}"
                    ));
                }
            };
            context.insert(alias, (source, limit));
        }
        Ok(Self {
            request: request.map(Arc::new),
            response: response.map(Arc::new),
            context,
        })
    }
}
