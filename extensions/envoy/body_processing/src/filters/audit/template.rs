// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Audit, Source,
    format::Field,
    limit::{DEFAULT_FIELD_BYTES, MAX_FIELD_BYTES, bounded_value},
};
use crate::{
    chain::Side,
    parser::{
        body::{Content, ParsedBody},
        llm::Fields,
    },
};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, sync::Arc};

impl Field {
    fn resolve(name: &str) -> Result<(Side, Self), String> {
        use Side::{Request, Response};
        Ok(match name {
            "llm.question" => (Request, Self::Question),
            "llm.toolDefinitions" => (Request, Self::Tools),
            "llm.systemInstructions" => (Request, Self::Instructions),
            "llm.request.model" => (Request, Self::Model),
            "llm.response.model" => (Response, Self::Model),
            "llm.request.messages" => (Request, Self::InputMessages),
            "llm.response.messages" => (Response, Self::OutputMessages),
            "llm.request.toolCallRefs" => (Request, Self::ToolRefs),
            "llm.response.toolCallRefs" => (Response, Self::ToolRefs),
            "llm.request.retainedText" => (Request, Self::RetainedText),
            "llm.response.retainedText" => (Response, Self::RetainedText),
            "llm.stream" => (Request, Self::Stream),
            "llm.maxTokens" => (Request, Self::MaxTokens),
            "llm.conversationId" => (Request, Self::ConversationId),
            "llm.previousResponseId" => (Request, Self::PreviousResponseId),
            "llm.answer" => (Response, Self::Answer),
            "llm.error" => (Response, Self::Error),
            "llm.responseId" => (Response, Self::ResponseId),
            "llm.finishReasons" => (Response, Self::FinishReasons),
            "llm.status" => (Response, Self::Status),
            "llm.incompleteReason" => (Response, Self::IncompleteReason),
            "llm.errorType" => (Response, Self::ErrorType),
            "llm.errorCode" => (Response, Self::ErrorCode),
            "llm.usage.inputTokens" => (Response, Self::Usage("inputTokens")),
            "llm.usage.outputTokens" => (Response, Self::Usage("outputTokens")),
            "llm.usage.cachedInputTokens" => (Response, Self::Usage("cachedInputTokens")),
            "llm.usage.cacheCreationInputTokens" => {
                (Response, Self::Usage("cacheCreationInputTokens"))
            }
            "llm.usage.reasoningTokens" => (Response, Self::Usage("reasoningTokens")),
            "llm.usage.totalTokens" => (Response, Self::Usage("totalTokens")),
            "llm.model" | "llm.messages" | "llm.toolCallRefs" | "llm.retainedText" => {
                let field = &name[4..];
                return Err(format!(
                    "ambiguous {name}; use llm.request.{field} or llm.response.{field}"
                ));
            }
            _ => return Err(format!("unknown LLM event field {name:?}")),
        })
    }

    fn retain(self, group: &mut BodyFields) {
        let fields = &mut group.fields;
        match self {
            Self::Question => fields.question = true,
            Self::Tools => fields.tools = true,
            Self::InputMessages => fields.input_messages = true,
            Self::OutputMessages => fields.output_messages = true,
            Self::RetainedText => fields.retained_text = true,
            Self::Instructions => fields.instructions = true,
            Self::Error => fields.error = true,
            Self::Answer => fields.answer = true,
            Self::FinishReasons => group.finish_reasons = true,
            Self::Usage(_) => fields.usage = true,
            Self::ToolRefs => fields.tool_call_refs = true,
            _ => {}
        }
    }
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

// Fields with the same retention limit can use the same audit projection. Each
// source (messages, question, tools, etc.) has its own counter in that projection.
pub(super) struct BodyFields {
    pub limit: usize,
    pub fields: Fields,
    pub finish_reasons: bool,
    // Aliases of the same field share its formatted value at this limit.
    pub columns: BTreeMap<Field, Vec<String>>,
}

impl BodyFields {
    pub(super) fn publish(&self, mut body: ParsedBody, output: &mut Map<String, Value>) -> bool {
        let mut clipped = body.truncated
            || matches!(&body.content, Content::Llm(view) if view.tool_refs.truncated);
        for (field, aliases) in &self.columns {
            let Some(source) = field.value(&mut body.content) else {
                continue;
            };
            let (value, shortened) = bounded_value(&source, self.limit);
            clipped |= shortened;
            if let Some(value) = value {
                for alias in &aliases[1..] {
                    output.insert(alias.clone(), value.clone());
                }
                output.insert(aliases[0].clone(), value);
            }
        }
        clipped
    }
}

#[derive(Default)]
pub(crate) struct Template {
    pub(super) body: Vec<BodyFields>,
    pub(super) wire_bytes: Vec<String>,
    pub(super) decoded_bytes: Vec<String>,
    pub(super) status: Vec<String>,
}

impl Template {
    fn event(&mut self, field: Field, alias: String, limit: usize) {
        let index = match self.body.iter().position(|p| p.limit == limit) {
            Some(i) => i,
            None => {
                self.body.push(BodyFields {
                    limit,
                    fields: Fields::default(),
                    finish_reasons: false,
                    columns: BTreeMap::new(),
                });
                self.body.len() - 1
            }
        };
        let group = &mut self.body[index];
        field.retain(group);
        group.columns.entry(field).or_default().push(alias);
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
                    let (side, field) =
                        Field::resolve(name).map_err(|e| format!("field {alias:?}: {e}"))?;
                    if command.limit.is_some()
                        && matches!(field, Field::Stream | Field::MaxTokens | Field::Usage(_))
                    {
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
                        .event(field, alias, limit);
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
