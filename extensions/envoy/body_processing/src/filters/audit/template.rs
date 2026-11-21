// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{AttributeSources, Audit, Directions};
use crate::parser::llm::Fields;
use serde_json::{Map, Value};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Copy)]
enum Field {
    Question,
    Tools,
    Messages,
    Answer,
    Usage(&'static str),
    ToolRefs,
    Model,
    Stream,
    Metadata(&'static str),
    RequestMeta(&'static str),
    ResponseMeta(&'static str),
    Instructions,
    Error,
    RetainedText,
}
impl Field {
    fn parse(name: &str) -> Result<Self, String> {
        match name {
            "llm.question" => Ok(Self::Question),
            "llm.toolDefinitions" => Ok(Self::Tools),
            "llm.messages" => Ok(Self::Messages),
            "llm.answer" => Ok(Self::Answer),
            "llm.toolCallRefs" => Ok(Self::ToolRefs),
            "llm.model" => Ok(Self::Model),
            "llm.stream" => Ok(Self::Stream),
            "llm.protocol" => Ok(Self::Metadata("llm.protocol")),
            "llm.operation" => Ok(Self::Metadata("gen_ai.operation.name")),
            "llm.systemInstructions" => Ok(Self::Instructions),
            "llm.error" => Ok(Self::Error),
            "llm.retainedText" => Ok(Self::RetainedText),
            "llm.maxTokens" => Ok(Self::RequestMeta("gen_ai.request.max_tokens")),
            "llm.conversationId" => Ok(Self::RequestMeta("gen_ai.conversation.id")),
            "llm.previousResponseId" => {
                Ok(Self::RequestMeta("gen_ai.request.previous_response.id"))
            }
            "llm.responseId" => Ok(Self::ResponseMeta("gen_ai.response.id")),
            "llm.finishReasons" => Ok(Self::ResponseMeta("gen_ai.response.finish_reasons")),
            "llm.status" => Ok(Self::ResponseMeta("llm.status")),
            "llm.incompleteReason" => Ok(Self::ResponseMeta("llm.incompleteReason")),
            "llm.errorType" => Ok(Self::ResponseMeta("error.type")),
            "llm.errorCode" => Ok(Self::ResponseMeta("agentio.response.error_code")),
            _ => name
                .strip_prefix("llm.usage.")
                .and_then(|n| projected_key(super::format::USAGE, n))
                .map(Self::Usage)
                .ok_or_else(|| format!("unknown LLM event field {name:?}")),
        }
    }

    fn key(self, request: bool) -> Option<&'static str> {
        match (self, request) {
            (Self::Question, true) => Some("llm.question"),
            (Self::Tools, true) => Some("gen_ai.tool.definitions"),
            (Self::Messages, true) => Some("gen_ai.input.messages"),
            (Self::Messages, false) => Some("gen_ai.output.messages"),
            (Self::Answer, false) => Some("llm.answer"),
            (Self::ToolRefs, _) => Some("agentio.tool.calls"),
            (Self::Model, true) => Some("gen_ai.request.model"),
            (Self::Model, false) => Some("gen_ai.response.model"),
            (Self::Stream, true) => Some("gen_ai.request.stream"),
            (Self::Metadata(key), _)
            | (Self::RequestMeta(key), true)
            | (Self::Usage(key) | Self::ResponseMeta(key), false) => Some(key),
            (Self::Instructions, true) => Some("gen_ai.system_instructions"),
            (Self::Error, false) => Some("llm.error"),
            (Self::RetainedText, _) => Some("llm.retainedText"),
            _ => None,
        }
    }

    fn retain(self, request: bool, fields: &mut Fields) {
        match self {
            Self::Question => fields.question = true,
            Self::Tools => fields.tools = true,
            Self::Messages | Self::RetainedText if request => fields.input_messages = true,
            Self::Messages | Self::RetainedText => fields.output_messages = true,
            Self::Instructions => fields.instructions = true,
            Self::Error => fields.error = true,
            Self::Answer => fields.answer = true,
            Self::Usage(_) => fields.usage = true,
            Self::ToolRefs => fields.tool_call_refs = true,
            Self::Model
            | Self::Stream
            | Self::Metadata(_)
            | Self::RequestMeta(_)
            | Self::ResponseMeta(_) => {}
        }
    }
}

fn projected_key(fields: &'static [(&str, &str)], name: &str) -> Option<&'static str> {
    fields
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, out)| *out)
}

enum Binding {
    Event(Field),
    Context,
    Record(&'static str),
}
pub(super) struct Template {
    fields: BTreeMap<String, Binding>,
    status_keys: Vec<Vec<u8>>,
}

impl Audit {
    pub(crate) fn compile(
        expressions: BTreeMap<String, String>,
        mut directions: Directions,
    ) -> Result<Self, String> {
        let mut context = BTreeMap::new();
        let mut bindings = BTreeMap::new();
        let mut status_keys = Vec::new();
        for (name, expression) in expressions {
            if name.is_empty() {
                return Err("empty log field name".into());
            }
            let binding = if let Some(event) = expression
                .strip_prefix("%EVENT(")
                .and_then(|s| s.strip_suffix(")%"))
            {
                let field = Field::parse(event)?;
                let mut matched = false;
                for (request, dir) in [
                    (true, &mut directions.request),
                    (false, &mut directions.response),
                ] {
                    if let Some(dir) = dir
                        && field.key(request).is_some()
                    {
                        field.retain(request, &mut dir.fields);
                        matched = true;
                    }
                }
                if !matched {
                    return Err(format!("{event} unavailable in enabled audit direction"));
                }
                Binding::Event(field)
            } else if expression == "%CAPTURE_STATUS%" {
                status_keys.push(serde_json::to_vec(&name).unwrap());
                continue;
            } else if let Some(key) = match expression.as_str() {
                "%DIRECTION%" => Some("direction"),
                "%CHAIN%" => Some("chain"),
                "%PATH%" => Some("path"),
                "%BYTES_SEEN%" => Some("bytesSeen"),
                "%DECODED_BYTES%" => Some("decodedBytes"),
                _ => None,
            } {
                Binding::Record(key)
            } else {
                context.insert(name.clone(), expression);
                Binding::Context
            };
            bindings.insert(name, binding);
        }
        let template = Template {
            fields: bindings,
            status_keys,
        };
        let limit = [directions.request, directions.response]
            .into_iter()
            .flatten()
            .map(|d| d.max_log_bytes)
            .min()
            .unwrap();
        // Guarantee that all explicitly selected status keys fit even on a parser error.
        if template.status_room(32) + 3 > limit {
            return Err("capture status field names exceed maxSize".into());
        }
        Ok(Self {
            template: Arc::new(template),
            attributes: AttributeSources::compile(context)?,
            directions,
        })
    }
}

impl Template {
    fn status_room(&self, len: usize) -> usize {
        self.status_keys
            .iter()
            .map(|name| name.len() + len + 4)
            .sum()
    }

    pub(super) fn render(
        &self,
        fields: &Map<String, Value>,
        context: &Map<String, Value>,
        direction: &str,
        status: &str,
        limit: usize,
    ) -> Vec<u8> {
        let mut line = vec![b'{'];
        let mut clipped = false;
        let budget = limit - 2 - self.status_room(status.len().max("truncated".len()));
        for (alias, binding) in &self.fields {
            let value = match binding {
                Binding::Event(field) => field
                    .key(direction == "request")
                    .and_then(|k| fields.get(k)),
                Binding::Record(key) => fields.get(*key),
                Binding::Context => context.get(alias),
            };
            let Some(value) = value else { continue };
            let start = line.len();
            if start > 1 {
                line.push(b',');
            }
            let mut writer = LineWriter {
                line: &mut line,
                limit: budget,
            };
            if serde_json::to_writer(&mut writer, alias).is_err()
                || std::io::Write::write_all(&mut writer, b":").is_err()
            {
                line.truncate(start);
                clipped = true;
                continue;
            }
            let value_start = writer.line.len();
            if serde_json::to_writer(&mut writer, value).is_err() {
                clipped = true;
                writer.line.truncate(value_start);
                if let Some(text) = value.as_str()
                    && !matches!(binding, Binding::Context)
                    && budget.saturating_sub(value_start) >= 2
                {
                    // Find the largest UTF-8 prefix whose JSON encoding fits, including escapes.
                    let mut lo = 0;
                    let mut hi = text.len().min(budget - value_start - 2);
                    while lo < hi {
                        let mid = lo + (hi - lo).div_ceil(2);
                        let prefix = &text[..text.floor_char_boundary(mid)];
                        if serde_json::to_writer(&mut writer, prefix).is_ok() {
                            lo = mid
                        } else {
                            hi = mid - 1
                        }
                        writer.line.truncate(value_start);
                    }
                    serde_json::to_writer(&mut writer, &text[..text.floor_char_boundary(lo)])
                        .unwrap();
                } else {
                    line.truncate(start);
                }
            }
        }
        let status = if clipped && status == "complete" {
            "truncated"
        } else {
            status
        };
        for key in &self.status_keys {
            if line.len() > 1 {
                line.push(b',');
            }
            line.extend_from_slice(key);
            line.push(b':');
            serde_json::to_writer(&mut line, status).unwrap();
        }
        line.push(b'}');
        line
    }

    // Test fixtures expose every normalized value to the existing protocol assertions.
    #[cfg(test)]
    pub(super) fn fixture(context: &Map<String, Value>) -> Self {
        let mut fields = BTreeMap::new();
        for key in [
            "chain",
            "requestID",
            "direction",
            "path",
            "bytesSeen",
            "decodedBytes",
            "llm.protocol",
            "attributesTruncated",
            "http.body",
            "llm.error",
            "agentio.tool.calls",
            "error.type",
            "agentio.response.error_code",
            "gen_ai.operation.name",
            "gen_ai.request.model",
            "gen_ai.response.model",
            "gen_ai.system_instructions",
            "gen_ai.input.messages",
            "gen_ai.output.messages",
            "gen_ai.tool.definitions",
        ]
        .into_iter()
        .chain(
            super::format::METADATA
                .iter()
                .chain(super::format::USAGE)
                .map(|(_, k)| *k),
        ) {
            fields.insert(key.to_owned(), Binding::Record(key));
        }
        fields.extend(context.keys().map(|key| (key.clone(), Binding::Context)));
        Self {
            fields,
            status_keys: vec![br#""captureStatus""#.to_vec()],
        }
    }
}

// serde_json stops at the first write that would exceed the remaining line budget.
struct LineWriter<'a> {
    line: &'a mut Vec<u8>,
    limit: usize,
}
impl std::io::Write for LineWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.line.len()) {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        self.line.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
