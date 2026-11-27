// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::limit::bounded_value;
use crate::parser::body::Content;
use serde_json::{Value, json};

/// The value source of a compiled EVENT column. Names in the log come from the template.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Field {
    Question,
    Tools,
    InputMessages,
    OutputMessages,
    Answer,
    FinishReasons,
    Usage(&'static str),
    ToolRefs,
    Instructions,
    Error,
    ErrorType,
    ErrorCode,
    RetainedText,
    Model,
    ResponseId,
    PreviousResponseId,
    Stream,
    MaxTokens,
    ConversationId,
    Status,
    IncompleteReason,
    #[cfg(test)]
    HttpBody,
    #[cfg(test)]
    Partial,
    #[cfg(test)]
    ToolRefsTruncated,
    #[cfg(test)]
    Truncated,
    #[cfg(test)]
    Operation,
}

impl Field {
    /// Messages have already been formatted and bounded while reading the borrowed
    /// parser output. Move them into the row; other fields are limited here.
    pub(super) fn value(
        self,
        content: &mut Content,
        limit: usize,
        clipped: &mut bool,
    ) -> Option<Value> {
        let mut bounded = |source: &Value| {
            let (value, shortened) = bounded_value(source, limit);
            *clipped |= shortened;
            value
        };
        let view = match content {
            Content::Llm(view) => view,
            Content::Http(_body) => {
                #[cfg(test)]
                if self == Self::HttpBody {
                    return bounded(_body);
                }
                return None;
            }
            Content::Empty => return None,
        };
        let doc = &mut view.document;
        let value = match self {
            Self::Model => doc.get("model")?,
            Self::ResponseId => doc.get("responseId")?,
            Self::PreviousResponseId => doc.get("previousResponseId")?,
            Self::Stream => doc.get("requestStream")?,
            Self::MaxTokens => doc.get("maxTokens")?,
            Self::ConversationId => doc.get("conversationId")?,
            Self::Status => doc.get("status")?,
            Self::IncompleteReason => doc.get("incompleteReason")?,
            Self::Question => doc.get("question")?,
            Self::Answer => doc.get("answer")?,
            Self::FinishReasons => doc.get("finishReasons")?,
            Self::RetainedText => doc.get("retainedText")?,
            Self::Usage(key) => doc.get("usage")?.get(key)?,
            Self::Error => doc.get("error")?,
            Self::ErrorCode => doc.get("error")?.get("code").filter(|v| v.is_string())?,
            Self::ErrorType => {
                let error = doc.get("error")?;
                error
                    .get("type")
                    .filter(|v| v.as_str().is_some_and(|s| s != "error"))
                    .or_else(|| error.get("code").filter(|v| v.is_string()))?
            }
            Self::InputMessages => return doc.as_object_mut()?.remove("inputMessages"),
            Self::OutputMessages => return doc.as_object_mut()?.remove("outputMessages"),
            Self::Instructions => doc.get("systemInstructions")?,
            Self::Tools => {
                let tools = doc.get_mut("tools")?;
                for tool in tools
                    .as_array_mut()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_object_mut)
                {
                    tool.entry("type").or_insert_with(|| "function".into());
                }
                tools
            }
            Self::ToolRefs => {
                return (!view.tool_refs.entries.is_empty())
                    .then(|| json!(&view.tool_refs.entries))
                    .and_then(|v| bounded(&v));
            }
            #[cfg(test)]
            Self::HttpBody => return None,
            #[cfg(test)]
            Self::Partial => return view.partial.then_some(Value::Bool(true)),
            #[cfg(test)]
            Self::ToolRefsTruncated => {
                return view.tool_refs.truncated.then_some(Value::Bool(true));
            }
            #[cfg(test)]
            Self::Truncated => doc.get("truncated")?,
            #[cfg(test)]
            Self::Operation => {
                return doc
                    .is_object()
                    .then(|| "chat".into())
                    .and_then(|v| bounded(&v));
            }
        };
        bounded(value)
    }
}
