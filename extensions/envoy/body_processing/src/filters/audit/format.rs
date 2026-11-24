// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::parser::body::Content;
use serde_json::{Map, Value, json};
use std::borrow::Cow;

fn project_image(block: &mut Map<String, Value>) {
    let (kind, from, to) = match block.remove("source").as_ref().and_then(Value::as_str) {
        Some("file") => ("file", "fileId", "file_id"),
        Some("url") => ("uri", "url", "uri"),
        Some("base64") => ("blob", "data", "content"),
        _ => unreachable!("unknown normalized image source"),
    };
    block.insert("type".into(), kind.into());
    block.insert("modality".into(), "image".into());
    if let Some(value) = block.remove(from) {
        block.insert(to.into(), value);
    }
    if let Some(mime) = block.remove("mediaType") {
        block.insert("mime_type".into(), mime);
    }
}

pub(super) fn project_parts(parts: &mut Value) {
    for part in parts.as_array_mut().into_iter().flatten() {
        let Some(block) = part.as_object_mut() else {
            continue;
        };
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(text) = block.remove("text") {
                    block.insert("content".into(), text);
                }
            }
            Some("tool_result") => {
                block.insert("type".into(), "tool_call_response".into());
                if let Some(id) = block.remove("toolCallId") {
                    block.insert("id".into(), id);
                }
                if let Some(mut response) = block.remove("content") {
                    project_parts(&mut response);
                    block.insert("response".into(), response);
                }
            }
            Some("tool_call") if block.get("server") == Some(&Value::Bool(true)) => {
                block.remove("server");
                block.insert("type".into(), "server_tool_call".into());
                let mut details = block.remove("arguments").unwrap_or_default();
                if !details.is_object() || details.get("type").is_some() {
                    details = json!({"arguments":details});
                }
                details["type"] = block["name"].clone();
                block.insert("server_tool_call".into(), details);
            }
            Some("image") => project_image(block),
            Some("attachment") => {
                block.insert("type".into(), "provider_content".into());
                block.remove("kind");
                block.remove("inlineData");
            }
            _ => (),
        }
    }
}

pub(super) fn message(value: &mut Value) {
    if let Some(msg) = value.as_object_mut() {
        if let Some(mut parts) = msg.remove("content") {
            project_parts(&mut parts);
            msg.insert("parts".into(), parts);
        }
        if let Some(reason) = msg.remove("finishReason") {
            msg.insert("finish_reason".into(), reason);
        }
    }
}

pub(super) fn messages(value: &mut Value) {
    for item in value.as_array_mut().into_iter().flatten() {
        message(item);
    }
}

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
    /// A budget group reads each field once. Structured values can be formatted in place
    /// on the group's owned view before their size is measured.
    pub(super) fn value(self, content: &mut Content) -> Option<Cow<'_, Value>> {
        let view = match content {
            Content::Llm(view) => view,
            Content::Http(_body) => {
                #[cfg(test)]
                if self == Self::HttpBody {
                    return Some(Cow::Borrowed(_body));
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
            // Request capture already formatted these before applying its retention limit.
            Self::InputMessages => doc.get("inputMessages")?,
            Self::Instructions => doc.get("systemInstructions")?,
            Self::OutputMessages => {
                let output = doc.get_mut("outputMessages")?;
                messages(output);
                output
            }
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
                    .then(|| Cow::Owned(json!(&view.tool_refs.entries)));
            }
            #[cfg(test)]
            Self::HttpBody => return None,
            #[cfg(test)]
            Self::Partial => return view.partial.then_some(Cow::Borrowed(&Value::Bool(true))),
            #[cfg(test)]
            Self::ToolRefsTruncated => {
                return view
                    .tool_refs
                    .truncated
                    .then_some(Cow::Borrowed(&Value::Bool(true)));
            }
            #[cfg(test)]
            Self::Truncated => doc.get("truncated")?,
            #[cfg(test)]
            Self::Operation => return doc.is_object().then(|| Cow::Owned("chat".into())),
        };
        Some(Cow::Borrowed(value))
    }
}
