// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod body;
pub(crate) mod json_capture;
pub(crate) mod llm;
mod multipart;
pub(crate) mod request;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BodyError {
    CaptureError,
    Incomplete,
    IncompleteStream,
    InvalidContent,
    InvalidEncoding,
    InvalidJson,
    InvalidMultipart,
    InvalidSse,
    InvalidText,
    MultipartHeadersTooLarge,
    TooLarge,
    UnknownProtocol,
    UnsupportedEncoding,
    UnsupportedMediaType,
}

/// Borrowed for one synchronous notification. Model offsets refer to decoded body bytes.
pub(crate) enum BodyEvent<'a> {
    LlmResponse(llm::stream::Event<'a>),
    LlmItem {
        item: &'a request::ItemEvent,
        clipped: bool,
    },
    // These wire events are part of the parser contract; audit reads the validated final model.
    #[allow(dead_code)]
    ModelStart(usize),
    #[allow(dead_code)]
    ModelData(&'a [u8]),
    #[allow(dead_code)]
    ModelEnd {
        range: std::ops::Range<usize>,
        value: Option<&'a str>,
    },
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Format {
    #[default]
    Http,
    UnknownProtocol,
    Metadata,
    Text,
    Json,
    OpenaiChatCompletions,
    OpenaiResponses,
    AnthropicMessages,
}

impl Format {
    pub(crate) fn protocol(self) -> Option<&'static str> {
        match self {
            Self::OpenaiChatCompletions => Some(llm::CHAT),
            Self::OpenaiResponses => Some(llm::RESPONSES),
            Self::AnthropicMessages => Some(llm::ANTHROPIC),
            _ => None,
        }
    }

    pub(crate) fn from_path(path: &str) -> Self {
        match path {
            "/v1/chat/completions" => Self::OpenaiChatCompletions,
            "/v1/responses" => Self::OpenaiResponses,
            "/v1/messages" => Self::AnthropicMessages,
            _ => Self::UnknownProtocol,
        }
    }
}

// Measure compact JSON without allocating another copy of the retained value.
pub(crate) fn encoded_len<T: serde::Serialize + ?Sized>(value: &T) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).expect("serializable protocol content");
    counter.0
}
