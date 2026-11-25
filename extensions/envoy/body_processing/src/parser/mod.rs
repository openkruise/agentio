// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod body;
pub(crate) mod http;
mod json;
pub(crate) mod llm;
mod multipart;

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

/// Events are borrowed for one synchronous notification to filters.
pub(crate) enum BodyEvent<'a> {
    Llm(llm::Event<'a>),
}

#[derive(Clone, Copy)]
pub(crate) enum ParserDirection {
    Request(crate::config::RequestParserConfig),
    Response(crate::config::ResponseParserConfig),
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
    #[serde(untagged)]
    Llm(llm::Protocol),
}

impl Format {
    pub(crate) fn protocol(self) -> Option<&'static str> {
        match self {
            Self::Llm(protocol) => Some(protocol.as_str()),
            _ => None,
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
