// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod body;
pub(crate) mod json_capture;
pub(crate) mod llm;
mod multipart;
pub(crate) mod request;

use serde::Deserialize;

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

// Count the JSON bytes charged by EPE's encoding/json, including HTML escaping,
// without allocating another serialized copy of a retained message.
pub(crate) fn encoded_len<T: serde::Serialize + ?Sized>(value: &T) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            self.0 += 5 * bytes
                .iter()
                .filter(|b| matches!(b, b'<' | b'>' | b'&'))
                .count();
            self.0 += 3 * bytes
                .windows(3)
                .filter(|w| matches!(*w, [0xe2, 0x80, 0xa8 | 0xa9]))
                .count();
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
