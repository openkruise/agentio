// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{ANTHROPIC, CHAT, RESPONSES};
use crate::parser::Format;
use serde::Deserialize;

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Protocol {
    OpenaiChatCompletions,
    OpenaiResponses,
    AnthropicMessages,
}

impl Protocol {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::OpenaiChatCompletions => CHAT,
            Self::OpenaiResponses => RESPONSES,
            Self::AnthropicMessages => ANTHROPIC,
        }
    }
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ProtocolSelection {
    #[default]
    Auto,
    #[serde(untagged)]
    Fixed(Protocol),
}

impl ProtocolSelection {
    pub(crate) fn resolve(self, path: &str) -> Format {
        let protocol = match self {
            Self::Fixed(protocol) => protocol,
            Self::Auto => match path {
                "/v1/chat/completions" => Protocol::OpenaiChatCompletions,
                "/v1/responses" => Protocol::OpenaiResponses,
                "/v1/messages" => Protocol::AnthropicMessages,
                _ => return Format::UnknownProtocol,
            },
        };
        Format::Llm(protocol)
    }
}
