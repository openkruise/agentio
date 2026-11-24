// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{BodyError, llm::LlmView};
use serde_json::Value;

#[derive(Clone)]
pub(crate) enum Content {
    Empty,
    Http(Value),
    Llm(LlmView),
}
#[derive(Clone)]
pub(crate) struct ParsedBody {
    pub truncated: bool,
    pub content: Content,
}

pub(crate) type Decoded = Result<ParsedBody, BodyError>;
