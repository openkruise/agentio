// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod audit;

use crate::{
    FilterOutput,
    parser::{BodyEvent, Format, body::Decoded},
};
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyHttpFilter;
use serde_json::Value;

#[derive(Clone, Copy, Default)]
#[cfg_attr(not(test), must_use)]
pub(crate) enum Decision {
    #[default]
    Continue,
}

impl Decision {
    pub fn merge(self, next: Self) -> Self {
        match (self, next) {
            (Self::Continue, Self::Continue) => Self::Continue,
        }
    }
}

pub(crate) enum BodyResult {
    Incomplete,
    Llm(Result<(bool, Value), &'static str>),
    Sse {
        status: Result<(), &'static str>,
        largest_event: usize,
    },
    Http(Decoded),
}

pub(crate) struct BodyEnd {
    pub bytes_seen: usize,
    pub decoded_bytes: Option<usize>,
    pub result: BodyResult,
}

pub(crate) trait BodyFilter {
    fn on_event(&mut self, event: &BodyEvent<'_>, bytes_seen: usize) -> Decision;
    fn on_end(self: Box<Self>, end: &BodyEnd, output: &mut FilterOutput) -> Decision;
}

pub(crate) struct RequestHeaders<'a> {
    pub chain: &'a str,
    pub path: &'a str,
    pub id: &'a str,
    pub format: Format,
}
pub(crate) struct StreamFilters {
    pub request: Option<Box<dyn BodyFilter>>,
    pub response: Option<Box<dyn BodyFilter>>,
}

pub(crate) enum ConfiguredFilter {
    Audit(audit::Audit),
}
impl ConfiguredFilter {
    pub(crate) fn start(
        &self,
        headers: &RequestHeaders<'_>,
        index: usize,
        envoy: &impl EnvoyHttpFilter,
    ) -> StreamFilters {
        match self {
            Self::Audit(config) => config.start(headers, index, envoy),
        }
    }
}
