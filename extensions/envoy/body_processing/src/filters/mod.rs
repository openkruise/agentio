// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod audit;

use crate::{
    FilterOutput,
    parser::{BodyError, BodyEvent, Format, body::ParsedBody, llm},
};
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyHttpFilter;

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
    Counts,
    Failed(BodyError),
    Llm(llm::Outcome),
    Http(ParsedBody),
}

pub(crate) struct BodyEnd {
    pub bytes_seen: usize,
    pub decoded_bytes: Option<usize>,
    pub result: BodyResult,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BodyInterest {
    pub events: bool,
    pub decoded_bytes: bool,
}

pub(crate) trait BodyFilter {
    fn interest(&self) -> BodyInterest {
        BodyInterest {
            events: true,
            decoded_bytes: false,
        }
    }
    fn on_event(&mut self, event: &BodyEvent<'_>, bytes_seen: usize) -> Decision;
    fn on_end(self: Box<Self>, end: &BodyEnd, output: &mut FilterOutput) -> Decision;
}

pub(crate) struct RequestHeaders<'a> {
    pub chain: &'a str,
    pub path: &'a str,
    pub format: Format,
    pub cel: std::cell::OnceCell<audit::cel::Headers>,
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
        output: &mut FilterOutput,
    ) -> StreamFilters {
        match self {
            Self::Audit(config) => config.start(headers, index, envoy, output),
        }
    }
}
