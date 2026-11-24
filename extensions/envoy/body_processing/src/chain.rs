// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    FilterOutput,
    config::FilterChain,
    filters::{BodyFilter, RequestHeaders},
    parser::Format,
};
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyHttpFilter;

mod gzip;
mod input;
pub(crate) use crate::parser::ParserDirection;
pub(crate) use input::DirectionStream;

#[derive(Clone, Copy)]
pub(crate) enum Side {
    Request,
    Response,
}

#[derive(Default)]
pub(crate) struct ActiveChain {
    request: DirectionStream,
    response: DirectionStream,
    pending: Vec<Box<dyn BodyFilter>>,
    format: Format,
}

fn header(envoy: &impl EnvoyHttpFilter, request: bool, key: &str) -> String {
    let b = if request {
        envoy.get_request_header_value(key)
    } else {
        envoy.get_response_header_value(key)
    };
    b.map(|b| String::from_utf8_lossy(b.as_slice()).into_owned())
        .unwrap_or_default()
}

impl ActiveChain {
    pub(crate) fn stream(&mut self, side: Side) -> &mut DirectionStream {
        match side {
            Side::Request => &mut self.request,
            Side::Response => &mut self.response,
        }
    }

    pub(crate) fn start_request(
        &mut self,
        chain: &FilterChain,
        format: Format,
        path: &str,
        envoy: &impl EnvoyHttpFilter,
        output: &mut FilterOutput,
    ) {
        self.format = format;
        let headers = RequestHeaders {
            chain: &chain.name,
            path,
            format,
            cel: Default::default(),
        };
        let mut requests = Vec::new();
        for (index, filter) in chain.filters.iter().enumerate() {
            let active = filter.start(&headers, index, envoy, output);
            requests.extend(active.request);
            self.pending.extend(active.response);
        }
        if requests.is_empty() {
            return;
        }
        let media = header(envoy, true, "content-type");
        // Multiple header lines describe stacked codings just like a comma-separated list.
        let encodings = envoy.get_request_header_values("content-encoding");
        let encoding = encodings
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_slice()))
            .collect::<Vec<_>>()
            .join(",");
        self.request = DirectionStream::new(
            ParserDirection::Request(chain.request_parser()),
            format,
            &media,
            &encoding,
            requests,
        );
    }

    pub(crate) fn start_response(&mut self, envoy: &impl EnvoyHttpFilter) {
        let contexts = std::mem::take(&mut self.pending);
        if !contexts.is_empty() {
            let media = header(envoy, false, "content-type");
            let encoding = header(envoy, false, "content-encoding");
            self.response = DirectionStream::new(
                ParserDirection::Response,
                self.format,
                &media,
                &encoding,
                contexts,
            );
        }
    }
}
