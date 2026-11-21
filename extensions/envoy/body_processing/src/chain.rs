// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    config::FilterChain,
    filters::audit::{RequestHeaders, ResponseAudit},
    parser::Format,
};
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyHttpFilter;

mod gzip;
mod input;
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
    pending: Vec<ResponseAudit>,
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
    ) {
        let id = header(envoy, true, "x-request-id");
        let media = header(envoy, true, "content-type");
        // Multiple header lines describe stacked codings just like a comma-separated list.
        let encodings = envoy.get_request_header_values("content-encoding");
        let encoding = encodings
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_slice()))
            .collect::<Vec<_>>()
            .join(",");
        let headers = RequestHeaders {
            chain: &chain.name,
            path,
            id: &id,
            format,
        };
        let mut requests = Vec::new();
        for (index, audit) in chain.audits.iter().enumerate() {
            let (request, response) = audit.start(&headers, index, envoy);
            requests.extend(request);
            self.pending.extend(response);
        }
        self.request = DirectionStream::new(false, &media, &encoding, requests);
    }

    pub(crate) fn start_response(&mut self, envoy: &impl EnvoyHttpFilter) {
        let contexts = std::mem::take(&mut self.pending);
        if !contexts.is_empty() {
            let media = header(envoy, false, "content-type");
            let encoding = header(envoy, false, "content-encoding");
            self.response = DirectionStream::new(
                true,
                &media,
                &encoding,
                contexts.into_iter().map(ResponseAudit::start),
            );
        }
    }
}
