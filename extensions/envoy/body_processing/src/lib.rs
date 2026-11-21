// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

mod chain;
mod config;
mod filters;
mod parser;

use chain::{ActiveChain, Side};
use config::{Settings, match_path};
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyCounterId, EnvoyHttpFilter, EnvoyHttpFilterConfig, HttpFilter, HttpFilterConfig,
    abi::{
        envoy_dynamic_module_type_on_http_filter_request_body_status as ReqBody,
        envoy_dynamic_module_type_on_http_filter_request_headers_status as ReqHeaders,
        envoy_dynamic_module_type_on_http_filter_request_trailers_status as ReqTrailers,
        envoy_dynamic_module_type_on_http_filter_response_body_status as ResBody,
        envoy_dynamic_module_type_on_http_filter_response_headers_status as ResHeaders,
        envoy_dynamic_module_type_on_http_filter_response_trailers_status as ResTrailers,
    },
    declare_init_functions, envoy_log_error,
};
use filters::Decision;
use std::{cell::RefCell, sync::Arc};

#[derive(Clone)]
struct Config {
    settings: Arc<Settings>,
    publish_errors: EnvoyCounterId,
}

struct Filter {
    config: Config,
    chain: RefCell<ActiveChain>,
    audit: RefCell<FilterOutput>,
}

const AUDIT_STATE_KEY: &[u8] = b"agentio.body_processing.audit";

#[derive(Default)]
struct FilterOutput(Vec<((usize, &'static str), Vec<u8>)>);

impl FilterOutput {
    fn record_audit(&mut self, index: usize, direction: &'static str, json: Vec<u8>) {
        self.0.push(((index, direction), json));
    }

    fn into_json_lines(mut self) -> Option<Vec<u8>> {
        // Preserve the logger order: filter declaration order, request before response.
        self.0.sort_unstable_by_key(|(order, _)| *order);
        let mut records = self.0.into_iter();
        let (_, mut output) = records.next()?;
        output.reserve(
            1 + records
                .as_slice()
                .iter()
                .map(|(_, line)| line.len() + 1)
                .sum::<usize>(),
        );
        output.push(b'\n');
        for (_, line) in records {
            output.extend_from_slice(&line);
            output.push(b'\n');
        }
        Some(output)
    }
}

impl Filter {
    fn finish(&self, side: Side, end: bool) -> Decision {
        let stream = std::mem::take(self.chain.borrow_mut().stream(side));
        stream.finish(end, &mut self.audit.borrow_mut())
    }

    fn body(&self, envoy: &mut impl EnvoyHttpFilter, side: Side, end: bool) -> Decision {
        let mut decision = Decision::Continue;
        let mut chain = self.chain.borrow_mut();
        let stream = chain.stream(side);
        let request = matches!(side, Side::Request);
        if stream.is_empty() {
            return decision;
        }
        let size = if request {
            envoy.get_received_request_body_size()
        } else {
            envoy.get_received_response_body_size()
        };
        if size > 0 {
            if stream.counts_bytes_only() {
                stream.count_bytes(size);
            } else {
                let buffers = if request {
                    envoy.get_received_request_body()
                } else {
                    envoy.get_received_response_body()
                };
                if let Some(buffers) = buffers {
                    for buf in buffers {
                        decision = decision.merge(stream.push(buf.as_slice()));
                    }
                } else {
                    stream.missing_buffer(size);
                }
            }
        }
        drop(chain);
        if end {
            decision = decision.merge(self.finish(side, true));
        }
        decision
    }
}

impl<H: EnvoyHttpFilter> HttpFilter<H> for Filter {
    fn on_request_headers(&self, envoy: &mut H, end: bool) -> ReqHeaders {
        let settings = &self.config.settings;
        let raw_path = envoy.get_request_header_value(":path");
        let path = raw_path
            .as_ref()
            .and_then(|p| std::str::from_utf8(p.as_slice()).ok())
            .unwrap_or("");
        let matched_path = match_path(path);
        let Some(chain) = settings.select(envoy, matched_path) else {
            return ReqHeaders::Continue;
        };
        let format = chain.format(matched_path);
        let path = path.split_once('?').map_or(path, |(p, _)| p);
        self.chain
            .borrow_mut()
            .start_request(chain, format, path, envoy);
        if end {
            match self.finish(Side::Request, true) {
                Decision::Continue => (),
            }
        }
        ReqHeaders::Continue
    }

    fn on_request_body(&self, envoy: &mut H, end: bool) -> ReqBody {
        match self.body(envoy, Side::Request, end) {
            Decision::Continue => ReqBody::Continue,
        }
    }
    fn on_request_trailers(&self, _: &mut H) -> ReqTrailers {
        match self.finish(Side::Request, true) {
            Decision::Continue => ReqTrailers::Continue,
        }
    }
    fn on_response_headers(&self, envoy: &mut H, end: bool) -> ResHeaders {
        self.chain.borrow_mut().start_response(envoy);
        if end {
            match self.finish(Side::Response, true) {
                Decision::Continue => (),
            }
        }
        ResHeaders::Continue
    }
    fn on_response_body(&self, envoy: &mut H, end: bool) -> ResBody {
        match self.body(envoy, Side::Response, end) {
            Decision::Continue => ResBody::Continue,
        }
    }
    fn on_response_trailers(&self, _: &mut H) -> ResTrailers {
        match self.finish(Side::Response, true) {
            Decision::Continue => ResTrailers::Continue,
        }
    }
    fn on_stream_complete(&self, envoy: &mut H) {
        match self.finish(Side::Request, false) {
            Decision::Continue => (),
        }
        match self.finish(Side::Response, false) {
            Decision::Continue => (),
        }
        if let Some(lines) = self.audit.take().into_json_lines()
            && !envoy.set_filter_state_bytes(AUDIT_STATE_KEY, &lines)
        {
            let _ = envoy.increment_counter(self.config.publish_errors, 1);
        }
    }
}

struct EmptyFilter;

impl<H: EnvoyHttpFilter> HttpFilter<H> for EmptyFilter {}

impl<H: EnvoyHttpFilter> HttpFilterConfig<H> for Config {
    fn new_http_filter(&self, _: &mut H) -> Box<dyn HttpFilter<H>> {
        if self.settings.is_empty() {
            return Box::new(EmptyFilter);
        }
        Box::new(Filter {
            config: self.clone(),
            chain: RefCell::default(),
            audit: RefCell::default(),
        })
    }
}

declare_init_functions!(init, new_config);
fn init() -> bool {
    true
}

fn new_config<C: EnvoyHttpFilterConfig, H: EnvoyHttpFilter>(
    envoy: &mut C,
    name: &str,
    bytes: &[u8],
) -> Option<Box<dyn HttpFilterConfig<H>>> {
    if name != "contentguard" {
        return None;
    }
    let settings = Settings::parse(bytes)
        .map_err(|e| envoy_log_error!("invalid contentguard config: {}", e))
        .ok()?;
    let publish_errors = envoy
        .define_counter("contentguard_publish_errors")
        .map_err(|e| envoy_log_error!("cannot register contentguard error counter: {:?}", e))
        .ok()?;
    Some(Box::new(Config {
        settings: Arc::new(settings),
        publish_errors,
    }))
}

#[cfg(test)]
mod tests;
