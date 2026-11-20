// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

mod audit;
mod capture;
mod json_capture;
mod multipart;
mod protocol;
mod response;
mod rules;
mod sse;

use audit::{Attributes, Audit};
use capture::Capture;
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
use serde::Deserialize;
use std::{cell::RefCell, sync::Arc};

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Settings {
    #[serde(default)]
    rules: Vec<rules::Rule>,
    #[serde(default)]
    audit: Audit,
    request: Option<Direction>,
    response: Option<Direction>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Direction {
    max_log_bytes: usize,
    #[serde(default)]
    format: Format,
    max_capture_bytes: Option<usize>,
    max_content_bytes: Option<usize>,
    fields: Option<Fields>,
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Format {
    #[default]
    Auto,
    Text,
    Json,
    OpenaiChatCompletions,
    OpenaiResponses,
    AnthropicMessages,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Fields {
    input_messages: bool,
    output_messages: bool,
    tools: bool,
}

impl Fields {
    const ALL: Self = Self {
        input_messages: true,
        output_messages: true,
        tools: true,
    };
}

#[derive(Clone)]
struct Config {
    settings: Arc<Settings>,
    publish_errors: EnvoyCounterId,
}

struct Filter {
    config: Config,
    request: RefCell<Option<Capture>>,
    response: RefCell<Option<Capture>>,
    response_context: RefCell<Option<ResponseContext>>,
}

struct ResponseContext {
    path: String,
    id: String,
    direction: Direction,
    attributes: Attributes,
}

impl Filter {
    fn finish(&self, slot: &RefCell<Option<Capture>>, envoy: &mut impl EnvoyHttpFilter, end: bool) {
        if let Some(capture) = slot.take() {
            let (key, record) = capture.encode(end);
            if !envoy.set_filter_state_bytes(key, &record) {
                let _ = envoy.increment_counter(self.config.publish_errors, 1);
            }
        }
    }

    fn body(&self, envoy: &mut impl EnvoyHttpFilter, request: bool, end: bool) {
        let slot = if request {
            &self.request
        } else {
            &self.response
        };
        if let Some(c) = slot.borrow_mut().as_mut() {
            let size = if request {
                envoy.get_received_request_body_size()
            } else {
                envoy.get_received_response_body_size()
            };
            if size > 0 {
                let buffers = if request {
                    envoy.get_received_request_body()
                } else {
                    envoy.get_received_response_body()
                };
                if let Some(buffers) = buffers {
                    for buf in buffers {
                        c.push(buf.as_slice());
                    }
                } else {
                    c.missing_buffer(size);
                }
            }
        }
        if end {
            self.finish(slot, envoy, true);
        }
    }
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

impl<H: EnvoyHttpFilter> HttpFilter<H> for Filter {
    fn on_request_headers(&self, envoy: &mut H, end: bool) -> ReqHeaders {
        let settings = &self.config.settings;
        let Some(format) = settings.select(envoy) else {
            return ReqHeaders::Continue;
        };
        let limit = [settings.request, settings.response]
            .into_iter()
            .flatten()
            .map(|d| d.max_log_bytes)
            .max()
            .unwrap();
        let attributes = settings.audit.snapshot(envoy, limit);
        let path = header(envoy, true, ":path");
        let id = header(envoy, true, "x-request-id");
        if let Some(mut d) = settings.request {
            if let Some(f) = format {
                d.format = f;
            }
            self.request.replace(Some(Capture::new(
                "request",
                &path,
                &id,
                &header(envoy, true, "content-type"),
                &header(envoy, true, "content-encoding"),
                d,
                (settings.audit.schema, &attributes),
            )));
            if end {
                self.finish(&self.request, envoy, true);
            }
        }
        if let Some(mut direction) = settings.response {
            if let Some(f) = format {
                direction.format = f;
            }
            self.response_context.replace(Some(ResponseContext {
                path,
                id,
                direction,
                attributes,
            }));
        }
        ReqHeaders::Continue
    }

    fn on_request_body(&self, envoy: &mut H, end: bool) -> ReqBody {
        self.body(envoy, true, end);
        ReqBody::Continue
    }
    fn on_request_trailers(&self, envoy: &mut H) -> ReqTrailers {
        self.finish(&self.request, envoy, true);
        ReqTrailers::Continue
    }
    fn on_response_headers(&self, envoy: &mut H, end: bool) -> ResHeaders {
        if let Some(ctx) = self.response_context.take() {
            self.response.replace(Some(Capture::new(
                "response",
                &ctx.path,
                &ctx.id,
                &header(envoy, false, "content-type"),
                &header(envoy, false, "content-encoding"),
                ctx.direction,
                (self.config.settings.audit.schema, &ctx.attributes),
            )));
            if end {
                self.finish(&self.response, envoy, true);
            }
        }
        ResHeaders::Continue
    }
    fn on_response_body(&self, envoy: &mut H, end: bool) -> ResBody {
        self.body(envoy, false, end);
        ResBody::Continue
    }
    fn on_response_trailers(&self, envoy: &mut H) -> ResTrailers {
        self.finish(&self.response, envoy, true);
        ResTrailers::Continue
    }
    fn on_stream_complete(&self, envoy: &mut H) {
        self.finish(&self.request, envoy, false);
        self.finish(&self.response, envoy, false);
    }
}

impl<H: EnvoyHttpFilter> HttpFilterConfig<H> for Config {
    fn new_http_filter(&self, _: &mut H) -> Box<dyn HttpFilter<H>> {
        Box::new(Filter {
            config: self.clone(),
            request: Default::default(),
            response: Default::default(),
            response_context: Default::default(),
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
    let settings: Settings = serde_json::from_slice(bytes)
        .map_err(|e| envoy_log_error!("invalid contentguard config: {}", e))
        .ok()?;
    if let Err(e) = settings.validate() {
        envoy_log_error!("invalid contentguard config: {}", e);
        return None;
    }
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
