// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod capture;
pub(crate) mod format;
pub(crate) mod projection;

use crate::parser::{Format, llm::Fields};
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, abi::envoy_dynamic_module_type_metadata_source as MetadataSource,
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub(crate) struct RequestHeaders<'a> {
    pub chain: &'a std::sync::Arc<str>,
    pub path: &'a str,
    pub id: &'a str,
    pub format: Format,
}

pub struct AttributeSources(BTreeMap<String, Source>);

enum Source {
    RequestHeader(String),
    FilterState(String),
    DynamicMetadata { namespace: String, key: String },
}

impl Source {
    fn parse(expression: &str) -> Result<Self, &'static str> {
        let (operator, args) = expression
            .strip_prefix('%')
            .and_then(|s| s.strip_suffix(")%"))
            .and_then(|s| s.split_once('('))
            .ok_or("expected a single %OPERATOR(arguments)% expression")?;
        let valid_key = |s: &str| {
            !s.is_empty() && !s.contains([':', '(', ')', '%']) && !s.chars().any(char::is_control)
        };
        match operator {
            "REQ" => {
                let name = args.strip_prefix(':').unwrap_or(args);
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                {
                    return Err("REQ requires one HTTP header name");
                }
                Ok(Self::RequestHeader(args.to_ascii_lowercase()))
            }
            "FILTER_STATE" => {
                let key = args
                    .strip_suffix(":PLAIN")
                    .filter(|k| valid_key(k))
                    .ok_or("expected %FILTER_STATE(key:PLAIN)%")?;
                Ok(Self::FilterState(key.into()))
            }
            "DYNAMIC_METADATA" => {
                let (namespace, key) = args
                    .split_once(':')
                    .filter(|(ns, k)| valid_key(ns) && valid_key(k))
                    .ok_or("expected %DYNAMIC_METADATA(namespace:key)% with one top-level key")?;
                Ok(Self::DynamicMetadata {
                    namespace: namespace.into(),
                    key: key.into(),
                })
            }
            _ => Err("supported operators are REQ, FILTER_STATE and DYNAMIC_METADATA"),
        }
    }
}

impl AttributeSources {
    pub fn compile(expressions: BTreeMap<String, String>) -> Result<Self, String> {
        let mut sources = BTreeMap::new();
        for (name, expression) in expressions {
            if name.is_empty() {
                return Err("attribute name must be non-empty".into());
            }
            if format::reserved_field(&name) {
                return Err(format!(
                    "attribute {name:?} conflicts with a built-in audit field"
                ));
            }
            let source =
                Source::parse(&expression).map_err(|e| format!("attribute {name:?}: {e}"))?;
            sources.insert(name, source);
        }
        Ok(Self(sources))
    }

    pub fn snapshot(&self, envoy: &impl EnvoyHttpFilter, limit: usize) -> Attributes {
        let mut attrs = Attributes::default();
        let mut remaining = limit;
        for (name, source) in &self.0 {
            let value = match source {
                Source::RequestHeader(k) => envoy.get_request_header_value(k),
                Source::FilterState(k) => envoy.get_filter_state_typed(k.as_bytes()),
                Source::DynamicMetadata { namespace, key } => {
                    envoy.get_metadata_string(MetadataSource::Dynamic, namespace, key)
                }
            };
            if let Some(buf) = value {
                if name.len() + buf.as_slice().len() > remaining {
                    attrs.truncated = true;
                    continue;
                }
                let text = String::from_utf8_lossy(buf.as_slice());
                remaining = remaining.saturating_sub(name.len() + text.len());
                attrs
                    .values
                    .insert(name.clone(), Value::String(text.into_owned()));
            }
        }
        attrs
    }
}

#[derive(Default)]
pub struct Attributes {
    pub values: Map<String, Value>,
    pub truncated: bool,
}

#[derive(Clone, Copy)]
#[cfg_attr(
    test,
    derive(serde::Deserialize),
    serde(deny_unknown_fields, rename_all = "camelCase")
)]
pub(crate) struct Direction {
    #[cfg_attr(test, serde(rename = "maxSize"))]
    pub(crate) max_log_bytes: usize,
    #[cfg_attr(test, serde(default))]
    pub(crate) format: Format,
    pub(crate) max_capture_bytes: Option<usize>,
    pub(crate) max_content_bytes: Option<usize>,
    #[cfg_attr(test, serde(default = "Fields::fixture_default"))]
    pub(crate) fields: Fields,
}

#[derive(Copy, Clone)]
pub struct Directions {
    pub request: Option<Direction>,
    pub response: Option<Direction>,
}

pub struct Audit {
    pub attributes: AttributeSources,
    pub directions: Directions,
}

pub(crate) struct ResponseAudit {
    chain: std::sync::Arc<str>,
    filter_index: usize,
    path: String,
    id: String,
    direction: Direction,
    attributes: Attributes,
}

impl Audit {
    pub(crate) fn start(
        &self,
        request: &RequestHeaders<'_>,
        index: usize,
        envoy: &impl EnvoyHttpFilter,
    ) -> (Option<capture::Capture>, Option<ResponseAudit>) {
        let limit = [self.directions.request, self.directions.response]
            .into_iter()
            .flatten()
            .map(|d| d.max_log_bytes)
            .max()
            .unwrap();
        let attributes = self.attributes.snapshot(envoy, limit);
        let capture = self.directions.request.map(|direction| {
            capture::Capture::start(
                "request",
                request.path,
                request.id,
                Direction {
                    format: request.format,
                    ..direction
                },
                capture::AuditContext {
                    chain: request.chain,
                    filter_index: index,
                    attributes: &attributes,
                },
            )
        });
        let pending = self.directions.response.map(|direction| ResponseAudit {
            chain: request.chain.clone(),
            filter_index: index,
            path: request.path.to_owned(),
            id: request.id.to_owned(),
            direction: Direction {
                format: request.format,
                ..direction
            },
            attributes,
        });
        (capture, pending)
    }
}

impl ResponseAudit {
    pub(crate) fn start(self) -> capture::Capture {
        capture::Capture::start(
            "response",
            &self.path,
            &self.id,
            self.direction,
            capture::AuditContext {
                chain: &self.chain,
                filter_index: self.filter_index,
                attributes: &self.attributes,
            },
        )
    }
}

pub(crate) fn included_fields(selectors: &[String], request: bool) -> Result<Fields, String> {
    let mut fields = Fields::default();
    for (index, selector) in selectors.iter().enumerate() {
        match selector.as_str() {
            "llm.messages" if request => fields.input_messages = true,
            "llm.messages" => fields.output_messages = true,
            "llm.toolCallRefs" => fields.tool_call_refs = true,
            "llm.toolDefinitions" if request => fields.tools = true,
            "llm.question" if request => fields.question = true,
            "llm.answer" if !request => fields.answer = true,
            _ => {
                let (direction, allowed) = if request {
                    (
                        "request",
                        "llm.messages, llm.question, llm.toolDefinitions, llm.toolCallRefs",
                    )
                } else {
                    ("response", "llm.messages, llm.answer, llm.toolCallRefs")
                };
                return Err(format!(
                    "{direction}.include[{index}]: unknown or unsupported {selector:?}, expected one of {allowed}"
                ));
            }
        }
    }
    Ok(fields)
}
