// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod capture;
pub(crate) mod format;
pub(crate) mod projection;
mod sse;
mod template;

use crate::parser::{Format, llm::Fields};
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, abi::envoy_dynamic_module_type_metadata_source as MetadataSource,
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

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
    template: std::sync::Arc<template::Template>,
    pub attributes: AttributeSources,
    pub directions: Directions,
}

impl Audit {
    pub(crate) fn start(
        &self,
        request: &super::RequestHeaders<'_>,
        index: usize,
        envoy: &impl EnvoyHttpFilter,
    ) -> super::StreamFilters {
        let limit = [self.directions.request, self.directions.response]
            .into_iter()
            .flatten()
            .map(|d| d.max_log_bytes)
            .max()
            .unwrap();
        let attributes = self.attributes.snapshot(envoy, limit);
        let start = |side, direction: Direction| -> Box<dyn super::BodyFilter> {
            Box::new(capture::Capture::with_template(
                side,
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
                self.template.clone(),
            ))
        };
        super::StreamFilters {
            request: self.directions.request.map(|d| start("request", d)),
            response: self.directions.response.map(|d| start("response", d)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FilterOutput,
        chain::{DirectionStream, ParserDirection},
        filters::{BodyFilter, Decision},
    };
    use serde_json::json;

    fn chat_records(
        body: &str,
        side: ParserDirection,
        specs: &[(usize, &[(&str, &str)])],
    ) -> Vec<Vec<u8>> {
        let (direction_name, media) = match side {
            ParserDirection::Request(_) => ("request", "application/json"),
            ParserDirection::Response => ("response", "text/event-stream"),
        };
        let filters = specs
            .iter()
            .enumerate()
            .map(|(index, (limit, fields))| {
                let dir: Direction =
                    serde_json::from_value(json!({"maxSize":limit,"fields":{}})).unwrap();
                let expressions = fields
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                let audit = Audit::compile(
                    expressions,
                    Directions {
                        request: matches!(side, ParserDirection::Request(_)).then_some(dir),
                        response: matches!(side, ParserDirection::Response).then_some(dir),
                    },
                )
                .unwrap();
                let direction = Direction {
                    format: Format::OpenaiChatCompletions,
                    ..audit
                        .directions
                        .request
                        .or(audit.directions.response)
                        .unwrap()
                };
                Box::new(capture::Capture::with_template(
                    direction_name,
                    "/chat",
                    "id",
                    direction,
                    capture::AuditContext {
                        chain: "llm",
                        filter_index: index,
                        attributes: &Default::default(),
                    },
                    audit.template,
                )) as Box<dyn BodyFilter>
            })
            .collect();
        let mut stream =
            DirectionStream::new(side, Format::OpenaiChatCompletions, media, "", filters);
        for chunk in body.as_bytes().chunks(13) {
            assert!(matches!(stream.push(chunk), Decision::Continue));
        }
        let mut output = FilterOutput::default();
        assert!(matches!(
            stream.finish(true, &mut output),
            Decision::Continue
        ));
        output
            .0
            .into_iter()
            .zip(specs)
            .map(|((_, line), (limit, _))| {
                assert!(line.len() < *limit);
                line
            })
            .collect::<Vec<_>>()
    }

    #[test]
    fn independent_templates_share_a_stream_and_report_final_line_clipping() {
        let question = "水\"".repeat(150);
        let body=json!({"model":"m","messages":[{"role":"user","content":question}],
            "tools":[{"type":"function","function":{"name":"weather","parameters":{"description":"d".repeat(3000)}}}]}).to_string();
        let run = |specs: &[(usize, &[(&str, &str)])]| {
            chat_records(&body, ParserDirection::Request(Default::default()), specs)
        };
        let q = (
            1024,
            &[
                ("first", "%EVENT(llm.question)%"),
                ("second", "%EVENT(llm.question)%"),
                ("status", "%CAPTURE_STATUS%"),
            ][..],
        );
        let t = (
            8192,
            &[
                ("tools", "%EVENT(llm.toolDefinitions)%"),
                ("status", "%CAPTURE_STATUS%"),
            ][..],
        );
        let a = run(&[q]).pop().unwrap();
        let b = run(&[t]).pop().unwrap();
        assert_eq!(run(&[q, t]), [a.clone(), b.clone()]);
        assert_eq!(run(&[t, q]), [b.clone(), a.clone()]);
        let tight = run(&[q, (1024, t.1)]);
        assert_eq!(tight[0], a);
        let read = |line: &[u8]| serde_json::from_slice::<Value>(line).unwrap();
        assert_eq!(read(&tight[1])["status"], "truncated");
        let a = read(&a);
        assert_eq!(a["first"], question);
        assert!(question.starts_with(a["second"].as_str().unwrap()));
        assert_ne!(a["first"], a["second"]);
        assert_eq!(a["status"], "truncated");
        let b = read(&b);
        assert_eq!(b["status"], "complete");
        assert_eq!(
            b["tools"][0]["parameters"]["description"]
                .as_str()
                .unwrap()
                .len(),
            3000
        );
    }

    #[test]
    fn sse_answer_and_usage_match_standalone_audits_in_either_order() {
        let content = "水".repeat(400);
        let chunk = json!({"model":"m","choices":[{"index":0,"delta":{"content":content},"finish_reason":"stop"}]});
        let counts =
            json!({"model":"m","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":7}});
        let body = format!("data: {chunk}\n\ndata: {counts}\n\ndata: [DONE]\n\n");
        let answer = (
            1024,
            &[
                ("answer", "%EVENT(llm.answer)%"),
                ("status", "%CAPTURE_STATUS%"),
            ][..],
        );
        let usage = (
            2048,
            &[
                ("input", "%EVENT(llm.usage.inputTokens)%"),
                ("output", "%EVENT(llm.usage.outputTokens)%"),
                ("status", "%CAPTURE_STATUS%"),
            ][..],
        );
        let run = |specs: &[(usize, &[(&str, &str)])]| {
            chat_records(&body, ParserDirection::Response, specs)
        };
        let a = run(&[answer]).pop().unwrap();
        let u = run(&[usage]).pop().unwrap();
        assert_eq!(run(&[answer, usage]), [a.clone(), u.clone()]);
        assert_eq!(run(&[usage, answer]), [u.clone(), a.clone()]);
        let read = |line: &[u8]| serde_json::from_slice::<Value>(line).unwrap();
        assert_eq!(read(&a), json!({"status":"truncated"}));
        assert_eq!(read(&u), json!({"input":5,"output":7,"status":"complete"}));
        assert_eq!(
            read(&run(&[(2048, answer.1), usage])[0]),
            json!({"answer":content,"status":"complete"})
        );
    }
}
