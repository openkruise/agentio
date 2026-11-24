// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod capture;
pub(crate) mod format;
mod limit;
pub(crate) mod projection;
mod sse;
mod template;

use crate::chain::Side;
#[cfg(test)]
use crate::parser::{Format, llm::Fields};
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, abi::envoy_dynamic_module_type_metadata_source as MetadataSource,
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

enum Source {
    Chain,
    Path,
    Protocol,
    Operation,
    RequestHeader(String),
    FilterState(String),
    DynamicMetadata {
        namespace: String,
        key: String,
        kind: MetadataType,
    },
}

enum MetadataType {
    String,
    Number,
    Bool,
}

impl Source {
    fn parse(operator: &str, args: &str, limit: Option<usize>) -> Result<Self, &'static str> {
        let valid_key = |s: &str| {
            !s.is_empty() && !s.contains([':', '(', ')', '%']) && !s.chars().any(char::is_control)
        };
        let kind = match operator {
            "REQ" => {
                let name = args.strip_prefix(':').unwrap_or(args);
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                {
                    return Err("REQ requires one HTTP header name");
                }
                return Ok(Self::RequestHeader(args.to_ascii_lowercase()));
            }
            "FILTER_STATE" => {
                let key = args
                    .strip_suffix(":PLAIN")
                    .filter(|k| valid_key(k))
                    .ok_or("expected %FILTER_STATE(key:PLAIN)%")?;
                return Ok(Self::FilterState(key.into()));
            }
            "DYNAMIC_METADATA" => MetadataType::String,
            "DYNAMIC_METADATA_NUMBER" => MetadataType::Number,
            "DYNAMIC_METADATA_BOOL" => MetadataType::Bool,
            _ => return Err("unsupported audit operator"),
        };
        if limit.is_some() && !matches!(kind, MetadataType::String) {
            return Err("numeric and boolean metadata do not take a byte limit");
        }
        let (namespace, key) = args
            .split_once(':')
            .filter(|(ns, k)| valid_key(ns) && valid_key(k))
            .ok_or("expected a namespace and one top-level key separated by ':'")?;
        Ok(Self::DynamicMetadata {
            namespace: namespace.into(),
            key: key.into(),
            kind,
        })
    }
}

#[derive(Clone, Default)]
pub(crate) struct Attributes {
    pub values: Map<String, Value>,
    pub truncated: bool,
}

impl Attributes {
    fn insert(&mut self, alias: &str, text: &str, limit: usize) {
        let prefix = limit::string_prefix(text, limit);
        self.truncated |= prefix.len() != text.len();
        self.values.insert(alias.into(), prefix.into());
    }

    fn capture(
        &mut self,
        alias: &str,
        source: &Source,
        limit: usize,
        headers: &super::RequestHeaders<'_>,
        envoy: &impl EnvoyHttpFilter,
    ) {
        let bytes = match source {
            Source::Chain => return self.insert(alias, headers.chain, limit),
            Source::Path => return self.insert(alias, headers.path, limit),
            Source::Protocol | Source::Operation => {
                if let Some(protocol) = headers.format.protocol() {
                    let value = if matches!(source, Source::Protocol) {
                        protocol
                    } else {
                        "chat"
                    };
                    self.insert(alias, value, limit);
                }
                return;
            }
            Source::RequestHeader(key) => envoy.get_request_header_value(key),
            Source::FilterState(key) => envoy.get_filter_state_typed(key.as_bytes()),
            Source::DynamicMetadata {
                namespace,
                key,
                kind,
            } => match kind {
                MetadataType::String => {
                    envoy.get_metadata_string(MetadataSource::Dynamic, namespace, key)
                }
                MetadataType::Number => {
                    if let Some(number) = envoy
                        .get_metadata_number(MetadataSource::Dynamic, namespace, key)
                        .and_then(serde_json::Number::from_f64)
                    {
                        self.values.insert(alias.into(), Value::Number(number));
                    }
                    return;
                }
                MetadataType::Bool => {
                    if let Some(value) =
                        envoy.get_metadata_bool(MetadataSource::Dynamic, namespace, key)
                    {
                        self.values.insert(alias.into(), Value::Bool(value));
                    }
                    return;
                }
            },
        };
        if let Some(bytes) = bytes {
            self.insert(alias, &String::from_utf8_lossy(bytes.as_slice()), limit);
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Direction {
    pub(crate) field_bytes: usize,
    #[serde(default)]
    pub(crate) format: Format,
    #[serde(default = "Fields::fixture_default")]
    pub(crate) fields: Fields,
}

pub struct Audit {
    request: Option<std::sync::Arc<template::Template>>,
    response: Option<std::sync::Arc<template::Template>>,
    // Header, Filter State and Dynamic Metadata values are sampled at request headers.
    context: BTreeMap<String, (Source, usize)>,
}

impl Audit {
    pub(crate) fn start(
        &self,
        request: &super::RequestHeaders<'_>,
        index: usize,
        envoy: &impl EnvoyHttpFilter,
        output: &mut crate::FilterOutput,
    ) -> super::StreamFilters {
        let mut attrs = Attributes::default();
        for (alias, (source, limit)) in &self.context {
            attrs.capture(alias, source, *limit, request, envoy);
        }
        // Create the record at request headers, including when all values are missing
        // or the stream ends before response headers.
        let row = output.audit(index);
        row.append(&mut attrs.values);
        if let Some(response) = &self.response {
            for key in &response.status {
                row.insert(key.clone(), "incomplete".into());
            }
        }
        let start =
            |side, template: &std::sync::Arc<template::Template>| -> Box<dyn super::BodyFilter> {
                Box::new(capture::Capture::new(
                    side,
                    index,
                    template.clone(),
                    attrs.truncated,
                ))
            };
        super::StreamFilters {
            request: self.request.as_ref().map(|t| start(Side::Request, t)),
            response: self.response.as_ref().map(|t| start(Side::Response, t)),
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

    const REQUEST_ID: &str = "d2455d2a-4017-42cf-a384-49bdfb96a2de";
    type FormatFields<'a> = &'a [(&'a str, &'a str)];

    fn chat_records(
        body: &str,
        side: ParserDirection,
        specs: &[FormatFields],
        note: &str,
    ) -> Vec<Vec<u8>> {
        let media = if matches!(side, ParserDirection::Request(_)) {
            "application/json"
        } else {
            "text/event-stream"
        };
        protocol_records(
            Format::OpenaiChatCompletions,
            media,
            body,
            side,
            specs,
            note,
        )
    }

    fn protocol_records(
        format: Format,
        media: &str,
        body: &str,
        side: ParserDirection,
        specs: &[FormatFields],
        note: &str,
    ) -> Vec<Vec<u8>> {
        let request = matches!(side, ParserDirection::Request(_));
        let direction = if request {
            Side::Request
        } else {
            Side::Response
        };
        let mut logs = FilterOutput::default();
        let filters = specs
            .iter()
            .enumerate()
            .map(|(index, fields)| {
                let expressions = fields
                    .iter()
                    .map(|(name, expr)| (name.to_string(), expr.to_string()))
                    .collect();
                let audit = Audit::compile(expressions).unwrap();
                let mut attrs = Attributes::default();
                for (alias, (source, limit)) in &audit.context {
                    let Source::RequestHeader(header) = source else {
                        unreachable!()
                    };
                    let value = match header.as_str() {
                        "x-request-id" => REQUEST_ID,
                        "x-note" => note,
                        _ => continue,
                    };
                    attrs.insert(alias, value, *limit);
                }
                let template = if request {
                    audit.request
                } else {
                    audit.response
                }
                .unwrap();
                logs.audit(index).append(&mut attrs.values);
                Box::new(capture::Capture::new(
                    direction,
                    index,
                    template,
                    attrs.truncated,
                )) as Box<dyn BodyFilter>
            })
            .collect();
        let mut stream = DirectionStream::new(side, format, media, "", filters);
        let chunk_size = if body.len() > 1 << 20 { 16 << 10 } else { 13 };
        for part in body.as_bytes().chunks(chunk_size) {
            assert!(matches!(stream.push(part), Decision::Continue));
        }
        assert!(matches!(stream.finish(true, &mut logs), Decision::Continue));
        logs.0
            .into_values()
            .map(|row| serde_json::to_vec(&row).unwrap())
            .collect()
    }
    fn read(line: &[u8]) -> Value {
        serde_json::from_slice(line).unwrap()
    }

    #[test]
    fn parser_compaction_only_truncates_the_selected_request_fields() {
        let side = ParserDirection::Request(crate::config::RequestParserConfig {
            max_item_size: 1024,
        });
        let question: FormatFields = &[
            ("q", "%EVENT(llm.question)%"),
            ("s", "%CAPTURE_STATUS(request)%"),
        ];
        let messages: FormatFields = &[
            ("m", "%EVENT(llm.request.messages)%"),
            ("s", "%CAPTURE_STATUS(request)%"),
        ];
        let picture = json!({"type":"image_url","image_url":{"url":format!("data:image/png;base64,{}", "A".repeat(4096))}});
        let body = json!({"messages":[{"role":"user","content":[picture,{"type":"text","text":"what?"}]}]}).to_string();
        let logs = chat_records(&body, side, &[messages, question], "");
        assert_eq!(read(&logs[0])["s"], "truncated");
        assert_eq!(read(&logs[1]), json!({"q":"what?","s":"complete"}));

        let name = "my_repo_function_name_my_repo_function_name_extra_long_but_valid";
        let body = format!(
            r#"{{"model":"m","messages":[{{"role":"assistant","content":"{}","tool_calls":[{{"id":"call_1","type":"function","function":{{"arguments":"{{}}","name":"{name}"}}}}]}}]}}"#,
            "x".repeat(843)
        );
        let fields: FormatFields = &[
            ("refs", "%EVENT(llm.request.toolCallRefs)%"),
            ("s", "%CAPTURE_STATUS(request)%"),
        ];
        let row = read(&chat_records(&body, side, &[fields], "")[0]);
        assert_eq!(row, json!({"s":"truncated"}));
    }

    #[test]
    fn retained_text_aliases_keep_their_own_prefix() {
        let text = "x".repeat(300);
        for (side, body) in [
            (
                ParserDirection::Request(Default::default()),
                json!({"messages":[{"role":"user","content":text}]}),
            ),
            (
                ParserDirection::Response,
                json!({"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":text}}]}),
            ),
        ] {
            let (small, large, messages, full, status) = match side {
                ParserDirection::Request(_) => (
                    "%EVENT(llm.request.retainedText):128%",
                    "%EVENT(llm.request.retainedText):1024%",
                    "%EVENT(llm.request.messages):128%",
                    "%EVENT(llm.request.retainedText):8192%",
                    "%CAPTURE_STATUS(request)%",
                ),
                ParserDirection::Response => (
                    "%EVENT(llm.response.retainedText):128%",
                    "%EVENT(llm.response.retainedText):1024%",
                    "%EVENT(llm.response.messages):128%",
                    "%EVENT(llm.response.retainedText):8192%",
                    "%CAPTURE_STATUS(response)%",
                ),
            };
            let fields: FormatFields = &[
                ("small", small),
                ("large", large),
                ("messages", messages),
                ("s", status),
            ];
            let full: FormatFields = &[("only", full), ("s", status)];
            let records = protocol_records(
                Format::OpenaiChatCompletions,
                "application/json",
                &body.to_string(),
                side,
                &[fields, full],
                "",
            );
            assert_eq!(
                read(&records[0]),
                json!({"small":["x".repeat(124)],"large":[text],"s":"truncated"})
            );
            assert_eq!(read(&records[1]), json!({"only":[text],"s":"complete"}));
        }
    }

    #[test]
    fn omitted_tool_results_preserve_the_last_question_and_omitted_system_is_absent() {
        let side = ParserDirection::Request(crate::config::RequestParserConfig {
            max_item_size: 1024,
        });
        let first = json!({"role":"user","content":"What time?"});
        let blocks = vec![json!({"type":"text","text":"ok"}); 80];
        let q: FormatFields = &[
            ("q", "%EVENT(llm.question)%"),
            ("s", "%CAPTURE_STATUS(request)%"),
        ];
        for (format, body) in [
            (
                Format::OpenaiChatCompletions,
                json!({"messages":[first,{"role":"tool","tool_call_id":"c","content":blocks}]}),
            ),
            (
                Format::OpenaiResponses,
                json!({"input":[first,{"type":"function_call_output","call_id":"c","output":blocks}]}),
            ),
            (
                Format::AnthropicMessages,
                json!({"model":"m","max_tokens":32,"messages":[first,{"role":"user","content":[{"type":"tool_result","tool_use_id":"c","content":blocks}]}]}),
            ),
        ] {
            let row = read(
                &protocol_records(
                    format,
                    "application/json",
                    &body.to_string(),
                    side,
                    &[q],
                    "",
                )[0],
            );
            assert_eq!(row, json!({"q":"What time?","s":"partial"}));
        }
        let sys: FormatFields = &[
            ("system", "%EVENT(llm.systemInstructions)%"),
            ("s", "%CAPTURE_STATUS(request)%"),
        ];
        let body = json!({"model":"m","max_tokens":32,"messages":[first],"system":blocks});
        let rows = protocol_records(
            Format::AnthropicMessages,
            "application/json",
            &body.to_string(),
            side,
            &[sys, q],
            "",
        );
        assert_eq!(read(&rows[0]), json!({"s":"truncated"}));
        assert_eq!(read(&rows[1]), json!({"q":"What time?","s":"partial"}));
    }

    #[test]
    fn oversized_json_responses_keep_late_metadata_and_report_lost_answer_bytes() {
        let metadata: FormatFields = &[
            ("model", "%EVENT(llm.response.model)%"),
            ("id", "%EVENT(llm.responseId)%"),
            ("tokens", "%EVENT(llm.usage.totalTokens)%"),
            ("reasons", "%EVENT(llm.finishReasons)%"),
            ("s", "%CAPTURE_STATUS(response)%"),
        ];
        let answer: FormatFields = &[
            ("answer", "%EVENT(llm.answer):1048576%"),
            ("s", "%CAPTURE_STATUS(response)%"),
        ];
        let msg = json!({"role":"assistant","content":"y".repeat(2<<20)});
        let large_choice = json!({"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"ok"},
            "logprobs":{"content":vec![json!({"token":"a","logprob":-0.123,"bytes":[97],"top_logprobs":[]});20000]}});
        for (i, choice) in [
            json!({"index":0,"finish_reason":"stop","message":msg}),
            large_choice,
        ]
        .iter()
        .enumerate()
        {
            let body = format!(
                r#"{{"choices":[{choice}],"model":"test-model","id":"chat-1","usage":{{"total_tokens":8}}}}"#
            );
            let rows = protocol_records(
                Format::OpenaiChatCompletions,
                "application/json",
                &body,
                ParserDirection::Response,
                &[metadata, answer],
                "",
            );
            assert_eq!(
                read(&rows[0]),
                json!({"model":"test-model","id":"chat-1","tokens":8,"reasons":["stop"],"s":if i == 0 { "complete" } else { "partial" }})
            );
            if i == 0 {
                let row = read(&rows[1]);
                let prefix = row["answer"].as_str().unwrap();
                assert!(
                    !prefix.is_empty()
                        && prefix.len() < 1 << 20
                        && prefix.bytes().all(|b| b == b'y')
                );
                assert_eq!(row["s"], "truncated");
            }
        }
    }

    #[test]
    fn oversized_tool_results_and_business_names_keep_protocol_identity() {
        let refs: FormatFields = &[
            ("r", "%EVENT(llm.request.toolCallRefs)%"),
            ("s", "%CAPTURE_STATUS(request)%"),
        ];
        let text: FormatFields = &[
            ("t", "%EVENT(llm.request.retainedText)%"),
            ("s", "%CAPTURE_STATUS(request)%"),
        ];
        let blocks = vec![json!({"type":"text","text":"secret tool output"}); 80];
        let call = json!({"role":"assistant","tool_calls":[{"id":"c","type":"function","function":{"name":"lookup","arguments":"{}"}}]});
        let expected = json!({"r":[{"id":"c","kind":"call","name":"lookup"}],"s":"complete"});
        for (format, body, fields, want) in [
            (
                Format::AnthropicMessages,
                json!({"model":"m","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"c","name":"lookup","input":{"name":"z".repeat(4096)}}]}]}),
                refs,
                expected.clone(),
            ),
            (
                Format::OpenaiChatCompletions,
                json!({"messages":[{"role":"user","content":blocks},call]}),
                refs,
                expected,
            ),
            (
                Format::OpenaiChatCompletions,
                json!({"messages":[{"role":"user","content":"question"},call,{"role":"tool","tool_call_id":"c","content":blocks}]}),
                text,
                json!({"t":["question"],"s":"complete"}),
            ),
        ] {
            for limit in [1024, 65536] {
                let side = ParserDirection::Request(crate::config::RequestParserConfig {
                    max_item_size: limit,
                });
                let row = read(
                    &protocol_records(
                        format,
                        "application/json",
                        &body.to_string(),
                        side,
                        &[fields],
                        "",
                    )[0],
                );
                let mut expected = want.clone();
                if limit == 1024 && matches!(format, Format::OpenaiChatCompletions) {
                    expected["s"] = "partial".into();
                }
                assert_eq!(row, expected);
            }
        }
    }

    #[test]
    fn chat_answer_uses_choice_zero_and_text_preview_uses_all_choices() {
        let answer: FormatFields = &[
            ("a", "%EVENT(llm.answer)%"),
            ("s", "%CAPTURE_STATUS(response)%"),
        ];
        let both: FormatFields = &[
            ("a", "%EVENT(llm.answer)%"),
            ("t", "%EVENT(llm.response.retainedText)%"),
            ("s", "%CAPTURE_STATUS(response)%"),
        ];
        let doc = json!({"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"first"}},{"index":1,"message":{"role":"assistant","content":"x".repeat(2<<20)}}]});
        let row = read(
            &protocol_records(
                Format::OpenaiChatCompletions,
                "application/json",
                &doc.to_string(),
                ParserDirection::Response,
                &[answer],
                "",
            )[0],
        );
        assert_eq!(row, json!({"a":"first","s":"complete"}));
        let wire = [
            json!({"model":"m","choices":[{"index":1,"delta":{"role":"assistant","content":"second"}},{"index":0,"delta":{"role":"assistant","content":"first"}}]}),
            json!({"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c","type":"function","function":{"name":"f","arguments":"x".repeat(2<<20)}}]},"finish_reason":"tool_calls"},{"index":1,"delta":{},"finish_reason":"stop"}]}),
        ].iter().map(|frame| format!("data: {frame}\n\n")).collect::<String>() + "data: [DONE]\n\n";
        let rows = chat_records(&wire, ParserDirection::Response, &[both, answer], "");
        assert_eq!(
            read(&rows[0]),
            json!({"a":"first","t":["first","second"],"s":"complete"})
        );
        assert_eq!(read(&rows[1]), row);
    }

    #[test]
    fn responses_array_instructions_and_error_metadata_survive_document_limits() {
        let fields: FormatFields = &[
            ("m", "%EVENT(llm.response.model)%"),
            ("t", "%EVENT(llm.errorType)%"),
            ("c", "%EVENT(llm.errorCode)%"),
            ("s", "%CAPTURE_STATUS(response)%"),
        ];
        for entries in [1, 20000] {
            let body = json!({"model":"g","instructions":[{"role":"developer","content":"Use tools"}],"status":"failed",
                "error":{"type":"server_error","code":"internal_error"},"output":[],
                "logprobs":vec![json!({"token":"a","logprob":-0.125,"bytes":[97],"top_logprobs":[]});entries]});
            let row = read(
                &protocol_records(
                    Format::OpenaiResponses,
                    "application/json",
                    &body.to_string(),
                    ParserDirection::Response,
                    &[fields],
                    "",
                )[0],
            );
            assert_eq!(
                row,
                json!({"m":"g","t":"server_error","c":"internal_error","s":if entries == 1 { "complete" } else { "partial" }})
            );
        }
    }

    #[test]
    fn answer_header_and_usage_have_independent_field_limits() {
        let part = "水\\\"\nxy".repeat(128);
        let text = part.repeat(80);
        assert_eq!(text.len(), 80 << 10);
        let frame = |part: &str| {
            format!(
                "data: {}\n\n",
                json!({"model":"test-model","choices":[{"index":0,"delta":{"content":part}}]})
            )
        };
        let end = concat!(
            "data: {\"model\":\"test-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"model\":\"test-model\",\"choices\":[],\"usage\":{\"total_tokens\":8}}\n\ndata: [DONE]\n\n",
        );
        let usage: FormatFields = &[
            ("tokens", "%EVENT(llm.usage.totalTokens)%"),
            ("status", "%CAPTURE_STATUS(response)%"),
        ];
        let standalone = chat_records(
            &(frame(&text) + end),
            ParserDirection::Response,
            &[usage],
            "",
        )
        .pop()
        .unwrap();
        assert_eq!(read(&standalone), json!({"tokens":8,"status":"complete"}));
        for alias in ["answer", "zreply"] {
            let combined: FormatFields = &[
                (alias, "%EVENT(llm.answer):768%"),
                ("long", "%EVENT(llm.answer):131072%"),
                ("tokens", "%EVENT(llm.usage.totalTokens)%"),
                ("model", "%EVENT(llm.response.model)%"),
                ("status", "%CAPTURE_STATUS(response)%"),
                ("id", "%REQ(x-REQUEST-ID)%"),
                ("note", "%REQ(X-NOTE):128%"),
            ];
            let large_header = "\n".repeat(80 << 10);
            let mut previous = None;
            for wire in [frame(&text) + end, frame(&part).repeat(80) + end] {
                let run = |specs: &[FormatFields]| {
                    chat_records(&wire, ParserDirection::Response, specs, &large_header)
                };
                let a = run(&[combined]).pop().unwrap();
                if let Some(first) = previous.replace(a.clone()) {
                    assert_eq!(a, first);
                }
                assert_eq!(run(&[combined, usage]), [a.clone(), standalone.clone()]);
                assert_eq!(run(&[usage, combined]), [standalone.clone(), a.clone()]);
                let row = read(&a);
                assert_eq!(row["id"], REQUEST_ID);
                assert_eq!(row["model"], "test-model");
                assert_eq!(row["tokens"], 8);
                assert_eq!(row["status"], "truncated");
                assert_eq!(row["long"], text);
                assert_eq!(row["note"], "\n".repeat(64));
                let prefix = row[alias].as_str().unwrap();
                assert!(text.starts_with(prefix));
                assert!(serde_json::to_vec(prefix).unwrap().len() - 2 <= 768);
                let next = text[prefix.len()..].chars().next().unwrap();
                assert!(
                    serde_json::to_vec(&format!("{prefix}{next}"))
                        .unwrap()
                        .len()
                        - 2
                        > 768
                );
            }
        }
    }

    #[test]
    fn default_budget_applies_to_each_alias_and_excludes_keys_and_delimiters() {
        let run = |text: &str, fields: FormatFields| {
            let body = json!({"model":"m","messages":[{"role":"user","content":text}]}).to_string();
            chat_records(
                &body,
                ParserDirection::Request(Default::default()),
                &[fields],
                "",
            )
            .pop()
            .unwrap()
        };
        let fields = &[
            ("first", "%EVENT(llm.question)%"),
            ("second", "%EVENT(llm.question)%"),
            ("status", "%CAPTURE_STATUS(request)%"),
        ];
        for n in [8192, 8193] {
            let row = run(&"x".repeat(n), fields);
            assert!(row.len() > 16384);
            let row = read(&row);
            assert_eq!(row["first"], "x".repeat(8192));
            assert_eq!(row["second"], row["first"]);
            assert_eq!(
                row["status"],
                if n == 8192 { "complete" } else { "truncated" }
            );
        }
        let row = read(&run(
            "abcd",
            &[
                ("short", "%EVENT(llm.question):2%"),
                ("full", "%EVENT(llm.question):4%"),
            ],
        ));
        assert_eq!(row, json!({"short":"ab","full":"abcd"}));
    }

    #[test]
    fn structured_fields_are_typed_and_separate_from_text() {
        let tools = json!([{"type":"function","function":{"name":"a","parameters":{}}},
                         {"type":"function","function":{"name":"b","parameters":{"description":"d".repeat(2000)}}}]);
        let body =
            json!({"model":"m","messages":[{"role":"user","content":"hello"}],"tools":tools})
                .to_string();
        let logs = chat_records(
            &body,
            ParserDirection::Request(Default::default()),
            &[&[
                ("tools", "%EVENT(llm.toolDefinitions):4096%"),
                ("small", "%EVENT(llm.toolDefinitions):128%"),
                ("question", "%EVENT(llm.question):4%"),
                ("model", "%EVENT(llm.request.model)%"),
                ("status", "%CAPTURE_STATUS(request)%"),
            ]],
            "",
        );
        let row = read(&logs[0]);
        assert_eq!(row["status"], "truncated");
        assert_eq!(row["question"], "hell");
        assert_eq!(row["model"], "m");
        assert_eq!(row["tools"].as_array().unwrap().len(), 2);
        assert_eq!(row["small"].as_array().unwrap().len(), 1);
        assert_eq!(row["small"][0], row["tools"][0]);
    }

    #[test]
    fn request_tool_limit_counts_normalized_json_and_preserves_the_prefix() {
        let desc = "<>&".repeat(40);
        let body = json!({"model":"m","messages": [], "tools": [
            {"type": "function", "function":{"name":"first", "description":desc}},
            {"type": "function", "function":{"name":"second"}}
        ]})
        .to_string();
        let tools =
            json!([{"name":"first", "description":desc, "parameters":null, "type":"function"}]);
        let size = serde_json::to_vec(&tools).unwrap().len();
        let at = format!("%EVENT(llm.toolDefinitions):{size}%");
        let under = format!("%EVENT(llm.toolDefinitions):{}%", size - 1);
        let row = read(
            &chat_records(
                &body,
                ParserDirection::Request(Default::default()),
                &[&[
                    ("tools", &at),
                    ("under", &under),
                    ("status", "%CAPTURE_STATUS(request)%"),
                ]],
                "",
            )[0],
        );
        assert_eq!(row, json!({"tools":tools, "status":"truncated"}));
    }

    #[test]
    fn clipping_an_image_in_one_audit_preserves_it_for_the_next() {
        let data = "YWFh".repeat(256);
        let body = json!({"messages":[{"role":"user","content":[
            {"type":"image_url","image_url":{"url":format!("data:image/png;base64,{data}"),"detail":"high"}},
            {"type":"image_url","image_url":{"url":"data:image/png;base64,YQ=="}},
            {"type":"text","text":"after image"}]}]});
        let rows = chat_records(
            &body.to_string(),
            ParserDirection::Request(Default::default()),
            &[
                &[("m", "%EVENT(llm.request.messages):256%")],
                &[("m", "%EVENT(llm.request.messages):4096%")],
            ],
            "",
        );
        let mut parts = json!([
            {"type":"blob","modality":"image","mime_type":"image/png","detail":"high"},
            {"type":"blob","modality":"image","mime_type":"image/png","content":"YQ=="},
            {"type":"text","content":"after image"}
        ]);
        assert_eq!(read(&rows[0])["m"][0]["parts"], parts);
        parts[0]["content"] = data.into();
        assert_eq!(read(&rows[1])["m"][0]["parts"], parts);
    }

    #[test]
    fn inline_files_share_the_remaining_message_budget_in_input_order() {
        let data = [
            "YWFh".repeat(1024),
            "YmJi".repeat(24),
            "Y2Nj".repeat(24),
            "ZGRk".repeat(5),
            "b2s=".into(),
        ];
        let prefix = "data:text/plain;base64,";
        let mut content: Vec<_> = data
            .iter()
            .map(|s| json!({"type":"input_file","file_data":format!("{prefix}{s}")}))
            .collect();
        content.push(json!({"type":"input_text","text":"after \"文件\""}));
        let input = json!({"input":[{"role":"user","content":"previous"},{"role":"user","content":content}]}).to_string();
        let run = |specs: &[FormatFields]| {
            protocol_records(
                Format::OpenaiResponses,
                "application/json",
                &input,
                ParserDirection::Request(Default::default()),
                specs,
                "",
            )
        };
        let full: FormatFields = &[
            ("m", "%EVENT(llm.request.messages):8192%"),
            ("s", "%CAPTURE_STATUS(request)%"),
        ];
        let wide = read(&run(&[full])[0]);
        assert_eq!(wide["s"], "complete");
        let mut exact = wide["m"].clone();
        for index in [0, 2] {
            exact[1]["parts"][index]["data"]["file_data"] = format!("{prefix}[omitted]").into();
        }
        let size = serde_json::to_vec(&exact).unwrap().len();
        let at = format!("%EVENT(llm.request.messages):{size}%");
        let under = format!("%EVENT(llm.request.messages):{}%", size - 1);
        let rows = run(&[
            &[("m", &at), ("s", "%CAPTURE_STATUS(request)%")],
            &[("m", &under)],
            full,
        ]);
        assert_eq!(read(&rows[0]), json!({"m":exact,"s":"truncated"}));
        exact[1]["parts"][3]["data"]["file_data"] = format!("{prefix}[omitted]").into();
        assert_eq!(read(&rows[1])["m"], exact);
        assert_eq!(read(&rows[2]), wide);
    }

    #[test]
    fn omitting_inline_files_preserves_later_text_and_tool_arguments() {
        let args = json!({"file_data":"user value", "bytes":"42"});
        let body = json!({"messages":[{"role":"assistant","content":[
            {"type":"file","file":{"filename":"p.pdf","file_data":"p".repeat(8192)}},
            {"type":"text","text":"after file"}],
            "tool_calls":[{"id":"c","type":"function","function":{"name":"read","arguments":args.to_string()}}]}]});
        let row = read(
            &chat_records(
                &body.to_string(),
                ParserDirection::Request(Default::default()),
                &[&[
                    ("messages", "%EVENT(llm.request.messages):1024%"),
                    ("status", "%CAPTURE_STATUS(request)%"),
                ]],
                "",
            )[0],
        );
        let parts = &row["messages"][0]["parts"];
        assert_eq!(
            parts[0]["data"]["file"],
            json!({"filename":"p.pdf","file_data":"[omitted]"})
        );
        assert_eq!(parts[1]["content"], "after file");
        assert_eq!(parts[2]["arguments"], args);
        assert_eq!(row["status"], "truncated");
    }

    #[test]
    fn template_sources_determine_each_directions_body_interest() {
        use crate::filters::BodyInterest;
        let events = BodyInterest {
            events: true,
            decoded_bytes: false,
        };
        let decoded = BodyInterest {
            events: false,
            decoded_bytes: true,
        };
        let wire = BodyInterest::default();
        for (fields, request, response) in [
            (
                vec![
                    "%REQ(X-ID)%",
                    "%CHAIN%",
                    "%PATH%",
                    "%EVENT(llm.operation)%",
                    "%EVENT(llm.protocol)%",
                    "%FILTER_STATE(k:PLAIN)%",
                    "%DYNAMIC_METADATA(ns:k)%",
                ],
                None,
                None,
            ),
            (
                vec!["%REQ(X-ID)%", "%EVENT(llm.question)%"],
                Some(events),
                None,
            ),
            (
                vec!["%EVENT(llm.usage.totalTokens)%", "%EVENT(llm.answer)%"],
                None,
                Some(events),
            ),
            (
                vec!["%EVENT(llm.request.model)%", "%EVENT(llm.response.model)%"],
                Some(events),
                Some(events),
            ),
            (
                vec!["%BYTES_SEEN(request)%", "%BYTES_SEEN(response)%"],
                Some(wire),
                Some(wire),
            ),
            (
                vec!["%DECODED_BYTES(request)%", "%CAPTURE_STATUS(response)%"],
                Some(decoded),
                Some(events),
            ),
        ] {
            let expressions = fields
                .iter()
                .enumerate()
                .map(|(i, expr)| (i.to_string(), expr.to_string()))
                .collect();
            let audit = Audit::compile(expressions).unwrap();
            let interest = |dir, t: Option<std::sync::Arc<template::Template>>| {
                t.map(|template| capture::Capture::new(dir, 0, template, false).interest())
            };
            assert_eq!(
                (
                    interest(Side::Request, audit.request),
                    interest(Side::Response, audit.response)
                ),
                (request, response),
                "{fields:?}"
            );
        }
    }

    #[test]
    fn byte_counters_can_observe_an_opaque_gzip_body_without_llm_events() {
        use std::io::Write;
        let plain = b"not an LLM document";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(plain).unwrap();
        let compressed = encoder.finish().unwrap();
        let side = ParserDirection::Request(Default::default());
        for decoded in [false, true] {
            let mut fields = BTreeMap::from([("wire".into(), "%BYTES_SEEN(request)%".into())]);
            if decoded {
                fields.insert("plain".into(), "%DECODED_BYTES(request)%".into());
            }
            let template = Audit::compile(fields).unwrap().request.unwrap();
            let capture = Box::new(capture::Capture::new(Side::Request, 0, template, false));
            let mut stream = DirectionStream::new(
                side,
                Format::OpenaiChatCompletions,
                "application/octet-stream",
                "gzip",
                vec![capture],
            );
            assert_eq!(stream.counts_bytes_only(), !decoded);
            if decoded {
                for chunk in compressed.chunks(3) {
                    stream.push(chunk);
                }
            } else {
                stream.count_bytes(compressed.len());
            }
            let mut output = FilterOutput::default();
            stream.finish(true, &mut output);
            let row = read(&output.into_json_lines().unwrap());
            assert_eq!(row["wire"], compressed.len());
            assert_eq!(
                row.get("plain"),
                decoded.then(|| json!(plain.len())).as_ref()
            );
        }
    }

    #[test]
    fn field_limit_syntax_is_validated_at_load() {
        let compile = |expr: &str| Audit::compile(BTreeMap::from([("field".into(), expr.into())]));
        for expr in [
            "%REQ(:authority):1%",
            "%FILTER_STATE(ns:PLAIN):128%",
            "%DYNAMIC_METADATA(ns:key):16%",
            "%DYNAMIC_METADATA_NUMBER(ns:key)%",
            "%DYNAMIC_METADATA_BOOL(ns:key)%",
            "%PATH:4%",
            "%EVENT(llm.request.messages):1048576%",
            "%EVENT(llm.response.messages):1048576%",
            "%CAPTURE_STATUS(response)%",
            "%BYTES_SEEN(request)%",
        ] {
            assert!(compile(expr).is_ok(), "{expr}");
        }
        for expr in [
            "%REQ(x):%",
            "%REQ(x):-1%",
            "%REQ(x):+1%",
            "%REQ(x):1KiB%",
            "%REQ(x):1048577%",
            "%REQ(x):0%",
            "%REQ(x):32:2%",
            "%REQ(x):2%tail",
            "%UNKNOWN%",
            "%CAPTURE_STATUS%",
            "%BYTES_SEEN%",
            "%DECODED_BYTES%",
            "%BYTES_SEEN(both)%",
            "%CAPTURE_STATUS(request):2%",
            "%BYTES_SEEN(response):2%",
            "%EVENT(llm.stream):4%",
            "%EVENT(llm.usage.totalTokens):4%",
            "%DYNAMIC_METADATA_NUMBER(ns:key):4%",
            "%DYNAMIC_METADATA_BOOL(ns:key):4%",
        ] {
            assert!(compile(expr).is_err(), "{expr}");
        }
        for field in ["model", "messages", "toolCallRefs", "retainedText"] {
            let error = compile(&format!("%EVENT(llm.{field})%")).err().unwrap();
            assert!(error.contains(&format!("llm.request.{field} or llm.response.{field}")));
        }
    }

    #[test]
    fn compacted_text_is_a_prefix_and_late_questions_survive_files() {
        let side = ParserDirection::Request(crate::config::RequestParserConfig {
            max_item_size: 1024,
        });
        let q: FormatFields = &[
            ("q", "%EVENT(llm.question)%"),
            ("s", "%CAPTURE_STATUS(request)%"),
        ];
        let long = "水".repeat(1600);
        let parts = json!([{"type":"text","text":"start "},{"type":"text","text":long},{"type":"text","text":"END"}]);
        let body = json!({"messages":[{"role":"user","content":parts}]}).to_string();
        let row = read(&chat_records(&body, side, &[q], "")[0]);
        let prefix = row["q"].as_str().unwrap();
        assert!(prefix.starts_with("start 水") && format!("start {long}END").starts_with(prefix));
        assert_eq!(row["s"], "truncated");

        let mut parts =
            vec![json!({"type":"input_image","image_url":"https://example.test/image.png"}); 40];
        parts.extend([
            json!({"type":"output_text","text":"unrelated"}),
            json!({"text":"Describe these images","type":"input_text"}),
        ]);
        let body = json!({"input":[{"content":parts,"role":"user"}]}).to_string();
        let result = protocol_records(
            Format::OpenaiResponses,
            "application/json",
            &body,
            side,
            &[q],
            "",
        );
        assert_eq!(
            read(&result[0]),
            json!({"q":"Describe these images","s":"partial"})
        );

        let long = "X".repeat(2 << 20);
        let parts = json!([{"type":"text","text":"start "},{"type":"text","text":long},{"type":"text","text":"END"}]);
        let answer: FormatFields = &[
            ("answer", "%EVENT(llm.answer):1048576%"),
            ("s", "%CAPTURE_STATUS(response)%"),
        ];
        let chat = json!({"model":"m","choices":[{"message":{"role":"assistant","content":parts,"refusal":"refusal"},"index":0}]});
        let anthropic = json!({"model":"m","content":parts,"stop_reason":"end_turn"});
        let responses = json!({"model":"m","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"start "},{"type":"output_text","text":long},{"type":"refusal","refusal":"END"}]}]});
        for (format, doc) in [
            (Format::OpenaiChatCompletions, chat),
            (Format::AnthropicMessages, anthropic),
            (Format::OpenaiResponses, responses),
        ] {
            let row = read(
                &protocol_records(
                    format,
                    "application/json",
                    &doc.to_string(),
                    ParserDirection::Response,
                    &[answer],
                    "",
                )[0],
            );
            let prefix = row["answer"].as_str().unwrap();
            assert!(
                prefix.starts_with("start X") && format!("start {long}END").starts_with(prefix)
            );
            assert_eq!(row["s"], "truncated");
        }
    }

    #[test]
    fn omitted_schema_closes_definition_prefix_and_never_certifies_skipped_grammar() {
        let props = (0..80)
            .map(|i| (format!("field_{i}"), json!({"type":"string"})))
            .collect::<serde_json::Map<_, _>>();
        let big =
            json!({"type":"function","function":{"name":"big","parameters":{"properties":props}}});
        let small = json!({"type":"function","function":{"name":"small"}});
        let side = ParserDirection::Request(crate::config::RequestParserConfig {
            max_item_size: 1024,
        });
        let tools: FormatFields = &[
            ("t", "%EVENT(llm.toolDefinitions)%"),
            ("s", "%CAPTURE_STATUS(request)%"),
        ];
        for (values, prefix_len) in [(json!([big, small]), 0), (json!([small, big, small]), 1)] {
            let body = json!({"messages":[],"tools":values}).to_string();
            let row = read(&chat_records(&body, side, &[tools], "")[0]);
            assert_eq!(row["s"], "truncated");
            assert_eq!(row["t"].as_array().map_or(0, Vec::len), prefix_len);
            if prefix_len > 0 {
                assert_eq!(row["t"][0]["name"], "small");
            }
        }
        let invalid = big.to_string().replacen("}}}}", ",}}}}", 1);
        assert!(serde_json::from_str::<Value>(&invalid).is_err());
        let body =
            format!(r#"{{"messages":[{{"role":"user","content":"hello"}}],"tools":[{invalid}]}}"#);
        let q: FormatFields = &[
            ("q", "%EVENT(llm.question)%"),
            ("s", "%CAPTURE_STATUS(request)%"),
        ];
        assert_eq!(
            read(&chat_records(&body, side, &[q], "")[0]),
            json!({"q":"hello","s":"partial"})
        );
        assert_eq!(
            read(
                &chat_records(
                    &body,
                    ParserDirection::Request(Default::default()),
                    &[q],
                    ""
                )[0]
            ),
            json!({"s":"invalid_json"})
        );
    }

    #[test]
    fn decoded_bytes_survive_an_unsupported_body_in_the_same_or_another_audit() {
        use std::io::Write;
        let plain = vec![b'x'; 48 << 10];
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&plain).unwrap();
        let gzip = encoder.finish().unwrap();
        for separate in [false, true] {
            let mut rows = vec![BTreeMap::from([(
                "n".into(),
                "%DECODED_BYTES(request)%".into(),
            )])];
            if separate {
                rows.push(BTreeMap::new());
            }
            rows.last_mut()
                .unwrap()
                .insert("s".into(), "%CAPTURE_STATUS(request)%".into());
            let filters = rows
                .into_iter()
                .enumerate()
                .map(|(index, fields)| {
                    let template = Audit::compile(fields).unwrap().request.unwrap();
                    Box::new(capture::Capture::new(Side::Request, index, template, false))
                        as Box<dyn BodyFilter>
                })
                .collect();
            let mut stream = DirectionStream::new(
                ParserDirection::Request(Default::default()),
                Format::OpenaiChatCompletions,
                "application/octet-stream",
                "gzip",
                filters,
            );
            for chunk in gzip.chunks(5) {
                stream.push(chunk);
            }
            let mut output = FilterOutput::default();
            stream.finish(true, &mut output);
            assert_eq!(output.0[&0]["n"], plain.len());
            assert_eq!(
                output.0[&usize::from(separate)]["s"],
                "unsupported_media_type"
            );
        }
    }

    #[test]
    fn screenshot_compacted_by_the_parser_keeps_its_metadata_in_both_audits() {
        let input = json!({"input":[
            {"type":"computer_call_output","call_id":"c","output":{
                "type":"computer_screenshot","detail":"original","image_url":format!("data:image/png;base64,{}", "YWFh".repeat(1024))}},
            {"role":"user","content":[{"type":"input_text","text":"after screenshot"}]}]});
        let rows = protocol_records(
            Format::OpenaiResponses,
            "application/json",
            &input.to_string(),
            ParserDirection::Request(crate::config::RequestParserConfig {
                max_item_size: 1024,
            }),
            &[
                &[
                    ("m", "%EVENT(llm.request.messages):1024%"),
                    ("s", "%CAPTURE_STATUS(request)%"),
                ],
                &[
                    ("m", "%EVENT(llm.request.messages):8192%"),
                    ("s", "%CAPTURE_STATUS(request)%"),
                ],
            ],
            "",
        );
        assert_eq!(rows[0], rows[1]);
        let row = read(&rows[0]);
        assert_eq!(row["s"], "truncated");
        assert_eq!(
            row["m"][0]["parts"][0]["response"][0]["data"],
            json!({"type":"computer_screenshot","detail":"original","image_url":"data:image/png;base64,[omitted]"})
        );
        assert_eq!(row["m"][1]["parts"][0]["content"], "after screenshot");
    }

    #[test]
    fn responses_files_and_tool_result_identity_are_preserved() {
        let side = ParserDirection::Request(crate::config::RequestParserConfig {
            max_item_size: 1024,
        });
        let fields: FormatFields = &[
            ("m", "%EVENT(llm.request.messages)%"),
            ("q", "%EVENT(llm.question)%"),
            ("r", "%EVENT(llm.request.toolCallRefs)%"),
        ];
        let data = format!("data:text/csv;base64,{}", "YSxi".repeat(500));
        for key in ["file_url", "file_data"] {
            let doc = json!({"input":[{"role":"user","content":[{"type":"input_file",(key):data},{"type":"input_text","text":"explain"}]},{"type":"computer_call_output","call_id":"c","output":{"type":"computer_screenshot","file_id":"f"}}]});
            let row = read(
                &protocol_records(
                    Format::OpenaiResponses,
                    "application/json",
                    &doc.to_string(),
                    side,
                    &[fields],
                    "",
                )[0],
            );
            assert_eq!(
                row["m"][0]["parts"][0]["data"][key],
                "data:text/csv;base64,[omitted]"
            );
            assert_eq!(row["q"], "explain");
            assert_eq!(row["m"][1]["role"], "tool");
            assert_eq!(
                row["m"][1]["parts"][0]["response"][0]["data"]["file_id"],
                "f"
            );
            assert_eq!(row["r"], json!([{"id":"c","kind":"result"}]));
        }
        let doc = json!({"messages":[{"role":"assistant","tool_calls":[{"type":"custom","id":"c","custom":{"name":"grammar","input":"x"}}]}]});
        assert_eq!(
            read(&chat_records(&doc.to_string(), side, &[fields], "")[0])["r"],
            json!([{"id":"c","kind":"call","name":"grammar"}])
        );
    }

    #[test]
    fn sse_null_deltas_errors_and_early_eof_preserve_observed_metadata() {
        let fields: FormatFields = &[
            ("reason", "%EVENT(llm.finishReasons)%"),
            ("model", "%EVENT(llm.response.model)%"),
            ("tokens", "%EVENT(llm.usage.totalTokens)%"),
            ("error", "%EVENT(llm.errorType)%"),
            ("s", "%CAPTURE_STATUS(response)%"),
            ("answer", "%EVENT(llm.answer)%"),
            ("calls", "%EVENT(llm.response.toolCallRefs)%"),
        ];
        let row = |format, wire: &str| {
            read(
                &protocol_records(
                    format,
                    "text/event-stream",
                    wire,
                    ParserDirection::Response,
                    &[fields],
                    "",
                )[0],
            )
        };
        let chat = include_str!("../../../testdata/openai.sse");
        let claude = include_str!("../../../testdata/anthropic.sse");
        let with_null = chat.replace(
            r#""function":{"arguments":"#,
            r#""function":{"name":null,"arguments":"#,
        );
        assert_ne!(with_null, chat);
        assert_eq!(
            row(Format::OpenaiChatCompletions, &with_null),
            row(Format::OpenaiChatCompletions, chat)
        );
        for (format, wire, end) in [
            (Format::OpenaiChatCompletions, chat, "data: [DONE]"),
            (Format::AnthropicMessages, claude, "event: message_stop"),
        ] {
            let mut expected = row(format, wire);
            assert!(expected["reason"].is_array());
            expected["s"] = "incomplete_stream".into();
            assert_eq!(row(format, wire.split_once(end).unwrap().0), expected);
        }
        let start = claude.split_once("event: ping").unwrap().0;
        let wire = format!(
            "{start}event: error\ndata: {{\"type\":\"error\",\"error\":{{\"type\":\"overloaded_error\",\"message\":\"busy\"}}}}\n\n"
        );
        assert_eq!(
            row(Format::AnthropicMessages, &wire),
            json!({"s":"complete","model":"test-claude","tokens":6,"error":"overloaded_error"})
        );
    }
}
