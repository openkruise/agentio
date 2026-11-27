// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

mod workloads;

use super::{
    Attributes, Audit, Source, capture::Capture, messages::ResponseMessages, template::Template,
};
use crate::{
    FilterOutput,
    chain::{DirectionStream, Side},
    filters::BodyFilter,
    parser::{
        Format, ParserDirection,
        llm::{self, Protocol, sse::Framer},
    },
};
use criterion::{BatchSize, Criterion, Throughput};
use serde_json::Value;
use std::{collections::BTreeMap, hint::black_box, sync::Arc};

struct Replay<'a> {
    protocol: Protocol,
    direction: ParserDirection,
    media: mime::Mime,
    chunks: Vec<&'a [u8]>,
}

impl Replay<'_> {
    fn parse(&self, mut on_event: impl FnMut(llm::Event<'_>)) -> llm::Outcome {
        let mut parser =
            llm::Parser::new(self.protocol, self.direction, Some(&self.media), "").unwrap();
        for chunk in &self.chunks {
            parser.push(chunk, &mut on_event).unwrap();
        }
        parser.finish(true, &mut on_event).unwrap()
    }

    fn capture(&self, templates: &[Arc<Template>]) -> FilterOutput {
        let side = match self.direction {
            ParserDirection::Request(_) => Side::Request,
            ParserDirection::Response(_) => Side::Response,
        };
        let filters = templates
            .iter()
            .enumerate()
            .map(|(index, t)| {
                Box::new(Capture::new(side, index, Arc::clone(t), false)) as Box<dyn BodyFilter>
            })
            .collect();
        let mut stream = DirectionStream::new(
            self.direction,
            Format::Llm(self.protocol),
            self.media.as_ref(),
            "",
            filters,
        );
        for chunk in &self.chunks {
            let _ = stream.push(chunk);
        }
        let mut rows = FilterOutput::default();
        let _ = stream.finish(true, &mut rows);
        rows
    }
}

fn message_template(direction: ParserDirection, limit: usize) -> Arc<Template> {
    let response = matches!(direction, ParserDirection::Response(_));
    let side = if response { "response" } else { "request" };
    let mut columns = BTreeMap::from([
        (
            "messages".into(),
            format!("%EVENT(llm.{side}.messages):{limit}%"),
        ),
        ("status".into(), format!("%CAPTURE_STATUS({side})%")),
        ("bytes".into(), format!("%BYTES_SEEN({side})%")),
    ]);
    if response {
        columns.insert("tokens".into(), "%EVENT(llm.usage.totalTokens)%".into());
    }
    let audit = Audit::compile(columns).unwrap();
    if response {
        audit.response
    } else {
        audit.request
    }
    .unwrap()
}

fn benchmark_stream(
    c: &mut Criterion,
    name: &str,
    protocol: Protocol,
    direction: ParserDirection,
    media: &str,
    body: &str,
) {
    let sse = media == "text/event-stream";
    let replay = Replay {
        protocol,
        direction,
        media: media.parse().unwrap(),
        chunks: if sse {
            body.split_inclusive("\n\n").map(str::as_bytes).collect()
        } else {
            body.as_bytes().chunks(16 * 1024).collect()
        },
    };
    let templates = [
        message_template(direction, 128),
        message_template(direction, 8192),
    ];
    // Check the real log records outside timing. A parse-error shortcut would look fast.
    let mut singles = Vec::new();
    for (t, limit) in templates.iter().zip([128, 8192]) {
        let line = replay
            .capture(std::slice::from_ref(t))
            .into_json_lines()
            .unwrap();
        let row: Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(row["bytes"], body.len());
        assert!(matches!(
            row["status"].as_str(),
            Some("complete" | "truncated" | "partial")
        ));
        assert!(row["messages"].as_array().is_some_and(|m| !m.is_empty()));
        assert!(serde_json::to_vec(&row["messages"]).unwrap().len() <= limit);
        if matches!(direction, ParserDirection::Response(_)) {
            assert!(row["tokens"].is_number());
        }
        if name == "request_inline_image_50m" {
            let parts = &row["messages"][0]["parts"];
            assert_eq!(parts[0]["mime_type"], "image/png");
            assert_eq!(parts[1]["content"], "after-image");
        }
        singles.extend_from_slice(&line);
    }
    assert_eq!(
        replay.capture(&templates).into_json_lines().unwrap(),
        singles
    );

    let mut group = c.benchmark_group(name);
    group.throughput(Throughput::Bytes(body.len() as u64));
    group.bench_function("parser", |b| {
        b.iter(|| {
            replay.parse(|event| {
                black_box(event);
            })
        })
    });
    for (label, selected) in [
        ("one_128b", &templates[..1]),
        ("one_8k", &templates[1..]),
        ("two_128b_8k", &templates[..]),
    ] {
        group.bench_function(label, |b| {
            b.iter(|| replay.capture(selected).into_json_lines().unwrap())
        });
    }
    if sse {
        let usage = Audit::compile(BTreeMap::from([(
            "tokens".into(),
            "%EVENT(llm.usage.totalTokens)%".into(),
        )]))
        .unwrap()
        .response
        .unwrap();
        let selected = std::slice::from_ref(&usage);
        let line = replay.capture(selected).into_json_lines().unwrap();
        let usage_row: Value = serde_json::from_slice(&line).unwrap();
        let expected_tokens = match protocol {
            Protocol::OpenaiChatCompletions => 75,
            Protocol::OpenaiResponses => 8,
            Protocol::AnthropicMessages => 12,
        };
        assert_eq!(usage_row["tokens"], expected_tokens);
        group.bench_function("usage_only", |b| {
            b.iter(|| replay.capture(selected).into_json_lines().unwrap())
        });
        group.bench_function("framing_and_json_decode", |b| {
            b.iter(|| {
                let mut framer = Framer::new(protocol);
                for chunk in &replay.chunks {
                    framer
                        .push(chunk, |frame| {
                            black_box(frame);
                            Ok(())
                        })
                        .unwrap();
                }
            })
        });
    }
    group.finish();

    if matches!(direction, ParserDirection::Response(_)) && !sse {
        benchmark_response_output(c, &replay, &templates);
    }
}

fn benchmark_response_output(c: &mut Criterion, replay: &Replay<'_>, templates: &[Arc<Template>]) {
    // Collect the Chat fixture's normalized choices outside the timed projection.
    let mut choices = Vec::new();
    replay.parse(|event| {
        if let llm::Event::Response(llm::stream::Event::OutputItem {
            output,
            value: Some(message),
            part: None,
            clipped: false,
            sealed: true,
        }) = event
        {
            choices.push((output.index, message.clone()));
        }
    });
    let mut group = c.benchmark_group("response_output_256k");
    for (t, limit) in templates.iter().zip([128, 8192]) {
        let project = || {
            let mut messages = ResponseMessages::default();
            for (index, message) in black_box(&choices) {
                messages.message(*index, message, limit);
            }
            messages.finish(false, None, limit)
        };
        let rows = replay.capture(std::slice::from_ref(t));
        assert_eq!(project().0.as_ref(), rows.records[&0].get("messages"));
        group.bench_function(format!("project_messages_{limit}"), |b| b.iter(project));
        group.bench_function(format!("encode_json_lines_{limit}"), |b| {
            b.iter_batched(
                || FilterOutput {
                    records: rows.records.clone(),
                    ..FilterOutput::default()
                },
                |rows| rows.into_json_lines().unwrap(),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn benchmark_session_header(c: &mut Criterion) {
    const ID: &str = "0195bea8-d235-7311-b78b-17e0309ef250";
    let mut group = c.benchmark_group("audit_session_header");
    for (client, key) in [
        ("codex", "session-id"),
        ("claude", "x-claude-code-session-id"),
    ] {
        let headers = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "gateway.test"),
            (":path", "/v1/messages"),
            ("user-agent", client),
            ("accept", "text/event-stream"),
            ("content-type", "application/json"),
            ("content-length", "8192"),
            ("accept-encoding", "gzip"),
            ("x-request-id", ID),
            ("x-tenant", "test"),
            (key, ID),
        ];
        for (name, expr) in [
            ("req", format!("%REQ({key})%")),
            (
                "req_fallback",
                "%REQ(SESSION-ID?X-CLAUDE-CODE-SESSION-ID)%".into(),
            ),
        ] {
            let audit = Audit::compile(BTreeMap::from([("session".into(), expr)])).unwrap();
            let (source, limit) = &audit.context["session"];
            let Source::RequestHeader(header) = source else {
                unreachable!()
            };
            let sample = || {
                let mut attrs = Attributes::default();
                let headers = black_box(&headers);
                let value = header
                    .get(|name| headers.iter().find(|(k, _)| *k == name).map(|(_, v)| *v))
                    .unwrap();
                attrs.insert("session", value, *limit);
                let mut output = FilterOutput::default();
                *output.audit(0) = attrs.values;
                output.into_json_lines().unwrap()
            };
            assert_eq!(sample(), format!("{{\"session\":\"{ID}\"}}\n").as_bytes());
            group.bench_function(format!("{client}/{name}"), |b| b.iter(sample));
        }
    }
    group.finish();
}

pub fn body_processing_benchmarks(c: &mut Criterion) {
    benchmark_session_header(c);
    let chat = Protocol::OpenaiChatCompletions;
    let request = ParserDirection::Request(Default::default());
    let response = ParserDirection::Response(Default::default());
    for (name, size, text) in [
        ("request_text_8k", 8 << 10, "q"),
        (
            "request_escaped_8k",
            8 << 10,
            "查 \"model\" 路径 C:\\temp\n",
        ),
        ("request_text_4m", 4 << 20, "q"),
    ] {
        benchmark_stream(
            c,
            name,
            chat,
            request,
            "application/json",
            &workloads::text_request(size, text),
        );
    }
    benchmark_stream(
        c,
        "request_inline_image_50m",
        chat,
        request,
        "application/json",
        &workloads::image_request(),
    );
    benchmark_stream(
        c,
        "response_json_256k",
        chat,
        response,
        "application/json",
        &workloads::json_response(),
    );
    let chat_stream = workloads::chat_stream();
    for (name, protocol, wire) in [
        ("sse_chat_64x128", chat, chat_stream.as_str()),
        (
            "sse_responses_tools",
            Protocol::OpenaiResponses,
            include_str!("../../testdata/responses.sse"),
        ),
        (
            "sse_anthropic_tools",
            Protocol::AnthropicMessages,
            include_str!("../../testdata/anthropic.sse"),
        ),
    ] {
        benchmark_stream(c, name, protocol, response, "text/event-stream", wire);
    }
}
