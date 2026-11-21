// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    filters::{BodyEnd, BodyFilter, BodyResult, Decision},
    parser::{BodyEvent, llm::stream::Event},
};
use std::{cell::RefCell, rc::Rc};

struct Probe {
    index: usize,
    seen: Rc<RefCell<Vec<(usize, Value)>>>,
}

impl BodyFilter for Probe {
    fn on_event(&mut self, event: &BodyEvent<'_>, _: usize) -> Decision {
        let BodyEvent::LlmResponse(event) = event else {
            panic!("unexpected request event")
        };
        let value = match event {
            Event::TextDelta { text, .. } => json!(["text", text]),
            Event::Usage(usage) => json!(["usage", usage]),
            Event::Detail { kind, value } => json!(["detail", kind, value]),
            Event::OutputItem { index, .. } => json!(["item", index]),
            Event::ReplaceOutput => json!("replace"),
            Event::Completed { .. } => json!("completed"),
        };
        self.seen.borrow_mut().push((self.index, value));
        Decision::Continue
    }

    fn on_end(self: Box<Self>, end: &BodyEnd, _: &mut FilterOutput) -> Decision {
        assert!(matches!(end.result, BodyResult::Sse { status: Ok(()), .. }));
        self.seen.borrow_mut().push((self.index, json!("end")));
        Decision::Continue
    }
}

#[test]
fn complete_frames_deliver_semantic_events_to_both_filters_before_http_end() {
    for (format, body) in [
        (
            Format::OpenaiChatCompletions,
            include_str!("../../testdata/openai.sse"),
        ),
        (
            Format::OpenaiResponses,
            include_str!("../../testdata/responses.sse"),
        ),
        (
            Format::AnthropicMessages,
            include_str!("../../testdata/anthropic.sse"),
        ),
    ] {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let filters = (0..2)
            .map(|index| {
                Box::new(Probe {
                    index,
                    seen: seen.clone(),
                }) as Box<dyn BodyFilter>
            })
            .collect();
        let mut stream = DirectionStream::new(
            ParserDirection::Response,
            format,
            "text/event-stream",
            "",
            filters,
        );
        for frame in body.split_inclusive("\n\n") {
            let before = seen.borrow().len();
            let (prefix, delimiter) = frame.as_bytes().split_at(frame.len() - 1);
            stream.push(prefix);
            assert_eq!(
                seen.borrow().len(),
                before,
                "incomplete frame reached a filter"
            );
            stream.push(delimiter);
            let observed = seen.borrow();
            let updates = &observed[before..];
            for pair in updates.chunks(2) {
                assert_eq!([pair[0].0, pair[1].0], [0, 1]);
                assert_eq!(pair[0].1, pair[1].1);
            }
            if frame.contains("你") && frame.contains("delta") {
                assert!(updates.iter().any(|(_, v)| *v == json!(["text", "你"])));
            }
            if frame.contains("\"usage\":{") {
                assert!(
                    updates
                        .iter()
                        .any(|(_, v)| v[0] == "usage" && v[1].is_object())
                );
            }
            if frame.contains("北京")
                && frame.contains("delta")
                && !frame.contains("output_item.done")
            {
                assert!(
                    updates.iter().any(|(_, v)| v[0] == "detail"),
                    "tool arguments must reach the filters during push"
                );
            }
        }
        assert_eq!(
            seen.borrow()
                .iter()
                .filter(|(_, v)| *v == "completed")
                .count(),
            2
        );
        let before = seen.borrow().len();
        stream.finish(true, &mut FilterOutput::default());
        assert_eq!(
            seen.borrow()[before..],
            [(0, json!("end")), (1, json!("end"))]
        );
    }
}

#[test]
fn responses_nonempty_terminal_output_replaces_even_an_oversized_item() {
    let fixture = include_str!("../../testdata/responses.sse");
    let (early, terminal) = fixture.split_once("event: response.completed").unwrap();
    let early = early.replace("\"你好\"", &format!("\"{}\"", "x".repeat(256)));
    let body = format!("{early}event: response.completed{terminal}data: [DONE]\n\n");
    let run = |wire: &str| {
        configured_record(
            "response",
            "/v1/responses",
            "text/event-stream",
            wire.as_bytes().chunks(3),
            &json!({"maxSize":4096,"maxContentBytes":32,"fields":{"answer":true}}),
            true,
        )
    };
    let record = run(&body);
    assert_eq!(record["llm.answer"], "你好no");
    assert_eq!(record["captureStatus"], "complete");
    assert_eq!(record["gen_ai.usage.output_tokens"], 3);

    // A small terminal snapshot also replaces structured messages discarded by
    // the shared 1 MiB parser budget, independently of the record's line limit.
    let huge_item = body.replace(&"x".repeat(256), &"x".repeat((1 << 20) + 1));
    let messages = configured_record(
        "response",
        "/v1/responses",
        "text/event-stream",
        huge_item.as_bytes().chunks(16384),
        &json!({"maxSize":8192,"maxCaptureBytes":(2<<20),"fields":{"outputMessages":true}}),
        true,
    );
    assert_eq!(messages["captureStatus"], "complete");
    assert_eq!(
        messages["gen_ai.output.messages"][0]["parts"][0]["content"],
        "你好"
    );

    let unconfirmed = run(&early);
    assert_eq!(unconfirmed["captureStatus"], "incomplete_stream");
    assert!(unconfirmed.get("llm.answer").is_none());
    let malformed = run(&format!("{body}data: {{broken}}\n\n"));
    assert_eq!(malformed["captureStatus"], "invalid_json");
    assert!(malformed.get("llm.answer").is_none());
    assert!(malformed.get("gen_ai.usage.output_tokens").is_none());
}

#[test]
fn responses_empty_or_omitted_terminal_output_keeps_the_confirmed_item_once() {
    let wire =
        include_str!("../../testdata/responses-refusal.sse").replace(",\"content_index\":0", "");
    for body in [
        wire.clone(),
        wire.replace(
            "\"output\":[],\"status\":\"completed\"",
            "\"status\":\"completed\"",
        ),
    ] {
        let record = configured_record(
            "response",
            "/v1/responses",
            "text/event-stream",
            body.as_bytes().chunks(1),
            &json!({"maxSize":2048,"fields":{"answer":true}}),
            true,
        );
        assert_eq!(record["llm.answer"], "I cannot help with that.");
        assert_eq!(record["captureStatus"], "complete");
    }
}
