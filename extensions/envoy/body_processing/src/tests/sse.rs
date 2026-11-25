// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    filters::{BodyEnd, BodyFilter, BodyResult, Decision},
    parser::{BodyEvent, llm::stream::Event},
};
use std::{cell::RefCell, rc::Rc};

#[test]
fn anthropic_mcp_deltas_reconstruct_the_same_arguments_as_json() {
    let wire = include_str!("../../testdata/anthropic.sse")
        .replace(
            r#""type":"tool_use""#,
            r#""type":"mcp_tool_use","server_name":"clock""#,
        )
        .replace(
            r#""stop_sequence":null"#,
            r#""stop_sequence":null,"container":null,"stop_details":null"#,
        );
    let mut doc: Value =
        serde_json::from_str(include_str!("../../testdata/anthropic.response.json")).unwrap();
    let tool = doc["content"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|b| b["type"] == "tool_use")
        .unwrap();
    tool["type"] = "mcp_tool_use".into();
    tool["server_name"] = "clock".into();
    let json = doc.to_string();
    let capture = |media, body: &str| {
        record(
            "response",
            "/v1/messages",
            media,
            body.as_bytes().chunks(13),
            8192,
            true,
        )
    };
    let sse = capture("text/event-stream", &wire);
    let document = capture("application/json", &json);
    assert_eq!(sse["captureStatus"], "complete");
    let parts = &sse["gen_ai.output.messages"][0]["parts"];
    let call = parts
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["type"] == "tool_call")
        .unwrap();
    assert_eq!(call["arguments"], json!({"city":"北京"}));
    assert_eq!(
        sse["gen_ai.output.messages"],
        document["gen_ai.output.messages"]
    );
}

struct Probe {
    index: usize,
    seen: Rc<RefCell<Vec<(usize, Value)>>>,
}

impl BodyFilter for Probe {
    fn on_event(&mut self, event: &BodyEvent<'_>, _: usize) -> Decision {
        let BodyEvent::Llm(crate::parser::llm::Event::Response(event)) = event else {
            panic!("unexpected request event")
        };
        let value = match event {
            Event::TextDelta { output, text, .. } => {
                json!(["text", text, output.index, output.answer_candidate])
            }
            Event::Usage(usage) => json!(["usage", usage]),
            Event::Detail { kind, value } => json!(["detail", kind, value]),
            Event::OutputItem { output, .. } => json!(["item", output.index]),
            Event::TextGap { .. } => json!("text_gap"),
            Event::ReplaceOutput => json!("replace"),
            Event::Completed { .. } => json!("completed"),
        };
        self.seen.borrow_mut().push((self.index, value));
        Decision::Continue
    }

    fn on_end(self: Box<Self>, end: &BodyEnd, _: &mut FilterOutput) -> Decision {
        assert!(matches!(
            end.result,
            BodyResult::Llm(crate::parser::llm::Outcome::Sse)
        ));
        self.seen.borrow_mut().push((self.index, json!("end")));
        Decision::Continue
    }
}

#[test]
fn complete_frames_deliver_semantic_events_to_both_filters_before_http_end() {
    for (format, body) in [
        (
            Format::Llm(Protocol::OpenaiChatCompletions),
            include_str!("../../testdata/openai.sse"),
        ),
        (
            Format::Llm(Protocol::OpenaiResponses),
            include_str!("../../testdata/responses.sse"),
        ),
        (
            Format::Llm(Protocol::AnthropicMessages),
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
            ParserDirection::Response(Default::default()),
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
                assert!(
                    updates
                        .iter()
                        .any(|(_, v)| v[0] == "text" && v[1] == "你" && v[3] == true)
                );
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
fn chat_emits_alternatives_with_their_answer_membership() {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let mut stream = DirectionStream::new(
        ParserDirection::Response(Default::default()),
        Format::Llm(Protocol::OpenaiChatCompletions),
        "text/event-stream",
        "",
        vec![Box::new(Probe {
            index: 0,
            seen: seen.clone(),
        })],
    );
    let choices = json!({"model":"m","choices":[
        {"index":1,"delta":{"content":"alternate"}}, {"index":0,"delta":{"content":"primary"}}]});
    stream.push(format!("data: {choices}\n\n").as_bytes());
    let text: Vec<_> = seen
        .borrow()
        .iter()
        .filter(|(_, v)| v[0] == "text")
        .map(|(_, v)| v.clone())
        .collect();
    assert_eq!(
        text,
        [
            json!(["text", "alternate", 1, false]),
            json!(["text", "primary", 0, true])
        ]
    );
}

#[test]
fn responses_nonempty_terminal_output_replaces_even_an_oversized_item() {
    let fixture = include_str!("../../testdata/responses.sse");
    let (early, terminal) = fixture.split_once("event: response.completed").unwrap();
    let early = early.replace("\"你好\"", &format!("\"{}\"", "x".repeat(5000)));
    let body = format!("{early}event: response.completed{terminal}data: [DONE]\n\n");
    let run = |wire: &str| {
        configured_record(
            "response",
            "/v1/responses",
            "text/event-stream",
            wire.as_bytes().chunks(3),
            &json!({"fieldBytes":4096,"fields":{"answer":true}}),
            true,
        )
    };
    let record = run(&body);
    assert_eq!(record["llm.answer"], "你好no");
    assert_eq!(record["captureStatus"], "complete");
    assert_eq!(record["gen_ai.usage.output_tokens"], 3);

    // A small terminal snapshot also replaces structured messages discarded by
    // the shared 1 MiB parser budget, independently of the audit field's limit.
    let huge_item = body.replace(&"x".repeat(5000), &"x".repeat((1 << 20) + 1));
    let messages = configured_record(
        "response",
        "/v1/responses",
        "text/event-stream",
        huge_item.as_bytes().chunks(16384),
        &json!({"fieldBytes":8192,"fields":{"outputMessages":true}}),
        true,
    );
    assert_eq!(messages["captureStatus"], "complete");
    assert_eq!(
        messages["gen_ai.output.messages"][0]["parts"][0]["content"],
        "你好"
    );

    let unconfirmed = run(&early);
    assert_eq!(unconfirmed["captureStatus"], "incomplete_stream");
    assert_eq!(unconfirmed["llm.answer"], "x".repeat(4096));
    let malformed = run(&format!("{body}data: {{broken}}\n\n"));
    assert_eq!(malformed["captureStatus"], "invalid_json");
    assert!(malformed.get("llm.answer").is_none());
    assert!(malformed.get("gen_ai.usage.output_tokens").is_none());
}

#[test]
fn responses_terminal_messages_fit_their_compact_json_size() {
    let text = "<p>&水</p>\u{2028}\u{2029}".repeat(32 * 1024);
    let output = json!([{"id":"m","type":"message","role":"assistant","content":[
        {"type":"output_text","text":text}]}]);
    let size = serde_json::to_vec(&output).unwrap().len();
    assert_eq!(crate::parser::encoded_len(&output), size);
    assert!(size < 1 << 20);
    let event = json!({"type":"response.completed","response":{
        "id":"r","model":"m","status":"completed","output":output}});
    let wire = format!("event: response.completed\ndata: {event}\n\n");
    let row = configured_record(
        "response",
        "/v1/responses",
        "text/event-stream",
        wire.as_bytes().chunks(16384),
        &json!({"fieldBytes":1 << 20,"fields":{"outputMessages":true}}),
        true,
    );
    assert_eq!(row["captureStatus"], "complete");
    assert_eq!(
        row["gen_ai.output.messages"][0]["parts"][0]["content"],
        text
    );
}

#[test]
fn interrupted_sse_preserves_framed_text_and_omits_unseen_usage() {
    let chat = concat!(
        "data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"重试\"}}]}\n\n",
        "data: {\"model\":\"m\",\"choices\":[],\"usage\":{\"total_tokens\":99}}",
    );
    let responses = include_str!("../../testdata/responses.sse")
        .split_once("event: response.output_item.done")
        .unwrap()
        .0;
    let anthropic = include_str!("../../testdata/anthropic.sse")
        .split_once("event: content_block_stop")
        .unwrap()
        .0;
    for (path, stream, text) in [
        ("/v1/chat/completions", chat, "重试"),
        ("/v1/responses", responses, "你好"),
        ("/v1/messages", anthropic, "你好"),
    ] {
        let r = configured_record(
            "response",
            path,
            "text/event-stream",
            stream.as_bytes().chunks(3),
            &json!({"fieldBytes":1024,"fields":{"answer":true}}),
            false,
        );
        assert_eq!(r["captureStatus"], "incomplete", "{path}");
        assert_eq!(r["llm.answer"], text, "{path}");
        if path == "/v1/chat/completions" {
            assert_eq!(r["gen_ai.response.model"], "m");
            assert!(r.get("agentio.usage.total_tokens").is_none());
        }
    }
    let framed = format!("{chat}\n\n");
    let row = configured_record(
        "response",
        "/v1/chat/completions",
        "text/event-stream",
        framed.as_bytes().chunks(3),
        &json!({"fieldBytes":1024,"fields":{"answer":true}}),
        false,
    );
    assert_eq!(row["captureStatus"], "incomplete");
    assert_eq!(row["agentio.usage.total_tokens"], 99);
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
            &json!({"fieldBytes":2048,"fields":{"answer":true}}),
            true,
        );
        assert_eq!(record["llm.answer"], "I cannot help with that.");
        assert_eq!(record["captureStatus"], "complete");
    }
}
