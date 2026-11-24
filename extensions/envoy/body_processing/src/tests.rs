// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

mod sse;

use crate::chain::{DirectionStream, ParserDirection};
use crate::filters::audit::capture::Capture;
use crate::{
    config::Settings,
    filters::audit::{Attributes, Direction, capture::AuditContext},
    parser::Format,
};
use serde_json::{Value, json};

use crate::FilterOutput;

pub(crate) fn fixture_stream(
    direction: ParserDirection,
    media: &str,
    encoding: &str,
    captures: impl IntoIterator<Item = crate::filters::audit::capture::Capture>,
) -> DirectionStream {
    let captures: Vec<_> = captures.into_iter().collect();
    let format = captures[0].format;
    let room = captures[0].document_room();
    assert!(captures.iter().all(|c| c.format == format));
    let filters = captures
        .into_iter()
        .map(|c| Box::new(c) as Box<dyn crate::filters::BodyFilter>)
        .collect();
    DirectionStream::with_limits(direction, format, media, encoding, filters, room, None)
}

fn parser_direction(response: bool) -> ParserDirection {
    if response {
        ParserDirection::Response
    } else {
        ParserDirection::Request(Default::default())
    }
}

fn encoded(stream: DirectionStream, complete: bool) -> Vec<u8> {
    let mut ctx = FilterOutput::default();
    stream.finish(complete, &mut ctx);
    ctx.into_json_lines().unwrap()
}

fn record(
    dir: &'static str,
    path: &str,
    media: &str,
    chunks: impl Iterator<Item = impl AsRef<[u8]>>,
    limit: usize,
    end: bool,
) -> Value {
    let settings = json!({"fieldBytes":limit});
    configured_record(dir, path, media, chunks, &settings, end)
}

fn configured_record(
    dir: &'static str,
    path: &str,
    media: &str,
    chunks: impl Iterator<Item = impl AsRef<[u8]>>,
    settings: &Value,
    end: bool,
) -> Value {
    let mut config: Direction = serde_json::from_value(settings.clone()).unwrap();
    let protocol = Format::from_path(path);
    if settings.get("format").is_none() && protocol != Format::UnknownProtocol {
        config.format = protocol;
    }
    let mut c = crate::tests::fixture_stream(
        parser_direction(dir == "response"),
        media,
        "",
        vec![Capture::start(
            dir,
            path,
            "test-id",
            config,
            AuditContext {
                chain: "test",
                filter_index: 0,
                attributes: &Default::default(),
            },
        )],
    );
    for chunk in chunks {
        c.push(chunk.as_ref());
    }
    let out = encoded(c, end);
    serde_json::from_slice(&out).unwrap()
}

#[test]
fn inline_image_across_slices_keeps_following_text() {
    let image = "A".repeat(24 * 1024);
    let body = json!({"model":"m","messages":[{"role":"user","content":[
        {"type":"image_url","image_url":{"url":format!("data:image/png;base64,{image}"),"detail":"high"}},
        {"type":"text","text":"after 🧪 \" \\"}]}]})
    .to_string();
    for chunk in [1, 7, 512, 65536] {
        let r = record(
            "request",
            "/v1/chat/completions",
            "application/json",
            body.as_bytes().chunks(chunk),
            1024,
            true,
        );
        assert_eq!(r["bytesSeen"], body.len());
        assert_eq!(r["captureStatus"], "truncated");
        let blocks = &r["gen_ai.input.messages"][0]["parts"];
        assert_eq!(
            blocks[0],
            json!({"type":"blob","modality":"image","mime_type":"image/png","detail":"high"})
        );
        assert_eq!(blocks[1]["content"], "after 🧪 \" \\");
    }
}

#[test]
fn multipart_validates_delimiter_suffix_and_keeps_later_fields() {
    for size in [12, 48000] {
        let file = "x".repeat(size) + "\r\n--boundary_X\0";
        let body = format!(
            "--boundary\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"test.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n{file}\r\n--boundary\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nafter file\r\n--boundary--\r\n"
        );
        for chunk in [1, 13, 65536] {
            let r = record(
                "request",
                "/upload",
                "multipart/form-data; boundary=\"boundary\"",
                body.as_bytes().chunks(chunk),
                2048,
                true,
            );
            let parts = &r["http.body"]["parts"];
            assert_eq!(parts[0]["bytes"], file.len());
            assert_eq!(parts[1]["text"], "after file");
            if size > 2048 {
                assert_eq!(r["captureStatus"], "truncated");
                assert_eq!(parts[0]["omitted"], true);
                assert!(parts[0].get("base64").is_none());
            } else {
                assert_eq!(r["captureStatus"], "complete");
                assert!(parts[0]["base64"].is_string());
            }
        }
    }
}

#[test]
fn response_formats_and_incomplete_streams() {
    let text = "data: 你好\n\n".repeat(500);
    let sse = record(
        "response",
        "/events",
        "text/event-stream",
        text.as_bytes().chunks(7),
        1024,
        true,
    );
    assert_eq!(sse["direction"], "response");
    assert_eq!(sse["captureStatus"], "truncated");
    assert!(sse["http.body"].as_str().unwrap().starts_with("data: 你好"));
    let doc =
        br#"{"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"OK"}}]}"#;
    let r = record(
        "response",
        "/v1/chat/completions",
        "application/json",
        doc.chunks(2),
        4096,
        true,
    );
    assert_eq!(r["captureStatus"], "complete");
    assert_eq!(r["gen_ai.output.messages"][0]["parts"][0]["content"], "OK");
    let r = record(
        "request",
        "/text",
        "text/plain",
        b"partial".chunks(3),
        1024,
        false,
    );
    assert_eq!(r["captureStatus"], "incomplete");
    let r = record(
        "request",
        "/business",
        "application/json",
        b"{broken}".chunks(1),
        1024,
        true,
    );
    assert_eq!(r["captureStatus"], "invalid_json");
}

#[test]
fn escaped_and_multibyte_text_clipping_produces_valid_json() {
    let body = json!({"prompt":"🧪\\\"\u{0000}".repeat(4000),"tail":"visible"}).to_string();
    let r = record(
        "request",
        "/business",
        "application/json",
        body.as_bytes().chunks(11),
        2048,
        true,
    );
    assert_eq!(r["captureStatus"], "truncated");
    assert_eq!(r["http.body"]["tail"], "visible");
}

#[test]
fn many_omitted_images_cannot_displace_the_following_text() {
    let image = json!({"type":"image_url","image_url":{"url":format!("data:image/png;base64,{}","a".repeat(3000))}});
    let mut blocks = vec![image; 100];
    blocks.push(json!({"type":"text","text":"after many files"}));
    let body = json!({"model":"m","messages":[{"role":"user","content":blocks}]}).to_string();
    let r = record(
        "request",
        "/v1/chat/completions",
        "application/json",
        body.as_bytes().chunks(17),
        1024,
        true,
    );
    assert_eq!(r["captureStatus"], "truncated");
    assert_eq!(r["llm.retainedText"], json!(["after many files"]));
}

#[test]
fn integer_ids_survive_audit_serialization() {
    let r = record(
        "request",
        "/event",
        "application/json",
        br#"{"id":9007199254740993}"#.chunks(2),
        1024,
        true,
    );
    assert_eq!(r["http.body"]["id"].as_u64(), Some(9_007_199_254_740_993));
}

// EPE fixture inputs are compared with this parser's normalized blocks after audit formatting.
fn assert_fixture(record: &Value, expected: &Value, response: bool) {
    let mut attributes = serde_json::Map::new();
    crate::filters::audit::format::project(
        expected.clone().into(),
        &mut attributes,
        response,
        true,
    );
    assert_eq!(record["llm.protocol"], expected["format"]);
    if let Some(partial) = expected.get("partial") {
        assert_eq!(&record["llm.partial"], partial);
    }
    for (key, value) in attributes {
        assert_eq!(record[&key], value, "{key}");
    }
}

#[test]
fn epe_protocol_fixtures() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
    for (file, path) in [
        ("anthropic-empty-tool.sse", "/v1/messages"),
        ("anthropic-usage.sse", "/v1/messages"),
        ("anthropic-citations.json", "/v1/messages"),
        ("responses-tools.sse", "/v1/responses"),
        ("responses-refusal.sse", "/v1/responses"),
        ("responses-truncated.json", "/v1/responses"),
        ("responses-parallel.json", "/v1/responses"),
        ("responses-media.json", "/v1/responses"),
        ("chat-empty-content.sse", "/v1/chat/completions"),
        ("chat-truncated.json", "/v1/chat/completions"),
        ("chat-annotations.sse", "/v1/chat/completions"),
        ("chat-obfuscation.sse", "/v1/chat/completions"),
    ] {
        let (name, ext) = file.rsplit_once('.').unwrap();
        let input = std::fs::read(base.join(file)).unwrap();
        let expected: Value =
            serde_json::from_slice(&std::fs::read(base.join(format!("{name}.want.json"))).unwrap())
                .unwrap();
        let direction = if matches!(name, "responses-parallel" | "responses-media") {
            "request"
        } else {
            "response"
        };
        let media = if ext == "sse" {
            "text/event-stream"
        } else {
            "application/json"
        };
        for chunk in [1, 7, 64, input.len()] {
            let got = record(direction, path, media, input.chunks(chunk), 16 << 10, true);
            assert_fixture(&got, &expected, direction == "response");
            assert_eq!(
                got["captureStatus"],
                if expected["partial"] == true {
                    "partial"
                } else {
                    "complete"
                }
            );
        }
    }
}

#[test]
fn explicit_format_and_field_selection() {
    let chat =
        json!({"format":"openai-chat-completions","fieldBytes":2048,"fields":{"tools":true}});
    let input = br#"{"model":"m","messages":[{}],"tools":[]}"#;
    let r = configured_record(
        "request",
        "/custom",
        "application/vnd.agent+json",
        input.chunks(1),
        &chat,
        true,
    );
    assert_fixture(
        &r,
        &json!({"format":"openai-chat-completions","model":"m","tools":[]}),
        false,
    );
    let mut config = chat.clone();
    config["fields"] = json!({"outputMessages":true});
    for index in ["0.0", "0e0", "0.5", "-1"] {
        let body = format!(
            r#"{{"model":"m","choices":[{{"index":{index},"message":{{"role":"assistant"}}}}]}}"#
        );
        let r = configured_record(
            "response",
            "/custom",
            "application/json",
            body.as_bytes().chunks(7),
            &config,
            true,
        );
        if matches!(index, "0.0" | "0e0") {
            assert_eq!(r["gen_ai.output.messages"][0]["index"], 0);
        } else {
            assert_eq!(r["captureStatus"], "invalid_content");
        }
    }
    assert_eq!(
        configured_record(
            "request",
            "/custom",
            "text/event-stream",
            input.chunks(1),
            &chat,
            true
        )["captureStatus"],
        "unsupported_media_type"
    );
}

#[test]
fn sse_keeps_late_usage_and_distinguishes_incomplete_events() {
    let input = include_str!("../testdata/anthropic-usage.sse");
    let expected: Value =
        serde_json::from_str(include_str!("../testdata/anthropic-usage.want.json")).unwrap();
    let mut config = json!({"format":"anthropic-messages","fieldBytes":2048});
    let run = |body: &str, settings: &Value| {
        configured_record(
            "response",
            "/custom",
            "text/event-stream",
            body.as_bytes().chunks(1),
            settings,
            true,
        )
    };
    let r = run(input, &config);
    assert_eq!(r["captureStatus"], "complete");
    assert_eq!(
        r["gen_ai.usage.input_tokens"],
        expected["usage"]["inputTokens"]
    );
    assert_eq!(
        r["gen_ai.usage.output_tokens"],
        expected["usage"]["outputTokens"]
    );
    assert!(r["gen_ai.output.messages"].is_array());
    config["fields"] = json!({});
    let r = run(input, &config);
    assert_eq!(r["captureStatus"], "complete");
    assert_eq!(
        r["gen_ai.usage.input_tokens"],
        expected["usage"]["inputTokens"]
    );
    assert_eq!(
        r["gen_ai.usage.output_tokens"],
        expected["usage"]["outputTokens"]
    );
    assert!(r.get("gen_ai.output.messages").is_none());
    assert_eq!(
        run(input.trim_end(), &config)["captureStatus"],
        "incomplete_stream"
    );
    let crlf = format!("\u{feff}: comment\r\n\r\n{}", input.replace('\n', "\r\n"));
    assert_eq!(
        run(&crlf, &config)["gen_ai.usage.input_tokens"],
        r["gen_ai.usage.input_tokens"]
    );
}

#[test]
fn partial_stream_still_checks_later_events() {
    let partial = include_str!("../testdata/chat-annotations.sse");
    let malformed = partial.replace("data: [DONE]", "data: {broken}");
    let r = record(
        "response",
        "/v1/chat/completions",
        "text/event-stream",
        malformed.as_bytes().chunks(7),
        4096,
        true,
    );
    assert_eq!(r["captureStatus"], "invalid_json");
    assert!(r.get("gen_ai.output.messages").is_none());
    assert!(r.get("llm.answer").is_none());
}

#[test]
fn documents_and_streams_produce_the_same_response() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
    for (provider, path) in [
        ("openai", "/v1/chat/completions"),
        ("responses", "/v1/responses"),
        ("anthropic", "/v1/messages"),
    ] {
        let expected: Value =
            serde_json::from_slice(&std::fs::read(base.join(format!("{provider}.json"))).unwrap())
                .unwrap();
        for (suffix, media) in [
            ("response.json", "application/json"),
            ("sse", "text/event-stream"),
        ] {
            let input = std::fs::read(base.join(format!("{provider}.{suffix}"))).unwrap();
            for chunk in [1, 17, input.len()] {
                let r = record("response", path, media, input.chunks(chunk), 8192, true);
                assert_eq!(r["captureStatus"], "complete");
                assert_fixture(&r, &expected, true);
            }
        }
    }
}

#[test]
fn explicit_document_decoders_validate_media_encoding_and_limits() {
    for (format, media, encoding, body, status, content) in [
        (
            "json",
            "application/vnd.test+json",
            "identity",
            b"[42]".as_slice(),
            "complete",
            json!([42]),
        ),
        (
            "json",
            "application/json",
            "",
            b"{",
            "invalid_json",
            Value::Null,
        ),
        (
            "json",
            "text/test+json",
            "",
            b"{}",
            "unsupported_media_type",
            Value::Null,
        ),
        (
            "text",
            "text/plain; charset=utf-8",
            "",
            b"",
            "complete",
            json!(""),
        ),
        ("text", "text/plain", "", b"1234", "complete", json!("1234")),
        ("text", "text/plain", "", b"12345", "too_large", Value::Null),
        (
            "text",
            "text/plain",
            "",
            b"\xff",
            "invalid_text",
            Value::Null,
        ),
        (
            "text",
            "text/plain; charset=iso-8859-1",
            "",
            b"abc",
            "unsupported_encoding",
            Value::Null,
        ),
        (
            "text",
            "text/plain",
            "gzip",
            b"abc",
            "invalid_encoding",
            Value::Null,
        ),
        (
            "text",
            "text/event-stream",
            "",
            b"abc",
            "unsupported_media_type",
            Value::Null,
        ),
    ] {
        let config: Direction =
            serde_json::from_value(json!({"format":format,"fieldBytes":1024})).unwrap();
        let mut capture = DirectionStream::with_limits(
            ParserDirection::Request(Default::default()),
            config.format,
            media,
            encoding,
            vec![Box::new(Capture::start(
                "request",
                "/custom",
                "id",
                config,
                AuditContext {
                    chain: "test",
                    filter_index: 0,
                    attributes: &Default::default(),
                },
            ))],
            4,
            Some(4),
        );
        for chunk in body.chunks(1) {
            capture.push(chunk);
        }
        let record: Value = serde_json::from_slice(&encoded(capture, true)).unwrap();
        assert_eq!(record["captureStatus"], status, "{format} {media} {body:?}");
        assert_eq!(record["http.body"], content);
        assert_eq!(record["bytesSeen"], body.len());
    }
}

#[test]
fn audit_attribute_expressions_are_checked_at_load() {
    for expression in [
        "prefix %REQ(X-TENANT)%",
        "%REQ(X-A)%%REQ(X-B)%",
        "%REQ()%",
        "%REQ(x bad)%",
        "%FILTER_STATE(sandbox)%",
        "%FILTER_STATE(:PLAIN)%",
        "%FILTER_STATE(sandbox:TYPED)%",
        "%DYNAMIC_METADATA(ns:parent:child)%",
        "%DYNAMIC_METADATA(:key)%",
        "%DYNAMIC_METADATA(ns:)%",
        "%DYNAMIC_METADATA_NUMBER(ns:parent:child)%",
        "%DYNAMIC_METADATA_BOOL(:flag)%",
        "%CEL(request.method)%",
    ] {
        let cfg = json!({"filterChains":[{"name":"test","parser":{"llm":{}},
            "filters":[{"audit":{"format":{"json":{"tenant":expression}}}}]}]});
        let error = Settings::parse(cfg.to_string().as_bytes()).err().unwrap();
        assert!(
            error.contains("tenant") && error.contains("filters[0].audit"),
            "{expression}: {error}"
        );
    }
}

#[test]
fn rejects_invalid_filter_chains() {
    let chain =
        json!({"name":"model","parser":{"llm":{}},"filters":[{"audit":{"format":{"json":{}}}}]});
    let parse = |chains| Settings::parse(json!({"filterChains":chains}).to_string().as_bytes());
    assert!(parse(json!([chain])).is_ok());
    assert!(
        Settings::parse(
            json!({"defaults": {}, "filterChains": [chain]})
                .to_string()
                .as_bytes()
        )
        .is_err()
    );
    assert!(parse(json!([])).unwrap().is_empty());
    assert!(parse(json!([chain, chain])).is_err());
    for (key, values) in [
        (
            "matcher",
            vec![
                json!({"hosts":[]}),
                json!({"hosts":["bad*host"]}),
                json!({"paths":["/a?x"]}),
                json!({"filterState":[{"key":"id","values":[]}]}),
                json!({"filterState":[{"key":"id","present":true}]}),
            ],
        ),
        (
            "parser",
            vec![
                json!({"http":{}}),
                json!({"llm":{},"http":{}}),
                json!({"llm":{"protocol":"oops"}}),
            ],
        ),
        (
            "filters",
            vec![
                json!([]),
                json!([{"deny":{}}]),
                json!([{"audit":{}}]),
                json!([{"audit":{"format":{}}}]),
                json!([{"audit":{"format":{"json":{}},"extra":true}}]),
                json!([{"audit":{"format":{"json":{"id":42}}}}]),
            ],
        ),
    ] {
        for value in values {
            let mut bad = chain.clone();
            bad[key] = value;
            assert!(parse(json!([bad])).is_err(), "{bad}");
        }
    }
}

#[test]
fn genai_keeps_native_conversation_when_a_header_is_clipped() {
    let settings =
        serde_json::from_value(json!({"fieldBytes":1024, "format":"openai-responses"})).unwrap();
    let mut attrs = Attributes::default();
    attrs.values.insert("tenant".into(), "tenant-a".into());
    // Escapes expand significantly in JSON even when the source fits in 1 KiB.
    attrs
        .values
        .insert("oversize".into(), "\n".repeat(700).into());
    for conversation in [json!("native"), json!({"id":"native"}), Value::Null] {
        let mut c = crate::tests::fixture_stream(
            ParserDirection::Request(Default::default()),
            "application/json",
            "",
            vec![Capture::start(
                "request",
                "/v1/responses",
                "id",
                settings,
                AuditContext {
                    chain: "test",
                    filter_index: 0,
                    attributes: &attrs,
                },
            )],
        );
        c.push(
            json!({"input":"hello","model":"m","conversation":conversation})
                .to_string()
                .as_bytes(),
        );
        let line = encoded(c, true);
        assert!(line.len() > 1024);
        let record: Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(record["attributesTruncated"], true);
        let a = &record;
        assert_eq!(
            a["gen_ai.conversation.id"].as_str(),
            (!conversation.is_null()).then_some("native")
        );
        assert_eq!(
            a["gen_ai.input.messages"][0]["parts"][0],
            json!({"type":"text","content":"hello"})
        );
        assert_eq!(a["tenant"], "tenant-a");
        assert_eq!(a["oversize"], "\n".repeat(512));
        assert_eq!(record["llm.protocol"], "openai-responses");
    }
}

fn genai_record(
    direction: &'static str,
    path: &str,
    media: &str,
    body: &str,
    fields: Value,
) -> Value {
    let mut settings: Direction =
        serde_json::from_value(json!({"fieldBytes":8192,"fields":fields})).unwrap();
    settings.format = Format::from_path(path);
    let mut c = crate::tests::fixture_stream(
        parser_direction(direction == "response"),
        media,
        "",
        vec![Capture::start(
            direction,
            path,
            "req",
            settings,
            AuditContext {
                chain: "test",
                filter_index: 0,
                attributes: &Default::default(),
            },
        )],
    );
    for chunk in body.as_bytes().chunks(7) {
        c.push(chunk);
    }
    let line = encoded(c, true);
    serde_json::from_slice(&line).unwrap()
}

#[test]
fn template_output_aliases_can_use_builtin_names() {
    let config = |name: &str| {
        let cfg = json!({"filterChains":[{"name":"llm","parser":{"llm":{}},"filters":[{"audit":{
            "format":{"json":{(name):"%REQ(X-TENANT)%"}}
        }}]}]});
        Settings::parse(cfg.to_string().as_bytes())
    };
    for name in [
        "direction",
        "captureStatus",
        "decodedBytes",
        "http.body",
        "llm.protocol",
        "llm.answer",
        "gen_ai.input.messages",
        "gen_ai.usage.cache_write.input_tokens",
        "agentio.tool.calls",
    ] {
        assert!(config(name).is_ok(), "{name}");
    }
    assert!(config("app.tenant.id").is_ok());
}

#[test]
fn system_instructions_follow_the_protocol_and_message_selection() {
    for (path, request, separate) in [
        (
            "/v1/messages",
            json!({"model":"m","system":[{"type":"text","text":"rules"}],"messages":[]}),
            true,
        ),
        (
            "/v1/responses",
            json!({"model":"m","instructions":"rules","input":[]}),
            true,
        ),
        (
            "/v1/chat/completions",
            json!({"model":"m","messages":[{"role":"system","content":"rules"}]}),
            false,
        ),
    ] {
        let body = request.to_string();
        let r = genai_record(
            "request",
            path,
            "application/json",
            &body,
            json!({"inputMessages":true}),
        );
        let parts = json!([{"type":"text","content":"rules"}]);
        if separate {
            assert_eq!(r["gen_ai.system_instructions"], parts);
            assert_eq!(r["gen_ai.input.messages"], json!([]));
        } else {
            assert_eq!(
                r["gen_ai.input.messages"][0],
                json!({"role":"system","parts":parts})
            );
            assert!(r.get("gen_ai.system_instructions").is_none());
        }
        let metadata = genai_record("request", path, "application/json", &body, json!({}));
        assert!(!metadata.to_string().contains("rules"));
        for old in ["content", "attributes", "status"] {
            assert!(r.get(old).is_none());
        }
    }
}

#[test]
fn anthropic_records_server_tools_and_skips_large_image_data() {
    let body = json!({"model":"m","messages":[{"role":"user","content":[
        {"type":"text","text":"before"},
        {"type":"image","source":{"type":"base64","media_type":"image/png","data":"A".repeat(16384)}},
        {"type":"text","text":"after"}]}]});
    let req = genai_record(
        "request",
        "/v1/messages",
        "application/json",
        &body.to_string(),
        json!({"inputMessages":true}),
    );
    assert_eq!(req["captureStatus"], "truncated");
    assert_eq!(
        req["gen_ai.input.messages"][0]["parts"],
        json!([
            {"type":"text","content":"before"}, {"type":"blob","modality":"image","mime_type":"image/png"}, {"type":"text","content":"after"}
        ])
    );
    let reply = json!({"model":"m","content":[{"type":"server_tool_use","id":"s","name":"web_search","input":{"query":"manual"}}],
        "stop_reason":"pause_turn","usage":{"input_tokens":2,"cache_creation_input_tokens":4}});
    let res = genai_record(
        "response",
        "/v1/messages",
        "application/json",
        &reply.to_string(),
        json!({"outputMessages":true}),
    );
    assert_eq!(req["requestID"], res["requestID"]);
    assert_eq!(res["direction"], "response");
    assert_eq!(res["gen_ai.usage.cache_write.input_tokens"], 4);
    assert_eq!(
        res["gen_ai.output.messages"][0]["parts"][0],
        json!({"type":"server_tool_call","id":"s","name":"web_search","server_tool_call":{"type":"web_search","query":"manual"}})
    );
}

#[test]
fn late_anthropic_usage_recognizes_fully_escaped_keys() {
    use std::fmt::Write;

    let key = "cache_creation_input_tokens";
    let mut escaped = String::new();
    for byte in key.bytes() {
        write!(escaped, "\\u{byte:04x}").unwrap();
    }
    // Fill the document with structural bytes so late usage is read by the scanner.
    let padding = "{},".repeat((1 << 20) / 3);
    for name in [key, escaped.as_str()] {
        let body = format!(
            r#"{{"model":"m","padding":[{padding}null],"content":[],"usage":{{"input_tokens":3,"output_tokens":2,"{name}":7}}}}"#
        );
        let row = configured_record(
            "response",
            "/v1/messages",
            "application/json",
            body.as_bytes().chunks(4096),
            &json!({"fieldBytes":4096,"fields":{}}),
            true,
        );
        assert_eq!(row["captureStatus"], "partial");
        assert_eq!(row["gen_ai.usage.cache_write.input_tokens"], 7);
        assert_eq!(row["gen_ai.usage.input_tokens"], 10);
        assert_eq!(row["agentio.usage.total_tokens"], 12);
    }
}

#[test]
fn summary_only_requests_preserve_call_result_link_and_explicit_parameters() {
    for (path, mut body) in [
        (
            "/v1/chat/completions",
            json!({"model":"m","max_tokens":123,"max_completion_tokens":42,"messages":[
            {"role":"assistant","tool_calls":[{"id":"c","function":{"name":"lookup","arguments":"secret"}}]},
            {"role":"tool","tool_call_id":"c","content":"secret"}]}),
        ),
        (
            "/v1/messages",
            json!({"model":"m","max_tokens":42,"messages":[
            {"role":"assistant","content":[{"type":"tool_use","name":"lookup","id":"c","input":{"arg":"secret"}}]},
            {"role":"user","content":[{"type":"tool_result","tool_use_id":"c","content":"secret"}]}]}),
        ),
        (
            "/v1/responses",
            json!({"model":"m","max_output_tokens":42,"previous_response_id":"resp-prev","input":[
            {"type":"function_call","call_id":"c","name":"lookup","arguments":"secret"},
            {"type":"function_call_output","call_id":"c","output":"secret"}]}),
        ),
    ] {
        body["stream"] = false.into();
        let r = genai_record(
            "request",
            path,
            "application/json",
            &body.to_string(),
            json!({"toolCallRefs":true}),
        );
        assert_eq!(r["captureStatus"], "complete");
        assert!(!r.to_string().contains("secret"));
        let a = &r;
        assert_eq!(a["gen_ai.request.stream"], false);
        assert_eq!(a["gen_ai.request.max_tokens"], 42);
        assert_eq!(
            a["agentio.tool.calls"],
            json!([{"id":"c","name":"lookup","kind":"call"},{"id":"c","kind":"result"}])
        );
        assert!(a.get("gen_ai.input.messages").is_none());
        assert_eq!(
            a["gen_ai.request.previous_response.id"],
            body["previous_response_id"]
        );
    }
    let r = genai_record(
        "request",
        "/v1/chat/completions",
        "application/json",
        r#"{"model":"m","max_tokens":7,"messages":[]}"#,
        json!({}),
    );
    assert_eq!(r["gen_ai.request.max_tokens"], 7);
    assert!(r.get("gen_ai.request.stream").is_none());
}

#[test]
fn metadata_and_summary_match_across_json_and_stream_when_messages_are_disabled() {
    for (path, doc, stream, id, reasons) in [
        (
            "/v1/chat/completions",
            include_str!("../testdata/openai.response.json"),
            include_str!("../testdata/openai.sse"),
            "chat-1",
            json!(["tool_calls", "stop"]),
        ),
        (
            "/v1/messages",
            include_str!("../testdata/anthropic.response.json"),
            include_str!("../testdata/anthropic.sse"),
            "msg_test",
            json!(["tool_use"]),
        ),
        (
            "/v1/responses",
            include_str!("../testdata/responses.response.json"),
            include_str!("../testdata/responses.sse"),
            "resp_1",
            Value::Null,
        ),
    ] {
        let mut doc: Value = serde_json::from_str(doc).unwrap();
        doc["id"] = id.into();
        let mut wire = stream.to_string();
        if path == "/v1/chat/completions" {
            wire = wire
                .replacen(
                    r#"{"model":"test-model""#,
                    r#"{"id":"chat-1","model":"test-model""#,
                    1,
                )
                .replace(r#""name":"lookup""#, r#""name":"look""#)
                .replace(
                    r#"{"arguments":"\"北京\"}""#,
                    r#"{"name":"up","arguments":"\"北京\"}""#,
                );
        }
        for enabled in [false, true] {
            let fields = if enabled {
                json!({"toolCallRefs":true})
            } else {
                json!({})
            };
            let json = genai_record(
                "response",
                path,
                "application/json",
                &doc.to_string(),
                fields.clone(),
            );
            let streamed = genai_record("response", path, "text/event-stream", &wire, fields);
            assert_eq!(streamed["captureStatus"], "complete");
            let mut streamed = streamed;
            streamed["bytesSeen"] = json["bytesSeen"].clone();
            assert_eq!(streamed, json, "{path}");
            let a = &json;
            assert_eq!(a["gen_ai.response.id"], id);
            assert_eq!(a["gen_ai.response.finish_reasons"], reasons);
            assert!(a.get("gen_ai.output.messages").is_none());
            assert_eq!(a.get("agentio.tool.calls").is_some(), enabled);
            if enabled {
                assert_eq!(a["agentio.tool.calls"][0]["name"], "lookup");
                assert!(a["agentio.tool.calls"][0].get("arguments").is_none());
            }
        }
    }
}

#[test]
fn response_errors_and_incomplete_status_are_independent_of_message_capture() {
    let body = r#"{"id":"r","status":"failed","model":"m","error":{"code":"server_error","message":"failed"}}"#;
    for (media, data) in [
        ("application/json", body.to_owned()),
        (
            "text/event-stream",
            format!(
                "event: response.failed\ndata: {{\"type\":\"response.failed\",\"response\":{body}}}\n\n"
            ),
        ),
    ] {
        let r = genai_record("response", "/v1/responses", media, &data, json!({}));
        assert_eq!(r["error.type"], "server_error");
        assert_eq!(r["agentio.response.error_code"], "server_error");
        assert_eq!(r["gen_ai.response.id"], "r");
        assert_eq!(r["llm.status"], "failed");
        assert!(r.get("llm.error").is_none());
    }
    let incomplete = r#"{"id":"r","status":"incomplete","model":"m","output":[],"incomplete_details":{"reason":"max_output_tokens"}}"#;
    let r = genai_record(
        "response",
        "/v1/responses",
        "application/json",
        incomplete,
        json!({}),
    );
    assert_eq!(r["llm.incompleteReason"], "max_output_tokens");
    let r = genai_record(
        "response",
        "/v1/messages",
        "application/json",
        r#"{"type":"error","error":{"type":"overloaded_error","message":"busy"}}"#,
        json!({}),
    );
    assert_eq!(r["error.type"], "overloaded_error");
    assert!(r.get("gen_ai.response.finish_reasons").is_none());
}

#[test]
fn questions_skip_tool_history_and_non_text_parts() {
    let records = [
        (
            "/v1/chat/completions",
            json!({"model":"m","messages":[
            {"role":"user","content":"old"},{"role":"user","content":[{"type":"text","text":"Hi"},{"type":"text","text":"!"}]},
            {"role":"tool","tool_call_id":"c","content":"secret"}]}),
        ),
        (
            "/v1/messages",
            json!({"model":"m","messages":[
            {"role":"user","content":[{"type":"tool_result","tool_use_id":"a","content":"secret"},{"type":"text","text":"Hi!"}]},
            {"role":"user","content":[{"type":"tool_result","tool_use_id":"c","content":[{"type":"text","text":"secret"}]}]}]}),
        ),
        (
            "/v1/responses",
            json!({"input":[{"role":"user","content":[{"type":"input_text","text":"Hi!"}]},
            {"type":"function_call_output","call_id":"c","output":"secret"}]}),
        ),
        ("/v1/responses", json!({"input":"Hi!"})),
    ];
    for (path, doc) in records {
        for messages in [false, true] {
            let r = genai_record(
                "request",
                path,
                "application/json",
                &doc.to_string(),
                json!({"question":true, "inputMessages":messages}),
            );
            assert_eq!(r["captureStatus"], "complete", "{path}: {r}");
            assert_eq!(r["llm.question"], "Hi!");
            assert_eq!(r.get("gen_ai.input.messages").is_some(), messages);
            if !messages {
                assert!(!r.to_string().contains("secret"));
            }
        }
    }
    let r = genai_record(
        "request",
        "/v1/messages",
        "application/json",
        r#"{"model":"m","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"c","content":"secret"}]}]}"#,
        json!({"question":true}),
    );
    assert!(r.get("llm.question").is_none());
    assert!(!r.to_string().contains("secret"));
}

#[test]
fn visible_answers_agree_across_streams_and_documents() {
    for (path, doc, sse, answer) in [
        (
            "/v1/chat/completions",
            include_str!("../testdata/openai.response.json"),
            include_str!("../testdata/openai.sse"),
            "你好",
        ),
        (
            "/v1/messages",
            include_str!("../testdata/anthropic.response.json"),
            include_str!("../testdata/anthropic.sse"),
            "你好",
        ),
        (
            "/v1/responses",
            include_str!("../testdata/responses.response.json"),
            include_str!("../testdata/responses.sse"),
            "你好no",
        ),
    ] {
        for (media, data) in [("application/json", doc), ("text/event-stream", sse)] {
            for messages in [false, true] {
                let r = genai_record(
                    "response",
                    path,
                    media,
                    data,
                    json!({"answer":true,"toolCallRefs":true,"outputMessages":messages}),
                );
                assert_eq!(r["captureStatus"], "complete", "{path}: {r}");
                assert_eq!(r["llm.answer"], answer, "{path}: {r}");
                assert_eq!(r.get("gen_ai.output.messages").is_some(), messages);
                assert!(r["agentio.tool.calls"].is_array());
                if !messages {
                    assert!(!r.to_string().contains("北京"));
                }
            }
        }
        let r = configured_record(
            "response",
            path,
            "text/event-stream",
            sse.as_bytes().chunks(7),
            &json!({"fields":{"answer":true},"fieldBytes":4096}),
            true,
        );
        assert_eq!(r["captureStatus"], "complete", "text alone fits: {r}");
        assert_eq!(r["llm.answer"], answer);
    }
    let tool_only = genai_record(
        "response",
        "/v1/chat/completions",
        "text/event-stream",
        include_str!("../testdata/chat-empty-content.sse"),
        json!({"answer":true}),
    );
    assert_eq!(tool_only["llm.answer"], "");
}

#[test]
fn oversized_tool_summary_keeps_independent_response_metadata() {
    let body = json!({"id":"resp-test","model":"m","status":"completed","output":[
        {"type":"function_call","call_id":"c","name":"x".repeat(1500),"arguments":"{}"}
    ]});
    let settings = serde_json::from_value(
        json!({"format":"openai-responses","fieldBytes":1024,"fields":{"toolCallRefs":true}}),
    )
    .unwrap();
    let mut c = crate::tests::fixture_stream(
        ParserDirection::Response,
        "application/json",
        "",
        vec![Capture::start(
            "response",
            "/v1/responses",
            "req",
            settings,
            AuditContext {
                chain: "test",
                filter_index: 0,
                attributes: &Default::default(),
            },
        )],
    );
    c.push(body.to_string().as_bytes());
    let line = encoded(c, true);
    let r: Value = serde_json::from_slice(&line).unwrap();
    assert_eq!(r["captureStatus"], "truncated");
    assert_eq!(r["llm.toolCallsTruncated"], true);
    assert_eq!(r["gen_ai.response.id"], "resp-test");
    assert!(r.get("agentio.tool.calls").is_none());
}

#[test]
fn filters_share_input_and_keep_independent_audit_budgets() {
    let input =
        include_str!("../testdata/chat-empty-content.sse").replace("Bash", &"B".repeat(1500));
    let response = json!({"format":"openai-chat-completions", "fieldBytes":4096});
    let attrs = Attributes::default();
    let captures: Vec<_> = [4096, 1024, 4096]
        .into_iter()
        .enumerate()
        .map(|(index, limit)| {
            let mut settings: Direction = serde_json::from_value(response.clone()).unwrap();
            settings.field_bytes = limit;
            settings.fields.output_messages = index != 2;
            Capture::start(
                "response",
                "/v1/chat/completions",
                "req",
                settings,
                AuditContext {
                    chain: "shared",
                    filter_index: index,
                    attributes: &attrs,
                },
            )
        })
        .collect();
    let mut stream =
        crate::tests::fixture_stream(ParserDirection::Response, "text/event-stream", "", captures);
    for chunk in input.as_bytes().chunks(7) {
        stream.push(chunk);
    }
    let mut ctx = FilterOutput::default();
    stream.finish(true, &mut ctx);
    let records: Vec<Value> = ctx
        .0
        .iter()
        .enumerate()
        .map(|(i, (key, bytes))| {
            assert_eq!(*key, i);
            Value::Object(bytes.clone())
        })
        .collect();
    assert_eq!(records[0]["captureStatus"], "complete");
    assert!(records[0]["gen_ai.output.messages"].is_array());
    assert_eq!(records[1]["captureStatus"], "truncated");
    assert_eq!(records[2]["captureStatus"], "complete");
    assert!(records[2].get("gen_ai.output.messages").is_none());
    assert!(records.iter().all(|r| r["bytesSeen"] == input.len()));
}

#[test]
fn streaming_answer_survives_another_audits_oversized_tool_arguments() {
    let captures = [json!({"outputMessages":true}), json!({"answer":true})]
        .into_iter()
        .enumerate()
        .map(|(index, fields)| {
            let dir = serde_json::from_value(json!({"format":"openai-chat-completions",
                "fieldBytes":if index==0{8192}else{1024}, "fields":fields}))
            .unwrap();
            Capture::start(
                "response",
                "/v1/chat/completions",
                "req",
                dir,
                AuditContext {
                    chain: "shared",
                    filter_index: index,
                    attributes: &Default::default(),
                },
            )
        });
    let mut stream =
        crate::tests::fixture_stream(ParserDirection::Response, "text/event-stream", "", captures);
    let delta = json!({"model":"m","choices":[{"index":0,"delta":{
        "tool_calls":[{"index":0,"function":{"arguments":"x".repeat(48<<10)}}]}}]});
    let event = format!("data: {delta}\n\n");
    for _ in 0..24 {
        stream.push(event.as_bytes());
    }
    stream.push(b"data: {\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"done\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n");
    let mut logs = FilterOutput::default();
    stream.finish(true, &mut logs);
    let logs = logs.0.into_values().map(Value::Object).collect::<Vec<_>>();
    assert_eq!(logs[0]["captureStatus"], "truncated");
    assert_eq!(logs[1]["captureStatus"], "complete");
    assert_eq!(logs[1]["llm.answer"], "done");
    assert!(logs[1].get("gen_ai.output.messages").is_none());
}

#[test]
fn mixed_consumers_match_their_standalone_records_in_either_order() {
    let sse = include_str!("../testdata/chat-empty-content.sse");
    let small = r#"{"model":"m","choices":[]}"#;
    let big = json!({"model":"m", "choices":[{"index":0, "message":{"role":"assistant","content":"a".repeat(1600)}}]}).to_string();
    for (media, body) in [
        ("text/event-stream", sse),
        ("application/json", small),
        ("application/json", big.as_str()),
    ] {
        let run = |indices: &[usize]| {
            let stages = indices.iter().enumerate().map(|(position, &index)| {
                let mut settings: Direction =
                    serde_json::from_value(json!({"fieldBytes":8192})).unwrap();
                settings.format = Format::OpenaiChatCompletions;
                settings.fields.answer = index == 0;
                settings.fields.output_messages = index == 1;
                if index == 2 {
                    settings.field_bytes = 1024;
                }
                Capture::start(
                    "response",
                    "/example",
                    "req",
                    settings,
                    AuditContext {
                        chain: "mixed",
                        filter_index: position,
                        attributes: &Attributes::default(),
                    },
                )
            });
            let mut stream =
                crate::tests::fixture_stream(ParserDirection::Response, media, "", stages);
            for chunk in body.as_bytes().chunks(7) {
                stream.push(chunk);
            }
            let mut ctx = FilterOutput::default();
            stream.finish(true, &mut ctx);
            ctx.0.into_values().collect::<Vec<_>>()
        };
        let expected: Vec<_> = (0..3).map(|i| run(&[i]).pop().unwrap()).collect();
        for order in [[0, 1, 2], [2, 1, 0]] {
            let actual = run(&order);
            assert_eq!(actual.len(), order.len());
            for (entry, index) in actual.iter().zip(order) {
                assert_eq!(entry, &expected[index], "{media} stage {index}");
                assert_eq!(entry["bytesSeen"], body.len());
            }
        }
    }
}

#[test]
fn fallback_text_is_scoped_to_selected_protocol_messages() {
    let image = json!({"type":"image_url","image_url":{"url":format!("data:image/png;base64,{}", "A".repeat(150))}});
    let mut parts = vec![image; 40];
    parts.push(json!({"type":"text","text":"after images"}));
    // Exercise both key orders. The model and remaining messages can arrive
    // after the bounded document has already filled up.
    let messages = json!([{"role":"user","content":parts}]);
    for body in [
        format!(
            r#"{{"model":"g","metadata":{{"text":"internal"}},"messages":{messages},"stream":true,"max_completion_tokens":12}}"#
        ),
        format!(
            r#"{{"messages":{messages},"metadata":{{"text":"internal"}},"model":"g","stream":true,"max_completion_tokens":12}}"#
        ),
    ] {
        for chunk in [1, 37, 65536] {
            for tools in [false, true] {
                let r = configured_record(
                    "request",
                    "/v1/chat/completions",
                    "application/json",
                    body.as_bytes().chunks(chunk),
                    &json!({"fieldBytes":1024,"fields":{"inputMessages":true,"tools":tools}}),
                    true,
                );
                assert_eq!(r["llm.retainedText"], json!(["after images"]));
                assert_eq!(r["captureStatus"], "truncated");
                assert_eq!(r["gen_ai.request.model"], "g");
                assert_eq!(r["gen_ai.request.stream"], true);
                assert_eq!(r["gen_ai.request.max_tokens"], 12);
            }
        }
    }
}

#[test]
fn text_starting_with_data_is_text_and_unselected_body_does_not_clip_metadata() {
    let body=json!({"model":"g","stream":true,"messages":[{"role":"user","content":format!("data: CSV {}", "x".repeat(65536))}]}).to_string();
    for (messages, status) in [(false, "complete"), (true, "truncated")] {
        let r = configured_record(
            "request",
            "/v1/chat/completions",
            "application/json",
            body.as_bytes().chunks(71),
            &json!({"fieldBytes":1024,"fields":{"inputMessages":messages, "question":messages}}),
            true,
        );
        assert_eq!(r["captureStatus"], status);
        assert_eq!(r["gen_ai.request.model"], "g");
        if messages {
            assert!(
                r["llm.question"]
                    .as_str()
                    .unwrap()
                    .starts_with("data: CSV ")
            );
            assert!(
                r["llm.retainedText"][0]
                    .as_str()
                    .unwrap()
                    .starts_with("data: CSV ")
            );
            assert!(r.get("gen_ai.input.messages").is_none());
        } else {
            assert!(r.get("gen_ai.input.messages").is_none());
        }
    }
}

#[test]
fn tool_history_keeps_result_role_and_links_in_both_projections() {
    let responses = json!({"input":[{"type":"custom_tool_call","name":"shell","call_id":"c","input":"42"},
        {"type":"custom_tool_call_output","call_id":"c","output":"done"},
        {"role":"assistant","content":[{"type":"refusal","text":"declined"}]}]});
    let anthropic = json!({"model":"m","messages":[{"role":"assistant","content":[
        {"type":"server_tool_use","id":"c","name":"web_search","input":{}},
        {"type":"web_search_tool_result","tool_use_id":"c","content":[]}] }]});
    for (path, body, name) in [
        ("/v1/responses", responses, "shell"),
        ("/v1/messages", anthropic, "web_search"),
    ] {
        for messages in [true, false] {
            let r = genai_record(
                "request",
                path,
                "application/json",
                &body.to_string(),
                json!({"inputMessages":messages,"toolCallRefs":true}),
            );
            assert_eq!(r["captureStatus"], "complete");
            assert_eq!(
                r["agentio.tool.calls"],
                json!([{"kind":"call","name":name,"id":"c"},{"kind":"result","id":"c"}])
            );
            if path == "/v1/responses" && messages {
                let history = &r["gen_ai.input.messages"];
                assert_eq!(history[0]["parts"][0]["arguments"], "42");
                assert_eq!(history[1]["role"], "tool");
                assert_eq!(history[1]["parts"][0]["type"], "tool_call_response");
                assert_eq!(history[2]["parts"][0]["type"], "refusal");
            }
        }
    }
}

#[test]
fn deployment_selected_chat_and_legacy_function_results() {
    let body=json!({"functions":[{"name":"lookup","parameters":{"type":"object"}}],"messages":[
        {"role":"user","content":"go"},{"role":"assistant","function_call":{"name":"lookup","arguments":"{}"}},
        {"role":"function","name":"lookup","content":"done"}]}).to_string();
    let r = configured_record(
        "request",
        "/openai/deployments/demo/chat/completions",
        "application/json",
        body.as_bytes().chunks(5),
        &json!({"format":"openai-chat-completions","fieldBytes":2048,"fields":{"tools":true,"toolCallRefs":true,"inputMessages":true,"question":true}}),
        true,
    );
    assert_eq!(r["captureStatus"], "complete");
    assert!(r.get("gen_ai.request.model").is_none());
    assert_eq!(r["llm.question"], "go");
    assert_eq!(r["gen_ai.tool.definitions"][0]["name"], "lookup");
    assert_eq!(
        r["agentio.tool.calls"][1],
        json!({"kind":"result","name":"lookup"})
    );
}

mod gzip {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    fn compress(bytes: &[u8]) -> Vec<u8> {
        let mut writer = GzEncoder::new(Vec::new(), Compression::fast());
        writer.write_all(bytes).unwrap();
        writer.finish().unwrap()
    }

    fn records(
        response: bool,
        encoding: &str,
        chunks: impl Iterator<Item = impl AsRef<[u8]>>,
        limits: &[usize],
        complete: bool,
    ) -> Vec<Value> {
        let attrs = Attributes::default();
        let captures = limits.iter().enumerate().map(|(index, limit)| {
            let settings: Direction = serde_json::from_value(
                json!({"format":"openai-responses","fieldBytes":limit,"fields":{"question":true}}),
            )
            .unwrap();
            Capture::start(
                if response { "response" } else { "request" },
                "/v1/responses",
                "req",
                settings,
                AuditContext {
                    chain: "gzip",
                    filter_index: index,
                    attributes: &attrs,
                },
            )
        });
        let mut stream = crate::tests::fixture_stream(
            parser_direction(response),
            "application/json",
            encoding,
            captures,
        );
        for chunk in chunks {
            stream.push(chunk.as_ref());
        }
        let mut ctx = FilterOutput::default();
        stream.finish(complete, &mut ctx);
        ctx.0.into_values().map(Value::Object).collect()
    }

    #[test]
    fn shared_decoding_with_member_boundaries_and_per_filter_limits() {
        let prefix = br#"{"model":"g","input":""#;
        let question = "hello".repeat(300);
        let suffix = format!("{question}\"}}");
        let size = prefix.len() + suffix.len();
        let wire = [compress(prefix), compress(b""), compress(suffix.as_bytes())].concat();
        for chunk in [1, 7, wire.len()] {
            for limits in [[2048, 1024], [1024, 2048]] {
                let results = records(false, "GZip", wire.chunks(chunk), &limits, true);
                for (r, limit) in results.iter().zip(limits) {
                    let text = r["llm.question"].as_str().unwrap();
                    if limit == 2048 {
                        assert_eq!(r["captureStatus"], "complete");
                        assert_eq!(text, question);
                    } else {
                        assert_eq!(r["captureStatus"], "truncated");
                        assert!(
                            !text.is_empty()
                                && text.len() < question.len()
                                && question.starts_with(text)
                        );
                    }
                    assert_eq!(r["bytesSeen"], wire.len());
                    assert_eq!(r["decodedBytes"], size);
                }
            }
        }
    }

    #[test]
    fn gzip_validates_trailer_and_does_not_publish_unverified_content() {
        let wire = compress(br#"{"input":"hello"}"#);
        let mut bad_crc = wire.clone();
        bad_crc[wire.len() - 8] ^= 1;
        let mut bad_size = wire.clone();
        bad_size[wire.len() - 4] ^= 1;
        let trailing = [wire.as_slice(), b"junk"].concat();
        for invalid in [
            bad_crc.as_slice(),
            &bad_size,
            &wire[..wire.len() - 1],
            &wire[..4],
            b"",
            &trailing,
        ] {
            let r = &records(false, "gzip", invalid.chunks(3), &[2048], true)[0];
            assert_eq!(r["captureStatus"], "invalid_encoding");
            assert_eq!(r["bytesSeen"], invalid.len());
            assert!(r.get("llm.question").is_none());
        }
        assert_eq!(
            records(false, "gzip", wire[..8].chunks(1), &[2048], false)[0]["captureStatus"],
            "incomplete"
        );
        for (response, encoding) in [(true, "gzip"), (false, "gzip, br"), (false, "br")] {
            let r = &records(response, encoding, wire.chunks(10), &[2048], true)[0];
            assert_eq!(r["captureStatus"], "unsupported_encoding");
            assert!(r.get("decodedBytes").is_none());
        }
    }

    #[test]
    fn decoded_ceiling_is_inclusive_and_shared_across_members() {
        let limit = 64 << 20;
        let mut writer = GzEncoder::new(Vec::new(), Compression::fast());
        let padding = [b' '; 16384];
        for _ in 0..limit / padding.len() - 1 {
            writer.write_all(&padding).unwrap();
        }
        writer.write_all(&padding[2..]).unwrap();
        writer.write_all(b"{}").unwrap();
        let mut wire = writer.finish().unwrap();
        let r = &records(false, "gzip", wire.chunks(997), &[2048], true)[0];
        assert_eq!(r["captureStatus"], "complete");
        assert_eq!(r["decodedBytes"], limit);
        wire.extend(compress(b" "));
        let r = &records(false, "gzip", wire.chunks(997), &[2048], true)[0];
        assert_eq!(r["captureStatus"], "too_large");
        assert_eq!(r["bytesSeen"], wire.len());
        assert_eq!(r["decodedBytes"], limit);
    }
}
