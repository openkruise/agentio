// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::capture::Capture;
use serde_json::{Value, json};

fn record(
    dir: &'static str,
    path: &str,
    media: &str,
    chunks: impl Iterator<Item = impl AsRef<[u8]>>,
    limit: usize,
    end: bool,
) -> Value {
    let settings = json!({"maxLogBytes":limit});
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
    let config: crate::Direction = serde_json::from_value(settings.clone()).unwrap();
    let limit = config.max_log_bytes;
    let mut c = Capture::new(
        dir,
        path,
        "test-id",
        media,
        "",
        config,
        (Default::default(), &Default::default()),
    );
    for chunk in chunks {
        c.push(chunk.as_ref());
    }
    let (_, out) = c.encode(end);
    assert!(out.len() < limit);
    serde_json::from_slice(&out).unwrap()
}

#[test]
fn inline_image_across_slices_keeps_following_text() {
    let image = "A".repeat(24 * 1024);
    let body = json!({"model":"m","messages":[{"role":"user","content":[
        {"type":"image_url","image_url":{"url":format!("data:image/png;base64,{image}")}},
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
        assert_eq!(r["status"], "truncated");
        let blocks = &r["content"]["inputMessages"][0]["content"];
        assert_eq!(blocks[0]["data"]["image_url"]["url"], "[omitted]");
        assert_eq!(blocks[1]["text"], "after 🧪 \" \\");
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
            let parts = &r["content"]["parts"];
            assert_eq!(parts[0]["bytes"], file.len());
            assert_eq!(parts[1]["text"], "after file");
            if size > 2048 {
                assert_eq!(r["status"], "truncated");
                assert_eq!(parts[0]["omitted"], true);
                assert!(parts[0].get("base64").is_none());
            } else {
                assert_eq!(r["status"], "complete");
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
    assert_eq!(sse["status"], "truncated");
    assert!(sse["content"].as_str().unwrap().starts_with("data: 你好"));
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
    assert_eq!(r["status"], "complete");
    assert_eq!(
        r["content"]["outputMessages"][0]["content"][0]["text"],
        "OK"
    );
    let r = record(
        "request",
        "/text",
        "text/plain",
        b"partial".chunks(3),
        1024,
        false,
    );
    assert_eq!(r["status"], "incomplete");
    let r = record(
        "request",
        "/business",
        "application/json",
        b"{broken}".chunks(1),
        1024,
        true,
    );
    assert_eq!(r["status"], "invalid_json");
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
    assert_eq!(r["status"], "truncated");
    assert_eq!(r["content"]["tail"], "visible");
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
    assert_eq!(r["status"], "truncated");
    assert_eq!(r["content"]["retainedText"], json!(["after many files"]));
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
    assert_eq!(r["content"]["id"].as_u64(), Some(9_007_199_254_740_993));
}

#[test]
fn epe_protocol_fixtures() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
    for (file, path) in [
        ("anthropic-empty-tool.sse", "/messages"),
        ("anthropic-usage.sse", "/messages"),
        ("anthropic-citations.json", "/messages"),
        ("responses-tools.sse", "/responses"),
        ("responses-refusal.sse", "/responses"),
        ("responses-truncated.json", "/responses"),
        ("responses-parallel.json", "/responses"),
        ("responses-media.json", "/responses"),
        ("chat-empty-content.sse", "/completions"),
        ("chat-truncated.json", "/completions"),
        ("chat-annotations.sse", "/completions"),
        ("chat-obfuscation.sse", "/completions"),
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
            assert_eq!(
                got["content"], expected,
                "{file}, chunk {chunk}, status {}",
                got["status"]
            );
            assert_eq!(
                got["status"],
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
    let chat = json!({"format":"openai-chat-completions","maxLogBytes":2048,"maxCaptureBytes":512,"fields":{"tools":true}});
    let input = br#"{"model":"m","messages":[{}],"tools":[]}"#;
    let r = configured_record(
        "request",
        "/custom",
        "application/vnd.agent+json",
        input.chunks(1),
        &chat,
        true,
    );
    assert_eq!(
        r["content"],
        json!({"format":"openai-chat-completions","model":"m","tools":[]})
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
            assert_eq!(r["content"]["outputMessages"][0]["index"], 0);
        } else {
            assert_eq!(r["status"], "invalid_content");
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
        )["status"],
        "unsupported_media_type"
    );
    config["maxCaptureBytes"] = json!(8);
    assert_eq!(
        configured_record(
            "request",
            "/custom",
            "application/json",
            input.chunks(3),
            &config,
            true
        )["status"],
        "too_large"
    );
}

#[test]
fn sse_limits_keep_late_usage_and_distinguish_incomplete_events() {
    let input = include_str!("../testdata/anthropic-usage.sse");
    let expected: Value =
        serde_json::from_str(include_str!("../testdata/anthropic-usage.want.json")).unwrap();
    let mut config = json!({"format":"anthropic-messages","maxLogBytes":2048,"maxCaptureBytes":4096,"maxContentBytes":2});
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
    assert_eq!(r["status"], "truncated");
    assert_eq!(r["content"]["usage"], expected["usage"]);
    assert!(r["content"].get("outputMessages").is_none());
    config["fields"] = json!({});
    let r = run(input, &config);
    assert_eq!(r["status"], "complete");
    assert_eq!(r["content"]["usage"], expected["usage"]);
    assert!(r["content"].get("outputMessages").is_none());
    assert_eq!(
        run(input.trim_end(), &config)["status"],
        "incomplete_stream"
    );
    let crlf = format!("\u{feff}: comment\r\n\r\n{}", input.replace('\n', "\r\n"));
    assert_eq!(run(&crlf, &config)["content"], r["content"]);
    config["maxCaptureBytes"] = json!(16);
    assert_eq!(run(input, &config)["status"], "too_large");
}

#[test]
fn partial_stream_still_checks_later_events() {
    let partial = include_str!("../testdata/chat-annotations.sse");
    let malformed = partial.replace("data: [DONE]", "data: {broken}");
    let r = record(
        "response",
        "/completions",
        "text/event-stream",
        malformed.as_bytes().chunks(7),
        4096,
        true,
    );
    assert_eq!(r["status"], "invalid_json");
    assert!(r["content"].is_null());
}

#[test]
fn documents_and_streams_produce_the_same_response() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
    for (provider, path) in [
        ("openai", "/completions"),
        ("responses", "/responses"),
        ("anthropic", "/messages"),
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
                assert_eq!(r["status"], "complete");
                assert_eq!(r["content"], expected, "{provider}.{suffix}, chunk {chunk}");
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
            "unsupported_encoding",
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
        let config =
            serde_json::from_value(json!({"format":format,"maxCaptureBytes":4,"maxLogBytes":1024}))
                .unwrap();
        let mut capture = Capture::new(
            "request",
            "/custom",
            "id",
            media,
            encoding,
            config,
            (Default::default(), &Default::default()),
        );
        for chunk in body.chunks(1) {
            capture.push(chunk);
        }
        let record: Value = serde_json::from_slice(&capture.encode(true).1).unwrap();
        assert_eq!(record["status"], status, "{format} {media} {body:?}");
        assert_eq!(record["content"], content);
        assert_eq!(record["bytesSeen"], body.len());
    }
}

#[test]
fn invalid_rule_or_attribute_rejects_configuration() {
    for bad in [
        json!({"rules":[{"match":{"hosts":["exa*mple.com"]},"action":"audit"}]}),
        json!({"rules":[{"match":{"hosts":[]},"action":"skip"}]}),
        json!({"rules":[{"match":{},"action":"skip","format":"auto"}]}),
        json!({"rules":[{"match":{},"action":"audit"},{"match":{},"action":"skip"}]}),
        json!({"rules":[{"match":{"filterState":[{"key":"id","present":true,"values":["x"]}]},"action":"audit"}]}),
        json!({"rules":[{"match":{"filterState":[{"key":"id","values":[]}]},"action":"audit"}]}),
        json!({"rules":[{"match":{"format":"json"},"action":"audit"}]}),
        json!({"audit":{"attributes":{"tenant":{"requestHeader":"x-tenant","filterState":"other"}}}}),
    ] {
        let mut config = bad.clone();
        config["response"] = json!({"maxLogBytes":1024});
        assert!(
            !serde_json::from_value::<crate::Settings>(config).is_ok_and(|c| c.validate().is_ok()),
            "{bad}"
        );
    }
}

#[test]
fn genai_uses_native_conversation_and_obeys_whole_line_limit() {
    let settings = serde_json::from_value(json!({"maxLogBytes":1024})).unwrap();
    let mut attrs = crate::audit::Attributes::default();
    attrs
        .values
        .insert("gen_ai.conversation.id".into(), "header-session".into());
    attrs.values.insert("tenant".into(), "tenant-a".into());
    // Escapes expand significantly in JSON even when the source fits in 1 KiB.
    attrs
        .values
        .insert("oversize".into(), "\n".repeat(700).into());
    for conversation in [json!("native"), json!({"id":"native"}), Value::Null] {
        let mut c = Capture::new(
            "request",
            "/responses",
            "id",
            "application/json",
            "",
            settings,
            (crate::audit::Schema::Genai, &attrs),
        );
        c.push(
            json!({"input":"hello","model":"m","conversation":conversation})
                .to_string()
                .as_bytes(),
        );
        let (_, line) = c.encode(true);
        assert!(line.len() < 1024);
        let record: Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(record["attributesTruncated"], true);
        let a = &record["attributes"];
        assert_eq!(
            a["gen_ai.conversation.id"],
            if conversation.is_null() {
                "header-session"
            } else {
                "native"
            }
        );
        assert_eq!(
            a["gen_ai.input.messages"][0]["parts"][0],
            json!({"type":"text","content":"hello"})
        );
        assert_eq!(a["tenant"], "tenant-a");
        assert!(a.get("oversize").is_none());
        assert_eq!(record["content"], json!({"format":"openai-responses"}));
    }
}

fn genai_record(
    direction: &'static str,
    path: &str,
    media: &str,
    body: &str,
    fields: Value,
) -> Value {
    let settings = serde_json::from_value(json!({"maxLogBytes":8192,"fields":fields})).unwrap();
    let mut c = Capture::new(
        direction,
        path,
        "req",
        media,
        "",
        settings,
        (crate::audit::Schema::Genai, &Default::default()),
    );
    for chunk in body.as_bytes().chunks(7) {
        c.push(chunk)
    }
    let (_, line) = c.encode(true);
    assert!(line.len() < 8192);
    serde_json::from_slice(&line).unwrap()
}

#[test]
fn summary_only_requests_preserve_call_result_link_and_explicit_parameters() {
    for (path, mut body) in [
        (
            "/completions",
            json!({"model":"m","max_tokens":123,"max_completion_tokens":42,"messages":[
            {"role":"assistant","tool_calls":[{"id":"c","function":{"name":"lookup","arguments":"secret"}}]},
            {"role":"tool","tool_call_id":"c","content":"secret"}]}),
        ),
        (
            "/messages",
            json!({"model":"m","max_tokens":42,"messages":[
            {"role":"assistant","content":[{"type":"tool_use","name":"lookup","id":"c","input":{"arg":"secret"}}]},
            {"role":"user","content":[{"type":"tool_result","tool_use_id":"c","content":"secret"}]}]}),
        ),
        (
            "/responses",
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
            json!({"toolCalls":true}),
        );
        assert_eq!(r["status"], "complete");
        assert!(!r.to_string().contains("secret"));
        let a = &r["attributes"];
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
        "/completions",
        "application/json",
        r#"{"model":"m","max_tokens":7,"messages":[]}"#,
        json!({}),
    );
    assert_eq!(r["attributes"]["gen_ai.request.max_tokens"], 7);
    assert!(r["attributes"].get("gen_ai.request.stream").is_none());
}

#[test]
fn metadata_and_summary_match_across_json_and_stream_when_messages_are_disabled() {
    for (path, doc, stream, id, reasons) in [
        (
            "/completions",
            include_str!("../testdata/openai.response.json"),
            include_str!("../testdata/openai.sse"),
            "chat-1",
            json!(["tool_calls", "stop"]),
        ),
        (
            "/messages",
            include_str!("../testdata/anthropic.response.json"),
            include_str!("../testdata/anthropic.sse"),
            "msg_test",
            json!(["tool_use"]),
        ),
        (
            "/responses",
            include_str!("../testdata/responses.response.json"),
            include_str!("../testdata/responses.sse"),
            "resp_1",
            Value::Null,
        ),
    ] {
        let mut doc: Value = serde_json::from_str(doc).unwrap();
        doc["id"] = id.into();
        let mut wire = stream.to_string();
        if path == "/completions" {
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
                json!({"toolCalls":true})
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
            assert_eq!(streamed["status"], "complete");
            assert_eq!(streamed["attributes"], json["attributes"], "{path}");
            assert_eq!(streamed["content"], json["content"]);
            let a = &json["attributes"];
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
        let r = genai_record("response", "/responses", media, &data, json!({}));
        assert_eq!(r["attributes"]["error.type"], "server_error");
        assert_eq!(
            r["attributes"]["agentio.response.error_code"],
            "server_error"
        );
        assert_eq!(r["attributes"]["gen_ai.response.id"], "r");
        assert_eq!(r["content"]["status"], "failed");
    }
    let incomplete = r#"{"id":"r","status":"incomplete","model":"m","output":[],"incomplete_details":{"reason":"max_output_tokens"}}"#;
    let r = genai_record(
        "response",
        "/responses",
        "application/json",
        incomplete,
        json!({}),
    );
    assert_eq!(r["content"]["incompleteReason"], "max_output_tokens");
    let r = genai_record(
        "response",
        "/messages",
        "application/json",
        r#"{"type":"error","error":{"type":"overloaded_error","message":"busy"}}"#,
        json!({}),
    );
    assert_eq!(r["attributes"]["error.type"], "overloaded_error");
    assert!(
        r["attributes"]
            .get("gen_ai.response.finish_reasons")
            .is_none()
    );
}

#[test]
fn oversized_tool_summary_keeps_independent_response_metadata() {
    let body = json!({"id":"resp-test","model":"m","status":"completed","output":[
        {"type":"function_call","call_id":"c","name":"x".repeat(1500),"arguments":"{}"}
    ]});
    let settings = serde_json::from_value(
        json!({"maxLogBytes":1024,"maxCaptureBytes":8192,"fields":{"toolCalls":true}}),
    )
    .unwrap();
    let mut c = Capture::new(
        "response",
        "/responses",
        "req",
        "application/json",
        "",
        settings,
        (crate::audit::Schema::Genai, &Default::default()),
    );
    c.push(body.to_string().as_bytes());
    let (_, line) = c.encode(true);
    assert!(line.len() < 1024);
    let r: Value = serde_json::from_slice(&line).unwrap();
    assert_eq!(r["status"], "truncated");
    assert_eq!(r["content"]["toolCallsTruncated"], true);
    assert_eq!(r["attributes"]["gen_ai.response.id"], "resp-test");
    assert!(r["attributes"].get("agentio.tool.calls").is_none());
}
