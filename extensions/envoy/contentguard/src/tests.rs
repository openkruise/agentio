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
    let mut c = Capture::new(dir, path, "test-id", media, "", limit);
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
        "/v1/messages",
        "text/event-stream",
        text.as_bytes().chunks(7),
        1024,
        true,
    );
    assert_eq!(sse["direction"], "response");
    assert_eq!(sse["status"], "truncated");
    assert!(sse["content"].as_str().unwrap().starts_with("data: 你好"));
    let doc = br#"{"choices":[{"message":{"content":"OK"}}]}"#;
    let r = record(
        "response",
        "/v1/chat/completions",
        "application/json",
        doc.chunks(2),
        4096,
        true,
    );
    assert_eq!(r["status"], "complete");
    assert_eq!(r["content"]["choices"][0]["message"]["content"], "OK");
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
