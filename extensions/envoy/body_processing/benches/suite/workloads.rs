// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use serde_json::json;

pub(super) fn text_request(bytes: usize, sample: &str) -> String {
    let prefix = r#"{"model":"bench","messages":[{"role":"user","content":""#;
    let suffix = r#""}]}"#;
    let encoded = serde_json::to_string(sample).unwrap();
    let pattern = &encoded[1..encoded.len() - 1];
    let room = bytes - prefix.len() - suffix.len();
    format!(
        "{prefix}{}{}{suffix}",
        pattern.repeat(room / pattern.len()),
        "q".repeat(room % pattern.len())
    )
}

pub(super) fn image_request() -> String {
    let prefix = r#"{"model":"bench","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,"#;
    let suffix = r#""}},{"type":"text","text":"after-image"}]}]}"#;
    // Keep the encoded payload on a base64 boundary and pad the JSON to exactly 50 MiB.
    let room = (50 << 20) - prefix.len() - suffix.len();
    format!(
        "{prefix}{}{suffix}{}",
        "A".repeat(room / 4 * 4),
        " ".repeat(room % 4)
    )
}

pub(super) fn json_response() -> String {
    json!({"model":"bench","choices":[{"index":0,"finish_reason":"stop",
        "message":{"role":"assistant","content":"r".repeat(256 << 10)}}],
        "usage":{"prompt_tokens":11,"completion_tokens":64,"total_tokens":75}})
    .to_string()
}

pub(super) fn chat_stream() -> String {
    let mut body = String::new();
    let mut frame = |value| {
        body.push_str("data: ");
        body.push_str(&serde_json::to_string(&value).unwrap());
        body.push_str("\n\n");
    };
    frame(json!({"model":"bench","choices":[{"index":0,"delta":{"role":"assistant"}}]}));
    let text = "s".repeat(128);
    for _ in 0..64 {
        frame(json!({"model":"bench","choices":[{"index":0,"delta":{"content":text}}]}));
    }
    frame(json!({"model":"bench","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}));
    frame(
        json!({"model":"bench","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":64,"total_tokens":75}}),
    );
    body.push_str("data: [DONE]\n\n");
    body
}
