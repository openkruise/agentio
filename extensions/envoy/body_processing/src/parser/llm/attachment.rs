// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use serde_json::{Value, json};

// Keep the provider part intact. inlineData maps JSON pointers in data to the
// prefix before the payload, so consumers can omit bytes without losing metadata.
pub(super) fn content_part(part: &Value, format: &str) -> Value {
    if let Some(image) = super::image::parse(part) {
        return image;
    }
    let (kind, payload, url) = match part["type"].as_str() {
        Some("input_file") => ("file", Some("/file_data"), Some("/file_url")),
        Some("file") => ("file", Some("/file/file_data"), None),
        Some("input_audio") => ("audio", Some("/input_audio/data"), None),
        Some("document") => (
            "document",
            (part["source"]["type"] == "base64").then_some("/source/data"),
            None,
        ),
        Some("computer_screenshot") => ("screenshot", None, Some("/image_url")),
        _ => return super::provider(part, format),
    };
    let mut block = json!({"type":"attachment","kind":kind,"format":format,"data":part});
    for path in payload.into_iter().chain(url) {
        let Some(value) = part.pointer(path).and_then(Value::as_str) else {
            continue;
        };
        if Some(path) == url && !value.starts_with("data:") {
            continue;
        }
        let prefix_len = data_uri_prefix(value.as_bytes()).len();
        let (prefix, data) = value.split_at(prefix_len);
        if data != "[omitted]" {
            block["inlineData"][path] = prefix.into();
        }
    }
    block
}

// The input can be a prefix of a large JSON string. Keep a bounded, unescaped
// MIME header when replacing its base64 data.
pub(crate) fn data_uri_prefix(value: &[u8]) -> &[u8] {
    if let Some(rest) = value.strip_prefix(b"data:")
        && let Some(end) = rest.iter().take(129).position(|&b| b == b',')
        && rest[..end].ends_with(b";base64")
        && rest[..end]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"/.+-;".contains(b))
    {
        return &value[..5 + end + 1];
    }
    &[]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::llm::RESPONSES;

    #[test]
    fn screenshot_events_distinguish_inline_data_from_references() {
        for (field, value, inline) in [
            ("image_url", "data:image/png;base64,YQ==", true),
            ("image_url", "https://example.test/screen.png", false),
            ("file_id", "file-42", false),
            ("image_url", "data:image/png;base64,[omitted]", false),
        ] {
            let raw = json!({"type":"computer_screenshot",(field):value,"detail":"original"});
            let input = json!({"type":"computer_call_output","call_id":"c1","output":raw});
            let message = crate::parser::llm::responses_item(&input).unwrap();
            let block = &message["content"][0]["content"][0];
            assert_eq!(block["type"], "attachment");
            assert_eq!(block["kind"], "screenshot");
            assert_eq!(block["format"], RESPONSES);
            assert_eq!(block["data"], raw);
            assert_eq!(
                block.get("inlineData"),
                inline
                    .then(|| json!({"/image_url":"data:image/png;base64,"}))
                    .as_ref()
            );
        }
    }
}
