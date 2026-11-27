// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use serde_json::{Value, json};

pub(super) fn parse(part: &Value) -> Option<Value> {
    let mut image = match part["type"].as_str()? {
        "image_url" => from_url(part["image_url"]["url"].as_str()?)?,
        "input_image" => match part["file_id"].as_str() {
            Some(id) => json!({"type":"image","source":"file","fileId":id}),
            None => from_url(part["image_url"].as_str()?)?,
        },
        "image" => {
            let source = &part["source"];
            match source["type"].as_str()? {
                "url" => from_url(source["url"].as_str()?)?,
                "base64" => inline(source.get("media_type").cloned(), source["data"].as_str()),
                _ => return None,
            }
        }
        _ => return None,
    };
    if let Some(detail) = part
        .get("detail")
        .or_else(|| part["image_url"].get("detail"))
    {
        image["detail"] = detail.clone();
    }
    Some(image)
}

fn from_url(url: &str) -> Option<Value> {
    if let Some((mime, data)) = url
        .strip_prefix("data:")
        .and_then(|s| s.split_once(";base64,"))
    {
        return Some(inline(Some(mime.into()), Some(data)));
    }
    (url != "[omitted]").then(|| json!({"type":"image","source":"url","url":url}))
}

fn inline(media_type: Option<Value>, data: Option<&str>) -> Value {
    let mut image = json!({"type":"image","source":"base64"});
    if let Some(mime) = media_type {
        image["mediaType"] = mime;
    }
    if let Some(data) = data.filter(|s| *s != "[omitted]") {
        image["data"] = data.into();
    }
    image
}
