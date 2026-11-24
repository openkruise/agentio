// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::parser::BodyError;
use crate::parser::llm::{ANTHROPIC, CHAT, RESPONSES, blocks, chat_message, responses_item};
use serde_json::{Value, json};

pub(crate) type Result<T> = std::result::Result<T, BodyError>;

pub(crate) fn index(v: &Value) -> Result<u32> {
    v.as_f64()
        .filter(|n| (0.0..=i32::MAX as f64).contains(n) && n.fract() == 0.0)
        .map(|n| n as u32)
        .ok_or(BodyError::InvalidContent)
}

fn opt_string(view: &mut Value, to: &str, from: &Value) -> Result<()> {
    if !from.is_null() {
        view[to] = from.as_str().ok_or(BodyError::InvalidContent)?.into();
    }
    Ok(())
}

fn copy_count(dst: &mut Value, key: &str, value: &Value) {
    if value.is_number() {
        dst[key] = value.clone();
    }
}

fn sum(values: &[&Value]) -> Value {
    if let Some(total) = values
        .iter()
        .try_fold(0_u64, |n, v| n.checked_add(v.as_u64()?))
    {
        Value::from(total)
    } else {
        Value::from(values.iter().filter_map(|v| v.as_f64()).sum::<f64>())
    }
}

pub(crate) fn usage_counts(format: &str, u: &Value) -> Value {
    let mut out = json!({});
    let (input, output, ind, outd) = if format == CHAT {
        (
            "prompt_tokens",
            "completion_tokens",
            "prompt_tokens_details",
            "completion_tokens_details",
        )
    } else if format == ANTHROPIC {
        (
            "input_tokens",
            "output_tokens",
            "prompt_tokens_details",
            "completion_tokens_details",
        )
    } else {
        (
            "input_tokens",
            "output_tokens",
            "input_tokens_details",
            "output_tokens_details",
        )
    };
    copy_count(&mut out, "inputTokens", &u[input]);
    copy_count(&mut out, "outputTokens", &u[output]);
    if format == ANTHROPIC {
        copy_count(&mut out, "cachedInputTokens", &u["cache_read_input_tokens"]);
        copy_count(
            &mut out,
            "cacheCreationInputTokens",
            &u["cache_creation_input_tokens"],
        );
    } else {
        copy_count(&mut out, "totalTokens", &u["total_tokens"]);
    }
    copy_count(&mut out, "cachedInputTokens", &u[ind]["cached_tokens"]);
    copy_count(&mut out, "reasoningTokens", &u[outd]["reasoning_tokens"]);
    if format == RESPONSES {
        copy_count(
            &mut out,
            "cacheCreationInputTokens",
            &u[ind]["cache_write_tokens"],
        );
    }
    out
}

pub(crate) fn anthropic_totals(out: &mut Value) {
    if out.get("inputTokens").is_some() {
        let zero = Value::from(0);
        out["inputTokens"] = sum(&[
            &out["inputTokens"],
            out.get("cachedInputTokens").unwrap_or(&zero),
            out.get("cacheCreationInputTokens").unwrap_or(&zero),
        ]);
        if out.get("outputTokens").is_some() {
            out["totalTokens"] = sum(&[&out["inputTokens"], &out["outputTokens"]]);
        }
    }
}

pub(crate) fn usage(format: &str, raw: &Value) -> Value {
    let mut counts = usage_counts(format, raw);
    if format == ANTHROPIC {
        anthropic_totals(&mut counts);
    }
    counts
}

pub(crate) fn metadata(format: &str, doc: &Value) -> Result<Value> {
    if !doc.is_object() {
        return Err(BodyError::InvalidContent);
    }
    let mut view = json!({"format":format});
    if let Some(error) = doc.get("error")
        && (format != RESPONSES || !error.is_null())
    {
        view["error"] = error.clone();
        if format != RESPONSES {
            return Ok(view);
        }
    }
    opt_string(&mut view, "model", &doc["model"])?;
    if view.get("model").is_none() && view.get("error").is_none() {
        return Err(BodyError::InvalidContent);
    }
    if doc["usage"].is_object() {
        view["usage"] = usage(format, &doc["usage"]);
    }
    if format == ANTHROPIC && !doc["stop_reason"].is_null() {
        doc["stop_reason"]
            .as_str()
            .ok_or(BodyError::InvalidContent)?;
    }
    if format == RESPONSES {
        opt_string(&mut view, "status", &doc["status"])?;
        opt_string(
            &mut view,
            "incompleteReason",
            &doc["incomplete_details"]["reason"],
        )?;
    }
    Ok(view)
}

pub(crate) fn normalize(format: &str, doc: &Value, output: bool) -> Result<Value> {
    let mut view = metadata(format, doc)?;
    if view.get("error").is_some() && (format != RESPONSES || !doc["output"].is_array()) {
        return Ok(view);
    }
    let collection = match format {
        CHAT => "choices",
        ANTHROPIC => "content",
        RESPONSES => "output",
        _ => return Err(BodyError::InvalidContent),
    };
    doc[collection]
        .as_array()
        .ok_or(BodyError::InvalidContent)?;
    if !output {
        return Ok(view);
    }
    let mut messages = vec![];
    match format {
        CHAT => {
            for choice in doc["choices"].as_array().ok_or(BodyError::InvalidContent)? {
                let mut m = chat_message(&choice["message"], format)?;
                m["index"] = index(&choice["index"])?.into();
                opt_string(&mut m, "finishReason", &choice["finish_reason"])?;
                messages.push(m);
            }
            messages.sort_by_key(|m| m["index"].as_u64());
        }
        ANTHROPIC => {
            doc["content"].as_array().ok_or(BodyError::InvalidContent)?;
            let mut m =
                json!({"index":0,"role":"assistant","content":blocks(&doc["content"],format)});
            opt_string(&mut m, "finishReason", &doc["stop_reason"])?;
            messages.push(m);
        }
        RESPONSES => {
            for (i, item) in doc["output"]
                .as_array()
                .ok_or(BodyError::InvalidContent)?
                .iter()
                .enumerate()
            {
                let mut m = responses_item(item)?;
                m["index"] = i.into();
                messages.push(m);
            }
        }
        _ => return Err(BodyError::InvalidContent),
    }
    view["outputMessages"] = messages.into();
    Ok(view)
}
