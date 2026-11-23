// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use std::io::{self, Write};

pub(super) const DEFAULT_FIELD_BYTES: usize = 8 * 1024;
pub(super) const MAX_FIELD_BYTES: usize = 1 << 20;

/// Longest UTF-8 prefix whose contents fit in a compact serde_json string.
/// Delimiters are outside the string's field budget.
pub(super) fn string_prefix(text: &str, limit: usize) -> &str {
    if text.len().saturating_mul(6) <= limit {
        return text;
    }
    let mut remaining = limit;
    for (i, byte) in text.bytes().take(limit).enumerate() {
        let cost = match byte {
            b'"' | b'\\' | b'\n' | b'\r' | b'\t' | 8 | 12 => 2,
            0..32 => 6,
            _ => 1,
        };
        if remaining < cost {
            return &text[..text.floor_char_boundary(i)];
        }
        remaining -= cost;
    }
    &text[..text.floor_char_boundary(limit.min(text.len()))]
}

// Stop measuring a structured value as soon as it exceeds the field budget.
struct Remaining(usize);

impl Write for Remaining {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or(io::ErrorKind::WriteZero)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn json_bytes(value: &Value, limit: usize) -> Option<usize> {
    let mut room = Remaining(limit);
    serde_json::to_writer(&mut room, value).ok()?;
    Some(limit - room.0)
}

/// Serialized length of the array after one more complete item; zero means no items yet.
pub(super) fn array_size_with(used: usize, item: &Value, limit: usize) -> Option<usize> {
    let overhead = if used == 0 { 2 } else { used + 1 };
    Some(overhead + json_bytes(item, limit.checked_sub(overhead)?)?)
}

/// Preserve the selected JSON type. Arrays may retain a prefix of whole items;
/// objects are atomic. Only fields with an available value reach this function.
pub(super) fn bounded_value(value: &Value, limit: usize) -> (Option<Value>, bool) {
    match value {
        Value::String(text) => {
            let prefix = string_prefix(text, limit);
            (Some(prefix.into()), prefix.len() != text.len())
        }
        Value::Array(items) => {
            if limit < 2 {
                return (None, true);
            }
            let mut used = 0;
            for (i, item) in items.iter().enumerate() {
                let Some(next) = array_size_with(used, item, limit) else {
                    return ((i > 0).then(|| Value::Array(items[..i].to_vec())), true);
                };
                used = next;
            }
            (Some(value.clone()), false)
        }
        Value::Object(_) if json_bytes(value, limit).is_none() => (None, true),
        _ => (Some(value.clone()), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn string_prefix_matches_compact_json_at_every_byte_boundary() {
        let controls: String = (0u8..32).map(char::from).collect();
        let text = format!("{controls}\\\"<>&水🧪\u{2028}a");
        for budget in 0..serde_json::to_vec(&text).unwrap().len() {
            let prefix = string_prefix(&text, budget);
            let fits = |s: &str| serde_json::to_vec(s).unwrap().len() - 2 <= budget;
            assert!(fits(prefix));
            if let Some(next) = text[prefix.len()..].chars().next() {
                assert!(!fits(&format!("{prefix}{next}")));
            }
        }
    }

    #[test]
    fn structured_limits_count_the_actual_json_and_keep_types() {
        let first = json!({"tool":"<>&水"});
        let array = json!([first, {"tool":"second"}]);
        let prefix = json!([first]);
        let size = |v: &Value| serde_json::to_vec(v).unwrap().len();
        assert_eq!(
            bounded_value(&array, size(&array)),
            (Some(array.clone()), false)
        );
        assert_eq!(
            bounded_value(&array, size(&prefix)),
            (Some(prefix.clone()), true)
        );
        assert_eq!(bounded_value(&array, size(&prefix) - 1), (None, true));
        assert_eq!(bounded_value(&first, size(&first) - 1), (None, true));
        assert_eq!(bounded_value(&json!([]), 1), (None, true));
        assert_eq!(bounded_value(&json!([]), 2), (Some(json!([])), false));
    }
}
