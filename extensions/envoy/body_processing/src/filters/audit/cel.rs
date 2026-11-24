// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use cel_core::{Activation, CelType, Env, EvalErrorKind, MapKey, Program, Value, ValueMap};
use std::sync::LazyLock;

const HEADERS: &str = "request.headers";
static ENV: LazyLock<Env> = LazyLock::new(|| {
    Env::with_standard_library()
        .with_variable(HEADERS, CelType::map(CelType::String, CelType::String))
});

pub(super) fn compile(expression: &str) -> Result<Program, String> {
    let ast = ENV.compile(expression).map_err(|e| e.to_string())?;
    match ast.result_type() {
        Some(
            CelType::String
            | CelType::Bool
            | CelType::Int
            | CelType::UInt
            | CelType::Double
            | CelType::Null
            | CelType::Dyn,
        ) => {}
        other => return Err(format!("expected a scalar log field, got {other:?}")),
    }
    ENV.program(&ast).map_err(|e| e.to_string())
}

/// Shared by the CEL columns evaluated in one request-headers callback.
pub(crate) struct Headers(Value);

impl Headers {
    pub(super) fn from_pairs<'a>(pairs: impl Iterator<Item = (&'a [u8], &'a [u8])>) -> Self {
        let mut headers = ValueMap::new();
        for (name, value) in pairs {
            // Envoy supplies lowercase keys. For repeated headers, %REQ also reads the first.
            let key = MapKey::from(String::from_utf8_lossy(name).as_ref());
            if !headers.contains_key(&key) {
                headers.insert(key, Value::from(String::from_utf8_lossy(value).as_ref()));
            }
        }
        Self(Value::Map(headers.into()))
    }
}

impl Activation for Headers {
    fn resolve(&self, name: &str) -> Option<Value> {
        (name == HEADERS).then(|| self.0.clone())
    }
}

impl super::Attributes {
    pub(super) fn capture_cel(
        &mut self,
        alias: &str,
        limit: usize,
        program: &Program,
        headers: &Headers,
    ) -> Result<(), EvalErrorKind> {
        match program.eval(headers) {
            Value::String(value) => self.insert(alias, &value, limit),
            Value::Bool(value) => self.insert(alias, if value { "true" } else { "false" }, limit),
            Value::Int(value) => self.insert(alias, &value.to_string(), limit),
            Value::UInt(value) => self.insert(alias, &value.to_string(), limit),
            Value::Double(value) => self.insert(alias, &value.to_string(), limit),
            Value::Null => {}
            Value::Error(error) if error.kind == EvalErrorKind::KeyNotFound => {}
            Value::Error(error) => return Err(error.kind),
            _ => return Err(EvalErrorKind::TypeMismatch),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_expressions_use_the_first_value_and_the_audit_field_limit() {
        let input = Headers::from_pairs(
            [
                (b"id".as_slice(), "雪a".as_bytes()),
                (b"id", b"second"),
                (b"empty", b""),
            ]
            .into_iter(),
        );
        let mut attrs = super::super::Attributes::default();
        for (alias, expr, limit) in [
            ("first", "request.headers['id']", 3),
            ("len", "size(request.headers['id'])", 8),
            ("empty", "request.headers['empty']", 8),
            ("missing", "request.headers['absent']", 8),
            ("null", "null", 8),
            ("contains", "request.headers['id'].startsWith('雪')", 8),
        ] {
            attrs
                .capture_cel(alias, limit, &compile(expr).unwrap(), &input)
                .unwrap();
        }
        assert_eq!(
            serde_json::Value::Object(attrs.values.clone()),
            serde_json::json!({"first":"雪","len":"2","empty":"","contains":"true"})
        );
        assert!(attrs.truncated);
        assert_eq!(
            attrs.capture_cel(
                "bad",
                32,
                &compile("int(request.headers['id'])").unwrap(),
                &input
            ),
            Err(EvalErrorKind::InvalidConversion)
        );
        assert!(!attrs.values.contains_key("bad"));
    }
}
