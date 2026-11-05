// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;

/// Canonical enum names from api/extensions/v1/snipolicy.proto.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    #[serde(rename = "SNI_ACTION_TLS_TERMINATION")]
    Terminate,
    #[serde(rename = "SNI_ACTION_PASSTHROUGH")]
    Passthrough,
    #[serde(rename = "SNI_ACTION_DENY")]
    Deny,
    #[serde(skip)]
    Cleartext,
}

impl Action {
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Terminate => b"terminate",
            Self::Passthrough => b"passthrough",
            Self::Deny => b"deny",
            Self::Cleartext => b"cleartext",
        }
    }
}

/// JSON emitted by protojson.Marshal(SniTrafficPolicy). Rules retain source order.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    #[serde(default)]
    r#match: SniMatch,
    action: Action,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SniMatch {
    #[serde(default)]
    sni: Vec<String>,
    #[serde(default)]
    ports: Vec<u32>,
}

impl Policy {
    pub fn evaluate(&self, sni: Option<&str>, port: Option<u32>) -> Action {
        // This JSON crosses the CONNECT boundary. Reject a malformed policy as a
        // whole, including invalid rules after the first match.
        if self
            .rules
            .iter()
            .flat_map(|r| &r.r#match.sni)
            .any(|p| !valid_pattern(p))
            || self
                .rules
                .iter()
                .flat_map(|r| &r.r#match.ports)
                .any(|p| !(1..=65535).contains(p))
        {
            return Action::Deny;
        }
        let name = sni.unwrap_or("");
        let name = name.strip_suffix('.').unwrap_or(name);
        self.rules
            .iter()
            .find(|r| {
                (r.r#match.ports.is_empty() || port.is_some_and(|p| r.r#match.ports.contains(&p)))
                    && r.r#match.sni.iter().any(|p| pattern_matches(p, name))
            })
            .map_or(Action::Passthrough, |r| r.action)
    }
}

// Preserve Agentio/ztunnel suffix semantics: *.example.com matches a.b.example.com.
fn pattern_matches(pattern: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let pattern = pattern.strip_suffix('.').unwrap_or(pattern);
    pattern == "*"
        || pattern.eq_ignore_ascii_case(name)
        || pattern.strip_prefix('*').is_some_and(|suffix| {
            name.len() > suffix.len()
                && name
                    .get(name.len() - suffix.len()..)
                    .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
        })
}

fn valid_pattern(pattern: &str) -> bool {
    let pattern = pattern.strip_suffix('.').unwrap_or(pattern);
    if pattern == "*" {
        return true;
    }
    let name = pattern.strip_prefix("*.").unwrap_or(pattern);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORDERED: &str = r#"{"rules":[
      {"match":{"sni":["skip.example.com"]},"action":"SNI_ACTION_PASSTHROUGH"},
      {"match":{"sni":["other.test","*.Example.COM."]},"action":"SNI_ACTION_TLS_TERMINATION"},
      {"match":{"sni":["*"]},"action":"SNI_ACTION_DENY"}
    ]}"#;

    #[test]
    fn preserves_agentio_order_suffix_and_normalization() {
        let policy: Policy = serde_json::from_str(ORDERED).unwrap();
        for (name, want) in [
            ("SKIP.EXAMPLE.COM.", Action::Passthrough),
            ("www.example.com", Action::Terminate),
            ("a.b.example.com", Action::Terminate),
            ("OTHER.TEST", Action::Terminate),
            ("example.com", Action::Deny),
            ("badexample.com", Action::Deny),
            ("example.com.evil", Action::Deny),
            ("", Action::Passthrough),
        ] {
            assert_eq!(policy.evaluate(Some(name), None), want, "{name}");
        }
        assert_eq!(policy.evaluate(None, None), Action::Passthrough);
    }

    #[test]
    fn explicit_empty_and_no_match_pass_through() {
        for json in [
            "{}",
            r#"{"rules":[]}"#,
            r#"{"rules":[{"match":{"sni":["exact.test"]},"action":"SNI_ACTION_TLS_TERMINATION"}]}"#,
        ] {
            let policy: Policy = serde_json::from_str(json).unwrap();
            assert_eq!(
                policy.evaluate(Some("different.test"), None),
                Action::Passthrough
            );
        }
    }

    #[test]
    fn original_destination_port_restricts_each_ordered_match() {
        let policy: Policy = serde_json::from_str(r#"{"rules":[
          {"match":{"sni":["skip.example.com"],"ports":[443,8443]},"action":"SNI_ACTION_PASSTHROUGH"},
          {"match":{"sni":["*.example.com"],"ports":[443]},"action":"SNI_ACTION_TLS_TERMINATION"},
          {"match":{"sni":["*"]},"action":"SNI_ACTION_DENY"}
        ]}"#).unwrap();
        for (name, port, want) in [
            (Some("skip.example.com"), Some(443), Action::Passthrough),
            (Some("skip.example.com"), Some(8443), Action::Passthrough),
            (Some("skip.example.com"), Some(9443), Action::Deny),
            (Some("api.example.com"), Some(443), Action::Terminate),
            (Some("api.example.com"), Some(8443), Action::Deny),
            (Some("api.example.com"), None, Action::Deny),
            (None, Some(443), Action::Passthrough),
        ] {
            assert_eq!(policy.evaluate(name, port), want, "{name:?}:{port:?}");
        }
    }

    #[test]
    fn invalid_later_port_rejects_entire_policy() {
        for port in [0, 65536] {
            let policy: Policy = serde_json::from_value(serde_json::json!({"rules":[
                {"match":{"sni":["*"]},"action":"SNI_ACTION_PASSTHROUGH"},
                {"match":{"sni":["*"],"ports":[port]},"action":"SNI_ACTION_DENY"}
            ]}))
            .unwrap();
            assert_eq!(
                policy.evaluate(Some("api.example.com"), Some(443)),
                Action::Deny
            );
        }
    }

    #[test]
    fn invalid_contract_is_not_an_empty_policy() {
        for json in [
            r#"{"policies":[]}"#,
            r#"{"rules":[{}]}"#,
            r#"{"rules":[{"action":"SNI_ACTION_UNSPECIFIED"}]}"#,
            r#"{"rules":[{"action":"cleartext"}]}"#,
            r#"{"rules":[{"action":99}]}"#,
            r#"{"rules":[{"action":"SNI_ACTION_DENY","match":{"host":["*"]}}]}"#,
        ] {
            assert!(serde_json::from_str::<Policy>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn invalid_later_pattern_rejects_the_entire_policy() {
        for pattern in [
            "",
            "foo*",
            "*bad.example",
            "*.example..",
            "a..b",
            "-bad.test",
            "bad-.test",
            "é.test",
        ] {
            let json = serde_json::json!({"rules":[
                {"match":{"sni":["*"]},"action":"SNI_ACTION_PASSTHROUGH"},
                {"match":{"sni":[pattern]},"action":"SNI_ACTION_TLS_TERMINATION"}
            ]});
            let policy: Policy = serde_json::from_value(json).unwrap();
            assert_eq!(
                policy.evaluate(Some("allowed.test"), None),
                Action::Deny,
                "{pattern}"
            );
        }
    }
}
