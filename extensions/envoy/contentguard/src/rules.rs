// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::{Format, Settings};
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyHttpFilter;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(rename = "match")]
    conditions: Conditions,
    action: Action,
    format: Option<Format>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Action {
    Audit,
    Skip,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
#[derive(Default)]
struct Conditions {
    hosts: Option<Vec<String>>,
    filter_state: Option<Vec<StateMatch>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateMatch {
    key: String,
    present: Option<bool>,
    values: Option<Vec<String>>,
}

fn hostname(authority: &str) -> &str {
    if let Some((host, port)) = authority.rsplit_once(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
        && (!host.contains(':') || host.ends_with(']'))
    {
        return host;
    }
    authority
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.len() > suffix.len() + 1
            && host
                .get(host.len() - suffix.len()..)
                .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
    } else {
        host.eq_ignore_ascii_case(pattern)
    }
}

impl Settings {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.request.is_none() && self.response.is_none() {
            return Err("configure request or response");
        }
        for d in [self.request, self.response].into_iter().flatten() {
            if !(1024..=1048576).contains(&d.max_log_bytes)
                || [d.max_capture_bytes, d.max_content_bytes]
                    .into_iter()
                    .flatten()
                    .any(|n| !(1..=64 << 20).contains(&n))
            {
                return Err(
                    "maxLogBytes must be 1024..1048576 and capture/content limits 1..67108864",
                );
            }
        }
        for (i, rule) in self.rules.iter().enumerate() {
            let c = &rule.conditions;
            if c.hosts.is_none() && c.filter_state.is_none() && i + 1 != self.rules.len() {
                return Err("a catch-all match must be last");
            }
            if matches!(rule.action, Action::Skip) && rule.format.is_some() {
                return Err("skip rules cannot set format");
            }
            if let Some(hosts) = &c.hosts
                && (hosts.is_empty()
                    || hosts.iter().any(|p| {
                        let h = p.strip_prefix("*.").unwrap_or(p);
                        if !p.starts_with("*.") && h.starts_with('[') && h.ends_with(']') {
                            return h[1..h.len() - 1].parse::<std::net::Ipv6Addr>().is_err();
                        }
                        h.split('.').any(|label| {
                            label.is_empty()
                                || !label
                                    .bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                        })
                    }))
            {
                return Err("hosts must contain exact hostnames or *.suffix patterns");
            }
            if let Some(states) = &c.filter_state
                && (states.is_empty()
                    || states.iter().any(|s| {
                        let valid = match (s.present, &s.values) {
                            (Some(true), None) => true,
                            (None, Some(values)) => !values.is_empty(),
                            _ => false,
                        };
                        s.key.is_empty() || !valid
                    }))
            {
                return Err("filterState needs a key and either present:true or non-empty values");
            }
        }
        self.audit.validate()
    }

    // Outer None skips the stream. Inner None retains each direction's own format.
    pub fn select(&self, envoy: &impl EnvoyHttpFilter) -> Option<Option<Format>> {
        if self.rules.is_empty() {
            return Some(None);
        }
        let authority = envoy.get_request_header_value(":authority");
        let host = authority
            .as_ref()
            .and_then(|s| std::str::from_utf8(s.as_slice()).ok())
            .map(hostname);
        let rule = self.rules.iter().find(|rule| {
            let c = &rule.conditions;
            c.hosts
                .as_ref()
                .is_none_or(|hosts| host.is_some_and(|h| hosts.iter().any(|p| host_matches(p, h))))
                && c.filter_state.iter().flatten().all(|s| {
                    if let Some(values) = &s.values {
                        envoy
                            .get_filter_state_typed(s.key.as_bytes())
                            .is_some_and(|v| values.iter().any(|p| p.as_bytes() == v.as_slice()))
                    } else {
                        envoy.has_filter_state(s.key.as_bytes())
                    }
                })
        })?;
        matches!(rule.action, Action::Audit).then_some(rule.format)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_authority_without_port_and_at_label_boundary() {
        assert!(host_matches("*.llm.test", hostname("A.b.LLM.test:443")));
        assert!(!host_matches("*.llm.test", hostname("llm.test:443")));
        assert!(!host_matches("*.llm.test", "badllm.test"));
        assert!(host_matches("llm.test", hostname("LLM.test:80")));
        assert!(host_matches("[::1]", hostname("[::1]:8443")));
    }
}
