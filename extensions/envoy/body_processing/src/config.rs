// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::filters::ConfiguredFilter;
use crate::{
    filters::audit::{Audit, Direction, Directions},
    parser::Format,
};
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyHttpFilter;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};

const DEFAULT_MAX_LOG_BYTES: usize = 8 * 1024;

// Wire configuration is resolved once when Envoy loads the filter.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ModuleConfig {
    filter_chains: Vec<ChainConfig>,
}

#[derive(Deserialize)]
#[serde(untagged, expecting = "a byte count or a size such as 16KiB")]
enum SizeValue {
    Bytes(usize),
    Quantity(String),
}

#[derive(Deserialize)]
#[serde(try_from = "SizeValue")]
struct LogSize(usize);

impl SizeValue {
    fn bytes(self) -> Result<usize, &'static str> {
        match self {
            SizeValue::Bytes(n) => Ok(n),
            SizeValue::Quantity(raw) => {
                let raw = raw.trim();
                let end = raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len());
                let (digits, unit) = raw.split_at(end);
                if digits.is_empty() {
                    return Err(
                        "size requires an unsigned integer, optionally followed by a size unit",
                    );
                }
                let scale = match unit.trim_start() {
                    "" | "B" => 1,
                    "KB" | "kB" => 1000,
                    "MB" => 1_000_000,
                    "Ki" | "KiB" => 1024,
                    "Mi" | "MiB" => 1024 * 1024,
                    _ => return Err("unknown size unit (use B, KB, KiB, MB or MiB)"),
                };
                digits
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| n.checked_mul(scale))
                    .ok_or("byte count overflows usize")
            }
        }
    }
}

impl TryFrom<SizeValue> for LogSize {
    type Error = &'static str;

    fn try_from(value: SizeValue) -> Result<Self, Self::Error> {
        let bytes = value.bytes()?;
        if !(1024..=1024 * 1024).contains(&bytes) {
            return Err("maxSize must be between 1 KiB and 1 MiB");
        }
        Ok(Self(bytes))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainConfig {
    name: String,
    #[serde(default)]
    matcher: Conditions,
    parser: ParserConfig,
    filters: Vec<FilterConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum FilterConfig {
    Audit(AuditConfig),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AuditConfig {
    max_size: Option<LogSize>,
    format: AuditFormat,
    request: Option<DirectionConfig>,
    response: Option<DirectionConfig>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditFormat {
    json: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
enum ParserConfig {
    Llm {
        #[serde(default)]
        protocol: Protocol,
        #[serde(default)]
        request: RequestParserConfig,
    },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RequestParserConfig {
    #[serde(deserialize_with = "item_size")]
    pub max_item_size: usize,
}

impl Default for RequestParserConfig {
    fn default() -> Self {
        Self {
            max_item_size: 1 << 20,
        }
    }
}

fn item_size<'de, D: serde::Deserializer<'de>>(d: D) -> Result<usize, D::Error> {
    use serde::de::Error;
    let bytes = SizeValue::deserialize(d)?
        .bytes()
        .map_err(D::Error::custom)?;
    if !(1024..=64 << 20).contains(&bytes) {
        return Err(D::Error::custom(
            "maxItemSize must be between 1 KiB and 64 MiB",
        ));
    }
    Ok(bytes)
}

#[derive(Copy, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Protocol {
    #[default]
    Auto,
    OpenaiChatCompletions,
    OpenaiResponses,
    AnthropicMessages,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DirectionConfig {
    max_size: Option<LogSize>,
    max_capture_bytes: Option<usize>,
    max_content_bytes: Option<usize>,
}

impl DirectionConfig {
    fn resolve(self, default_limit: usize) -> Result<Direction, String> {
        let limit = self.max_size.map_or(default_limit, |s| s.0);
        if [self.max_capture_bytes, self.max_content_bytes]
            .into_iter()
            .flatten()
            .any(|v| !(1..=64 << 20).contains(&v))
        {
            return Err("capture/content limits must be 1..67108864".into());
        }
        Ok(Direction {
            format: Format::UnknownProtocol,
            fields: Default::default(),
            max_log_bytes: limit,
            max_capture_bytes: self.max_capture_bytes,
            max_content_bytes: self.max_content_bytes,
        })
    }
}

impl Directions {
    fn resolve(
        request: Option<DirectionConfig>,
        response: Option<DirectionConfig>,
        limit: usize,
    ) -> Result<Self, String> {
        if request.is_none() && response.is_none() {
            return Err("audit requires a request or response direction".into());
        }
        Ok(Self {
            request: request.map(|v| v.resolve(limit)).transpose()?,
            response: response.map(|v| v.resolve(limit)).transpose()?,
        })
    }
}

pub struct FilterChain {
    pub name: std::sync::Arc<str>,
    matcher: Conditions,
    parser: ParserConfig,
    pub filters: Vec<ConfiguredFilter>,
}

impl FilterChain {
    pub fn request_parser(&self) -> RequestParserConfig {
        let ParserConfig::Llm { request, .. } = self.parser;
        request
    }

    pub fn format(&self, path: &str) -> Format {
        let ParserConfig::Llm { protocol, .. } = self.parser;
        match protocol {
            Protocol::Auto => Format::from_path(path),
            Protocol::OpenaiChatCompletions => Format::OpenaiChatCompletions,
            Protocol::OpenaiResponses => Format::OpenaiResponses,
            Protocol::AnthropicMessages => Format::AnthropicMessages,
        }
    }
}

pub struct Settings {
    chains: Vec<FilterChain>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Conditions {
    hosts: Option<Vec<String>>,
    paths: Option<Vec<String>>,
    filter_state: Option<Vec<StateMatch>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateMatch {
    key: String,
    #[serde(default, deserialize_with = "state_values")]
    values: Option<Vec<String>>,
}

// Omission tests existence. An explicitly supplied values field requires a list.
fn state_values<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Vec<String>>, D::Error> {
    Vec::deserialize(d).map(Some)
}

pub(crate) fn match_path(path: &str) -> &str {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    if path.len() > 1 {
        path.strip_suffix('/').unwrap_or(path)
    } else {
        path
    }
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
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let config: ModuleConfig = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let count = config.filter_chains.len();
        let mut chains = Vec::with_capacity(count);
        let mut names = HashSet::with_capacity(count);
        for (i, chain) in config.filter_chains.into_iter().enumerate() {
            if chain.name.trim().is_empty() || !names.insert(chain.name.clone()) {
                return Err(format!(
                    "filterChains[{i}] requires a nonempty, unique name"
                ));
            }
            // The chain identifier is included even in a minimum-size (1 KiB) record.
            if serde_json::to_string(&chain.name).unwrap().len() > 256 {
                return Err(format!(
                    "filterChains[{i}].name exceeds 256 serialized bytes"
                ));
            }
            let mut c = chain.matcher;
            if c.hosts.is_none() && c.paths.is_none() && c.filter_state.is_none() && i + 1 != count
            {
                return Err("a catch-all match must be last".into());
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
                return Err("hosts must contain exact hostnames or *.suffix patterns".into());
            }
            if let Some(paths) = &mut c.paths {
                if paths.is_empty()
                    || paths
                        .iter()
                        .any(|p| !p.starts_with('/') || p.contains(['?', '#', '*']))
                {
                    return Err(format!(
                        "filterChains[{i}].matcher.paths requires absolute, exact paths without a query or fragment"
                    ));
                }
                for path in paths {
                    path.truncate(match_path(path).len());
                }
            }
            if let Some(states) = &c.filter_state
                && (states.is_empty()
                    || states
                        .iter()
                        .any(|s| s.key.is_empty() || s.values.as_ref().is_some_and(Vec::is_empty)))
            {
                return Err(format!(
                    "filterChains[{i}].matcher.filterState requires a key and, when specified, non-empty values"
                ));
            }
            if chain.filters.is_empty() {
                return Err(format!(
                    "filterChains[{i}].filters requires at least one filter"
                ));
            }
            let mut filters = Vec::with_capacity(chain.filters.len());
            for (j, filter) in chain.filters.into_iter().enumerate() {
                let FilterConfig::Audit(audit) = filter;
                let audit_limit = audit.max_size.map_or(DEFAULT_MAX_LOG_BYTES, |s| s.0);
                let location = || format!("filterChains[{i}].filters[{j}].audit");
                let directions = Directions::resolve(audit.request, audit.response, audit_limit)
                    .map_err(|e| format!("{}: {e}", location()))?;
                filters.push(ConfiguredFilter::Audit(
                    Audit::compile(audit.format.json, directions)
                        .map_err(|e| format!("{}: {e}", location()))?,
                ));
            }
            chains.push(FilterChain {
                name: chain.name.into(),
                matcher: c,
                parser: chain.parser,
                filters,
            });
        }
        Ok(Self { chains })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }

    pub fn select(&self, envoy: &impl EnvoyHttpFilter, path: &str) -> Option<&FilterChain> {
        let authority = envoy.get_request_header_value(":authority");
        let host = authority
            .as_ref()
            .and_then(|s| std::str::from_utf8(s.as_slice()).ok())
            .map(hostname);
        self.chains.iter().find(|chain| {
            let c = &chain.matcher;
            c.hosts
                .as_ref()
                .is_none_or(|hosts| host.is_some_and(|h| hosts.iter().any(|p| host_matches(p, h))))
                && c.paths
                    .as_ref()
                    .is_none_or(|paths| paths.iter().any(|p| p == path))
                && c.filter_state.iter().flatten().all(|s| {
                    if let Some(values) = &s.values {
                        envoy
                            .get_filter_state_typed(s.key.as_bytes())
                            .is_some_and(|v| values.iter().any(|p| p.as_bytes() == v.as_slice()))
                    } else {
                        envoy.has_filter_state(s.key.as_bytes())
                    }
                })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_protocol_owns_both_directions() {
        use serde_json::json;
        for (protocol, path, format) in [
            ("auto", "/v1/messages/?v=1", Format::AnthropicMessages),
            (
                "auto",
                "/v1/chat/completions",
                Format::OpenaiChatCompletions,
            ),
            ("auto", "/v1/responses", Format::OpenaiResponses),
            ("auto", "/internal/messages", Format::UnknownProtocol),
            ("openai-responses", "/invoke", Format::OpenaiResponses),
        ] {
            let cfg = json!({"filterChains":[{"name":"model",
                "parser":{"llm":{"protocol":protocol}}, "filters":[{"audit":{"format":{"json":{}},"response":{}}}]}]});
            let settings = Settings::parse(cfg.to_string().as_bytes()).unwrap();
            let chain = &settings.chains[0];
            assert!(chain.format(match_path(path)) == format);
            let ConfiguredFilter::Audit(audit) = &chain.filters[0];
            assert!(audit.directions.request.is_none());
            assert_eq!(audit.directions.response.unwrap().max_log_bytes, 8192);
        }
    }

    #[test]
    fn llm_selectors_are_qualified_and_directional() {
        use serde_json::json;
        let audit = json!({
            "request": {}, "response": {}, "format":{"json":{
                "msgs":"%EVENT(llm.messages)%","ask":"%EVENT(llm.question)%","reply":"%EVENT(llm.answer)%",
                "tools":"%EVENT(llm.toolDefinitions)%","calls":"%EVENT(llm.toolCallRefs)%"
            }}
        });
        let parse = |audit: &serde_json::Value| {
            let config = json!({"filterChains": [{"name": "models", "parser": {"llm": {}}, "filters": [{"audit": audit}]}]});
            Settings::parse(config.to_string().as_bytes())
        };
        let settings = parse(&audit).unwrap();
        let ConfiguredFilter::Audit(resolved) = &settings.chains[0].filters[0];
        let req = resolved.directions.request.unwrap().fields;
        let res = resolved.directions.response.unwrap().fields;
        assert!(req.input_messages && req.question && req.tools && req.tool_call_refs);
        assert!(res.output_messages && res.answer && res.tool_call_refs);
        for invalid in ["answer", "http.answer", "llm.question"] {
            let audit = json!({"response":{}, "format":{"json":{"selected":format!("%EVENT({invalid})%")}}});
            let error = parse(&audit).err().unwrap();
            assert!(error.contains(invalid), "{error}");
        }
    }

    #[test]
    fn log_sizes_resolve_in_bytes_at_config_load() {
        use serde_json::json;
        for (size, bytes) in [
            (json!(1024), 1024),
            (json!("1024 B"), 1024),
            (json!("2KB"), 2000),
            (json!("16Ki"), 16384),
            (json!("2 KiB"), 2048),
            (json!("1MB"), 1_000_000),
            (json!("1MiB"), 1_048_576),
            (json!("1Mi"), 1_048_576),
        ] {
            let cfg = json!({"filterChains":[{"name":"test","parser":{"llm":{}},
                "filters":[{"audit":{"format":{"json":{}},"maxSize":size,"request":{},"response":{"maxSize":"3KB"}}}]}]});
            let settings = Settings::parse(cfg.to_string().as_bytes()).unwrap();
            let ConfiguredFilter::Audit(audit) = &settings.chains[0].filters[0];
            let dirs = audit.directions;
            assert_eq!(dirs.request.unwrap().max_log_bytes, bytes);
            assert_eq!(dirs.response.unwrap().max_log_bytes, 3000);
        }
        for invalid in [
            json!("1KB"),
            json!("2MiB"),
            json!("1.5KiB"),
            json!("8Kb/s"),
            json!("99999999999999999999MiB"),
            json!(-1),
        ] {
            assert!(serde_json::from_value::<LogSize>(invalid).is_err());
        }
    }

    #[test]
    fn request_item_size_resolves_independently_of_audit_limits() {
        use serde_json::json;
        let resolve = |llm| {
            let config = json!({"filterChains":[{"name":"models","parser":{"llm":llm},
                "filters":[{"audit":{"format":{"json":{}},"request":{"maxSize":"2KiB"}}}]}]});
            Settings::parse(config.to_string().as_bytes())
                .map(|s| s.chains[0].request_parser().max_item_size)
        };
        for llm in [json!({}), json!({"request":{}})] {
            assert_eq!(resolve(llm).unwrap(), 1 << 20);
        }
        for (size, bytes) in [
            (json!(1024), 1024),
            (json!("2MB"), 2_000_000),
            (json!("2MiB"), 2 << 20),
            (json!("64MiB"), 64 << 20),
        ] {
            assert_eq!(
                resolve(json!({"request":{"maxItemSize":size}})).unwrap(),
                bytes
            );
        }
        for size in [json!(1023), json!("65MiB"), json!("1.5MiB"), json!("4Mb/s")] {
            assert!(resolve(json!({"request":{"maxItemSize":size}})).is_err());
        }
        assert!(resolve(json!({"response":{"maxItemSize":"2MiB"}})).is_err());
    }

    #[test]
    fn directions_inherit_their_own_audit_size() {
        let config = serde_json::json!({
            "filterChains": [{
                "name": "models",
                "parser": {"llm": {}},
                "filters": [
                    {"audit": {"format":{"json":{}}, "maxSize": "4KiB", "request": {"maxSize": "16KiB"}, "response": {}}},
                    {"audit": {"format":{"json":{}}, "request": {}}}
                ]
            }]
        });
        let settings = Settings::parse(config.to_string().as_bytes()).unwrap();
        let [
            ConfiguredFilter::Audit(first),
            ConfiguredFilter::Audit(second),
        ] = &settings.chains[0].filters[..]
        else {
            panic!("expected two audits")
        };
        assert_eq!(first.directions.request.unwrap().max_log_bytes, 16384);
        assert_eq!(first.directions.response.unwrap().max_log_bytes, 4096);
        assert_eq!(second.directions.request.unwrap().max_log_bytes, 8192);
    }

    #[test]
    fn match_authority_without_port_and_at_label_boundary() {
        assert!(host_matches("*.llm.test", hostname("A.b.LLM.test:443")));
        assert!(!host_matches("*.llm.test", hostname("llm.test:443")));
        assert!(!host_matches("*.llm.test", "badllm.test"));
        assert!(host_matches("llm.test", hostname("LLM.test:80")));
        assert!(host_matches("[::1]", hostname("[::1]:8443")));
    }
}
