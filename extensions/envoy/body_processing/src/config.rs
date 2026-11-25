// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::filters::ConfiguredFilter;
use crate::{
    filters::audit::Audit,
    parser::{Format, llm::ProtocolSelection},
};
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyHttpFilter;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};

const DEFAULT_PARSER_BYTES: usize = 1 << 20;

// Wire configuration is resolved once when Envoy loads the filter.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ModuleConfig {
    #[serde(default)]
    filter_chains: Vec<ChainConfig>,
}

#[derive(Deserialize)]
#[serde(untagged, expecting = "a byte count or a size such as 16KiB")]
enum SizeValue {
    Bytes(usize),
    Quantity(String),
}

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
    format: AuditFormat,
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
        protocol: ProtocolSelection,
        #[serde(default)]
        request: RequestParserConfig,
        #[serde(default)]
        response: ResponseParserConfig,
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
            max_item_size: DEFAULT_PARSER_BYTES,
        }
    }
}

fn item_size<'de, D: serde::Deserializer<'de>>(d: D) -> Result<usize, D::Error> {
    parser_size(d, "maxItemSize")
}

#[derive(Clone, Copy, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ResponseParserConfig {
    #[serde(deserialize_with = "content_size")]
    pub max_content_size: usize,
}

impl Default for ResponseParserConfig {
    fn default() -> Self {
        Self {
            max_content_size: DEFAULT_PARSER_BYTES,
        }
    }
}

fn content_size<'de, D: serde::Deserializer<'de>>(d: D) -> Result<usize, D::Error> {
    parser_size(d, "maxContentSize")
}

fn parser_size<'de, D: serde::Deserializer<'de>>(d: D, field: &str) -> Result<usize, D::Error> {
    use serde::de::Error;
    let bytes = SizeValue::deserialize(d)?
        .bytes()
        .map_err(D::Error::custom)?;
    if !(1024..=(64 << 20)).contains(&bytes) {
        return Err(D::Error::custom(format!(
            "{field} must be between 1 KiB and 64 MiB"
        )));
    }
    Ok(bytes)
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

    pub fn response_parser(&self) -> ResponseParserConfig {
        let ParserConfig::Llm { response, .. } = self.parser;
        response
    }

    pub fn format(&self, path: &str) -> Format {
        let ParserConfig::Llm { protocol, .. } = self.parser;
        protocol.resolve(path)
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
    let host = if let Some((host, port)) = authority.rsplit_once(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
        && (!host.contains(':') || host.ends_with(']'))
    {
        host
    } else {
        authority
    };
    dns_name(host)
}

fn dns_name(host: &str) -> &str {
    if host.starts_with('[') {
        host
    } else {
        host.strip_suffix('.').unwrap_or(host)
    }
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
            if let Some(hosts) = &mut c.hosts {
                for host in hosts {
                    host.truncate(dns_name(host).len());
                }
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
                let location = || format!("filterChains[{i}].filters[{j}].audit");
                filters.push(ConfiguredFilter::Audit(
                    Audit::compile(audit.format.json)
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
    use crate::parser::llm::Protocol;

    #[test]
    fn selected_protocol_owns_both_directions() {
        use serde_json::json;
        for (protocol, path, format) in [
            (
                "auto",
                "/v1/messages/?v=1",
                Format::Llm(Protocol::AnthropicMessages),
            ),
            (
                "auto",
                "/v1/chat/completions",
                Format::Llm(Protocol::OpenaiChatCompletions),
            ),
            (
                "auto",
                "/v1/responses",
                Format::Llm(Protocol::OpenaiResponses),
            ),
            ("auto", "/internal/messages", Format::UnknownProtocol),
            (
                "openai-responses",
                "/invoke",
                Format::Llm(Protocol::OpenaiResponses),
            ),
        ] {
            let cfg = json!({"filterChains":[{"name":"model",
                "parser":{"llm":{"protocol":protocol}}, "filters":[{"audit":{"format":{"json":{}}}}]}]});
            let settings = Settings::parse(cfg.to_string().as_bytes()).unwrap();
            let chain = &settings.chains[0];
            assert!(chain.format(match_path(path)) == format);
            assert_eq!(chain.filters.len(), 1);
        }
    }

    #[test]
    fn llm_selectors_are_qualified_and_directional() {
        use serde_json::json;
        let audit = json!({
            "format":{"json":{
                "msgs":"%EVENT(llm.request.messages)%","ask":"%EVENT(llm.question)%","reply":"%EVENT(llm.answer)%",
                "tools":"%EVENT(llm.toolDefinitions)%","calls":"%EVENT(llm.response.toolCallRefs)%"
            }}
        });
        let parse = |audit: &serde_json::Value| {
            let config = json!({"filterChains": [{"name": "models", "parser": {"llm": {}}, "filters": [{"audit": audit}]}]});
            Settings::parse(config.to_string().as_bytes())
        };
        assert!(parse(&audit).is_ok());
        for invalid in [
            "answer",
            "http.answer",
            "llm.model",
            "llm.messages",
            "llm.request.answer",
        ] {
            let audit = json!({"format":{"json":{"selected":format!("%EVENT({invalid})%")}}});
            let error = parse(&audit).err().unwrap();
            assert!(error.contains(invalid), "{error}");
        }
    }

    #[test]
    fn parser_budgets_resolve_independently_of_audit_limits() {
        use serde_json::json;
        let resolve = |llm| {
            let config = json!({"filterChains":[{"name":"models","parser":{"llm":llm},
                "filters":[{"audit":{"format":{"json":{"q":"%EVENT(llm.question):2048%"}}}}]}]});
            Settings::parse(config.to_string().as_bytes()).map(|s| {
                let chain = &s.chains[0];
                (
                    chain.request_parser().max_item_size,
                    chain.response_parser().max_content_size,
                )
            })
        };
        for llm in [json!({}), json!({"request":{},"response":{}})] {
            assert_eq!(resolve(llm).unwrap(), (1 << 20, 1 << 20));
        }
        for (size, bytes) in [
            (json!(1024), 1024),
            (json!("2MB"), 2_000_000),
            (json!("2MiB"), 2 << 20),
            (json!("64MiB"), 64 << 20),
        ] {
            assert_eq!(
                resolve(json!({"request":{"maxItemSize":size}})).unwrap(),
                (bytes, 1 << 20)
            );
            assert_eq!(
                resolve(json!({"response":{"maxContentSize":size}})).unwrap(),
                (1 << 20, bytes)
            );
        }
        for size in [
            json!(1023),
            json!((64 << 20) + 1),
            json!("1.5MiB"),
            json!("4Mb/s"),
        ] {
            assert!(resolve(json!({"request":{"maxItemSize":size}})).is_err());
            assert!(resolve(json!({"response":{"maxContentSize":size}})).is_err());
        }
        assert!(resolve(json!({"response":{"maxItemSize":"2MiB"}})).is_err());
    }

    #[test]
    fn match_authority_without_port_and_at_label_boundary() {
        assert!(host_matches("*.llm.test", hostname("A.b.LLM.test:443")));
        assert!(!host_matches("*.llm.test", hostname("llm.test:443")));
        assert!(!host_matches("*.llm.test", "badllm.test"));
        assert!(host_matches("llm.test", hostname("LLM.test:80")));
        assert!(host_matches("[::1]", hostname("[::1]:8443")));
        for (pattern, authority) in [
            ("LLM.test.", "llm.TEST.:443"),
            ("*.llm.test.", "tenant.llm.test.:443"),
        ] {
            let config = |p: &str| {
                serde_json::json!({"filterChains":[{"name":"dns","matcher":{"hosts":[p]},
                "parser":{"llm":{}}, "filters":[{"audit":{"format":{"json":{}}}}]}]})
            };
            let settings = Settings::parse(config(pattern).to_string().as_bytes()).unwrap();
            let p = &settings.chains[0].matcher.hosts.as_ref().unwrap()[0];
            assert!(host_matches(p, hostname(authority)));
            assert!(!host_matches(p, hostname("tenant.llm.test..:443")));
            assert!(
                Settings::parse(config(&format!("{pattern}.")).to_string().as_bytes()).is_err()
            );
        }
    }
}
