// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    Direction, Fields, Format,
    audit::{AttributeSources, Schema},
};
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyHttpFilter;
use serde::Deserialize;

// Wire configuration is resolved once when Envoy loads the filter.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModuleConfig {
    #[serde(default)]
    defaults: Defaults,
    #[serde(default)]
    attributes: AttributeSources,
    rules: Vec<RuleConfig>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Defaults {
    schema: Schema,
    max_log_bytes: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleConfig {
    #[serde(rename = "match")]
    conditions: Conditions,
    skip: Option<bool>,
    audit: Option<AuditConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditConfig {
    schema: Option<Schema>,
    parsers: ParserConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParserConfig {
    llm: Option<LlmConfig>,
    generic: Option<GenericConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LlmConfig {
    #[serde(default)]
    protocol: Protocol,
    request: Option<DirectionConfig>,
    response: Option<DirectionConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenericConfig {
    request: Option<DirectionConfig>,
    response: Option<DirectionConfig>,
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

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
enum Include {
    Messages,
    ToolDefinitions,
    ToolCalls,
    Body,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DirectionConfig {
    #[serde(default)]
    include: Vec<Include>,
    max_log_bytes: Option<usize>,
    max_capture_bytes: Option<usize>,
    max_content_bytes: Option<usize>,
}

impl DirectionConfig {
    fn resolve(
        self,
        llm: bool,
        request: bool,
        default_limit: usize,
    ) -> Result<Direction, &'static str> {
        let mut fields = Fields::default();
        let mut format = Format::Metadata;
        for item in self.include {
            match item {
                Include::Messages if llm && request => fields.input_messages = true,
                Include::Messages if llm => fields.output_messages = true,
                Include::ToolDefinitions if llm && request => fields.tools = true,
                Include::ToolCalls if llm => fields.tool_calls = true,
                Include::Body if !llm => format = Format::Generic,
                _ => {
                    return Err(
                        "invalid include: llm accepts messages, toolCalls and request-only toolDefinitions; generic accepts body",
                    );
                }
            }
        }
        if !llm && self.max_content_bytes.is_some() {
            return Err("maxContentBytes is only supported by the llm parser");
        }
        let limit = self.max_log_bytes.unwrap_or(default_limit);
        if !(1024..=1048576).contains(&limit)
            || [self.max_capture_bytes, self.max_content_bytes]
                .into_iter()
                .flatten()
                .any(|v| !(1..=64 << 20).contains(&v))
        {
            return Err("maxLogBytes must be 1024..1048576 and capture/content limits 1..67108864");
        }
        Ok(Direction {
            format,
            fields,
            max_log_bytes: limit,
            max_capture_bytes: self.max_capture_bytes,
            max_content_bytes: self.max_content_bytes,
        })
    }
}

#[derive(Copy, Clone)]
pub struct Directions {
    pub request: Option<Direction>,
    pub response: Option<Direction>,
}
impl Directions {
    fn resolve(
        request: Option<DirectionConfig>,
        response: Option<DirectionConfig>,
        llm: bool,
        limit: usize,
    ) -> Result<Self, &'static str> {
        if request.is_none() && response.is_none() {
            return Err("a parser requires a request or response direction");
        }
        Ok(Self {
            request: request.map(|v| v.resolve(llm, true, limit)).transpose()?,
            response: response.map(|v| v.resolve(llm, false, limit)).transpose()?,
        })
    }
}

pub struct Audit {
    pub schema: Schema,
    llm: Option<(Protocol, Directions)>,
    generic: Option<Directions>,
}
impl Audit {
    fn compile(
        config: AuditConfig,
        defaults: &Defaults,
        limit: usize,
    ) -> Result<Self, &'static str> {
        if config.parsers.llm.is_none() && config.parsers.generic.is_none() {
            return Err("configure an llm or generic parser");
        }
        let llm = if let Some(l) = config.parsers.llm {
            Some((
                l.protocol,
                Directions::resolve(l.request, l.response, true, limit)?,
            ))
        } else {
            None
        };
        let generic = config
            .parsers
            .generic
            .map(|g| Directions::resolve(g.request, g.response, false, limit))
            .transpose()?;
        Ok(Self {
            schema: config.schema.unwrap_or(defaults.schema),
            llm,
            generic,
        })
    }

    pub fn directions(&self, path: &str, media: &str) -> Option<Directions> {
        if let Some((protocol, mut directions)) = self.llm {
            let detected = Format::from_path(path);
            let format = match protocol {
                Protocol::Auto => detected,
                _ if self.generic.is_some()
                    && detected.is_none()
                    && !crate::is_json_media(media) =>
                {
                    None
                }
                Protocol::OpenaiChatCompletions => Some(Format::OpenaiChatCompletions),
                Protocol::OpenaiResponses => Some(Format::OpenaiResponses),
                Protocol::AnthropicMessages => Some(Format::AnthropicMessages),
            };
            if let Some(format) = format {
                for direction in [&mut directions.request, &mut directions.response]
                    .into_iter()
                    .flatten()
                {
                    direction.format = format;
                }
                return Some(directions);
            }
        }
        self.generic
    }
}

pub struct Settings {
    rules: Vec<(Conditions, Option<Audit>)>,
    pub attributes: AttributeSources,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
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
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let config: ModuleConfig = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let limit = config.defaults.max_log_bytes.unwrap_or(8192);
        if !(1024..=1048576).contains(&limit) {
            return Err("defaults.maxLogBytes must be 1024..1048576".into());
        }
        if config.rules.is_empty() {
            return Err(
                "configure at least one rule; use a final match: {} to audit all streams".into(),
            );
        }
        config.attributes.validate()?;
        let count = config.rules.len();
        let mut rules = Vec::with_capacity(count);
        for (i, rule) in config.rules.into_iter().enumerate() {
            let c = rule.conditions;
            if c.hosts.is_none() && c.filter_state.is_none() && i + 1 != count {
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
                return Err(
                    "filterState needs a key and either present:true or non-empty values".into(),
                );
            }
            let audit = match (rule.skip, rule.audit) {
                (Some(true), None) => None,
                (None, Some(a)) => Some(
                    Audit::compile(a, &config.defaults, limit)
                        .map_err(|e| format!("rules[{i}].audit: {e}"))?,
                ),
                _ => return Err(format!("rules[{i}] requires either skip: true or audit")),
            };
            rules.push((c, audit));
        }
        Ok(Self {
            rules,
            attributes: config.attributes,
        })
    }

    pub fn select(&self, envoy: &impl EnvoyHttpFilter) -> Option<&Audit> {
        let authority = envoy.get_request_header_value(":authority");
        let host = authority
            .as_ref()
            .and_then(|s| std::str::from_utf8(s.as_slice()).ok())
            .map(hostname);
        let (_, audit) = self.rules.iter().find(|(c, _)| {
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
        audit.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_protocol_owns_both_directions() {
        use serde_json::json;
        for explicit in [false, true] {
            let mut llm = json!({"response": {"include": ["toolCalls"]}});
            if explicit {
                llm["protocol"] = "openai-responses".into();
            }
            let config = json!({"defaults":{"schema":"genai","maxLogBytes":16384},"rules":[
                {"match":{},"audit":{"schema":"agentio","parsers":{
                    "llm":llm,"generic":{"request":{"include":[],"maxLogBytes":2048}}
                }}}
            ]});
            let settings = Settings::parse(config.to_string().as_bytes()).unwrap();
            let policy = settings.rules[0].1.as_ref().unwrap();
            assert!(policy.schema == Schema::Agentio);
            for (path, media, expect_llm) in [
                ("/v1/messages/?v=1", "text/plain", true),
                ("/invoke", "application/vnd.test+json", explicit),
                ("/upload", "multipart/form-data; boundary=b", false),
            ] {
                let directions = policy.directions(path, media).unwrap();
                if expect_llm {
                    assert!(directions.request.is_none());
                    let response = directions.response.unwrap();
                    assert!(
                        response.format
                            == if explicit {
                                Format::OpenaiResponses
                            } else {
                                Format::AnthropicMessages
                            }
                    );
                    assert!(response.fields.tool_calls && !response.fields.output_messages);
                    assert_eq!(response.max_log_bytes, 16384);
                } else {
                    assert!(directions.response.is_none());
                    let request = directions.request.unwrap();
                    assert!(request.format == Format::Metadata);
                    assert_eq!(request.max_log_bytes, 2048);
                }
            }
        }
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
