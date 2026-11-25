// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::config::Settings;
use envoy_proxy_dynamic_modules_rust_sdk::{
    ConfigValidatorConfig, ConfigValidatorContext, ConfigValidatorResource,
};
use prost::Message;
use prost_types::Any;

const RESOURCE: &str = "agentio.body_processing";
const MODULE_TYPE: &str =
    "type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter";

// Read only the fields used in Agentio's ECDS resource. Envoy owns validation
// of the outer protobufs and the other extensions on the same ADS stream.
#[derive(Message)]
struct TypedExtensionConfig {
    #[prost(message, optional, tag = "2")]
    typed_config: Option<Any>,
}

#[derive(Message)]
struct DynamicModuleFilter {
    #[prost(string, tag = "2")]
    filter_name: String,
    #[prost(message, optional, tag = "3")]
    filter_config: Option<Any>,
}

struct Validator;

pub(super) fn new_config(name: &str, _: &[u8]) -> Option<Box<dyn ConfigValidatorConfig>> {
    (name == RESOURCE).then(|| Box::new(Validator) as Box<dyn ConfigValidatorConfig>)
}

fn validate_rules(bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let module = TypedExtensionConfig::decode(bytes)?
        .typed_config
        .ok_or("missing typed_config")?;
    if module.type_url != MODULE_TYPE {
        return Err("expected DynamicModuleFilter".into());
    }
    let filter = DynamicModuleFilter::decode(module.value.as_slice())?;
    if filter.filter_name != "body_processing" {
        return Err("expected body_processing filter".into());
    }
    let rules = filter
        .filter_config
        .ok_or("missing filter_config")?
        .to_msg::<String>()?;
    Settings::parse(rules.as_bytes())?;
    Ok(())
}

fn validate_resources(resources: &[ConfigValidatorResource<'_>]) -> Result<(), String> {
    for resource in resources {
        if resource.name == RESOURCE
            && let Some(bytes) = resource.resource
        {
            validate_rules(bytes).map_err(|err| format!("{RESOURCE}: {err}"))?;
        }
    }
    Ok(())
}

impl ConfigValidatorConfig for Validator {
    fn validate(
        &self,
        _: &ConfigValidatorContext,
        _: &str,
        resources: &[ConfigValidatorResource<'_>],
    ) -> Result<(), String> {
        validate_resources(resources)
    }

    fn validate_delta(
        &self,
        _: &ConfigValidatorContext,
        _: &str,
        added: &[ConfigValidatorResource<'_>],
        _: &[&str],
    ) -> Result<(), String> {
        validate_resources(added)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn validate_only_the_body_processing_resource_with_the_filter_compiler() {
        fn resource<'a>(
            name: &'static str,
            bytes: Option<&'a [u8]>,
        ) -> ConfigValidatorResource<'a> {
            ConfigValidatorResource {
                name: Cow::Borrowed(name),
                version: Cow::Borrowed("1"),
                aliases: vec![],
                ttl: None,
                resource: bytes,
            }
        }
        // Other ECDS extensions and TTL heartbeats carry no audit rules.
        assert!(
            validate_resources(&[resource("limits", Some(&[0xff])), resource(RESOURCE, None)])
                .is_ok()
        );
        for (rules, expected_error) in [
            ("{}", None),
            (r#"{"filterChains":[]}"#, None),
            (r#"{"filterChains":null}"#, Some("expected a sequence")),
            (
                r#"{"filterChains":[{"name":"c","parser":{"llm":{}},"filters":[{"audit":{"format":{"json":{"q":"%EVENT(llm.question)%"}}}}]}]}"#,
                None,
            ),
            (
                r#"{"filterChains":[{"name":"c","parser":{"llm":{}},"filters":[]}]}"#,
                Some("at least one filter"),
            ),
            (
                r#"{"filterChains":[{"name":"c","parser":{"llm":{}},"filters":[{"audit":{"format":{"json":{"q":"%BAD%"}}}}]}]}"#,
                Some("unsupported audit expression"),
            ),
        ] {
            let filter = DynamicModuleFilter {
                filter_name: "body_processing".into(),
                filter_config: Some(Any::from_msg(&rules.to_owned()).unwrap()),
            };
            let bytes = TypedExtensionConfig {
                typed_config: Some(Any {
                    type_url: MODULE_TYPE.into(),
                    value: filter.encode_to_vec(),
                }),
            }
            .encode_to_vec();
            let result = validate_resources(&[resource(RESOURCE, Some(&bytes))]);
            match expected_error {
                Some(reason) => assert!(result.unwrap_err().contains(reason)),
                None => result.unwrap(),
            }
        }
    }
}
