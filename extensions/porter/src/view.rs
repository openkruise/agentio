// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use prost::Message;
use prost_types::{Any, Struct, Value, value::Kind};

use crate::traffic::Policy;
use crate::wire::{
    agentio::{sandbox::Sandbox, security::TrafficPolicy},
    istio::workload::{NetworkMode, Workload},
    kruise::networking::extensions::v1::{PolicyReference, SniAction, SniRule, SniTrafficPolicy},
};

pub const WORKLOAD: &str = "type.googleapis.com/istio.workload.Workload";
pub const SANDBOX: &str = "type.googleapis.com/agentio.sandbox.Sandbox";

pub const TRAFFIC_POLICY: &str = "type.googleapis.com/agentio.security.TrafficPolicy";

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ResourceKind {
    Workload,
    Sandbox,
    TrafficPolicy,
}

impl ResourceKind {
    pub const ALL: [Self; 3] = [Self::Workload, Self::Sandbox, Self::TrafficPolicy];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Workload => 0,
            Self::Sandbox => 1,
            Self::TrafficPolicy => 2,
        }
    }

    pub const fn type_url(self) -> &'static str {
        match self {
            Self::Workload => WORKLOAD,
            Self::Sandbox => SANDBOX,
            Self::TrafficPolicy => TRAFFIC_POLICY,
        }
    }

    pub fn from_type_url(type_url: &str) -> Option<Self> {
        match type_url {
            WORKLOAD => Some(Self::Workload),
            SANDBOX => Some(Self::Sandbox),
            TRAFFIC_POLICY => Some(Self::TrafficPolicy),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum View {
    Workload(WorkloadView),
    Sandbox(SandboxView),
    TrafficPolicy(Policy),
}

#[derive(Debug)]
pub struct WorkloadView {
    pub uid: String,
    pub name: String,
    pub namespace: String,
    pub principal: String,
    pub host_network: bool,
    pub traffic_policies: Option<Vec<String>>,
    pub rules: Vec<SniRule>,
}

#[derive(Debug)]
pub struct SandboxView {
    pub uid: String,
    pub workload_uid: String,
    pub traffic_policy: Option<Policy>,
    pub rules: Vec<SniRule>,
}

pub fn string(s: impl Into<String>) -> Value {
    Value {
        kind: Some(Kind::StringValue(s.into())),
    }
}

pub fn object(fields: impl IntoIterator<Item = (String, Value)>) -> Value {
    Value {
        kind: Some(Kind::StructValue(Struct {
            fields: fields.into_iter().collect(),
        })),
    }
}

pub fn list(values: Vec<Value>) -> Value {
    Value {
        kind: Some(Kind::ListValue(prost_types::ListValue { values })),
    }
}

fn matches(value: &Any, name: &str) -> bool {
    value.type_url.rsplit('/').next() == Some(name)
}

fn rules(values: &[Any]) -> Result<Vec<SniRule>> {
    let mut result = Vec::new();
    for value in values
        .iter()
        .filter(|v| matches(v, "kruise.networking.extensions.v1.SniTrafficPolicy"))
    {
        for rule in SniTrafficPolicy::decode(value.value.as_slice())
            .context("decode SNI traffic policy")?
            .rules
        {
            if SniAction::try_from(rule.action).context("invalid SNI action")?
                == SniAction::Unspecified
            {
                bail!("unsupported SNI action");
            }
            result.push(rule);
        }
    }
    Ok(result)
}

// Keep typed rules in the cache; expand only the response being sent.
pub fn project_rules(values: &[SniRule]) -> impl Iterator<Item = Value> + '_ {
    values.iter().map(|rule| {
        let action = SniAction::try_from(rule.action).unwrap();
        let mut fields = BTreeMap::new();
        fields.insert("action".into(), string(action.as_str_name()));
        if let Some(sni_match) = &rule.r#match {
            let mut matched = BTreeMap::new();
            if !sni_match.sni.is_empty() {
                matched.insert(
                    "sni".into(),
                    list(sni_match.sni.iter().cloned().map(string).collect()),
                );
            }
            if !sni_match.ports.is_empty() {
                matched.insert(
                    "ports".into(),
                    list(
                        sni_match
                            .ports
                            .iter()
                            .map(|port| Value {
                                kind: Some(Kind::NumberValue(f64::from(*port))),
                            })
                            .collect(),
                    ),
                );
            }
            fields.insert("match".into(), object(matched));
        }
        object(fields)
    })
}

pub fn decode(kind: ResourceKind, value: &Any) -> Result<View> {
    if value.type_url != kind.type_url() {
        bail!(
            "incorrect resource type {}, expected {}",
            value.type_url,
            kind.type_url()
        );
    }
    match kind {
        ResourceKind::TrafficPolicy => Ok(View::TrafficPolicy(Policy::compile(
            TrafficPolicy::decode(value.value.as_slice())?,
        )?)),
        ResourceKind::Workload => {
            let workload = Workload::decode(value.value.as_slice())?;
            let values: Vec<_> = workload
                .extensions
                .into_iter()
                .filter_map(|e| e.config)
                .collect();
            let principal =
                if !workload.trust_domain.is_empty() && !workload.service_account.is_empty() {
                    format!(
                        "spiffe://{}/ns/{}/sa/{}",
                        workload.trust_domain, workload.namespace, workload.service_account
                    )
                } else {
                    String::new()
                };
            Ok(View::Workload(WorkloadView {
                uid: workload.uid,
                name: workload.name,
                namespace: workload.namespace,
                principal,
                host_network: workload.network_mode == NetworkMode::HostNetwork as i32,
                rules: rules(&values)?,
                traffic_policies: traffic_references(&values)?,
            }))
        }
        ResourceKind::Sandbox => {
            let sandbox = Sandbox::decode(value.value.as_slice())?;
            Ok(View::Sandbox(SandboxView {
                uid: sandbox.uid,
                workload_uid: sandbox.attester.map(|a| a.workload_uid).unwrap_or_default(),
                rules: rules(&sandbox.extensions)?,
                traffic_policy: sandbox.traffic_policy.map(Policy::compile).transpose()?,
            }))
        }
    }
}

fn traffic_references(values: &[Any]) -> Result<Option<Vec<String>>> {
    let mut names = None;
    for value in values
        .iter()
        .filter(|v| matches(v, "kruise.networking.extensions.v1.PolicyReference"))
    {
        let reference = PolicyReference::decode(value.value.as_slice())?;
        if reference.type_url != TRAFFIC_POLICY {
            continue;
        }
        if names.is_some() {
            bail!("duplicate TrafficPolicy binding");
        }
        if reference
            .resource_names
            .iter()
            .any(|name| name.is_empty() || name == "*")
        {
            bail!("invalid TrafficPolicy reference");
        }
        names = Some(reference.resource_names);
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::kruise::networking::extensions::v1::SniMatch;

    #[test]
    fn sni_projection_preserves_action_order_and_ports() {
        let policy = SniTrafficPolicy {
            rules: vec![
                SniRule {
                    r#match: Some(SniMatch {
                        sni: vec!["skip.example.com".into()],
                        ports: vec![443, 8443],
                    }),
                    action: SniAction::Passthrough as i32,
                },
                SniRule {
                    r#match: Some(SniMatch {
                        sni: vec!["*".into()],
                        ports: vec![],
                    }),
                    action: SniAction::Deny as i32,
                },
            ],
        };
        let decoded = rules(&[Any {
            type_url: "type.googleapis.com/kruise.networking.extensions.v1.SniTrafficPolicy".into(),
            value: policy.encode_to_vec(),
        }])
        .unwrap();
        let projected: Vec<_> = project_rules(&decoded).collect();
        assert_eq!(
            projected,
            vec![
                object([
                    ("action".into(), string("SNI_ACTION_PASSTHROUGH")),
                    (
                        "match".into(),
                        object([
                            ("sni".into(), list(vec![string("skip.example.com")])),
                            (
                                "ports".into(),
                                list(vec![
                                    Value {
                                        kind: Some(Kind::NumberValue(443.0))
                                    },
                                    Value {
                                        kind: Some(Kind::NumberValue(8443.0))
                                    },
                                ])
                            ),
                        ])
                    ),
                ]),
                object([
                    ("action".into(), string("SNI_ACTION_DENY")),
                    (
                        "match".into(),
                        object([("sni".into(), list(vec![string("*")]))])
                    ),
                ]),
            ]
        );
    }

    fn binding(names: &[&str]) -> Any {
        Any {
            type_url: "type.googleapis.com/kruise.networking.extensions.v1.PolicyReference".into(),
            value: PolicyReference {
                type_url: TRAFFIC_POLICY.into(),
                resource_names: names.iter().map(|name| (*name).into()).collect(),
            }
            .encode_to_vec(),
        }
    }

    #[test]
    fn bindings_preserve_presence_and_order_and_reject_ambiguity() {
        assert_eq!(traffic_references(&[]).unwrap(), None);
        assert_eq!(traffic_references(&[binding(&[])]).unwrap(), Some(vec![]));
        assert_eq!(
            traffic_references(&[binding(&["b", "a"])]).unwrap(),
            Some(vec!["b".into(), "a".into()])
        );
        assert!(traffic_references(&[binding(&["a"]), binding(&["b"])]).is_err());
        for name in ["", "*"] {
            assert!(traffic_references(&[binding(&[name])]).is_err());
        }
        let mut other = binding(&["unused"]);
        other.value = PolicyReference {
            type_url: "another.policy.Type".into(),
            resource_names: vec!["unused".into()],
        }
        .encode_to_vec();
        assert_eq!(traffic_references(&[other]).unwrap(), None);
    }
}
