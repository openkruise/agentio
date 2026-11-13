// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::wire::agentio::security::{SniAction, SniRule};
use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use prost::Message;
use prost_types::{Any, Struct, Value, value::Kind};

use crate::tcp::Policy;
use crate::wire::{
    agentio::{
        extensions::{PolicyReference, PolicyResourceReference},
        sandbox::Sandbox,
        security::SecurityProfile,
    },
    istio::workload::{NetworkMode, Workload},
};

pub const WORKLOAD: &str = "type.googleapis.com/istio.workload.Workload";
pub const SECURITY_PROFILE: &str = "type.googleapis.com/agentio.security.SecurityProfile";
pub const SANDBOX: &str = "type.googleapis.com/agentio.sandbox.Sandbox";

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ResourceKind {
    Workload,
    Sandbox,
    SecurityProfile,
}

impl ResourceKind {
    pub const ALL: [Self; 3] = [Self::Workload, Self::Sandbox, Self::SecurityProfile];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Workload => 0,
            Self::Sandbox => 1,
            Self::SecurityProfile => 2,
        }
    }

    pub const fn type_url(self) -> &'static str {
        match self {
            Self::Workload => WORKLOAD,
            Self::Sandbox => SANDBOX,
            Self::SecurityProfile => SECURITY_PROFILE,
        }
    }

    pub fn from_type_url(type_url: &str) -> Option<Self> {
        match type_url {
            WORKLOAD => Some(Self::Workload),
            SANDBOX => Some(Self::Sandbox),
            SECURITY_PROFILE => Some(Self::SecurityProfile),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum View {
    Workload(WorkloadView),
    Sandbox(SandboxView),
    SecurityProfile(SecurityProfileView),
}

#[derive(Debug)]
pub struct WorkloadView {
    pub uid: String,
    pub name: String,
    pub namespace: String,
    pub principal: String,
    pub host_network: bool,
    pub profiles: Option<Vec<PolicyResourceReference>>,
}

#[derive(Debug)]
pub struct SandboxView {
    pub uid: String,
    pub workload_uid: String,
    pub profile: Option<SecurityProfileView>,
}

#[derive(Debug)]
pub struct SecurityProfileView {
    pub uid: String,
    pub tcp_policy: Policy,
    pub rules: Vec<SniRule>,
}

impl SecurityProfileView {
    pub fn project_connection(&self, include_sni: bool) -> Value {
        object([
            ("uid".into(), string(&self.uid)),
            (
                "sniPolicy".into(),
                object([(
                    "rules".into(),
                    list(if include_sni {
                        project_rules(&self.rules).collect()
                    } else {
                        Vec::new()
                    }),
                )]),
            ),
            ("tcpPolicy".into(), self.tcp_policy.project()),
        ])
    }

    fn compile(profile: SecurityProfile) -> Result<Self> {
        let rules = profile.sni_policy.unwrap_or_default().rules;
        for rule in &rules {
            if SniAction::try_from(rule.action).context("invalid SNI action")?
                == SniAction::Unspecified
            {
                bail!("unsupported SNI action");
            }
        }
        Ok(Self {
            uid: profile.uid,
            tcp_policy: Policy::compile(profile.tcp_policy.context("missing TCP policy")?)?,
            rules,
        })
    }
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
                profiles: profile_references(&values)?,
            }))
        }
        ResourceKind::Sandbox => {
            let sandbox = Sandbox::decode(value.value.as_slice())?;
            Ok(View::Sandbox(SandboxView {
                uid: sandbox.uid,
                workload_uid: sandbox.attester.map(|a| a.workload_uid).unwrap_or_default(),
                profile: inline_profile(&sandbox.extensions)?,
            }))
        }
        ResourceKind::SecurityProfile => Ok(View::SecurityProfile(SecurityProfileView::compile(
            SecurityProfile::decode(value.value.as_slice())?,
        )?)),
    }
}

fn profile_references(values: &[Any]) -> Result<Option<Vec<PolicyResourceReference>>> {
    let mut result = None;
    for value in values
        .iter()
        .filter(|v| matches(v, "agentio.extensions.PolicyReference"))
    {
        let references = PolicyReference::decode(value.value.as_slice())?;
        if references.type_url != SECURITY_PROFILE {
            continue;
        }
        if result.is_some() {
            bail!("duplicate SecurityProfile binding");
        }
        for reference in &references.resources {
            if reference.name.is_empty() {
                bail!("empty SecurityProfile reference");
            }
        }
        result = Some(references.resources);
    }
    Ok(result)
}

fn inline_profile(values: &[Any]) -> Result<Option<SecurityProfileView>> {
    let mut result = None;
    for value in values.iter().filter(|v| v.type_url == SECURITY_PROFILE) {
        if result.is_some() {
            bail!("duplicate inline SecurityProfile");
        }
        result = Some(SecurityProfileView::compile(SecurityProfile::decode(
            value.value.as_slice(),
        )?)?);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::agentio::security::SniMatch;
    use crate::wire::agentio::security::SniPolicy as SniTrafficPolicy;

    #[test]
    fn http_json_is_not_parsed_by_porter() {
        let profile = SecurityProfileView::compile(SecurityProfile {
            name: "policy".into(),
            uid: "uid".into(),
            policy_json: b"not HTTP JSON".to_vec(),
            tcp_policy: Some(Default::default()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(profile.uid, "uid");
        assert!(profile.rules.is_empty());
    }

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
        let projected: Vec<_> = project_rules(&policy.rules).collect();
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
}
