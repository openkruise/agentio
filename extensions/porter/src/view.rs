// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use prost::Message;
use prost_types::{Any, Struct, Value, value::Kind};

use crate::wire::{
    agentio::sandbox::Sandbox,
    istio::workload::{NetworkMode, Workload},
    kruise::networking::extensions::v1::{SniAction, SniRule, SniTrafficPolicy, WorkloadMetadata},
};

pub const WORKLOAD: &str = "type.googleapis.com/istio.workload.Workload";
pub const SANDBOX: &str = "type.googleapis.com/agentio.sandbox.Sandbox";

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum ResourceKind {
    Workload,
    Sandbox,
}

impl ResourceKind {
    pub const ALL: [Self; 2] = [Self::Workload, Self::Sandbox];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Workload => 0,
            Self::Sandbox => 1,
        }
    }

    pub const fn type_url(self) -> &'static str {
        match self {
            Self::Workload => WORKLOAD,
            Self::Sandbox => SANDBOX,
        }
    }

    pub fn from_type_url(type_url: &str) -> Option<Self> {
        match type_url {
            WORKLOAD => Some(Self::Workload),
            SANDBOX => Some(Self::Sandbox),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum View {
    Workload(WorkloadView),
    Sandbox(SandboxView),
}

#[derive(Debug)]
pub struct WorkloadView {
    pub uid: String,
    pub name: String,
    pub namespace: String,
    pub principal: String,
    pub host_network: bool,
    pub encoded_labels: String,
    pub rules: Vec<SniRule>,
}

#[derive(Debug)]
pub struct SandboxView {
    pub uid: String,
    pub workload_uid: String,
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
            let mut labels = Vec::new();
            for value in values
                .iter()
                .filter(|v| matches(v, "kruise.networking.extensions.v1.WorkloadMetadata"))
            {
                let metadata = WorkloadMetadata::decode(value.value.as_slice())
                    .context("decode workload metadata")?;
                labels.extend(metadata.labels.into_iter().map(|(k, v)| format!("{k}={v}")));
            }
            labels.sort();
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
                encoded_labels: STANDARD.encode(labels.join(",")),
                rules: rules(&values)?,
            }))
        }
        ResourceKind::Sandbox => {
            let sandbox = Sandbox::decode(value.value.as_slice())?;
            Ok(View::Sandbox(SandboxView {
                uid: sandbox.uid,
                workload_uid: sandbox.attester.map(|a| a.workload_uid).unwrap_or_default(),
                rules: rules(&sandbox.extensions)?,
            }))
        }
    }
}
