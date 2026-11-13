// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

use tonic::Status;
use tracing::debug;

use super::certificate_instance;

/// Connection evidence and the request's unverified Sandbox selection.
#[derive(Clone, Copy)]
pub struct Evidence<'a> {
    /// TLS-verified peer certificate captured by the gateway, as PEM or URL-encoded PEM.
    /// Empty when no certificate was captured; never sourced from a request header.
    pub certificate: &'a str,
    /// Direct connection peer IP, which need not identify the Sandbox. Empty if absent.
    pub peer_ip: &'a str,
    /// TLS-authenticated peer principal supplied by the gateway. Empty if absent.
    pub principal: &'a str,
    /// Unverified request selection; empty means no Sandbox was requested.
    pub requested_sandbox_id: &'a str,
}

pub enum WorkloadIdentity {
    /// WDS resource name or alias identifying an authenticated workload instance.
    /// The Adapter must bind this key to trusted evidence; Pod/IP checks do not apply.
    Instance(String),
    /// Default-network IP lookup for a non-hostNetwork Pod in the configured cluster.
    /// The resolver must verify its Pod identity and matching principal.
    Peer { ip: IpAddr, principal: String },
}

/// Discovery must still validate the selected Workload and Sandbox binding.
pub struct ConnectionIdentity {
    pub workload: WorkloadIdentity,
    /// Empty permits the gateway's Workload-name fallback; nonempty requires binding checks.
    pub sandbox_id: String,
}

/// Runtime authentication shares the request deadline with discovery and policy evaluation.
/// A runtime that authenticates a Sandbox directly must derive its ID from trusted evidence.
#[tonic::async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(
        &self,
        evidence: Evidence<'_>,
        deadline: tokio::time::Instant,
    ) -> Result<ConnectionIdentity, Status>;
}

pub struct Native;

#[tonic::async_trait]
impl Authenticator for Native {
    async fn authenticate(
        &self,
        evidence: Evidence<'_>,
        _deadline: tokio::time::Instant,
    ) -> Result<ConnectionIdentity, Status> {
        let instance = certificate_instance(evidence.certificate).map_err(|error| {
            debug!(reason = "invalid_certificate", %error, "request denied");
            Status::permission_denied("invalid certificate identity")
        })?;
        let workload = if let Some(instance) = instance {
            WorkloadIdentity::Instance(instance)
        } else {
            let ip = evidence
                .peer_ip
                .parse::<IpAddr>()
                .map_err(|_| Status::permission_denied("missing fallback identity"))?;
            if evidence.principal.is_empty() {
                return Err(Status::permission_denied("missing fallback identity"));
            }
            WorkloadIdentity::Peer {
                ip: ip.to_canonical(),
                principal: evidence.principal.into(),
            }
        };
        Ok(ConnectionIdentity {
            workload,
            sandbox_id: evidence.requested_sandbox_id.into(),
        })
    }
}
