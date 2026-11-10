// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

use tonic::Status;
use tracing::debug;

use super::certificate_instance;

/// Evidence captured by the gateway from its authenticated downstream connection.
#[derive(Clone, Copy)]
pub struct Evidence<'a> {
    pub certificate: &'a str,
    pub peer_ip: &'a str,
    pub principal: &'a str,
    pub sandbox_id: &'a str,
}

pub enum WorkloadIdentity {
    Instance(String),
    Peer { ip: IpAddr, principal: String },
}

/// Discovery must still validate the selected Workload and Sandbox binding.
pub struct ConnectionIdentity {
    pub workload: WorkloadIdentity,
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
            sandbox_id: evidence.sandbox_id.into(),
        })
    }
}
