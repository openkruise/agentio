// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::{borrow::Cow, sync::Arc, time::Duration};

use tracing::debug;

use crate::{
    discovery::{Client, DemandError},
    identity::{Authenticator, ConnectionIdentity, Evidence as IdentityEvidence, WorkloadIdentity},
    view::{ResourceKind, View},
};

pub(super) struct ResolveRequest<'a> {
    pub identity: IdentityEvidence<'a>,
    pub connection_policy: bool,
}

pub(super) struct Resolved {
    pub workload: Arc<View>,
    pub sandbox: Option<Arc<View>>,
    pub profiles: Vec<Arc<View>>,
    pub instance: Option<String>,
}

pub(super) struct Resolver<'a> {
    pub client: &'a Arc<Client>,
    pub authenticator: &'a dyn Authenticator,
    pub cluster_id: &'a str,
    pub timeout: Duration,
    pub sandbox_by_workload: bool,
}

struct RequestSnapshot {
    profiles: Vec<Arc<View>>,
    workload: Arc<View>,
    sandbox: Option<Arc<View>>,
}

#[derive(Clone, Debug, thiserror::Error)]
pub(super) enum ResolveError {
    #[error("TCP policy is unavailable")]
    PolicyUnavailable,
    #[error("deadline exceeded")]
    Timeout,
    #[error("snapshot construction deadline exceeded")]
    Deadline,
    #[error("connection denied")]
    Denied,
    #[error(transparent)]
    Discovery(#[from] DemandError),
    #[error("identity provider failed: {0}")]
    Authentication(tonic::Status),
}

impl Resolver<'_> {
    pub async fn resolve(&self, request: &ResolveRequest<'_>) -> Result<Resolved, ResolveError> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        tokio::time::timeout_at(deadline, async {
            let identity = self
                .authenticator
                .authenticate(request.identity, deadline)
                .await
                .map_err(|status| match status.code() {
                    tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => {
                        ResolveError::Denied
                    }
                    _ => ResolveError::Authentication(status),
                })?;
            if !self.client.sandbox_mode && !identity.sandbox_id.is_empty() {
                debug!(reason = "sandbox_mode_disabled", "request denied");
                return Err(ResolveError::Denied);
            }
            let mut invalidated = self.client.invalidations();
            loop {
                let epoch = *invalidated.borrow_and_update();
                // A clear invalidates all dependencies; retries share the original deadline.
                tokio::select! {
                    biased;
                    _ = invalidated.changed() => continue,
                    result = self.resolve_once(request.connection_policy, &identity, deadline) => {
                        if self.client.current_epoch() == epoch {
                            break result;
                        }
                    }
                }
            }
        })
        .await
        .map_err(|_| ResolveError::Timeout)?
    }

    // Construct the complete candidate before emitting metadata or allowing CONNECT.
    async fn snapshot(
        &self,
        lookup: &str,
        instance: Option<&str>,
        principal: &str,
        sandbox_id: &str,
        request_deadline: tokio::time::Instant,
        connection_policy: bool,
    ) -> Result<RequestSnapshot, ResolveError> {
        let mut dependencies = self
            .client
            .dependencies(ResourceKind::SecurityProfile, Some(request_deadline));
        loop {
            if tokio::time::Instant::now() >= request_deadline {
                return Err(ResolveError::Deadline);
            }
            let mut sandbox_lookup = Cow::Borrowed(sandbox_id);
            let workload = self
                .client
                .pin(ResourceKind::Workload, lookup, Some(request_deadline));
            let sandbox = async {
                if sandbox_id.is_empty() {
                    return Ok(None);
                }
                self.client
                    .pin(ResourceKind::Sandbox, sandbox_id, Some(request_deadline))
                    .await
                    .map(Some)
            };
            let (workload, mut sandbox) = tokio::try_join!(workload, sandbox)?;
            let View::Workload(source) = workload.value.as_ref() else {
                unreachable!("typed Workload watch")
            };
            if instance.is_none()
                && (source.host_network
                    || source.principal != principal
                    || source.name.is_empty()
                    || source.namespace.is_empty()
                    || source.uid
                        != format!(
                            "{}//Pod/{}/{}",
                            self.cluster_id, source.namespace, source.name
                        ))
            {
                debug!(reason = "fallback_workload_mismatch", "request denied");
                return Err(ResolveError::Denied);
            }
            if sandbox_id.is_empty()
                && self.client.sandbox_mode
                && self.sandbox_by_workload
                && !source.namespace.is_empty()
                && !source.name.is_empty()
            {
                // Use authenticated WDS identity, never CONNECT name headers.
                sandbox_lookup = Cow::Owned(format!("{}/{}", source.namespace, source.name));
                sandbox = match self
                    .client
                    .pin(
                        ResourceKind::Sandbox,
                        &sandbox_lookup,
                        Some(request_deadline),
                    )
                    .await
                {
                    Ok(resource) => Some(resource),
                    Err(DemandError::NotFound) => None,
                    Err(error) => return Err(error.into()),
                };
            }
            if let Some(resource) = &sandbox {
                let View::Sandbox(value) = resource.value.as_ref() else {
                    unreachable!("typed Sandbox watch")
                };
                if (!sandbox_id.is_empty() && value.uid != sandbox_id)
                    || value.workload_uid != source.uid
                {
                    debug!(reason = "sandbox_binding_mismatch", "request denied");
                    return Err(ResolveError::Denied);
                }
            }
            let references = if connection_policy {
                source
                    .profiles
                    .as_deref()
                    .ok_or(ResolveError::PolicyUnavailable)?
            } else {
                &[]
            };
            let names: Vec<_> = references.iter().map(|r| r.name.clone()).collect();
            let profiles = dependencies.resolve(&names).await;
            let mut keys = vec![(ResourceKind::Workload, lookup)];
            if !sandbox_lookup.is_empty() {
                keys.push((ResourceKind::Sandbox, sandbox_lookup.as_ref()));
            }
            let profile_offset = keys.len();
            keys.extend(
                names
                    .iter()
                    .map(|name| (ResourceKind::SecurityProfile, name.as_str())),
            );
            let captured = self.client.capture(&keys)?;
            if !captured[0]
                .as_ref()
                .is_some_and(|after| Arc::ptr_eq(&workload.value, after))
            {
                continue;
            }
            if !sandbox_lookup.is_empty() {
                match (&sandbox, &captured[1]) {
                    (Some(before), Some(after)) if Arc::ptr_eq(&before.value, after) => {}
                    (None, None) => {}
                    _ => continue,
                }
            }
            let profiles = profiles?;
            if profiles.iter().enumerate().any(|(i, before)| {
                !captured[profile_offset + i]
                    .as_ref()
                    .is_some_and(|after| Arc::ptr_eq(before, after))
            }) {
                continue;
            }
            for (reference, profile) in references.iter().zip(&profiles) {
                let View::SecurityProfile(profile) = profile.as_ref() else {
                    unreachable!("typed SecurityProfile watch")
                };
                if !reference.uid.is_empty() && profile.uid != reference.uid {
                    return Err(ResolveError::PolicyUnavailable);
                }
            }
            return Ok(RequestSnapshot {
                profiles,
                workload: workload.value,
                sandbox: sandbox.map(|s| s.value),
            });
        }
    }

    async fn resolve_once(
        &self,
        connection_policy: bool,
        identity: &ConnectionIdentity,
        request_deadline: tokio::time::Instant,
    ) -> Result<Resolved, ResolveError> {
        let sandbox_id = identity.sandbox_id.as_str();
        let (lookup, instance, principal) = match &identity.workload {
            WorkloadIdentity::Instance(instance) => (
                Cow::Borrowed(instance.as_str()),
                Some(instance.as_str()),
                "",
            ),
            WorkloadIdentity::Peer { ip, principal } => {
                (Cow::Owned(format!("/{ip}")), None, principal.as_str())
            }
        };
        let RequestSnapshot {
            workload,
            sandbox,
            profiles,
        } = self
            .snapshot(
                &lookup,
                instance,
                principal,
                sandbox_id,
                request_deadline,
                connection_policy,
            )
            .await?;
        Ok(Resolved {
            profiles,
            workload,
            sandbox,
            instance: instance.map(str::to_owned),
        })
    }
}
