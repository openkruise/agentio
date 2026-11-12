// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::{borrow::Cow, sync::Arc, time::Duration};

use futures_util::FutureExt;
use tracing::{debug, info};

use crate::{
    discovery::{Client, DemandError},
    identity::{Authenticator, ConnectionIdentity, Evidence as IdentityEvidence, WorkloadIdentity},
    traffic::{self, Target},
    view::{ResourceKind, View},
};

pub(super) struct ResolveRequest<'a> {
    pub identity: IdentityEvidence<'a>,
    pub target: Option<Target>,
}

pub(super) struct Resolved {
    pub workload: Arc<View>,
    pub sandbox: Option<Arc<View>>,
    pub instance: Option<String>,
}

pub(super) struct Resolver<'a> {
    pub client: &'a Arc<Client>,
    pub authenticator: &'a dyn Authenticator,
    pub cluster_id: &'a str,
    pub timeout: Duration,
}

struct RequestSnapshot {
    workload: Arc<View>,
    sandbox: Option<Arc<View>>,
    policies: Vec<Arc<View>>,
    workload_decision: Option<traffic::Evaluation>,
}

#[derive(Clone, Debug, thiserror::Error)]
pub(super) enum ResolveError {
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
                    result = self.resolve_once(request.target, &identity, deadline) => {
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
        target: Option<Target>,
        request_deadline: tokio::time::Instant,
    ) -> Result<RequestSnapshot, ResolveError> {
        let mut dependencies = self
            .client
            .dependencies(ResourceKind::TrafficPolicy, Some(request_deadline));
        loop {
            if tokio::time::Instant::now() >= request_deadline {
                return Err(ResolveError::Deadline);
            }
            let mut candidate = None;
            let resolution = {
                // Share the authenticated Workload lookup between binding validation and
                // platform policy discovery; neither path waits for the other to finish.
                let workload = async {
                    let held = self
                        .client
                        .pin(ResourceKind::Workload, lookup, Some(request_deadline))
                        .await?;
                    let resource = held.value.clone();
                    candidate = Some(held);
                    let View::Workload(workload) = resource.as_ref() else {
                        unreachable!("typed Workload watch")
                    };
                    if instance.is_none()
                        && (workload.host_network
                            || workload.principal != principal
                            || workload.name.is_empty()
                            || workload.namespace.is_empty()
                            || workload.uid
                                != format!(
                                    "{}//Pod/{}/{}",
                                    self.cluster_id, workload.namespace, workload.name
                                ))
                    {
                        debug!(reason = "fallback_workload_mismatch", "request denied");
                        return Err(ResolveError::Denied);
                    }
                    Ok::<_, ResolveError>(resource)
                }
                .shared();
                let sandbox = async {
                    if sandbox_id.is_empty() {
                        return Ok(None);
                    }
                    let resource = self
                        .client
                        .pin(ResourceKind::Sandbox, sandbox_id, Some(request_deadline))
                        .await?;
                    let View::Sandbox(sandbox) = resource.value.as_ref() else {
                        unreachable!("typed Sandbox watch")
                    };
                    if sandbox.uid != sandbox_id {
                        debug!(reason = "sandbox_id_mismatch", "request denied");
                        return Err(ResolveError::Denied);
                    }
                    Ok(Some(resource))
                };
                let identity = async {
                    let (workload, sandbox) = tokio::try_join!(workload.clone(), sandbox)?;
                    let View::Workload(source) = workload.as_ref() else {
                        unreachable!("typed Workload watch")
                    };
                    if let Some(resource) = &sandbox {
                        let View::Sandbox(sandbox) = resource.value.as_ref() else {
                            unreachable!("typed Sandbox watch")
                        };
                        if sandbox.workload_uid != source.uid {
                            debug!(reason = "sandbox_workload_mismatch", "request denied");
                            return Err(ResolveError::Denied);
                        }
                    }
                    Ok((workload, sandbox))
                };
                let policies = async {
                    if let Some(target) = target {
                        let resource = workload.clone().await?;
                        let View::Workload(workload) = resource.as_ref() else {
                            unreachable!("typed Workload watch")
                        };
                        let Some(references) = &workload.traffic_policies else {
                            debug!(reason = "traffic_binding_missing", "request denied");
                            return Err(ResolveError::Denied);
                        };
                        // Preserve policy order and resolve the complete stage: an earlier
                        // ALLOW can override a later DENY within the platform policy set.
                        let policies = dependencies.resolve(references).await?;
                        let evaluation = traffic::evaluate(
                            policies.iter().map(|value| {
                                let View::TrafficPolicy(policy) = value.as_ref() else {
                                    unreachable!("typed TrafficPolicy watch")
                                };
                                policy
                            }),
                            target,
                        );
                        let policy = evaluation
                            .matched_rule
                            .map(|(index, _)| references[index].as_str());
                        if !evaluation.allowed {
                            log_policy(
                                &workload.uid,
                                sandbox_id,
                                target,
                                "workload",
                                policy,
                                &evaluation,
                            );
                            return Err(ResolveError::Denied);
                        }
                        return Ok((policies, Some(evaluation)));
                    }
                    Ok((Vec::new(), None))
                };
                // A denial cancels the other branch's pending demands. Only ALLOW needs
                // both identity validation and all required policy checks to complete.
                tokio::try_join!(identity, policies)
            };

            if matches!(&resolution, Err(ResolveError::Denied)) {
                return Err(ResolveError::Denied);
            }
            let mut keys = vec![(ResourceKind::Workload, lookup)];
            if !sandbox_id.is_empty() {
                keys.push((ResourceKind::Sandbox, sandbox_id));
            }
            if target.is_some()
                && let Some(resource) = &candidate
            {
                let View::Workload(workload) = resource.value.as_ref() else {
                    unreachable!("typed Workload watch")
                };
                if let Some(names) = &workload.traffic_policies {
                    keys.extend(
                        names
                            .iter()
                            .map(|name| (ResourceKind::TrafficPolicy, name.as_str())),
                    );
                }
            }
            let captured = self.client.capture(&keys)?;
            // Any Workload change invalidates the candidate, not just a missing policy.
            if let (Some(before), Some(after)) = (&candidate, &captured[0])
                && !Arc::ptr_eq(&before.value, after)
            {
                continue;
            }
            let ((workload, sandbox), (policies, workload_decision)) = resolution?;
            if captured[0].is_none() {
                continue;
            }
            if let Some(before) = &sandbox {
                match &captured[1] {
                    Some(after) if Arc::ptr_eq(&before.value, after) => {}
                    _ => continue,
                }
            }
            // A hot dependency can be evicted before capture; rebuild before allowing.
            if captured.iter().any(Option::is_none) {
                continue;
            }
            // Reuse evaluations only when capture still contains the same policy objects.
            if captured
                .iter()
                .skip(if sandbox.is_some() { 2 } else { 1 })
                .zip(&policies)
                .any(|(after, before)| !Arc::ptr_eq(before, after.as_ref().unwrap()))
            {
                continue;
            }
            return Ok(RequestSnapshot {
                workload,
                sandbox: sandbox.map(|held| held.value),
                policies,
                workload_decision,
            });
        }
    }

    async fn resolve_once(
        &self,
        target: Option<Target>,
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
            policies: _policies,
            workload_decision,
        } = self
            .snapshot(
                &lookup,
                instance,
                principal,
                sandbox_id,
                target,
                request_deadline,
            )
            .await?;
        let View::Workload(source) = workload.as_ref() else {
            unreachable!("typed Workload watch")
        };
        if let Some(target) = target {
            let references = source.traffic_policies.as_ref().unwrap();
            let evaluation = workload_decision.as_ref().unwrap();
            let policy = evaluation
                .matched_rule
                .map(|(index, _)| references[index].as_str());
            log_policy(
                &source.uid,
                sandbox_id,
                target,
                "workload",
                policy,
                evaluation,
            );
        }
        Ok(Resolved {
            workload,
            sandbox,
            instance: instance.map(str::to_owned),
        })
    }
}

fn log_policy(
    workload: &str,
    sandbox_id: &str,
    target: Target,
    stage: &str,
    policy: Option<&str>,
    evaluation: &traffic::Evaluation,
) {
    info!(
        target: "agentio_porter::policy",
        event = "traffic_policy_decision",
        workload,
        sandbox_id,
        destination = %target.address,
        protocol = if target.protocol == crate::wire::agentio::security::traffic_policy::Protocol::Udp {
            "udp"
        } else {
            "tcp"
        },
        stage,
        policy,
        rule_index = evaluation.matched_rule.map(|(_, index)| index),
        action = if evaluation.allowed { "allow" } else { "deny" },
        reason = evaluation.reason,
        "request target policy evaluated"
    );
}
