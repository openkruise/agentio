// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::{
    borrow::Cow,
    collections::BTreeMap,
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::{FutureExt, Stream};
use prost_types::{Struct, value::Kind};
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, info};

use crate::{
    discovery::{Client, DemandError},
    identity::certificate_instance,
    metrics::{ConnectResult, Metrics, Protocol},
    traffic::{self, Target},
    view::{self, ResourceKind, View},
    wire::extproc::{
        self, external_processor_server::ExternalProcessor,
        processing_response::Response as Decision,
    },
};

#[derive(Clone)]
pub struct Processor {
    pub client: Arc<Client>,
    pub cluster_id: String,
    pub timeout: Duration,
    pub enable_traffic_policy: bool,
}

struct RequestSnapshot {
    workload: Arc<View>,
    sandbox: Option<Arc<View>>,
    policies: Vec<Arc<View>>,
    sandbox_decision: Option<traffic::Evaluation>,
    workload_decision: Option<traffic::Evaluation>,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
enum ResolveError {
    #[error("snapshot construction deadline exceeded")]
    Deadline,
    #[error("connection denied")]
    Denied,
    #[error(transparent)]
    Discovery(#[from] DemandError),
}

fn attribute<'a>(attributes: Option<&'a Struct>, key: &str) -> &'a str {
    let value = attributes.and_then(|attributes| attributes.fields.get(key));
    let value = match value.and_then(|value| value.kind.as_ref()) {
        Some(Kind::StructValue(wrapper)) => wrapper.fields.get("value"),
        _ => value,
    };
    match value.and_then(|value| value.kind.as_ref()) {
        Some(Kind::StringValue(value)) => value,
        _ => "",
    }
}

fn denied() -> extproc::ProcessingResponse {
    extproc::ProcessingResponse {
        response: Some(Decision::ImmediateResponse(extproc::ImmediateResponse {
            status: Some(extproc::HttpStatus { code: 403 }),
            body: b"connection denied".to_vec(),
            details: "agentio_connect_denied".into(),
        })),
        dynamic_metadata: None,
    }
}

impl Processor {
    pub async fn handle(
        &self,
        message: extproc::ProcessingRequest,
    ) -> Result<extproc::ProcessingResponse, Status> {
        let started = Instant::now();
        let (udp, target) = {
            let headers = message
                .request_headers
                .ok_or_else(|| Status::invalid_argument("CONNECT requires request headers"))?;
            let (mut method, mut authority, mut upgrade) =
                (Cow::Borrowed(""), Cow::Borrowed(""), Cow::Borrowed(""));
            for header in headers.headers.iter().flat_map(|headers| &headers.headers) {
                let target = match header.key.as_str() {
                    ":method" => &mut method,
                    ":authority" => &mut authority,
                    "upgrade" => &mut upgrade,
                    _ => continue,
                };
                *target = if header.raw_value.is_empty() {
                    Cow::Borrowed(header.value.as_str())
                } else {
                    String::from_utf8_lossy(&header.raw_value)
                };
            }
            let udp = method == "GET" && upgrade.eq_ignore_ascii_case("connect-udp");
            if (method != "CONNECT" && !udp) || authority.is_empty() {
                return Err(Status::invalid_argument(
                    "expected CONNECT with an authority",
                ));
            }
            let target = if self.enable_traffic_policy {
                Some(Target::parse(&authority, udp).map_err(|error| {
                    Status::invalid_argument(format!("invalid CONNECT target: {error}"))
                })?)
            } else {
                None
            };
            (udp, target)
        };
        let mut measurement = ConnectMeasurement {
            metrics: self.client.metrics.clone(),
            started,
            protocol: if udp { "udp" } else { "tcp" },
            result: "canceled",
        };
        let attributes = message.attributes.get("envoy.filters.http.ext_proc");
        let certificate = attribute(attributes, "filter_state['agentio.peer.certificate']");
        let peer_ip = attribute(attributes, "filter_state['agentio.downstream.ip']");
        let principal = attribute(attributes, "filter_state['agentio.peer.principal']");
        let sandbox_id = attribute(attributes, "filter_state['agentio.sandbox.uid']");
        let request_deadline = tokio::time::Instant::now() + self.timeout;
        let result = tokio::time::timeout_at(request_deadline, async {
            let mut invalidated = self.client.invalidations();
            loop {
                let epoch = *invalidated.borrow_and_update();
                // A clear invalidates every dependency already held by this
                // request. Restart resolution under the original deadline.
                tokio::select! {
                    biased;
                    _ = invalidated.changed() => continue,
                    result = self.resolve(
                        certificate,
                        peer_ip,
                        principal,
                        sandbox_id,
                        (udp, target),
                        request_deadline,
                    ) => {
                        if self.client.current_epoch() == epoch {
                            break result;
                        }
                    }
                }
            }
        })
        .await;
        let response = match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(ResolveError::Denied)) => Ok(denied()),
            Ok(Err(ResolveError::Discovery(DemandError::NotFound))) => {
                debug!(reason = "resource_not_found", "CONNECT denied");
                Ok(denied())
            }
            Ok(Err(error)) => Err(Status::unavailable(format!(
                "CONNECT processing failed: {error}"
            ))),
            Err(_) => Err(Status::unavailable(
                "CONNECT processing failed: deadline exceeded",
            )),
        };
        measurement.result = match &response {
            Ok(response)
                if matches!(
                    response.response,
                    Some(extproc::processing_response::Response::ImmediateResponse(_))
                ) =>
            {
                "denied"
            }
            Ok(_) => "allowed",
            Err(_) => "error",
        };
        response
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
                        debug!(reason = "fallback_workload_mismatch", "CONNECT denied");
                        return Err(ResolveError::Denied);
                    }
                    Ok::<_, ResolveError>(resource)
                }
                .shared();
                let sandbox = async {
                    if sandbox_id.is_empty() {
                        return Ok((None, None));
                    }
                    let resource = self
                        .client
                        .pin(ResourceKind::Sandbox, sandbox_id, Some(request_deadline))
                        .await?;
                    let View::Sandbox(sandbox) = resource.value.as_ref() else {
                        unreachable!("typed Sandbox watch")
                    };
                    if sandbox.uid != sandbox_id {
                        debug!(reason = "sandbox_id_mismatch", "CONNECT denied");
                        return Err(ResolveError::Denied);
                    }
                    let evaluation = target
                        .map(|target| traffic::evaluate(sandbox.traffic_policy.iter(), target));
                    if let (Some(target), Some(evaluation)) = (target, &evaluation)
                        && !evaluation.allowed
                    {
                        log_policy(
                            &sandbox.workload_uid,
                            sandbox_id,
                            target,
                            "sandbox",
                            None,
                            evaluation,
                        );
                        return Err(ResolveError::Denied);
                    }
                    Ok((Some(resource), evaluation))
                };
                let identity = async {
                    let (workload, (sandbox, sandbox_decision)) =
                        tokio::try_join!(workload.clone(), sandbox)?;
                    let View::Workload(source) = workload.as_ref() else {
                        unreachable!("typed Workload watch")
                    };
                    if let Some(resource) = &sandbox {
                        let View::Sandbox(sandbox) = resource.value.as_ref() else {
                            unreachable!("typed Sandbox watch")
                        };
                        if sandbox.workload_uid != source.uid {
                            debug!(reason = "sandbox_workload_mismatch", "CONNECT denied");
                            return Err(ResolveError::Denied);
                        }
                    }
                    Ok((workload, sandbox, sandbox_decision))
                };
                let policies = async {
                    if let Some(target) = target {
                        let resource = workload.clone().await?;
                        let View::Workload(workload) = resource.as_ref() else {
                            unreachable!("typed Workload watch")
                        };
                        let Some(references) = &workload.traffic_policies else {
                            debug!(reason = "traffic_binding_missing", "CONNECT denied");
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
            let ((workload, sandbox, sandbox_decision), (policies, workload_decision)) =
                resolution?;
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
                sandbox_decision,
                workload_decision,
            });
        }
    }

    async fn resolve(
        &self,
        certificate: &str,
        peer_ip: &str,
        principal: &str,
        sandbox_id: &str,
        (udp, target): (bool, Option<Target>),
        request_deadline: tokio::time::Instant,
    ) -> Result<extproc::ProcessingResponse, ResolveError> {
        let instance = match certificate_instance(certificate) {
            Ok(instance) => instance,
            Err(error) => {
                debug!(reason = "invalid_certificate", %error, "CONNECT denied");
                return Ok(denied());
            }
        };
        let lookup = if let Some(instance) = instance.as_deref() {
            Cow::Borrowed(instance)
        } else {
            let ip = match peer_ip.parse::<IpAddr>() {
                Ok(ip) if !principal.is_empty() => ip,
                _ => {
                    debug!(reason = "missing_fallback_identity", "CONNECT denied");
                    return Ok(denied());
                }
            };
            Cow::Owned(format!("/{}", ip.to_canonical()))
        };
        let RequestSnapshot {
            workload,
            sandbox,
            policies: _policies,
            sandbox_decision,
            workload_decision,
        } = self
            .snapshot(
                &lookup,
                instance.as_deref(),
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
            if let Some(evaluation) = &sandbox_decision {
                log_policy(&source.uid, sandbox_id, target, "sandbox", None, evaluation);
            }
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
        let View::Workload(workload) = workload.as_ref() else {
            unreachable!("typed Workload watch")
        };
        let mut rules = Vec::new();
        if !udp && let Some(sandbox) = sandbox {
            let View::Sandbox(sandbox) = sandbox.as_ref() else {
                unreachable!("typed Sandbox watch")
            };
            rules.extend(view::project_rules(&sandbox.rules));
        }
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "workload".into(),
            view::object([
                ("uid".into(), view::string(&workload.uid)),
                ("name".into(), view::string(&workload.name)),
                ("namespace".into(), view::string(&workload.namespace)),
            ]),
        );
        if let Some(instance) = instance {
            metadata.insert("workload_instance".into(), view::string(instance));
        }
        if !udp {
            rules.extend(view::project_rules(&workload.rules));
            let policy = if rules.is_empty() {
                view::object([])
            } else {
                view::object([("rules".into(), view::list(rules))])
            };
            metadata.insert("sni".into(), view::object([("policy".into(), policy)]));
        }
        Ok(extproc::ProcessingResponse {
            response: Some(Decision::RequestHeaders(extproc::HeadersResponse {
                response: Some(extproc::CommonResponse {}),
            })),
            dynamic_metadata: Some(Struct {
                fields: BTreeMap::from([("agentio".into(), view::object(metadata))]),
            }),
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
        "CONNECT policy evaluated"
    );
}

struct ConnectMeasurement {
    metrics: Arc<Metrics>,
    started: Instant,
    protocol: &'static str,
    result: &'static str,
}

impl Drop for ConnectMeasurement {
    fn drop(&mut self) {
        self.metrics
            .connect_results
            .get_or_create(&ConnectResult {
                protocol: self.protocol,
                result: self.result,
            })
            .inc();
        self.metrics
            .connect
            .get_or_create(&Protocol {
                protocol: self.protocol,
            })
            .observe(self.started.elapsed().as_secs_f64());
    }
}

#[tonic::async_trait]
impl ExternalProcessor for Processor {
    type ProcessStream =
        Pin<Box<dyn Stream<Item = Result<extproc::ProcessingResponse, Status>> + Send>>;

    async fn process(
        &self,
        request: Request<Streaming<extproc::ProcessingRequest>>,
    ) -> Result<Response<Self::ProcessStream>, Status> {
        let handler = self.clone();
        let mut input = request.into_inner();
        Ok(Response::new(Box::pin(async_stream::try_stream! {
            let message = input.message().await?
                .ok_or_else(|| Status::invalid_argument("missing CONNECT headers"))?;
            yield handler.handle(message).await?;
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::CacheConfig;

    #[test]
    fn attributes_accept_direct_and_wrapped_strings() {
        let attributes = Struct {
            fields: BTreeMap::from([
                ("direct".into(), view::string("certificate")),
                (
                    "wrapped".into(),
                    view::object([("value".into(), view::string("principal"))]),
                ),
                ("empty_wrapper".into(), view::object([])),
                ("wrong_type".into(), view::list(vec![])),
            ]),
        };
        assert_eq!(attribute(Some(&attributes), "direct"), "certificate");
        assert_eq!(attribute(Some(&attributes), "wrapped"), "principal");
        for key in ["empty_wrapper", "wrong_type", "missing"] {
            assert_eq!(attribute(Some(&attributes), key), "");
        }
        assert_eq!(attribute(None, "missing"), "");
    }

    fn header(key: &str, value: &str, raw_value: &[u8]) -> extproc::HeaderValue {
        extproc::HeaderValue {
            key: key.into(),
            value: value.into(),
            raw_value: raw_value.into(),
        }
    }

    #[tokio::test]
    async fn header_selection_preserves_raw_values_and_last_value_wins() {
        let cases = [
            (
                "raw method takes priority",
                vec![header(":method", "GET", b"CONNECT")],
                Some("tcp"),
            ),
            (
                "last method takes priority",
                vec![
                    header(":method", "GET", b""),
                    header(":method", "CONNECT", b""),
                ],
                Some("tcp"),
            ),
            (
                "last invalid method is rejected",
                vec![
                    header(":method", "CONNECT", b""),
                    header(":method", "POST", b""),
                ],
                None,
            ),
            (
                "raw upgrade is case insensitive",
                vec![
                    header(":method", "GET", b""),
                    header("upgrade", "ignored", b"CoNnEcT-UdP"),
                ],
                Some("udp"),
            ),
            (
                "malformed raw method remains invalid",
                vec![header(":method", "CONNECT", b"\xff")],
                None,
            ),
            (
                "malformed authority is rejected",
                vec![
                    header(":method", "CONNECT", b""),
                    header(":authority", "", b"\xff"),
                ],
                None,
            ),
        ];
        for (name, selected_headers, expected_protocol) in cases {
            let metrics = Metrics::new();
            let processor = Processor {
                client: Client::new(
                    CacheConfig {
                        max_entries: 100,
                        idle_ttl: Duration::from_secs(60),
                    },
                    metrics.clone(),
                ),
                cluster_id: "Kubernetes".into(),
                timeout: Duration::from_secs(1),
                enable_traffic_policy: true,
            };
            let mut headers = vec![
                header(":authority", "192.0.2.1:443", b""),
                header("unrelated", "", b"\xff"),
            ];
            headers.extend(selected_headers);
            let response = processor
                .handle(extproc::ProcessingRequest {
                    request_headers: Some(extproc::HttpHeaders {
                        headers: Some(extproc::HeaderMap { headers }),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .await;
            if let Some(protocol) = expected_protocol {
                // Header validation passes; missing identity still denies the request.
                assert!(
                    matches!(
                        response.unwrap().response,
                        Some(Decision::ImmediateResponse(_))
                    ),
                    "{name}"
                );
                assert_eq!(
                    metrics
                        .connect_results
                        .get_or_create(&ConnectResult {
                            protocol,
                            result: "denied",
                        })
                        .get(),
                    1,
                    "{name}"
                );
            } else {
                assert_eq!(
                    response.unwrap_err().code(),
                    tonic::Code::InvalidArgument,
                    "{name}"
                );
            }
        }
    }
}
