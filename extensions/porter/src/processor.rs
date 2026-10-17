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

use futures_util::Stream;
use prost_types::{Struct, value::Kind};
use tonic::{Request, Response, Status, Streaming};
use tracing::debug;

use crate::{
    discovery::{Client, DemandError},
    identity::certificate_instance,
    metrics::{ConnectResult, Metrics, Protocol},
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
        let udp = {
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
            udp
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
        let sandbox_id = attribute(attributes, "filter_state['sandbox.id']");
        let request_deadline = tokio::time::Instant::now() + self.timeout;
        let result = tokio::time::timeout_at(
            request_deadline,
            self.resolve(
                certificate,
                peer_ip,
                principal,
                sandbox_id,
                udp,
                request_deadline,
            ),
        )
        .await;
        let response = match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(DemandError::NotFound)) => {
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

    async fn resolve(
        &self,
        certificate: &str,
        peer_ip: &str,
        principal: &str,
        sandbox_id: &str,
        udp: bool,
        request_deadline: tokio::time::Instant,
    ) -> Result<extproc::ProcessingResponse, DemandError> {
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
        let workload = self
            .client
            .demand(ResourceKind::Workload, &lookup, Some(request_deadline))
            .await?;
        let View::Workload(workload) = workload.as_ref() else {
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
            return Ok(denied());
        }
        let mut rules = Vec::new();
        if !sandbox_id.is_empty() {
            let sandbox = self
                .client
                .demand(ResourceKind::Sandbox, sandbox_id, Some(request_deadline))
                .await?;
            let View::Sandbox(sandbox) = sandbox.as_ref() else {
                unreachable!("typed Sandbox watch")
            };
            if sandbox.uid != sandbox_id || sandbox.workload_uid != workload.uid {
                debug!(reason = "sandbox_workload_mismatch", "CONNECT denied");
                return Ok(denied());
            }
            if !udp {
                rules.extend(view::project_rules(&sandbox.rules));
            }
        }
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "workload".into(),
            view::object([
                ("name".into(), view::string(&workload.name)),
                ("namespace".into(), view::string(&workload.namespace)),
            ]),
        );
        metadata.insert(
            "workload_labels".into(),
            view::string(&workload.encoded_labels),
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
                "authority retains lossy UTF-8 behavior",
                vec![
                    header(":method", "CONNECT", b""),
                    header(":authority", "", b"\xff"),
                ],
                Some("tcp"),
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
            };
            let mut headers = vec![
                header(":authority", "example:443", b""),
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
