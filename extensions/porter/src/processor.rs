// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

mod agentgateway;
mod agentio_egress;
mod resolve;

use std::{
    borrow::Cow,
    collections::BTreeMap,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::Stream;
use prost_types::{Struct, Value, value::Kind};
use tonic::{Request, Response, Status, Streaming};
use tracing::debug;

use crate::{
    discovery::{Client, DemandError},
    view::{self, View},
    wire::extproc::{
        self, external_processor_server::ExternalProcessor,
        processing_response::Response as Decision,
    },
};
use resolve::{IdentityEvidence, ResolveError, ResolveRequest, Resolved, Resolver};

#[derive(Clone)]
pub struct Processor {
    pub client: Arc<Client>,
    pub cluster_id: String,
    pub timeout: Duration,
    pub enable_traffic_policy: bool,
    pub enable_sni_traffic_policy: bool,
    pub gateway: Gateway,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Gateway {
    AgentioEgress,
    Agentgateway,
}

struct ParsedRequest<'a> {
    resolution: ResolveRequest<'a>,
    protocol: &'static str,
}

struct Headers<'a> {
    method: Cow<'a, str>,
    authority: Cow<'a, str>,
    upgrade: Cow<'a, str>,
}

fn headers(headers: Option<&extproc::HttpHeaders>) -> Result<Headers<'_>, Status> {
    let headers = headers.ok_or_else(|| Status::invalid_argument("missing request headers"))?;
    let mut result = Headers {
        method: Cow::Borrowed(""),
        authority: Cow::Borrowed(""),
        upgrade: Cow::Borrowed(""),
    };
    for header in headers.headers.iter().flat_map(|headers| &headers.headers) {
        let target = match header.key.as_str() {
            ":method" => &mut result.method,
            ":authority" => &mut result.authority,
            "upgrade" => &mut result.upgrade,
            _ => continue,
        };
        *target = if header.raw_value.is_empty() {
            Cow::Borrowed(header.value.as_str())
        } else {
            String::from_utf8_lossy(&header.raw_value)
        };
    }
    Ok(result)
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

fn identity(attributes: Option<&Struct>) -> IdentityEvidence<'_> {
    IdentityEvidence {
        certificate: attribute(attributes, "filter_state['agentio.peer.certificate']"),
        peer_ip: attribute(attributes, "filter_state['agentio.downstream.ip']"),
        principal: attribute(attributes, "filter_state['agentio.peer.principal']"),
        sandbox_id: attribute(attributes, "filter_state['agentio.sandbox.id']"),
    }
}

fn identity_metadata(workload: &View, instance: Option<String>) -> BTreeMap<String, Value> {
    let View::Workload(workload) = workload else {
        unreachable!("typed Workload watch")
    };
    let mut fields = BTreeMap::from([
        ("resource_name".into(), view::string(&workload.uid)),
        ("name".into(), view::string(&workload.name)),
        ("namespace".into(), view::string(&workload.namespace)),
    ]);
    if let Some(instance) = instance {
        fields.insert("uid".into(), view::string(instance));
    }
    BTreeMap::from([("workload".into(), view::object(fields))])
}

fn allowed(metadata: BTreeMap<String, Value>) -> extproc::ProcessingResponse {
    extproc::ProcessingResponse {
        response: Some(Decision::RequestHeaders(extproc::HeadersResponse {
            response: Some(extproc::CommonResponse {}),
        })),
        dynamic_metadata: Some(Struct {
            fields: BTreeMap::from([("agentio".into(), view::object(metadata))]),
        }),
    }
}

impl Processor {
    pub async fn handle(
        &self,
        message: extproc::ProcessingRequest,
    ) -> Result<extproc::ProcessingResponse, Status> {
        let started = Instant::now();
        let attributes = message.attributes.get("envoy.filters.http.ext_proc");
        let parsed = match self.gateway {
            Gateway::AgentioEgress => agentio_egress::parse(
                message.request_headers.as_ref(),
                attributes,
                self.enable_traffic_policy,
            ),
            Gateway::Agentgateway => agentgateway::parse(
                message.request_headers.as_ref(),
                attributes,
                self.enable_traffic_policy,
            ),
        }?;
        // Identity resolution only borrows attributes; release headers before awaiting discovery.
        drop(message.request_headers);
        let mut measurement =
            (self.gateway == Gateway::AgentioEgress).then(|| agentio_egress::ConnectMeasurement {
                metrics: self.client.metrics.clone(),
                started,
                protocol: parsed.protocol,
                result: "canceled",
            });
        let resolver = Resolver {
            client: &self.client,
            cluster_id: &self.cluster_id,
            timeout: self.timeout,
        };
        let response = match resolver.resolve(&parsed.resolution).await {
            Ok(resolved) => Ok(match self.gateway {
                Gateway::AgentioEgress => agentio_egress::encode(
                    resolved,
                    parsed.protocol,
                    self.enable_sni_traffic_policy,
                ),
                Gateway::Agentgateway => agentgateway::encode(resolved),
            }),
            Err(ResolveError::Denied) => Ok(denied()),
            Err(ResolveError::Discovery(DemandError::NotFound)) => {
                debug!(reason = "resource_not_found", "request denied");
                Ok(denied())
            }
            Err(error) => Err(Status::unavailable(format!(
                "request processing failed: {error}"
            ))),
        };
        if let Some(measurement) = &mut measurement {
            measurement.result = match &response {
                Ok(response)
                    if matches!(response.response, Some(Decision::ImmediateResponse(_))) =>
                {
                    "denied"
                }
                Ok(_) => "allowed",
                Err(_) => "error",
            };
        }
        response
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
                .ok_or_else(|| Status::invalid_argument("missing request headers"))?;
            yield handler.handle(message).await?;
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        discovery::CacheConfig,
        metrics::{ConnectResult, Metrics},
    };

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
                gateway: crate::processor::Gateway::AgentioEgress,
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
                enable_sni_traffic_policy: true,
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
