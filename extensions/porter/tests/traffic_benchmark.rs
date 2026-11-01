// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

//! Opt-in, identical-input baseline/candidate benchmark. Uses real local TLS ADS
//! and ext_proc gRPC; the inventory server substitutes for Agentiod compilation.

use agentio_porter::{
    discovery::{CacheConfig, Client, TransportConfig},
    metrics::Metrics,
    processor::Processor,
    wire::{
        ads,
        agentio::security::{TrafficPolicy, traffic_policy as tp},
        extproc,
        istio::workload::{Extension, Workload},
        kruise::networking::extensions::v1::{
            PolicyReference, SniAction, SniMatch, SniRule, SniTrafficPolicy, WorkloadMetadata,
        },
    },
};
use futures_util::Stream;
use prost::Message;
use prost_types::{Any, Struct, Value, value::Kind};
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use std::{
    collections::{BTreeMap, HashMap},
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::{
    Request, Response, Status, Streaming,
    transport::{Identity, Server, ServerTlsConfig},
};

const WDS: &str = "type.googleapis.com/istio.workload.Workload";
const TP: &str = "type.googleapis.com/agentio.security.TrafficPolicy";

fn pack(type_url: &str, value: impl Message) -> Any {
    Any {
        type_url: type_url.into(),
        value: value.encode_to_vec(),
    }
}

#[derive(Clone)]
struct Ads(Arc<HashMap<String, Any>>);

#[tonic::async_trait]
impl ads::aggregated_discovery_service_server::AggregatedDiscoveryService for Ads {
    type DeltaAggregatedResourcesStream =
        Pin<Box<dyn Stream<Item = Result<ads::DeltaDiscoveryResponse, Status>> + Send>>;
    async fn delta_aggregated_resources(
        &self,
        request: Request<Streaming<ads::DeltaDiscoveryRequest>>,
    ) -> Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
        assert_eq!(
            request.metadata().get("authorization").unwrap(),
            "Bearer benchmark"
        );
        let mut input = request.into_inner();
        let inventory = self.0.clone();
        Ok(Response::new(Box::pin(async_stream::try_stream! {
            let mut nonce = 0;
            while let Some(request) = input.message().await? {
                assert!(request.error_detail.is_none(), "benchmark received NACK: {:?}", request.error_detail);
                if request.resource_names_subscribe.is_empty() && request.resource_names_unsubscribe.is_empty() { continue; }
                nonce += 1;
                let mut reply = ads::DeltaDiscoveryResponse { type_url: request.type_url.clone(), nonce: nonce.to_string(), ..Default::default() };
                for name in request.resource_names_subscribe.into_iter().filter(|name| name != "*") {
                    match inventory.get(&name).filter(|body| body.type_url == request.type_url) {
                        Some(body) => reply.resources.push(ads::Resource { name, version: "1".into(), resource: Some(body.clone()), ..Default::default() }),
                        None => reply.removed_resources.push(name),
                    }
                }
                yield reply;
            }
        })))
    }
}

fn inventory(
    policies: usize,
    rules: usize,
    count: usize,
) -> (HashMap<String, Any>, Vec<extproc::ProcessingRequest>) {
    let mut resources = HashMap::new();
    let mut requests = Vec::new();
    let key = KeyPair::generate().unwrap();
    for i in 0..count {
        let uid = format!("source-{i}");
        let mut certificate = CertificateParams::default();
        certificate
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 57874, 5, 1],
                format!(r#"{{"registry":"bench","uid":"{uid}"}}"#).into_bytes(),
            ));
        let certificate = certificate.self_signed(&key).unwrap().pem();
        let references: Vec<String> = (0..policies).map(|j| format!("policy/{i}/{j}")).collect();
        for (j, name) in references.iter().enumerate() {
            let mut body = tp::RuleSet::default();
            for k in 0..rules {
                let last = j == policies - 1 && k == rules - 1;
                body.rules.push(tp::Rule {
                    action: if last {
                        tp::Action::Allow
                    } else {
                        tp::Action::Deny
                    } as i32,
                    r#match: Some(tp::Match {
                        destination_ips: vec![tp::Address {
                            address: if last {
                                vec![192, 0, 2, 1]
                            } else {
                                vec![198, 51, 100, (k % 256) as u8]
                            },
                            length: 32,
                        }],
                        ports: vec![tp::PortMatch {
                            protocol: tp::Protocol::Tcp as i32,
                            port: Some(443),
                            end_port: None,
                        }],
                        ..Default::default()
                    }),
                });
            }
            resources.insert(
                name.clone(),
                pack(
                    TP,
                    TrafficPolicy {
                        egress: Some(body),
                        ..Default::default()
                    },
                ),
            );
        }
        let extensions = vec![
            Extension {
                name: "traffic-policy-reference".into(),
                config: Some(pack(
                    "type.googleapis.com/kruise.networking.extensions.v1.PolicyReference",
                    PolicyReference {
                        type_url: TP.into(),
                        resource_names: references,
                    },
                )),
            },
            Extension {
                name: "metadata".into(),
                config: Some(pack(
                    "type.googleapis.com/kruise.networking.extensions.v1.WorkloadMetadata",
                    WorkloadMetadata {
                        labels: (0..20)
                            .map(|j| (format!("label-{j}"), format!("value-{j}")))
                            .collect(),
                        ..Default::default()
                    },
                )),
            },
            Extension {
                name: "sni".into(),
                config: Some(pack(
                    "type.googleapis.com/kruise.networking.extensions.v1.SniTrafficPolicy",
                    SniTrafficPolicy {
                        rules: (0..8)
                            .map(|j| SniRule {
                                r#match: Some(SniMatch {
                                    sni: vec![format!("host-{j}.example.com")],
                                }),
                                action: SniAction::TlsTermination as i32,
                            })
                            .collect(),
                    },
                )),
            },
        ];
        resources.insert(
            format!("workload-instance/bench/{uid}"),
            pack(
                WDS,
                Workload {
                    uid: uid.clone(),
                    name: uid,
                    namespace: "bench".into(),
                    extensions,
                    ..Default::default()
                },
            ),
        );
        requests.push(extproc::ProcessingRequest {
            request_headers: Some(extproc::HttpHeaders {
                headers: Some(extproc::HeaderMap {
                    headers: vec![
                        extproc::HeaderValue {
                            key: ":method".into(),
                            value: "CONNECT".into(),
                            ..Default::default()
                        },
                        extproc::HeaderValue {
                            key: ":authority".into(),
                            value: "192.0.2.1:443".into(),
                            ..Default::default()
                        },
                    ],
                }),
                ..Default::default()
            }),
            attributes: HashMap::from([(
                "envoy.filters.http.ext_proc".into(),
                Struct {
                    fields: BTreeMap::from([(
                        "filter_state['agentio.peer.certificate']".into(),
                        Value {
                            kind: Some(Kind::StringValue(certificate)),
                        },
                    )]),
                },
            )]),
        });
    }
    (resources, requests)
}

fn allowed(response: extproc::ProcessingResponse) {
    assert!(matches!(
        response.response,
        Some(extproc::processing_response::Response::RequestHeaders(_))
    ));
}

fn report(case: &str, mode: &str, mut samples: Vec<f64>, elapsed: Duration) {
    samples.sort_by(f64::total_cmp);
    println!(
        "{}",
        serde_json::json!({"case":case, "mode":mode, "requests":samples.len(),
        "mean_us":samples.iter().sum::<f64>()/samples.len() as f64,
        "p50_us":samples[samples.len()/2], "p99_us":samples[(samples.len()*99/100).min(samples.len()-1)],
        "rps":samples.len() as f64/elapsed.as_secs_f64()})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "performance benchmark; run release build in isolation with --nocapture"]
async fn connect_traffic_policy_benchmark() {
    let samples: usize = std::env::var("PORTER_BENCH_REQUESTS")
        .unwrap_or_else(|_| "5000".into())
        .parse()
        .unwrap();
    assert!(samples >= 100);
    for (policies, rules) in [(0, 0), (1, 16), (8, 16), (8, 128), (32, 32)] {
        let case = format!("{policies}x{rules}");
        let (resources, requests) = inventory(policies, rules, 101);
        let stop = CancellationToken::new();
        let directory = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let roots = directory.path().join("root.pem");
        let token = directory.path().join("token");
        std::fs::write(&roots, cert.cert.pem()).unwrap();
        std::fs::write(&token, "benchmark").unwrap();
        let ads_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ads_port = ads_listener.local_addr().unwrap().port();
        let ads_server = tokio::spawn(
            Server::builder()
                .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(
                    cert.cert.pem(),
                    cert.signing_key.serialize_pem(),
                )))
                .unwrap()
                .add_service(
                    ads::aggregated_discovery_service_server::AggregatedDiscoveryServiceServer::new(
                        Ads(Arc::new(resources)),
                    ),
                )
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(ads_listener),
                    stop.clone().cancelled_owned(),
                ),
        );
        let client = Client::new(
            CacheConfig {
                max_entries: 10000,
                idle_ttl: Duration::from_secs(600),
            },
            Metrics::new(),
        );
        let discovery = tokio::spawn(client.clone().run(
            TransportConfig {
                address: format!("localhost:{ads_port}"),
                root_path: roots.to_string_lossy().into(),
                token_path: token.to_string_lossy().into(),
                node: ads::Node {
                    id: "agentio-porter~benchmark".into(),
                    ..Default::default()
                },
            },
            stop.clone(),
        ));
        let mut ready = client.readiness();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !*ready.borrow_and_update() {
                ready.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let processor = Processor {
            client,
            cluster_id: "Kubernetes".into(),
            timeout: Duration::from_secs(4),
            enable_traffic_policy: true,
        };

        // Unique Workload AND policy names: each sample requires fresh TLS ADS requests.
        let begin = Instant::now();
        let mut durations = Vec::new();
        for request in &requests[1..] {
            let start = Instant::now();
            allowed(processor.handle(request.clone()).await.unwrap());
            durations.push(start.elapsed().as_secs_f64() * 1e6);
        }
        report(&case, "cold_handler_tls_ads", durations, begin.elapsed());
        for _ in 0..1000 {
            allowed(processor.handle(requests[0].clone()).await.unwrap());
        }
        let begin = Instant::now();
        let mut durations = Vec::with_capacity(samples);
        for _ in 0..samples {
            let start = Instant::now();
            allowed(processor.handle(requests[0].clone()).await.unwrap());
            durations.push(start.elapsed().as_secs_f64() * 1e6);
        }
        report(&case, "hot_handler", durations, begin.elapsed());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(
            Server::builder()
                .add_service(
                    extproc::external_processor_server::ExternalProcessorServer::new(processor),
                )
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    stop.clone().cancelled_owned(),
                ),
        );
        let rpc = extproc::external_processor_client::ExternalProcessorClient::connect(format!(
            "http://127.0.0.1:{port}"
        ))
        .await
        .unwrap();
        for concurrency in [1, 16] {
            let begin = Instant::now();
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..concurrency {
                let mut rpc = rpc.clone();
                let request = requests[0].clone();
                tasks.spawn(async move {
                    let mut durations = Vec::new();
                    for _ in 0..samples / concurrency {
                        let start = Instant::now();
                        let mut stream = rpc
                            .process(tokio_stream::iter([request.clone()]))
                            .await
                            .unwrap()
                            .into_inner();
                        allowed(stream.message().await.unwrap().unwrap());
                        assert!(stream.message().await.unwrap().is_none());
                        durations.push(start.elapsed().as_secs_f64() * 1e6);
                    }
                    durations
                });
            }
            let mut durations = Vec::new();
            while let Some(result) = tasks.join_next().await {
                durations.extend(result.unwrap());
            }
            report(
                &case,
                &format!("hot_grpc_c{concurrency}"),
                durations,
                begin.elapsed(),
            );
        }
        drop(rpc);
        stop.cancel();
        discovery.await.unwrap();
        server.await.unwrap().unwrap();
        ads_server.await.unwrap().unwrap();
    }
}
