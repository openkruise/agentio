// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use agentio_porter::{
    discovery::{CacheConfig, Client, DemandError, TransportConfig},
    metrics::{Metrics, ResourceType},
    view::ResourceKind,
    wire::{
        ads::{
            self,
            aggregated_discovery_service_server::{
                AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
            },
        },
        istio::workload::Workload,
    },
};
use futures_util::Stream;
use prost::Message;
use std::{pin::Pin, time::Duration};
use tokio::sync::{broadcast, mpsc, watch};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::{
    Request, Response, Status, Streaming,
    transport::{Identity, Server, ServerTlsConfig},
};

#[derive(Clone)]
struct Ads {
    seen: mpsc::UnboundedSender<ads::DeltaDiscoveryRequest>,
    disconnect: broadcast::Sender<()>,
}

#[tonic::async_trait]
impl AggregatedDiscoveryService for Ads {
    type DeltaAggregatedResourcesStream =
        Pin<Box<dyn Stream<Item = Result<ads::DeltaDiscoveryResponse, Status>> + Send>>;

    async fn delta_aggregated_resources(
        &self,
        request: Request<Streaming<ads::DeltaDiscoveryRequest>>,
    ) -> Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
        if request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            != Some("Bearer token")
        {
            return Err(Status::unauthenticated("invalid token"));
        }
        let mut input = request.into_inner();
        let seen = self.seen.clone();
        let mut disconnect = self.disconnect.subscribe();
        Ok(Response::new(Box::pin(async_stream::try_stream! {
            loop {
                let message = tokio::select! {
                    _ = disconnect.recv() => Err(Status::unavailable("test disconnect")),
                    message = input.message() => message,
                }?;
                let Some(message) = message else {
                    break;
                };
                seen.send(message.clone()).unwrap();
                if message.resource_names_subscribe.is_empty()
                    && message.resource_names_unsubscribe.is_empty()
                {
                    continue;
                }
                let mut reply = ads::DeltaDiscoveryResponse {
                    type_url: message.type_url.clone(),
                    nonce: "nonce".into(),
                    ..Default::default()
                };
                for name in message.resource_names_subscribe {
                    if name == "*" {
                        continue;
                    }
                    if name == "invalid" {
                        reply.resources.push(ads::Resource {
                            name,
                            resource: Some(prost_types::Any {
                                type_url: ResourceKind::Workload.type_url().into(),
                                value: vec![255],
                            }),
                            ..Default::default()
                        });
                        continue;
                    }
                    if name == "missing" {
                        reply.removed_resources.push(name);
                        continue;
                    }
                    reply.resources.push(ads::Resource {
                        name: "canonical".into(),
                        aliases: vec![name.clone()],
                        resource: Some(prost_types::Any {
                            type_url: ResourceKind::Workload.type_url().into(),
                            value: Workload {
                                uid: "canonical".into(),
                                name: if name == "large" {
                                    "x".repeat(5 * 1024 * 1024)
                                } else {
                                    String::new()
                                },
                                ..Default::default()
                            }.encode_to_vec(),
                        }),
                        ..Default::default()
                    });
                }
                yield reply;
            }
        })))
    }
}

async fn ready(r: &mut watch::Receiver<bool>, value: bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while *r.borrow_and_update() != value {
            r.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tls_auth_initial_handshake_eviction_and_token_reload() {
    let dir = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let root = dir.path().join("root.pem");
    let token = dir.path().join("token");
    tokio::fs::write(&root, cert.cert.pem()).await.unwrap();
    tokio::fs::write(&token, "token").await.unwrap();
    let (seen, mut requests) = mpsc::unbounded_channel();
    let (disconnect, _) = broadcast::channel(1);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = CancellationToken::new();
    let server_stop = stop.clone();
    let server = tokio::spawn(
        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(
                cert.cert.pem(),
                cert.signing_key.serialize_pem(),
            )))
            .unwrap()
            .add_service(AggregatedDiscoveryServiceServer::new(Ads {
                seen,
                disconnect: disconnect.clone(),
            }))
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                server_stop.cancelled_owned(),
            ),
    );
    let c = Client::new(
        CacheConfig {
            max_entries: 10,
            idle_ttl: Duration::from_millis(50),
        },
        Metrics::new(),
    );
    let mut health = c.readiness();
    let transport = TransportConfig {
        address: format!("localhost:{port}"),
        root_path: root.to_string_lossy().into(),
        token_path: token.to_string_lossy().into(),
        node: ads::Node {
            id: "agentio-porter~test".into(),
            metadata: None,
        },
    };
    let client = tokio::spawn(c.clone().run(transport, stop.clone()));
    let expiry = tokio::spawn(c.clone().expire(stop.clone()));
    ready(&mut health, true).await;
    for _ in 0..2 {
        let req = requests.recv().await.unwrap();
        assert_eq!(req.node.unwrap().id, "agentio-porter~test");
        assert_eq!(req.resource_names_subscribe, ["*"]);
        assert_eq!(req.resource_names_unsubscribe, ["*"]);
    }
    c.demand(ResourceKind::Workload, "alias", None)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if requests.recv().await.unwrap().resource_names_unsubscribe == ["alias"] {
                break;
            }
        }
    })
    .await
    .unwrap();
    let large = c
        .demand(ResourceKind::Workload, "large", None)
        .await
        .unwrap();
    assert!(matches!(
        large.as_ref(),
        agentio_porter::view::View::Workload(w) if w.name.len() == 5 * 1024 * 1024
    ));
    assert_eq!(
        c.demand(ResourceKind::Workload, "missing", None)
            .await
            .unwrap_err(),
        DemandError::NotFound
    );
    let invalid = tokio::spawn({
        let c = c.clone();
        async move { c.demand(ResourceKind::Workload, "invalid", None).await }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if requests.recv().await.unwrap().error_detail.is_some() {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        c.metrics
            .nacks
            .get_or_create(&ResourceType {
                resource_type: ResourceKind::Workload.type_url()
            })
            .get(),
        1
    );
    invalid.abort();
    assert!(invalid.await.unwrap_err().is_cancelled());
    tokio::fs::write(&token, "bad-token").await.unwrap();
    disconnect.send(()).unwrap();
    ready(&mut health, false).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!*health.borrow());
    tokio::fs::write(&token, "token").await.unwrap();
    ready(&mut health, true).await;
    c.demand(ResourceKind::Workload, "alias", None)
        .await
        .unwrap();
    assert!(c.metrics.reconnects.get() >= 1);
    stop.cancel();
    client.await.unwrap();
    expiry.await.unwrap();
    server.await.unwrap().unwrap();
}
