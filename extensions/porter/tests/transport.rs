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
use std::{
    collections::VecDeque,
    io::{Read, Seek},
    pin::Pin,
    time::Duration,
};
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
    disconnect: broadcast::Sender<Option<Status>>,
    handshake: Option<watch::Receiver<bool>>,
    delayed_rejections: Option<(mpsc::UnboundedSender<tokio::time::Instant>, Duration)>,
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
            if let Some((attempts, delay)) = &self.delayed_rejections {
                attempts.send(tokio::time::Instant::now()).unwrap();
                tokio::time::sleep(*delay).await;
            }
            return Err(Status::unauthenticated("invalid token"));
        }
        let mut input = request.into_inner();
        let seen = self.seen.clone();
        let mut disconnect = self.disconnect.subscribe();
        let mut queued = VecDeque::new();
        if let Some(mut gate) = self.handshake.clone() {
            while !*gate.borrow_and_update() {
                tokio::select! {
                    changed = gate.changed() => changed.unwrap(),
                    message = input.message() => {
                        let message = message?.ok_or_else(|| Status::cancelled("request closed"))?;
                        seen.send(message.clone()).unwrap();
                        queued.push_back(message);
                    },
                }
            }
        }
        Ok(Response::new(Box::pin(async_stream::try_stream! {
            loop {
                let message = if let Some(message) = queued.pop_front() {
                    message
                } else {
                    let message = tokio::select! {
                        closed = disconnect.recv() => match closed.unwrap() {
                            Some(error) => Err(error),
                            None => Ok(None),
                        },
                        message = input.message() => message,
                    }?;
                    let Some(message) = message else { break; };
                    seen.send(message.clone()).unwrap();
                    message
                };
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
    let mut logs = tempfile::tempfile().unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .fmt_fields(tracing_subscriber::fmt::format::JsonFields::default())
        .event_format(agentio_porter::logging::JsonFormat)
        .with_writer(logs.try_clone().unwrap())
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
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
                handshake: None,
                delayed_rejections: None,
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
    for _ in ResourceKind::ALL {
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
    disconnect
        .send(Some(Status::unavailable("test disconnect")))
        .unwrap();
    ready(&mut health, false).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!*health.borrow());
    tokio::fs::write(&token, "token").await.unwrap();
    ready(&mut health, true).await;
    c.demand(ResourceKind::Workload, "alias", None)
        .await
        .unwrap();
    assert!(c.metrics.reconnects.get() >= 1);
    let retries = c.metrics.reconnects.get();
    disconnect.send(None).unwrap();
    ready(&mut health, false).await;
    ready(&mut health, true).await;
    c.demand(ResourceKind::Workload, "alias", None)
        .await
        .unwrap();
    assert!(c.metrics.reconnects.get() > retries);
    stop.cancel();
    client.await.unwrap();
    expiry.await.unwrap();
    server.await.unwrap().unwrap();
    logs.rewind().unwrap();
    let mut output = String::new();
    logs.read_to_string(&mut output).unwrap();
    let events: Vec<serde_json::Value> = output
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(events.iter().any(|event| event["level"] == "debug"
        && event["message"] == "ADS stream closed"
        && event.get("error").is_none()));
    assert!(
        events.iter().any(|event| event["level"] == "warn"
            && event["message"] == "ADS disconnected"
            && event["error"].as_str().unwrap().contains("invalid token")),
        "{output}"
    );
}

#[tokio::test]
async fn reconnect_keeps_grace_cache_during_rpc_handshake_without_replaying_it() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let root = dir.path().join("root.pem");
        let token = dir.path().join("token");
        tokio::fs::write(&root, cert.cert.pem()).await.unwrap();
        tokio::fs::write(&token, "token").await.unwrap();
        let (seen, mut requests) = mpsc::unbounded_channel();
        let (disconnect, _) = broadcast::channel(1);
        let (gate, handshake) = watch::channel(true);
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
                    handshake: Some(handshake),
                    delayed_rejections: None,
                }))
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    server_stop.cancelled_owned(),
                ),
        );
        let c = Client::new(CacheConfig::default(), Metrics::new());
        let mut health = c.readiness();
        let client = tokio::spawn(c.clone().run(
            TransportConfig {
                address: format!("localhost:{port}"),
                root_path: root.to_string_lossy().into(),
                token_path: token.to_string_lossy().into(),
                node: ads::Node {
                    id: "porter-grace-test".into(),
                    metadata: None,
                },
            },
            stop.clone(),
        ));
        let expiry = tokio::spawn(c.clone().expire(stop.clone()));
        ready(&mut health, true).await;
        c.demand(ResourceKind::Workload, "warm", None)
            .await
            .unwrap();
        gate.send_replace(false);
        tokio::fs::write(&token, "bad-token").await.unwrap();
        disconnect
            .send(Some(Status::unavailable("test disconnect")))
            .unwrap();
        ready(&mut health, false).await;
        while requests.try_recv().is_ok() {}
        // At least one authenticated RPC attempt has failed before the next
        // begins. Failure must not discard the grace cache.
        while c.metrics.reconnects.get() < 2 {
            tokio::task::yield_now().await;
        }
        assert_eq!(c.metrics.connected.get(), 0);
        c.demand(ResourceKind::Workload, "warm", None)
            .await
            .unwrap();
        tokio::fs::write(&token, "token").await.unwrap();
        let mut pending = Box::pin(c.demand(ResourceKind::Workload, "pending", None));
        assert!(futures_util::poll!(&mut pending).is_pending());
        // The server reads initial requests but deliberately does not establish
        // the RPC. TLS/TCP are connected; ADS has not yet succeeded.
        let mut initial = Vec::new();
        while initial.len() < ResourceKind::ALL.len() {
            let request = requests.recv().await.unwrap();
            assert!(
                !request
                    .resource_names_subscribe
                    .iter()
                    .any(|name| name == "warm")
            );
            if request.node.is_some() {
                initial.push(request);
            }
        }
        assert_eq!(
            initial
                .iter()
                .find(|r| r.type_url == ResourceKind::Workload.type_url())
                .unwrap()
                .resource_names_subscribe,
            ["pending"]
        );
        assert_eq!(c.metrics.connected.get(), 0);
        assert!(!*health.borrow());
        c.demand(ResourceKind::Workload, "warm", None)
            .await
            .unwrap();
        assert_eq!(
            c.metrics.cache.get(),
            2,
            "handshake must retain the warm cache and pending demand"
        );
        gate.send_replace(true);
        pending.await.unwrap();
        ready(&mut health, true).await;
        assert_eq!(c.metrics.connected.get(), 1);
        assert_eq!(
            c.metrics.cache.get(),
            1,
            "successful RPC must clear idle historical interests"
        );
        c.demand(ResourceKind::Workload, "warm", None)
            .await
            .unwrap();
        // A post-reconnect use must actually rediscover warm, rather than get an
        // old value left in a cache that was replayed during initial().
        loop {
            let request = requests.recv().await.unwrap();
            if request.resource_names_subscribe == ["warm"] {
                assert!(request.node.is_none());
                break;
            }
        }
        stop.cancel();
        client.await.unwrap();
        expiry.await.unwrap();
        server.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn slow_failed_reconnects_do_not_reset_backoff_using_cached_sync_state() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let root = dir.path().join("root.pem");
        let token = dir.path().join("token");
        tokio::fs::write(&root, cert.cert.pem()).await.unwrap();
        tokio::fs::write(&token, "token").await.unwrap();
        let (seen, _requests) = mpsc::unbounded_channel();
        let (disconnect, _) = broadcast::channel(1);
        let (rejections, mut attempts) = mpsc::unbounded_channel();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = CancellationToken::new();
        let server_stop = stop.clone();
        let rejection_delay = Duration::from_millis(1100);
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
                    handshake: None,
                    delayed_rejections: Some((rejections, rejection_delay)),
                }))
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    server_stop.cancelled_owned(),
                ),
        );
        let c = Client::new(CacheConfig::default(), Metrics::new());
        let mut health = c.readiness();
        let client = tokio::spawn(c.clone().run(
            TransportConfig {
                address: format!("localhost:{port}"),
                root_path: root.to_string_lossy().into(),
                token_path: token.to_string_lossy().into(),
                node: ads::Node::default(),
            },
            stop.clone(),
        ));
        let expiry = tokio::spawn(c.clone().expire(stop.clone()));
        ready(&mut health, true).await;
        c.demand(ResourceKind::Workload, "warm", None)
            .await
            .unwrap();
        tokio::fs::write(&token, "bad-token").await.unwrap();
        disconnect
            .send(Some(Status::unavailable("test disconnect")))
            .unwrap();
        ready(&mut health, false).await;
        let first = attempts.recv().await.unwrap();
        let second = attempts.recv().await.unwrap();
        let third = attempts.recv().await.unwrap();
        // Each RPC rejects after >1s while the old cache is still synced. It
        // must retain the 200ms then 400ms exponential backoff, not reset to
        // the 100ms initial value because an earlier stream once received data.
        assert!(second - first >= rejection_delay + Duration::from_millis(200));
        assert!(third - second >= rejection_delay + Duration::from_millis(400));
        assert_eq!(c.metrics.connected.get(), 0);
        c.demand(ResourceKind::Workload, "warm", None)
            .await
            .unwrap();
        stop.cancel();
        client.await.unwrap();
        expiry.await.unwrap();
        server.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}
