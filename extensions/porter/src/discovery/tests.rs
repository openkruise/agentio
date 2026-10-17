// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    processor::Processor,
    wire::{extproc, istio::workload::Workload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use prost::Message;

fn client(max: usize, ttl: Duration) -> Arc<Client> {
    Client::new(
        CacheConfig {
            max_entries: max,
            idle_ttl: ttl,
        },
        Metrics::new(),
    )
}

fn resource(name: &str, aliases: &[&str]) -> ads::Resource {
    ads::Resource {
        name: name.into(),
        aliases: aliases.iter().map(|s| s.to_string()).collect(),
        resource: Some(prost_types::Any {
            type_url: ResourceKind::Workload.type_url().into(),
            value: Workload {
                uid: name.into(),
                name: name.into(),
                ..Default::default()
            }
            .encode_to_vec(),
        }),
        ..Default::default()
    }
}

fn response(resources: Vec<ads::Resource>, removed: &[&str]) -> Response {
    Response {
        type_url: ResourceKind::Workload.type_url().into(),
        resources,
        removed_resources: removed.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

#[tokio::test(start_paused = true)]
async fn workload_and_sandbox_share_connect_deadline() {
    let fixtures: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../../tests/fixtures.json")).unwrap();
    let fixture = fixtures
        .iter()
        .find(|fixture| fixture["name"] == "sandbox-first")
        .unwrap();
    let request = extproc::ProcessingRequest::decode(
        STANDARD
            .decode(fixture["request"].as_str().unwrap())
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let client = client(100, Duration::from_secs(60));
    let processor = Processor {
        client: client.clone(),
        cluster_id: "Kubernetes".into(),
        timeout: Duration::from_millis(100),
    };
    let mut processing = Box::pin(processor.handle(request));
    assert!(futures_util::poll!(&mut processing).is_pending());

    // Spend most of the CONNECT budget waiting for the Workload resource.
    tokio::time::advance(Duration::from_millis(60)).await;
    let workload_name = client.state.lock().unwrap().types[ResourceKind::Workload.index()]
        .entries
        .keys()
        .next()
        .unwrap()
        .clone();
    let resource_key = format!("{}|{workload_name}", ResourceKind::Workload.type_url());
    let workload = prost_types::Any::decode(
        STANDARD
            .decode(fixture["resources"][&resource_key].as_str().unwrap())
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    client
        .apply(
            ResourceKind::Workload,
            &response(
                vec![ads::Resource {
                    name: workload_name,
                    resource: Some(workload),
                    ..Default::default()
                }],
                &[],
            ),
        )
        .unwrap();
    assert!(futures_util::poll!(&mut processing).is_pending());
    assert!(
        client.state.lock().unwrap().types[ResourceKind::Sandbox.index()]
            .entries
            .contains_key("kruise:sandbox")
    );

    // Sandbox lookup gets the remaining 40 ms, not a new 100 ms budget.
    tokio::time::advance(Duration::from_millis(39)).await;
    assert!(futures_util::poll!(&mut processing).is_pending());
    tokio::time::advance(Duration::from_millis(1)).await;
    let std::task::Poll::Ready(response) = futures_util::poll!(&mut processing) else {
        panic!("CONNECT deadline was reset between Workload and Sandbox lookup");
    };
    let error = response.unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unavailable);
    assert!(error.message().contains("deadline exceeded"));
}

#[tokio::test]
async fn disabled_bounds_keep_persistent_interest() {
    let c = client(0, Duration::ZERO);
    let old = c.acquire(ResourceKind::Workload, "one").unwrap();
    let generation = old.generation.id;
    drop(old);
    assert_eq!(
        c.state.lock().unwrap().types[0].entries["one"]
            .generation
            .id,
        generation
    );
    c.apply(
        ResourceKind::Workload,
        &response(vec![resource("one", &[])], &[]),
    )
    .unwrap();
    c.demand(ResourceKind::Workload, "one", None).await.unwrap();
    assert_eq!(Client::size(&c.state.lock().unwrap()), 1);
    assert_eq!(c.metrics.cache.get(), 0); // No managed cache in this mode.
    c.apply(ResourceKind::Workload, &response(vec![], &["one"]))
        .unwrap();
    assert_eq!(Client::size(&c.state.lock().unwrap()), 0);
}

#[tokio::test]
async fn coalesces_demands_and_preserves_generation() {
    let c = client(10, Duration::from_secs(60));
    let mut sent = Default::default();
    let initial = c.initial(&Node::default(), &mut sent);
    assert!(
        initial
            .iter()
            .all(|r| r.resource_names_subscribe == ["*"] && r.resource_names_unsubscribe == ["*"])
    );
    let mut a = c.acquire(ResourceKind::Workload, "alias").unwrap();
    let mut b = c.acquire(ResourceKind::Workload, "alias").unwrap();
    assert_eq!(a.generation.id, b.generation.id);
    let batch = c.outgoing(&mut sent);
    assert_eq!(batch[0].resource_names_subscribe, ["alias"]);
    c.apply(
        ResourceKind::Workload,
        &response(vec![resource("one", &["alias"])], &[]),
    )
    .unwrap();
    a.success = true;
    b.success = true;
    drop(a);
    drop(b);
    assert!(matches!(
        c.demand(ResourceKind::Workload, "alias", None).await.unwrap().as_ref(),
        View::Workload(w) if w.uid == "one"
    ));
    let old = c.acquire(ResourceKind::Workload, "alias").unwrap();
    c.apply(ResourceKind::Workload, &response(vec![], &["one"]))
        .unwrap();
    assert!(matches!(old.generation.value.borrow().1, Outcome::Missing));
    let new = c.acquire(ResourceKind::Workload, "alias").unwrap();
    assert_ne!(old.generation.id, new.generation.id);
    drop(old);
    assert_eq!(c.state.lock().unwrap().types[0].entries["alias"].users, 1);
    assert_eq!(c.outgoing(&mut sent)[0].resource_names_subscribe, ["alias"]);
    drop(new);
}

#[tokio::test]
async fn alias_collision_reassignment_and_atomic_rejection() {
    let c = client(10, Duration::from_secs(60));
    let _lease = c.acquire(ResourceKind::Workload, "alias").unwrap();
    c.apply(
        ResourceKind::Workload,
        &response(
            vec![resource("one", &["alias"]), resource("two", &["alias"])],
            &[],
        ),
    )
    .unwrap();
    assert!(matches!(
        c.state.lock().unwrap().types[0].resolve("alias"),
        Outcome::Ambiguous
    ));
    c.apply(ResourceKind::Workload, &response(vec![], &["one"]))
        .unwrap();
    assert!(matches!(
        c.state.lock().unwrap().types[0].resolve("alias"),
        Outcome::Ready(_)
    ));
    c.apply(
        ResourceKind::Workload,
        &response(vec![resource("three", &["alias"])], &["two"]),
    )
    .unwrap();
    assert!(matches!(
        c.state.lock().unwrap().types[0].resolve("alias"),
        Outcome::Ready(v) if matches!(v.as_ref(), View::Workload(w) if w.uid == "three")
    ));
    let mut bad = resource("three", &["alias"]);
    bad.resource.as_mut().unwrap().value = vec![255];
    assert!(
        c.apply(ResourceKind::Workload, &response(vec![bad], &[]))
            .is_err()
    );
    assert!(matches!(
        c.state.lock().unwrap().types[0].resolve("alias"),
        Outcome::Ready(_)
    ));
    let mut ttl = resource("three", &["alias"]);
    ttl.ttl = Some(Default::default());
    assert!(
        c.apply(ResourceKind::Workload, &response(vec![ttl], &[]))
            .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn expiration_is_idle_and_does_not_evict_waiters() {
    let c = client(1, Duration::from_secs(1));
    let mut a = c.acquire(ResourceKind::Workload, "one").unwrap();
    let mut b = c.acquire(ResourceKind::Workload, "two").unwrap();
    assert_eq!(Client::size(&c.state.lock().unwrap()), 2);
    c.apply(
        ResourceKind::Workload,
        &response(vec![resource("one", &[]), resource("two", &[])], &[]),
    )
    .unwrap();
    a.success = true;
    drop(a);
    assert!(!c.state.lock().unwrap().types[0].entries.contains_key("one"));
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(c.state.lock().unwrap().types[0].entries.contains_key("two"));
    b.success = true;
    drop(b);
    let stop = CancellationToken::new();
    let task = tokio::spawn(c.clone().expire(stop.clone()));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert_eq!(Client::size(&c.state.lock().unwrap()), 0);
    assert_eq!(
        c.metrics
            .cache_evictions
            .get_or_create(&Eviction {
                resource_type: ResourceKind::Workload.type_url(),
                reason: "capacity"
            })
            .get(),
        1
    );
    assert_eq!(
        c.metrics
            .cache_evictions
            .get_or_create(&Eviction {
                resource_type: ResourceKind::Workload.type_url(),
                reason: "idle_ttl"
            })
            .get(),
        1
    );
    stop.cancel();
    task.await.unwrap();
}

#[tokio::test]
async fn cancellation_releases_only_last_waiter_and_reconnect_drops_stale_values() {
    let c = client(10, Duration::from_secs(60));
    let a = tokio::spawn({
        let c = c.clone();
        async move { c.demand(ResourceKind::Workload, "one", None).await }
    });
    let b = tokio::spawn({
        let c = c.clone();
        async move { c.demand(ResourceKind::Workload, "one", None).await }
    });
    tokio::task::yield_now().await;
    a.abort();
    let _ = a.await;
    assert_eq!(c.state.lock().unwrap().types[0].entries["one"].users, 1);
    c.apply(
        ResourceKind::Workload,
        &response(vec![resource("one", &[])], &[]),
    )
    .unwrap();
    b.await.unwrap().unwrap();
    c.reset();
    assert!(!*c.ready.borrow());
    let mut next = Box::pin(c.demand(ResourceKind::Workload, "one", None));
    assert!(futures_util::poll!(next.as_mut()).is_pending());
    c.apply(ResourceKind::Workload, &response(vec![], &[]))
        .unwrap();
    assert!(futures_util::poll!(next.as_mut()).is_pending());
    c.apply(ResourceKind::Workload, &response(vec![], &["one"]))
        .unwrap();
    assert_eq!(next.await.unwrap_err(), DemandError::NotFound);
}

#[tokio::test]
async fn reconnect_partial_sync_never_revalidates_an_old_value() {
    let c = client(10, Duration::from_secs(60));
    let _a = c.acquire(ResourceKind::Workload, "a").unwrap();
    let _b = c.acquire(ResourceKind::Workload, "b").unwrap();
    c.apply(
        ResourceKind::Workload,
        &response(vec![resource("a", &[]), resource("b", &[])], &[]),
    )
    .unwrap();
    c.demand(ResourceKind::Workload, "b", None).await.unwrap();
    c.reset();
    let mut waiting = Box::pin(c.demand(ResourceKind::Workload, "b", None));
    assert!(futures_util::poll!(waiting.as_mut()).is_pending());
    c.apply(
        ResourceKind::Workload,
        &response(vec![resource("a", &[])], &[]),
    )
    .unwrap();
    c.demand(ResourceKind::Workload, "a", None).await.unwrap();
    assert!(futures_util::poll!(waiting.as_mut()).is_pending());
    // A second reconnect must not revalidate either the previous stream's
    // value or an older value retained by a per-subscription watch.
    c.reset();
    c.apply(
        ResourceKind::Workload,
        &response(vec![resource("a", &[])], &[]),
    )
    .unwrap();
    assert!(futures_util::poll!(waiting.as_mut()).is_pending());
    c.apply(
        ResourceKind::Workload,
        &response(vec![resource("replacement", &["b"])], &[]),
    )
    .unwrap();
    assert!(matches!(waiting.await.unwrap().as_ref(), View::Workload(w) if w.uid == "replacement"));
    assert_eq!(
        c.metrics
            .cache_lookups
            .get_or_create(&DemandResult {
                resource_type: ResourceKind::Workload.type_url(),
                result: "miss"
            })
            .get(),
        1
    );
    // A removed generation stays terminal across a reset.
    c.apply(ResourceKind::Workload, &response(vec![], &["replacement"]))
        .unwrap();
    c.reset();
    assert!(matches!(
        c.current(&_b.generation.value.borrow()),
        Outcome::Missing
    ));
}

#[tokio::test]
async fn cache_lookup_metrics_count_calls_not_wakeups() {
    let c = client(10, Duration::from_secs(60));
    let mut cold = Box::pin(c.demand(ResourceKind::Workload, "one", None));
    assert!(futures_util::poll!(cold.as_mut()).is_pending());
    c.reset();
    assert!(futures_util::poll!(cold.as_mut()).is_pending());
    c.apply(
        ResourceKind::Workload,
        &response(vec![resource("one", &[])], &[]),
    )
    .unwrap();
    cold.await.unwrap();
    c.demand(ResourceKind::Workload, "one", None).await.unwrap();
    assert_eq!(
        c.metrics
            .cache_lookups
            .get_or_create(&DemandResult {
                resource_type: ResourceKind::Workload.type_url(),
                result: "miss"
            })
            .get(),
        1
    );
    assert_eq!(
        c.metrics
            .cache_lookups
            .get_or_create(&DemandResult {
                resource_type: ResourceKind::Workload.type_url(),
                result: "hit"
            })
            .get(),
        1
    );
    let encoded = c.metrics.encode().unwrap();
    assert!(encoded.contains("agentio_porter_demand_cache_lookups_total{"));
    assert!(encoded.contains(concat!(
        "agentio_xds_client_demand_waiters{",
        "resource_type=\"type.googleapis.com/istio.workload.Workload\"} 0"
    )));
}

#[tokio::test]
async fn pending_ack_is_bounded_and_receive_progress_independent() {
    let c = client(10, Duration::from_secs(60));
    let _lease = c.acquire(ResourceKind::Workload, "one").unwrap();
    let mut sent = Default::default();
    c.initial(&Node::default(), &mut sent);
    // Do not poll the writer while applying a burst (transport backpressure).
    for n in 0..100 {
        c.apply(
            ResourceKind::Workload,
            &response(vec![resource("one", &[])], &[]),
        )
        .unwrap();
        c.state.lock().unwrap().types[0].ack = Some((n.to_string(), None));
    }
    let batch = c.outgoing(&mut sent);
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].response_nonce, "99");
    assert!(matches!(
        c.state.lock().unwrap().types[0].resolve("one"),
        Outcome::Ready(_)
    ));
}

#[tokio::test]
async fn matches_wire_contract_corpus() {
    #[derive(serde::Deserialize)]
    struct Fixture {
        name: String,
        request: String,
        response: Option<String>,
        code: i32,
        resources: HashMap<String, String>,
    }
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("../../tests/fixtures.json")).unwrap();
    for f in fixtures {
        let c = client(100, Duration::from_secs(60));
        for (key, value) in f.resources {
            let (kind, name) = key.split_once('|').unwrap();
            let kind = ResourceKind::from_type_url(kind).unwrap();
            let mut lease = c.acquire(kind, name).unwrap();
            c.apply(
                kind,
                &Response {
                    type_url: kind.type_url().into(),
                    resources: vec![ads::Resource {
                        name: name.into(),
                        resource: Some(
                            prost_types::Any::decode(STANDARD.decode(value).unwrap().as_slice())
                                .unwrap(),
                        ),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            )
            .unwrap();
            lease.success = true;
            drop(lease);
        }
        let p = Processor {
            client: c.clone(),
            cluster_id: "Kubernetes".into(),
            timeout: Duration::from_millis(100),
        };
        let request =
            extproc::ProcessingRequest::decode(STANDARD.decode(f.request).unwrap().as_slice())
                .unwrap();
        // Serve explicit not-found for names absent from this fixture.
        let server = tokio::spawn({
            let c = c.clone();
            async move {
                loop {
                    tokio::task::yield_now().await;
                    for kind in ResourceKind::ALL {
                        let pending = {
                            let s = c.state.lock().unwrap();
                            s.types[kind.index()]
                                .entries
                                .keys()
                                .filter(|n| {
                                    matches!(s.types[kind.index()].resolve(n), Outcome::Pending)
                                })
                                .cloned()
                                .collect::<Vec<_>>()
                        };
                        if !pending.is_empty() {
                            c.apply(
                                kind,
                                &Response {
                                    type_url: kind.type_url().into(),
                                    removed_resources: pending,
                                    ..Default::default()
                                },
                            )
                            .unwrap();
                        }
                    }
                }
            }
        });
        let result = p.handle(request).await;
        server.abort();
        let _ = server.await;
        let outcome = match &result {
            Ok(r)
                if matches!(
                    r.response,
                    Some(extproc::processing_response::Response::ImmediateResponse(_))
                ) =>
            {
                "denied"
            }
            Ok(_) => "allowed",
            Err(_) => "error",
        };
        let encoded = c.metrics.encode().unwrap();
        if f.code != 3 {
            assert!(
                encoded.lines().any(|line| line
                    .starts_with("agentio_porter_connect_requests_total{")
                    && line.contains(&format!("result=\"{outcome}\""))
                    && line.ends_with(" 1")),
                "{}: {}",
                f.name,
                encoded
            );
        } else {
            assert!(
                !encoded
                    .lines()
                    .any(|line| line.starts_with("agentio_porter_connect_requests_total{")),
                "{}",
                f.name
            );
        }
        match f.response {
            Some(expected) => assert_eq!(
                result.unwrap(),
                extproc::ProcessingResponse::decode(STANDARD.decode(expected).unwrap().as_slice())
                    .unwrap(),
                "{}",
                f.name
            ),
            None => assert_eq!(result.unwrap_err().code() as i32, f.code, "{}", f.name),
        }
    }
}

#[tokio::test]
async fn reconnect_discards_idle_interests_and_rediscovers_aliases() {
    // Disconnect has the same semantics with and without idle retention bounds.
    for max in [0, 10] {
        let client = client(max, Duration::ZERO);
        let mut first = Box::pin(client.demand(ResourceKind::Workload, "alias", None));
        assert!(futures_util::poll!(&mut first).is_pending());
        client
            .apply(
                ResourceKind::Workload,
                &response(vec![resource("old", &["alias"])], &[]),
            )
            .unwrap();
        first.await.unwrap();
        client.reset();
        {
            let state = client.state.lock().unwrap();
            assert!(state.idle.is_empty());
            assert!(state.types[0].entries.is_empty());
            assert!(state.types[0].resources.is_empty());
            assert!(state.types[0].aliases.is_empty());
        }
        assert_eq!(client.metrics.cache.get(), 0);
        let mut sent = Default::default();
        let initial = client.initial(&Node::default(), &mut sent);
        assert_eq!(initial[0].resource_names_subscribe, ["*"]);
        assert_eq!(initial[0].resource_names_unsubscribe, ["*"]);
        let mut next = Box::pin(client.demand(ResourceKind::Workload, "alias", None));
        assert!(futures_util::poll!(&mut next).is_pending());
        assert_eq!(
            client.outgoing(&mut sent)[0].resource_names_subscribe,
            ["alias"]
        );
        client
            .apply(
                ResourceKind::Workload,
                &response(vec![resource("new", &["alias"])], &[]),
            )
            .unwrap();
        assert!(matches!(next.await.unwrap().as_ref(), View::Workload(w) if w.uid == "new"));
    }
}

#[tokio::test]
async fn reconnect_preserves_shared_waiters_and_cancellation() {
    let client = client(10, Duration::from_secs(60));
    let mut first = Box::pin(client.demand(ResourceKind::Workload, "pending", None));
    let mut second = Box::pin(client.demand(ResourceKind::Workload, "pending", None));
    let mut sandbox = Box::pin(client.demand(ResourceKind::Sandbox, "sandbox", None));
    assert!(futures_util::poll!(&mut first).is_pending());
    assert!(futures_util::poll!(&mut second).is_pending());
    assert!(futures_util::poll!(&mut sandbox).is_pending());
    let generation = client.state.lock().unwrap().types[0].entries["pending"]
        .generation
        .id;
    client.reset();
    // Repeated failed reconnect attempts must preserve the same waiters too.
    client.reset();
    let mut sent = Default::default();
    let initial = client.initial(&Node::default(), &mut sent);
    assert_eq!(initial[0].resource_names_subscribe, ["pending"]);
    assert_eq!(initial[1].resource_names_subscribe, ["sandbox"]);
    assert_eq!(sent[0]["pending"], generation);
    drop(first);
    assert_eq!(
        client.state.lock().unwrap().types[0].entries["pending"].users,
        1
    );
    client
        .apply(
            ResourceKind::Workload,
            &response(vec![resource("pending", &[])], &[]),
        )
        .unwrap();
    second.await.unwrap();
    drop(sandbox);
    assert_eq!(
        client.outgoing(&mut sent)[0].resource_names_unsubscribe,
        ["sandbox"]
    );
}
