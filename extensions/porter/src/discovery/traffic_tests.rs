// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    processor::Processor,
    wire::{
        agentio::{
            sandbox::{Sandbox, sandbox::Attester},
            security::{TrafficPolicy, traffic_policy as proto},
        },
        extproc,
        istio::workload::{Extension, Workload},
        kruise::networking::extensions::v1::PolicyReference,
    },
};
use prost::Message;
use prost_types::Any;
use std::collections::BTreeMap;

const UID: &str = "Kubernetes//Pod/demo/source";

fn any(type_url: &str, message: impl Message) -> Any {
    Any {
        type_url: type_url.into(),
        value: message.encode_to_vec(),
    }
}

fn workload(names: Option<&[&str]>) -> Any {
    any(
        view::WORKLOAD,
        Workload {
            uid: UID.into(),
            name: "source".into(),
            namespace: "demo".into(),
            trust_domain: "cluster.local".into(),
            service_account: "default".into(),
            extensions: names
                .map(|names| {
                    vec![Extension {
                        name: "traffic-policy-reference".into(),
                        config: Some(any(
                            "type.googleapis.com/kruise.networking.extensions.v1.PolicyReference",
                            PolicyReference {
                                type_url: view::TRAFFIC_POLICY.into(),
                                resource_names: names.iter().map(|s| (*s).into()).collect(),
                            },
                        )),
                    }]
                })
                .unwrap_or_default(),
            ..Default::default()
        },
    )
}

fn policy(action: proto::Action) -> TrafficPolicy {
    TrafficPolicy {
        egress: Some(proto::RuleSet {
            rules: vec![proto::Rule {
                action: action as i32,
                r#match: Some(proto::Match::default()),
            }],
        }),
        ..Default::default()
    }
}

fn seed(c: &Arc<Client>, kind: ResourceKind, name: &str, body: Any) {
    let mut lease = c.acquire(kind, name).unwrap();
    c.apply(
        kind,
        &Response {
            type_url: kind.type_url().into(),
            resources: vec![ads::Resource {
                name: name.into(),
                resource: Some(body),
                ..Default::default()
            }],
            ..Default::default()
        },
    )
    .unwrap();
    lease.success = true;
}

fn processor() -> Processor {
    Processor {
        client: Client::new(CacheConfig::default(), Metrics::new()),
        cluster_id: "Kubernetes".into(),
        timeout: Duration::from_millis(100),
        enable_traffic_policy: true,
    }
}

fn request(sandbox: &str, udp: bool) -> extproc::ProcessingRequest {
    let headers = [
        (":method", if udp { "GET" } else { "CONNECT" }),
        (":authority", "192.0.2.1:443"),
        ("upgrade", if udp { "connect-udp" } else { "" }),
    ]
    .into_iter()
    .map(|(key, value)| extproc::HeaderValue {
        key: key.into(),
        value: value.into(),
        ..Default::default()
    })
    .collect();
    extproc::ProcessingRequest {
        request_headers: Some(extproc::HttpHeaders {
            headers: Some(extproc::HeaderMap { headers }),
            ..Default::default()
        }),
        attributes: std::collections::HashMap::from([(
            "envoy.filters.http.ext_proc".into(),
            prost_types::Struct {
                fields: BTreeMap::from([
                    (
                        "filter_state['agentio.downstream.ip']".into(),
                        view::string("10.0.0.1"),
                    ),
                    (
                        "filter_state['agentio.peer.principal']".into(),
                        view::string("spiffe://cluster.local/ns/demo/sa/default"),
                    ),
                    ("filter_state['sandbox.id']".into(), view::string(sandbox)),
                ]),
            },
        )]),
    }
}

fn allowed(response: extproc::ProcessingResponse) -> bool {
    matches!(
        response.response,
        Some(extproc::processing_response::Response::RequestHeaders(_))
    )
}

#[tokio::test(start_paused = true)]
async fn sandbox_and_workload_policies_load_concurrently() {
    for udp in [false, true] {
        let p = processor();
        let c = &p.client;
        let mut pending = Box::pin(p.handle(request("sandbox", udp)));
        assert!(futures_util::poll!(&mut pending).is_pending());
        let mut sent = Default::default();
        let requests = c.outgoing(&mut sent);
        assert!(requests.iter().any(|r| {
            r.type_url == view::WORKLOAD && r.resource_names_subscribe == ["/10.0.0.1"]
        }));
        assert!(
            requests.iter().any(|r| {
                r.type_url == view::SANDBOX && r.resource_names_subscribe == ["sandbox"]
            }),
            "Sandbox demand must start before Workload arrives"
        );

        seed(
            c,
            ResourceKind::Workload,
            "/10.0.0.1",
            workload(Some(&["allow"])),
        );
        assert!(futures_util::poll!(&mut pending).is_pending());
        assert!(
            c.outgoing(&mut sent).iter().any(|r| {
                r.type_url == view::TRAFFIC_POLICY && r.resource_names_subscribe == ["allow"]
            }),
            "Platform policy demand must not wait for Sandbox"
        );
        seed(
            c,
            ResourceKind::TrafficPolicy,
            "allow",
            any(view::TRAFFIC_POLICY, policy(proto::Action::Allow)),
        );
        assert!(
            futures_util::poll!(&mut pending).is_pending(),
            "Platform ALLOW must still wait for Sandbox"
        );
        seed(
            c,
            ResourceKind::Sandbox,
            "sandbox",
            any(
                view::SANDBOX,
                Sandbox {
                    uid: "sandbox".into(),
                    attester: Some(Attester {
                        workload_uid: UID.into(),
                    }),
                    traffic_policy: Some(policy(proto::Action::Allow)),
                    ..Default::default()
                },
            ),
        );
        assert!(allowed(pending.await.unwrap()));
    }
}

fn assert_denied(response: extproc::ProcessingResponse) {
    let Some(extproc::processing_response::Response::ImmediateResponse(response)) =
        response.response
    else {
        panic!("expected immediate denial");
    };
    assert_eq!(response.status.unwrap().code, 403);
}

#[tokio::test(start_paused = true)]
async fn sandbox_rejection_does_not_wait_for_platform_policy() {
    for udp in [false, true] {
        for (sandbox_id, workload_uid, action) in [
            ("sandbox", UID, proto::Action::Deny),
            ("sandbox", "other-workload", proto::Action::Allow),
            ("other-sandbox", UID, proto::Action::Allow),
        ] {
            let p = processor();
            seed(
                &p.client,
                ResourceKind::Workload,
                "/10.0.0.1",
                workload(Some(&["pending"])),
            );
            let mut pending = Box::pin(p.handle(request("sandbox", udp)));
            assert!(futures_util::poll!(&mut pending).is_pending());
            // Both independent demands have started before the rejecting Sandbox arrives.
            assert!(
                p.client.state.lock().unwrap().types[ResourceKind::TrafficPolicy.index()]
                    .entries
                    .contains_key("pending")
            );
            seed(
                &p.client,
                ResourceKind::Sandbox,
                "sandbox",
                any(
                    view::SANDBOX,
                    Sandbox {
                        uid: sandbox_id.into(),
                        attester: Some(Attester {
                            workload_uid: workload_uid.into(),
                        }),
                        traffic_policy: Some(policy(action)),
                        ..Default::default()
                    },
                ),
            );
            let std::task::Poll::Ready(response) = futures_util::poll!(&mut pending) else {
                panic!("Sandbox rejection waited for platform policy");
            };
            assert_denied(response.unwrap());
            assert_eq!(
                p.client
                    .metrics
                    .waiters
                    .get_or_create(&ResourceType {
                        resource_type: view::TRAFFIC_POLICY,
                    })
                    .get(),
                0,
                "rejection must cancel the outstanding policy wait"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn sandbox_denial_does_not_wait_for_workload() {
    for udp in [false, true] {
        let p = processor();
        let mut pending = Box::pin(p.handle(request("sandbox", udp)));
        assert!(futures_util::poll!(&mut pending).is_pending());
        seed(
            &p.client,
            ResourceKind::Sandbox,
            "sandbox",
            any(
                view::SANDBOX,
                Sandbox {
                    uid: "sandbox".into(),
                    attester: Some(Attester {
                        workload_uid: UID.into(),
                    }),
                    traffic_policy: Some(policy(proto::Action::Deny)),
                    ..Default::default()
                },
            ),
        );
        let std::task::Poll::Ready(response) = futures_util::poll!(&mut pending) else {
            panic!("Sandbox DENY waited for Workload");
        };
        assert_denied(response.unwrap());
        assert_eq!(
            p.client
                .metrics
                .waiters
                .get_or_create(&ResourceType {
                    resource_type: view::WORKLOAD,
                })
                .get(),
            0
        );
    }
}

#[tokio::test(start_paused = true)]
async fn workload_rejection_does_not_wait_for_sandbox() {
    for udp in [false, true] {
        for reason in ["policy", "identity", "binding"] {
            let p = processor();
            let mut pending = Box::pin(p.handle(request("sandbox", udp)));
            assert!(futures_util::poll!(&mut pending).is_pending());
            let mut body = Workload::decode(
                workload(if reason == "binding" {
                    None
                } else {
                    Some(&["policy"])
                })
                .value
                .as_slice(),
            )
            .unwrap();
            if reason == "identity" {
                body.service_account = "other-account".into();
            }
            seed(
                &p.client,
                ResourceKind::Workload,
                "/10.0.0.1",
                any(view::WORKLOAD, body),
            );
            if reason == "policy" {
                assert!(futures_util::poll!(&mut pending).is_pending());
                seed(
                    &p.client,
                    ResourceKind::TrafficPolicy,
                    "policy",
                    any(view::TRAFFIC_POLICY, policy(proto::Action::Deny)),
                );
            }
            let std::task::Poll::Ready(response) = futures_util::poll!(&mut pending) else {
                panic!("Workload {reason} rejection waited for Sandbox");
            };
            assert_denied(response.unwrap());
            assert_eq!(
                p.client
                    .metrics
                    .waiters
                    .get_or_create(&ResourceType {
                        resource_type: view::SANDBOX,
                    })
                    .get(),
                0
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn sandbox_allow_still_waits_for_platform_policy() {
    for udp in [false, true] {
        for action in [proto::Action::Allow, proto::Action::Deny] {
            let p = processor();
            seed(
                &p.client,
                ResourceKind::Workload,
                "/10.0.0.1",
                workload(Some(&["policy"])),
            );
            seed(
                &p.client,
                ResourceKind::Sandbox,
                "sandbox",
                any(
                    view::SANDBOX,
                    Sandbox {
                        uid: "sandbox".into(),
                        attester: Some(Attester {
                            workload_uid: UID.into(),
                        }),
                        traffic_policy: Some(policy(proto::Action::Allow)),
                        ..Default::default()
                    },
                ),
            );
            let mut pending = Box::pin(p.handle(request("sandbox", udp)));
            assert!(futures_util::poll!(&mut pending).is_pending());
            seed(
                &p.client,
                ResourceKind::TrafficPolicy,
                "policy",
                any(view::TRAFFIC_POLICY, policy(action)),
            );
            let response = pending.await.unwrap();
            if action == proto::Action::Allow {
                assert!(allowed(response));
            } else {
                assert_denied(response);
            }
        }
    }
}

#[tokio::test]
async fn disabled_policy_preserves_identity_and_skips_policy_demands() {
    for udp in [false, true] {
        let mut p = processor();
        p.enable_traffic_policy = false;
        for names in [None, Some(&["unavailable-policy"][..])] {
            seed(
                &p.client,
                ResourceKind::Workload,
                "/10.0.0.1",
                workload(names),
            );
            seed(
                &p.client,
                ResourceKind::Sandbox,
                "sandbox",
                any(
                    view::SANDBOX,
                    Sandbox {
                        uid: "sandbox".into(),
                        attester: Some(Attester {
                            workload_uid: UID.into(),
                        }),
                        traffic_policy: Some(policy(proto::Action::Deny)),
                        ..Default::default()
                    },
                ),
            );
            let mut req = request("sandbox", udp);
            let headers = &mut req
                .request_headers
                .as_mut()
                .unwrap()
                .headers
                .as_mut()
                .unwrap()
                .headers;
            headers
                .iter_mut()
                .find(|h| h.key == ":authority")
                .unwrap()
                .value = "example.com:443".into();
            let response = p.handle(req).await.unwrap();
            let metadata = response.dynamic_metadata.as_ref().unwrap();
            let Some(prost_types::value::Kind::StructValue(agentio)) =
                &metadata.fields["agentio"].kind
            else {
                panic!("expected Agentio metadata");
            };
            assert!(agentio.fields.contains_key("workload"));
            assert!(allowed(response));
            assert!(
                p.client.state.lock().unwrap().types[ResourceKind::TrafficPolicy.index()]
                    .entries
                    .is_empty()
            );
        }
        // Disabling policy enforcement must not disable Sandbox identity validation.
        seed(
            &p.client,
            ResourceKind::Sandbox,
            "sandbox",
            any(
                view::SANDBOX,
                Sandbox {
                    uid: "sandbox".into(),
                    attester: Some(Attester {
                        workload_uid: "another-workload".into(),
                    }),
                    ..Default::default()
                },
            ),
        );
        assert!(!allowed(p.handle(request("sandbox", udp)).await.unwrap()));
    }
}

#[tokio::test]
async fn policy_logs_identify_destination_binding_and_final_decision() {
    use tracing::instrument::WithSubscriber;

    // tracing's callsite interest cache is process-wide. Other parallel tests can
    // first register the policy callsite without this test's local subscriber.
    // Isolate log capture while keeping the rest of the suite parallel.
    const ISOLATED: &str = "PORTER_POLICY_LOG_TEST_ISOLATED";
    if std::env::var_os(ISOLATED).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "discovery::traffic_tests::policy_logs_identify_destination_binding_and_final_decision",
                "--nocapture",
            ])
            .env(ISOLATED, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated policy logging test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }

    let output = tempfile::tempfile().unwrap();
    let subscriber = tracing_subscriber::fmt()
        .fmt_fields(tracing_subscriber::fmt::format::JsonFields::default())
        .event_format(crate::logging::JsonFormat)
        .with_env_filter("info")
        .with_writer(output.try_clone().unwrap())
        .finish();
    async {
        let p = processor();
        seed(
            &p.client,
            ResourceKind::Workload,
            "/10.0.0.1",
            workload(Some(&["demo/allow"])),
        );
        seed(
            &p.client,
            ResourceKind::TrafficPolicy,
            "demo/allow",
            any(view::TRAFFIC_POLICY, policy(proto::Action::Allow)),
        );
        assert!(allowed(p.handle(request("", false)).await.unwrap()));

        seed(
            &p.client,
            ResourceKind::TrafficPolicy,
            "demo/allow",
            any(view::TRAFFIC_POLICY, policy(proto::Action::Deny)),
        );
        assert!(!allowed(p.handle(request("", true)).await.unwrap()));

        seed(
            &p.client,
            ResourceKind::TrafficPolicy,
            "demo/allow",
            any(
                view::TRAFFIC_POLICY,
                TrafficPolicy {
                    egress: Some(proto::RuleSet { rules: vec![] }),
                    ..Default::default()
                },
            ),
        );
        assert!(!allowed(p.handle(request("", false)).await.unwrap()));

        seed(
            &p.client,
            ResourceKind::Workload,
            "/10.0.0.1",
            workload(Some(&[])),
        );
        assert!(allowed(p.handle(request("", false)).await.unwrap()));

        seed(
            &p.client,
            ResourceKind::Sandbox,
            "sandbox",
            any(
                view::SANDBOX,
                Sandbox {
                    uid: "sandbox".into(),
                    attester: Some(Attester {
                        workload_uid: UID.into(),
                    }),
                    traffic_policy: Some(policy(proto::Action::Deny)),
                    ..Default::default()
                },
            ),
        );
        assert!(!allowed(p.handle(request("sandbox", false)).await.unwrap()));
    }
    .with_subscriber(subscriber)
    .await;

    use std::io::{Read, Seek};
    let mut reader = output;
    reader.rewind().unwrap();
    let mut text = String::new();
    reader.read_to_string(&mut text).unwrap();
    let events: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 5);
    for event in &events {
        assert_eq!(event["level"], "info");
        assert_eq!(event["event"], "traffic_policy_decision");
        assert_eq!(event["message"], "CONNECT policy evaluated");
        assert_eq!(event["scope"], "agentio_porter::policy");
        assert_eq!(event["workload"], UID);
        assert_eq!(event["destination"], "192.0.2.1:443");
    }
    let fields = &events[0];
    assert_eq!(fields["policy"], "demo/allow");
    assert_eq!(fields["rule_index"], 0);
    assert_eq!(fields["action"], "allow");
    assert_eq!(fields["reason"], "rule_match");
    assert_eq!(events[1]["protocol"], "udp");
    assert_eq!(events[1]["action"], "deny");
    assert_eq!(events[2]["reason"], "no_matching_rule");
    assert!(events[2].get("policy").is_none());
    assert!(events[2].get("rule_index").is_none());
    assert_eq!(events[3]["reason"], "no_egress_policy");
    assert_eq!(events[4]["stage"], "sandbox");
    assert_eq!(events[4]["sandbox_id"], "sandbox");
    assert_eq!(events[4]["rule_index"], 0);
    assert!(events[4].get("policy").is_none());
}

#[tokio::test]
async fn ordered_policy_stages_and_binding_presence() {
    for udp in [false, true] {
        let p = processor();
        let c = &p.client;
        seed(c, ResourceKind::Workload, "/10.0.0.1", workload(None));
        assert!(!allowed(p.handle(request("", udp)).await.unwrap()));
        seed(c, ResourceKind::Workload, "/10.0.0.1", workload(Some(&[])));
        assert!(allowed(p.handle(request("", udp)).await.unwrap()));

        seed(
            c,
            ResourceKind::TrafficPolicy,
            "allow",
            any(view::TRAFFIC_POLICY, policy(proto::Action::Allow)),
        );
        seed(
            c,
            ResourceKind::TrafficPolicy,
            "deny",
            any(view::TRAFFIC_POLICY, policy(proto::Action::Deny)),
        );
        seed(
            c,
            ResourceKind::Workload,
            "/10.0.0.1",
            workload(Some(&["allow", "deny"])),
        );
        assert!(allowed(p.handle(request("", udp)).await.unwrap()));
        seed(
            c,
            ResourceKind::Workload,
            "/10.0.0.1",
            workload(Some(&["deny", "allow"])),
        );
        assert!(!allowed(p.handle(request("", udp)).await.unwrap()));

        // Sandbox ALLOW cannot override a Workload DENY.
        seed(
            c,
            ResourceKind::Sandbox,
            "sandbox",
            any(
                view::SANDBOX,
                Sandbox {
                    uid: "sandbox".into(),
                    attester: Some(Attester {
                        workload_uid: UID.into(),
                    }),
                    traffic_policy: Some(policy(proto::Action::Allow)),
                    ..Default::default()
                },
            ),
        );
        assert!(!allowed(p.handle(request("sandbox", udp)).await.unwrap()));
        seed(
            c,
            ResourceKind::Workload,
            "/10.0.0.1",
            workload(Some(&["allow"])),
        );
        assert!(allowed(p.handle(request("sandbox", udp)).await.unwrap()));
        seed(
            c,
            ResourceKind::Sandbox,
            "sandbox",
            any(
                view::SANDBOX,
                Sandbox {
                    uid: "sandbox".into(),
                    attester: Some(Attester {
                        workload_uid: UID.into(),
                    }),
                    traffic_policy: Some(policy(proto::Action::Deny)),
                    ..Default::default()
                },
            ),
        );
        assert!(!allowed(p.handle(request("sandbox", udp)).await.unwrap()));
    }
}

#[tokio::test(start_paused = true)]
async fn missing_reference_blocks_earlier_allow_and_demands_are_parallel() {
    let p = processor();
    let c = &p.client;
    seed(
        c,
        ResourceKind::Workload,
        "/10.0.0.1",
        workload(Some(&["allow", "missing", "also-missing"])),
    );
    seed(
        c,
        ResourceKind::TrafficPolicy,
        "allow",
        any(view::TRAFFIC_POLICY, policy(proto::Action::Allow)),
    );
    let mut pending = Box::pin(p.handle(request("", false)));
    assert!(futures_util::poll!(&mut pending).is_pending());
    {
        let state = c.state.lock().unwrap();
        let entries = &state.types[ResourceKind::TrafficPolicy.index()].entries;
        assert!(entries.contains_key("missing") && entries.contains_key("also-missing"));
    }
    c.apply(
        ResourceKind::TrafficPolicy,
        &Response {
            type_url: view::TRAFFIC_POLICY.into(),
            removed_resources: vec!["missing".into()],
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!allowed(pending.await.unwrap()));
}

#[tokio::test]
async fn connect_authority_and_udp_protocol_reach_the_evaluator() {
    let p = processor();
    seed(
        &p.client,
        ResourceKind::Workload,
        "/10.0.0.1",
        workload(Some(&["p"])),
    );
    let mut body = policy(proto::Action::Allow);
    let matched = body.egress.as_mut().unwrap().rules[0]
        .r#match
        .as_mut()
        .unwrap();
    matched.destination_ips = vec![proto::Address {
        address: vec![192, 0, 2, 1],
        length: 32,
    }];
    matched.ports = vec![proto::PortMatch {
        protocol: proto::Protocol::Tcp as i32,
        port: Some(443),
        end_port: None,
    }];
    seed(
        &p.client,
        ResourceKind::TrafficPolicy,
        "p",
        any(view::TRAFFIC_POLICY, body),
    );
    assert!(allowed(p.handle(request("", false)).await.unwrap()));
    assert!(!allowed(p.handle(request("", true)).await.unwrap()));
    for destination in ["192.0.2.2:443", "192.0.2.1:444"] {
        let mut r = request("", false);
        r.request_headers
            .as_mut()
            .unwrap()
            .headers
            .as_mut()
            .unwrap()
            .headers[1]
            .value = destination.into();
        assert!(!allowed(p.handle(r).await.unwrap()));
    }
}

#[tokio::test(start_paused = true)]
async fn policy_not_found_timeout_update_and_reconnect() {
    let p = processor();
    let c = &p.client;
    seed(
        c,
        ResourceKind::Workload,
        "/10.0.0.1",
        workload(Some(&["p"])),
    );
    let mut pending = Box::pin(p.handle(request("", false)));
    assert!(futures_util::poll!(&mut pending).is_pending());
    c.apply(
        ResourceKind::TrafficPolicy,
        &Response {
            type_url: view::TRAFFIC_POLICY.into(),
            removed_resources: vec!["p".into()],
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!allowed(pending.await.unwrap()));

    let mut pending = Box::pin(p.handle(request("", false)));
    assert!(futures_util::poll!(&mut pending).is_pending());
    tokio::time::advance(Duration::from_millis(100)).await;
    assert_eq!(pending.await.unwrap_err().code(), tonic::Code::Unavailable);

    seed(
        c,
        ResourceKind::TrafficPolicy,
        "p",
        any(view::TRAFFIC_POLICY, policy(proto::Action::Allow)),
    );
    assert!(allowed(p.handle(request("", false)).await.unwrap()));
    seed(
        c,
        ResourceKind::TrafficPolicy,
        "p",
        any(view::TRAFFIC_POLICY, policy(proto::Action::Deny)),
    );
    assert!(!allowed(p.handle(request("", false)).await.unwrap()));

    // Invalid replacements retain the previous valid denial.
    let mut invalid = policy(proto::Action::Allow);
    invalid.egress.as_mut().unwrap().rules[0].r#match = None;
    assert!(
        c.apply(
            ResourceKind::TrafficPolicy,
            &Response {
                type_url: view::TRAFFIC_POLICY.into(),
                resources: vec![ads::Resource {
                    name: "p".into(),
                    resource: Some(any(view::TRAFFIC_POLICY, invalid)),
                    ..Default::default()
                }],
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(!allowed(p.handle(request("", false)).await.unwrap()));

    c.reset();
    let mut pending = Box::pin(p.handle(request("", false)));
    assert!(futures_util::poll!(&mut pending).is_pending());
    seed(
        c,
        ResourceKind::Workload,
        "/10.0.0.1",
        workload(Some(&["p"])),
    );
    assert!(futures_util::poll!(&mut pending).is_pending()); // old policy cannot authorize
    seed(
        c,
        ResourceKind::TrafficPolicy,
        "p",
        any(view::TRAFFIC_POLICY, policy(proto::Action::Allow)),
    );
    assert!(allowed(pending.await.unwrap()));
}

#[tokio::test(start_paused = true)]
async fn policy_demands_share_workload_deadline() {
    let p = processor();
    let mut pending = Box::pin(p.handle(request("", false)));
    assert!(futures_util::poll!(&mut pending).is_pending());
    tokio::time::advance(Duration::from_millis(80)).await;
    seed(
        &p.client,
        ResourceKind::Workload,
        "/10.0.0.1",
        workload(Some(&["p"])),
    );
    assert!(futures_util::poll!(&mut pending).is_pending());
    tokio::time::advance(Duration::from_millis(20)).await;
    assert_eq!(pending.await.unwrap_err().code(), tonic::Code::Unavailable);
}

#[tokio::test(start_paused = true)]
async fn hot_dependency_batch_preserves_order_metrics_ttl_and_invalidation() {
    let c = Client::new(
        CacheConfig {
            max_entries: 10,
            idle_ttl: Duration::from_secs(1),
        },
        Metrics::new(),
    );
    let names = vec!["deny".into(), "allow".into()];
    seed(
        &c,
        ResourceKind::TrafficPolicy,
        "deny",
        any(view::TRAFFIC_POLICY, policy(proto::Action::Deny)),
    );
    seed(
        &c,
        ResourceKind::TrafficPolicy,
        "allow",
        any(view::TRAFFIC_POLICY, policy(proto::Action::Allow)),
    );
    tokio::time::advance(Duration::from_millis(800)).await;
    let values = c
        .demand_many(ResourceKind::TrafficPolicy, &names, None)
        .await
        .unwrap();
    let target = crate::traffic::Target::parse("192.0.2.1:443", false).unwrap();
    let View::TrafficPolicy(first) = values[0].as_ref() else {
        panic!()
    };
    let View::TrafficPolicy(second) = values[1].as_ref() else {
        panic!()
    };
    assert!(!crate::traffic::evaluate([first], target).allowed);
    assert!(crate::traffic::evaluate([second], target).allowed);
    assert_eq!(
        c.metrics
            .cache_lookups
            .get_or_create(&DemandResult {
                resource_type: view::TRAFFIC_POLICY,
                result: "hit"
            })
            .get(),
        2
    );
    tokio::time::advance(Duration::from_millis(800)).await;
    // Batch use refreshed both retained interests.
    assert!(c.cached_many(ResourceKind::TrafficPolicy, &names).is_some());
    c.apply(
        ResourceKind::TrafficPolicy,
        &Response {
            type_url: view::TRAFFIC_POLICY.into(),
            removed_resources: vec!["allow".into()],
            ..Default::default()
        },
    )
    .unwrap();
    assert!(c.cached_many(ResourceKind::TrafficPolicy, &names).is_none());
    assert!(
        c.cached_many(ResourceKind::TrafficPolicy, &names[..1])
            .is_some()
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(
        c.cached_many(ResourceKind::TrafficPolicy, &names[..1])
            .is_none()
    );

    seed(
        &c,
        ResourceKind::TrafficPolicy,
        "deny",
        any(view::TRAFFIC_POLICY, policy(proto::Action::Deny)),
    );
    c.reset();
    assert!(
        c.cached_many(ResourceKind::TrafficPolicy, &names[..1])
            .is_none()
    );
}

#[tokio::test(start_paused = true)]
async fn connect_revalidates_old_workload_across_reconnect_or_grace_expiry() {
    for clear in ["reconnect", "expiry", "late-expiry"] {
        for sandbox in [false, true] {
            let mut p = processor();
            p.timeout = Duration::from_secs(4);
            let c = &p.client;
            seed(
                c,
                ResourceKind::Workload,
                "/10.0.0.1",
                workload(Some(if sandbox { &[] } else { &["allow"] })),
            );
            c.disconnected();
            tokio::time::advance(Duration::from_secs(2)).await;
            let mut pending =
                Box::pin(p.handle(request(if sandbox { "sandbox" } else { "" }, false)));
            assert!(futures_util::poll!(&mut pending).is_pending());
            // This request has consumed the old Workload and is awaiting a
            // Sandbox or policy. Clear while that Arc remains in its future.
            if clear == "reconnect" {
                c.established();
            } else {
                tokio::time::advance(Duration::from_secs(3)).await;
                if clear == "expiry" {
                    c.expire_disconnected();
                }
                // late-expiry deliberately leaves the timer unpolled. A ready
                // resolve branch must check the deadline before returning ALLOW.
            }
            if sandbox {
                seed(
                    c,
                    ResourceKind::Sandbox,
                    "sandbox",
                    any(
                        view::SANDBOX,
                        Sandbox {
                            uid: "sandbox".into(),
                            attester: Some(Attester {
                                workload_uid: UID.into(),
                            }),
                            ..Default::default()
                        },
                    ),
                );
            } else {
                seed(
                    c,
                    ResourceKind::TrafficPolicy,
                    "allow",
                    any(view::TRAFFIC_POLICY, policy(proto::Action::Allow)),
                );
            }
            assert!(
                futures_util::poll!(&mut pending).is_pending(),
                "old Workload must not allow after cache invalidation"
            );
            // The replacement Workload no longer has a valid binding. It must
            // determine the decision, even though the old dependencies allow.
            seed(c, ResourceKind::Workload, "/10.0.0.1", workload(None));
            assert_denied(pending.await.unwrap());
        }
    }
}

#[tokio::test(start_paused = true)]
async fn reconnect_and_expiry_do_not_restart_the_four_second_connect_budget() {
    for expires in [false, true] {
        let mut p = processor();
        p.timeout = Duration::from_secs(4);
        let c = &p.client;
        seed(
            c,
            ResourceKind::Workload,
            "/10.0.0.1",
            workload(Some(&["pending"])),
        );
        c.disconnected();
        tokio::time::advance(Duration::from_secs(2)).await;
        let mut pending = Box::pin(p.handle(request("", false)));
        assert!(futures_util::poll!(&mut pending).is_pending());
        tokio::time::advance(Duration::from_secs(3)).await;
        if expires {
            c.expire_disconnected();
        } else {
            c.established();
        }
        assert!(futures_util::poll!(&mut pending).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        let std::task::Poll::Ready(result) = futures_util::poll!(&mut pending) else {
            panic!("cache invalidation extended the four-second request budget");
        };
        assert!(result.unwrap_err().message().contains("deadline exceeded"));
    }
}

#[tokio::test(start_paused = true)]
async fn complete_dependency_cache_serves_connect_only_within_disconnect_grace() {
    let p = processor();
    let c = &p.client;
    seed(
        c,
        ResourceKind::Workload,
        "/10.0.0.1",
        workload(Some(&["allow"])),
    );
    seed(
        c,
        ResourceKind::TrafficPolicy,
        "allow",
        any(view::TRAFFIC_POLICY, policy(proto::Action::Allow)),
    );
    seed(
        c,
        ResourceKind::Sandbox,
        "sandbox",
        any(
            view::SANDBOX,
            Sandbox {
                uid: "sandbox".into(),
                attester: Some(Attester {
                    workload_uid: UID.into(),
                }),
                traffic_policy: Some(policy(proto::Action::Allow)),
                ..Default::default()
            },
        ),
    );
    c.disconnected();
    tokio::time::advance(Duration::from_millis(4999)).await;
    for udp in [false, true] {
        assert!(allowed(p.handle(request("sandbox", udp)).await.unwrap()));
    }
    tokio::time::advance(Duration::from_millis(1)).await;
    let mut pending = Box::pin(p.handle(request("sandbox", false)));
    assert!(futures_util::poll!(&mut pending).is_pending());
    let state = c.state.lock().unwrap();
    assert!(
        state
            .types
            .iter()
            .all(|kind| kind.resources.is_empty() && kind.aliases.is_empty())
    );
}
