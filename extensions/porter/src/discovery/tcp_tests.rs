// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::wire::agentio::security::{TcpAction, TcpMatch, TcpPolicy, TcpRule};
use crate::{
    processor::{Gateway, Processor},
    wire::{
        agentio::{
            extensions::{PolicyReference, PolicyResourceReference},
            sandbox::{Sandbox, sandbox::Attester},
            security::SecurityProfile,
        },
        extproc,
        istio::workload::{Extension, Workload},
    },
};
use prost::Message;
use prost_types::{Any, Struct, Value, value::Kind};
use std::collections::BTreeMap;

const UID: &str = "Kubernetes//Pod/ns/pod";
const SANDBOX: &str = "kruise:sandbox";

fn policy(action: Option<TcpAction>) -> Any {
    Any {
        type_url: view::SECURITY_PROFILE.into(),
        value: SecurityProfile {
            name: "shared".into(),
            uid: "uid".into(),
            sni_policy: None,
            tcp_policy: Some(TcpPolicy {
                rules: action
                    .into_iter()
                    .map(|action| TcpRule {
                        name: "all".into(),
                        action: action as i32,
                        r#match: vec![TcpMatch {
                            cidrs: vec!["0.0.0.0/0".into()],
                            ports: vec![],
                        }],
                    })
                    .collect(),
            }),
            ..Default::default()
        }
        .encode_to_vec(),
    }
}

fn processor() -> Processor {
    Processor {
        authenticator: Arc::new(crate::identity::Native),
        client: Client::new(
            CacheConfig {
                max_entries: 100,
                idle_ttl: Duration::from_secs(60),
            },
            Metrics::new(),
            true,
        ),
        cluster_id: "Kubernetes".into(),
        timeout: Duration::from_millis(100),
        enable_sni_traffic_policy: true,
        gateway: Gateway::AgentioEgress,
    }
}

fn workload() -> Workload {
    Workload {
        uid: UID.into(),
        name: "pod".into(),
        namespace: "ns".into(),
        trust_domain: "cluster.local".into(),
        service_account: "default".into(),
        ..Default::default()
    }
}

fn seed(
    client: &Arc<Client>,
    kind: ResourceKind,
    name: &str,
    aliases: &[&str],
    value: impl Message,
) {
    let mut lease = client.acquire(kind, name).unwrap();
    client
        .apply(
            kind,
            &Response {
                type_url: kind.type_url().into(),
                resources: vec![ads::Resource {
                    name: name.into(),
                    aliases: aliases.iter().map(|s| (*s).into()).collect(),
                    resource: Some(Any {
                        type_url: kind.type_url().into(),
                        value: value.encode_to_vec(),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            },
        )
        .unwrap();
    lease.success = true;
}

fn seed_workload(client: &Arc<Client>, policy: Option<Any>) {
    let w = if let Some(policy) = policy {
        seed(
            client,
            ResourceKind::SecurityProfile,
            "shared",
            &[],
            SecurityProfile::decode(policy.value.as_slice()).unwrap(),
        );
        referenced_workload(&["shared"])
    } else {
        workload()
    };
    seed(client, ResourceKind::Workload, UID, &["/192.0.2.10"], w);
}

fn request(sandbox: &str) -> extproc::ProcessingRequest {
    extproc::ProcessingRequest {
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
                        value: "198.51.100.1:443".into(),
                        ..Default::default()
                    },
                ],
            }),
            ..Default::default()
        }),
        attributes: HashMap::from([(
            "envoy.filters.http.ext_proc".into(),
            Struct {
                fields: BTreeMap::from([
                    (
                        "filter_state['agentio.downstream.ip']".into(),
                        view::string("192.0.2.10"),
                    ),
                    (
                        "filter_state['agentio.peer.principal']".into(),
                        view::string("spiffe://cluster.local/ns/ns/sa/default"),
                    ),
                    (
                        "filter_state['agentio.sandbox.id']".into(),
                        view::string(sandbox),
                    ),
                ]),
            },
        )]),
    }
}

fn metadata(response: extproc::ProcessingResponse) -> Struct {
    assert!(matches!(
        response.response,
        Some(extproc::processing_response::Response::RequestHeaders(_))
    ));
    let mut metadata = response.dynamic_metadata.unwrap();
    let Some(Kind::StructValue(agentio)) = metadata.fields.remove("agentio").unwrap().kind else {
        panic!("missing agentio metadata")
    };
    agentio
}

fn connection_profiles(response: extproc::ProcessingResponse) -> Vec<Value> {
    let fields = metadata(response).fields;
    assert!(
        !fields.contains_key("tcp") && !fields.contains_key("sni"),
        "legacy policy metadata must not be emitted"
    );
    let Some(Kind::StructValue(connection)) = &fields["connection"].kind else {
        panic!("missing connection")
    };
    let Some(Kind::StructValue(policy)) = &connection.fields["policy"].kind else {
        panic!("missing policy")
    };
    let Some(Kind::ListValue(profiles)) = &policy.fields["profiles"].kind else {
        panic!("missing profiles")
    };
    profiles.values.clone()
}

fn assert_policies(response: extproc::ProcessingResponse, actions: &[Option<TcpAction>]) {
    let profiles = connection_profiles(response);
    assert_eq!(profiles.len(), actions.len());
    for (profile, action) in profiles.iter().zip(actions) {
        let Some(Kind::StructValue(profile)) = &profile.kind else {
            panic!("invalid profile")
        };
        let source = SecurityProfile::decode(policy(*action).value.as_slice()).unwrap();
        assert_eq!(
            profile.fields["tcpPolicy"],
            crate::tcp::Policy::compile(source.tcp_policy.unwrap())
                .unwrap()
                .project()
        );
    }
}

#[tokio::test]
async fn policies_are_forwarded_without_legacy_decisions_and_missing_policy_fails_closed() {
    for enable_sni in [true, false] {
        for action in [Some(TcpAction::Allow), Some(TcpAction::Deny), None] {
            let mut p = processor();
            p.enable_sni_traffic_policy = enable_sni;
            seed_workload(&p.client, action.map(|a| policy(Some(a))));
            let result = p.handle(request("")).await;
            if action.is_none() {
                assert_eq!(result.unwrap_err().code(), tonic::Code::Unavailable);
                continue;
            }
            assert_policies(result.unwrap(), &[action]);
        }
    }
    assert!(
        ResourceKind::from_type_url("type.googleapis.com/agentio.security.TrafficPolicy").is_none()
    );
}

#[tokio::test]
async fn empty_profile_allows_but_missing_referenced_profile_does_not() {
    let p = processor();
    seed_workload(&p.client, Some(policy(None)));
    assert_policies(p.handle(request("")).await.unwrap(), &[None]);
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&["unavailable"]),
    );
    assert_eq!(
        p.handle(request("")).await.unwrap_err().code(),
        tonic::Code::Unavailable
    );
}

#[tokio::test]
async fn shared_and_inline_rules_form_one_ordered_chain() {
    for (shared, inline) in [
        (Some(TcpAction::Allow), Some(TcpAction::Deny)),
        (Some(TcpAction::Deny), Some(TcpAction::Allow)),
        (None, Some(TcpAction::Deny)),
        (None, None),
    ] {
        let p = processor();
        seed_workload(&p.client, Some(policy(shared)));
        seed(
            &p.client,
            ResourceKind::Sandbox,
            SANDBOX,
            &[],
            Sandbox {
                uid: SANDBOX.into(),
                attester: Some(Attester {
                    workload_uid: UID.into(),
                }),
                extensions: vec![policy(inline)],
            },
        );
        assert_policies(p.handle(request(SANDBOX)).await.unwrap(), &[shared, inline]);
    }
}

#[tokio::test]
async fn sandbox_without_inline_profile_uses_shared_rules_or_default_allow() {
    for shared in [Some(TcpAction::Allow), Some(TcpAction::Deny), None] {
        let p = processor();
        if let Some(action) = shared {
            seed_workload(&p.client, Some(policy(Some(action))));
        } else {
            seed(
                &p.client,
                ResourceKind::Workload,
                UID,
                &["/192.0.2.10"],
                referenced_workload(&[]),
            );
        }
        seed(
            &p.client,
            ResourceKind::Sandbox,
            SANDBOX,
            &[],
            Sandbox {
                uid: SANDBOX.into(),
                attester: Some(Attester {
                    workload_uid: UID.into(),
                }),
                ..Default::default()
            },
        );
        assert_policies(
            p.handle(request(SANDBOX)).await.unwrap(),
            &shared.map(|a| vec![Some(a)]).unwrap_or_default(),
        );
    }
}

#[tokio::test]
async fn workload_update_while_waiting_for_sandbox_rebuilds_snapshot() {
    let p = processor();
    seed_workload(&p.client, Some(policy(Some(TcpAction::Allow))));
    let mut pending = Box::pin(p.handle(request(SANDBOX)));
    assert!(futures_util::poll!(&mut pending).is_pending());
    seed_workload(&p.client, Some(policy(Some(TcpAction::Deny))));
    seed(
        &p.client,
        ResourceKind::Sandbox,
        SANDBOX,
        &[],
        Sandbox {
            uid: SANDBOX.into(),
            attester: Some(Attester {
                workload_uid: UID.into(),
            }),
            extensions: vec![policy(None)],
        },
    );
    assert_policies(pending.await.unwrap(), &[Some(TcpAction::Deny), None]);
}

#[tokio::test]
async fn agentgateway_keeps_identity_only_contract() {
    let mut p = processor();
    p.gateway = Gateway::Agentgateway;
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        workload(),
    );
    let mut req = request("");
    let headers = &mut req
        .request_headers
        .as_mut()
        .unwrap()
        .headers
        .as_mut()
        .unwrap()
        .headers;
    headers[0].value = "GET".into();
    headers[1].value = "api.example.com".into();
    let fields = metadata(p.handle(req).await.unwrap()).fields;
    assert!(fields.contains_key("workload"));
    assert!(!fields.contains_key("sni") && !fields.contains_key("tcp"));
    assert_eq!(
        p.handle(request(SANDBOX)).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
}

fn referenced_workload(names: &[&str]) -> Workload {
    let mut w = workload();
    w.extensions.push(Extension {
        name: "security-profile-reference".into(),
        config: Some(Any {
            type_url: "type.googleapis.com/agentio.extensions.PolicyReference".into(),
            value: PolicyReference {
                type_url: view::SECURITY_PROFILE.into(),
                resources: names
                    .iter()
                    .map(|name| PolicyResourceReference {
                        name: (*name).into(),
                        uid: "uid".into(),
                        extensions: vec![],
                    })
                    .collect(),
            }
            .encode_to_vec(),
        }),
    });
    w
}

fn shared_profile(name: &str, action: Option<TcpAction>) -> SecurityProfile {
    let mut profile = SecurityProfile::decode(policy(action).value.as_slice()).unwrap();
    profile.name = name.into();
    profile
}

#[tokio::test]
async fn shared_profiles_update_without_workload_and_preserve_binding_order() {
    use crate::wire::agentio::security::{
        SniAction, SniMatch, SniPolicy as SniTrafficPolicy, SniRule,
    };
    let p = processor();
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&["second", "first"]),
    );
    seed(
        &p.client,
        ResourceKind::SecurityProfile,
        "first",
        &[],
        shared_profile("first", Some(TcpAction::Allow)),
    );
    let mut pending = Box::pin(p.handle(request("")));
    assert!(futures_util::poll!(&mut pending).is_pending());
    let mut second = shared_profile("second", Some(TcpAction::Deny));
    second.sni_policy = Some(SniTrafficPolicy {
        rules: vec![SniRule {
            action: SniAction::Deny as i32,
            r#match: Some(SniMatch {
                sni: vec!["blocked.example".into()],
                ports: vec![443],
            }),
        }],
    });
    seed(
        &p.client,
        ResourceKind::SecurityProfile,
        "second",
        &[],
        second.clone(),
    );
    assert_policies(
        pending.await.unwrap(),
        &[Some(TcpAction::Deny), Some(TcpAction::Allow)],
    );
    second.tcp_policy = shared_profile("second", None).tcp_policy;
    second.sni_policy.as_mut().unwrap().rules[0].action = SniAction::Passthrough as i32;
    seed(
        &p.client,
        ResourceKind::SecurityProfile,
        "second",
        &[],
        second.clone(),
    );
    let profiles = connection_profiles(p.handle(request("")).await.unwrap());
    let Some(Kind::StructValue(profile)) = &profiles[0].kind else {
        panic!("missing profile")
    };
    assert_eq!(
        profile.fields["sniPolicy"],
        view::object([(
            "rules".into(),
            view::list(view::project_rules(&second.sni_policy.unwrap().rules).collect())
        )])
    );
    assert_policies(
        p.handle(request("")).await.unwrap(),
        &[None, Some(TcpAction::Allow)],
    );
    p.client
        .apply(
            ResourceKind::SecurityProfile,
            &Response {
                type_url: view::SECURITY_PROFILE.into(),
                removed_resources: vec!["second".into()],
                ..Default::default()
            },
        )
        .unwrap();
    assert!(p.handle(request("")).await.is_err());
    seed(
        &p.client,
        ResourceKind::SecurityProfile,
        "second",
        &[],
        shared_profile("second", Some(TcpAction::Deny)),
    );
    assert_policies(
        p.handle(request("")).await.unwrap(),
        &[Some(TcpAction::Deny), Some(TcpAction::Allow)],
    );
    let mut replacement = shared_profile("second", None);
    replacement.uid = "replacement".into();
    seed(
        &p.client,
        ResourceKind::SecurityProfile,
        "second",
        &[],
        replacement,
    );
    assert_eq!(
        p.handle(request("")).await.unwrap_err().code(),
        tonic::Code::Unavailable
    );
}

#[tokio::test]
async fn empty_binding_allows_and_changed_binding_rebuilds_pending_snapshot() {
    let p = processor();
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&[]),
    );
    assert_policies(p.handle(request("")).await.unwrap(), &[]);
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&["old"]),
    );
    let mut pending = Box::pin(p.handle(request("")));
    assert!(futures_util::poll!(&mut pending).is_pending());
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&["new"]),
    );
    seed(
        &p.client,
        ResourceKind::SecurityProfile,
        "new",
        &[],
        shared_profile("new", Some(TcpAction::Deny)),
    );
    seed(
        &p.client,
        ResourceKind::SecurityProfile,
        "old",
        &[],
        shared_profile("old", Some(TcpAction::Allow)),
    );
    assert_policies(pending.await.unwrap(), &[Some(TcpAction::Deny)]);
}

#[tokio::test]
async fn withdrawn_reference_does_not_reject_the_replacement_binding() {
    let p = processor();
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&["old"]),
    );
    let mut pending = Box::pin(p.handle(request("")));
    assert!(futures_util::poll!(&mut pending).is_pending());
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&[]),
    );
    p.client
        .apply(
            ResourceKind::SecurityProfile,
            &Response {
                type_url: view::SECURITY_PROFILE.into(),
                removed_resources: vec!["old".into()],
                ..Default::default()
            },
        )
        .unwrap();
    assert_policies(pending.await.unwrap(), &[]);
}

#[tokio::test]
async fn profile_source_name_is_independent_of_its_discovery_name() {
    let p = processor();
    let name = "namespaced/ns/shared";
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&[name]),
    );
    let mut profile = shared_profile("shared", None);
    profile.namespace = "ns".into();
    seed(&p.client, ResourceKind::SecurityProfile, name, &[], profile);
    assert_policies(p.handle(request("")).await.unwrap(), &[None]);
}

struct RuntimeIdentity {
    delay: Duration,
    failure: Option<tonic::Code>,
}

#[tonic::async_trait]
impl crate::identity::Authenticator for RuntimeIdentity {
    async fn authenticate(
        &self,
        _evidence: crate::identity::Evidence<'_>,
        deadline: tokio::time::Instant,
    ) -> Result<crate::identity::ConnectionIdentity, tonic::Status> {
        assert!(deadline > tokio::time::Instant::now());
        tokio::time::sleep(self.delay).await;
        if let Some(code) = self.failure {
            return Err(tonic::Status::new(code, "runtime authentication failed"));
        }
        Ok(crate::identity::ConnectionIdentity {
            workload: crate::identity::WorkloadIdentity::Instance("runtime-instance".into()),
            sandbox_id: "runtime-sandbox".into(),
        })
    }
}

#[tokio::test(start_paused = true)]
async fn runtime_authentication_shares_deadline_and_never_falls_back() {
    let mut p = processor();
    seed_workload(&p.client, Some(policy(None)));
    assert!(is_allowed(p.handle(request("")).await.unwrap()));
    for (failure, expected) in [
        (tonic::Code::PermissionDenied, None),
        (tonic::Code::Unavailable, Some(tonic::Code::Unavailable)),
    ] {
        p.authenticator = Arc::new(RuntimeIdentity {
            delay: Duration::ZERO,
            failure: Some(failure),
        });
        match expected {
            None => assert!(!is_allowed(p.handle(request("")).await.unwrap())),
            Some(code) => assert_eq!(p.handle(request("")).await.unwrap_err().code(), code),
        }
    }
    p.authenticator = Arc::new(RuntimeIdentity {
        delay: p.timeout * 2,
        failure: None,
    });
    let started = tokio::time::Instant::now();
    assert_eq!(
        p.handle(request("")).await.unwrap_err().code(),
        tonic::Code::Unavailable
    );
    assert_eq!(started.elapsed(), p.timeout);
}

fn is_allowed(response: extproc::ProcessingResponse) -> bool {
    matches!(
        response.response,
        Some(extproc::processing_response::Response::RequestHeaders(_))
    )
}

#[tokio::test]
async fn runtime_identity_preserves_binding_and_gateway_constraints() {
    let mut p = processor();
    p.authenticator = Arc::new(RuntimeIdentity {
        delay: Duration::ZERO,
        failure: None,
    });
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["runtime-instance"],
        referenced_workload(&[]),
    );
    let mut sandbox = Sandbox {
        uid: "runtime-sandbox".into(),
        attester: Some(Attester {
            workload_uid: UID.into(),
        }),
        ..Default::default()
    };
    seed(
        &p.client,
        ResourceKind::Sandbox,
        "runtime-sandbox",
        &[],
        sandbox.clone(),
    );
    let response = metadata(p.handle(request("forged-sandbox")).await.unwrap());
    assert_eq!(
        response.fields["sandbox"],
        view::object([("id".into(), view::string("runtime-sandbox"))])
    );
    p.gateway = Gateway::Agentgateway;
    let mut req = request("");
    req.request_headers
        .as_mut()
        .unwrap()
        .headers
        .as_mut()
        .unwrap()
        .headers[0]
        .value = "GET".into();
    assert_eq!(
        p.handle(req).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    p.gateway = Gateway::AgentioEgress;
    sandbox.attester.as_mut().unwrap().workload_uid = "different-workload".into();
    seed(
        &p.client,
        ResourceKind::Sandbox,
        "runtime-sandbox",
        &[],
        sandbox,
    );
    assert!(!is_allowed(p.handle(request("")).await.unwrap()));
}
