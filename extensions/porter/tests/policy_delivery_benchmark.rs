// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

//! Delivery/cache prototypes, not additional production xDS resource support.
//! Uses real Workload/Delta protobufs, TCP compiler and SNI metadata projection.

use agentio_porter::wire::agentio::security::{
    SniAction, SniMatch, SniPolicy as SniTrafficPolicy, SniRule, TcpAction, TcpMatch, TcpPolicy,
    TcpRule,
};
use agentio_porter::{
    tcp, view,
    wire::{
        ads,
        agentio::extensions::{PolicyReference, PolicyResourceReference, WorkloadMetadata},
        extproc,
        istio::workload::{Extension, Workload},
    },
};
use anyhow::{Context, Result, bail, ensure};
use prost::Message;
use prost_types::{Any, Struct, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hint::black_box,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const WDS: &str = view::WORKLOAD;
const SP: &str = "type.googleapis.com/agentio.bench.SecurityProfile";
const SNI: &str = "type.googleapis.com/agentio.extensions.SniTrafficPolicy";
const TCP: &str = "type.googleapis.com/agentio.extensions.TCPPolicy";
const REFS: &str = "type.googleapis.com/agentio.extensions.PolicyReference";

// Test-local wire shape: no generated production APIs or new dependencies.
#[derive(Clone, PartialEq, Message)]
struct Profile {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    uid: String,
    #[prost(message, optional, tag = "3")]
    sni: Option<SniTrafficPolicy>,
    #[prost(message, optional, tag = "4")]
    tcp: Option<TcpPolicy>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    InlineSplit,
    InlineUnified,
    InlineProfiles,
    RefUnifiedLookup,
    RefUnifiedBound,
    RefSplitLookup,
    RefSplitBound,
}

impl Mode {
    const ALL: [Self; 7] = [
        Self::InlineSplit,
        Self::InlineUnified,
        Self::InlineProfiles,
        Self::RefUnifiedLookup,
        Self::RefUnifiedBound,
        Self::RefSplitLookup,
        Self::RefSplitBound,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::InlineSplit => "inline_split",
            Self::InlineUnified => "inline_unified",
            Self::InlineProfiles => "inline_profiles",
            Self::RefUnifiedLookup => "ref_unified_lookup",
            Self::RefUnifiedBound => "ref_unified_bound",
            Self::RefSplitLookup => "ref_split_lookup",
            Self::RefSplitBound => "ref_split_bound",
        }
    }
    fn referenced(self) -> bool {
        !matches!(
            self,
            Self::InlineSplit | Self::InlineUnified | Self::InlineProfiles
        )
    }
    fn split(self) -> bool {
        matches!(self, Self::RefSplitLookup | Self::RefSplitBound)
    }
    fn bound(self) -> bool {
        matches!(self, Self::RefUnifiedBound | Self::RefSplitBound)
    }
}

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    workloads: usize,
    groups: usize,
    profiles: usize,
    tcp: usize,
    sni: usize,
}

const CASES: [Case; 6] = [
    Case {
        name: "shared-1k",
        workloads: 1000,
        groups: 1,
        profiles: 1,
        tcp: 128,
        sni: 16,
    },
    Case {
        name: "shared-10k-small",
        workloads: 10000,
        groups: 1,
        profiles: 1,
        tcp: 16,
        sni: 8,
    },
    Case {
        name: "layered-1k",
        workloads: 1000,
        groups: 1,
        profiles: 8,
        tcp: 16,
        sni: 8,
    },
    Case {
        name: "distinct-1k",
        workloads: 1000,
        groups: 1000,
        profiles: 1,
        tcp: 128,
        sni: 16,
    },
    Case {
        name: "tcp-heavy-1k",
        workloads: 1000,
        groups: 1,
        profiles: 1,
        tcp: 1024,
        sni: 64,
    },
    Case {
        name: "sni-heavy-1k",
        workloads: 1000,
        groups: 1,
        profiles: 1,
        tcp: 16,
        sni: 256,
    },
];

fn profile_name(group: usize, index: usize) -> String {
    format!("bench/g{group:04}-p{index:02}")
}
fn workload_name(index: usize) -> String {
    format!("bench/workload-{index:05}")
}
fn pack(type_url: &str, value: impl Message) -> Any {
    Any {
        type_url: type_url.into(),
        value: value.encode_to_vec(),
    }
}

fn profile(case: Case, group: usize, index: usize, revision: usize) -> Profile {
    Profile {
        name: profile_name(group, index),
        uid: format!("uid-{group:04}-{index:02}"),
        sni: Some(SniTrafficPolicy {
            rules: (0..case.sni)
                .map(|i| SniRule {
                    r#match: Some(SniMatch {
                        sni: vec![
                            format!("v{revision}-g{group}-p{index}-host{i}.example.com"),
                            "*.example.net".into(),
                        ],
                        ports: vec![443, 8443],
                    }),
                    action: if revision == 0 {
                        SniAction::TlsTermination
                    } else {
                        SniAction::Deny
                    } as i32,
                })
                .collect(),
        }),
        tcp: Some(TcpPolicy {
            rules: (0..case.tcp)
                .map(|i| {
                    let last = i == case.tcp - 1;
                    let matches = last && (index == case.profiles - 1 || revision > 0);
                    TcpRule {
                        name: format!("p{index}-rule-{i}"),
                        action: if matches && revision == 0 {
                            TcpAction::Allow
                        } else {
                            TcpAction::Deny
                        } as i32,
                        r#match: vec![TcpMatch {
                            cidrs: vec![if matches {
                                "192.0.2.1/32".into()
                            } else {
                                format!("198.51.100.{}/32", i % 256)
                            }],
                            ports: vec![443],
                        }],
                    }
                })
                .collect(),
        }),
    }
}

fn workload(case: Case, mode: Mode, index: usize, revision: usize, changed: bool) -> Any {
    let group = index % case.groups;
    let profiles: Vec<_> = (0..if mode.referenced() { 0 } else { case.profiles })
        .map(|p| {
            profile(
                case,
                group,
                p,
                if changed && group == 0 && p == 0 {
                    revision
                } else {
                    0
                },
            )
        })
        .collect();
    let refs = PolicyReference {
        type_url: SP.into(),
        resources: (0..case.profiles)
            .map(|p| PolicyResourceReference {
                name: profile_name(group, p),
                uid: format!("uid-{group:04}-{p:02}"),
                extensions: vec![],
            })
            .collect(),
    };
    // Existing inline Workloads already carry SP references for EPE; include them in every mode.
    let mut extensions = vec![Extension {
        name: "security-profile-reference".into(),
        config: Some(pack(REFS, refs)),
    }];
    if mode == Mode::InlineProfiles {
        extensions.extend(profiles.into_iter().map(|p| Extension {
            name: "security-policy".into(),
            config: Some(pack(SP, p)),
        }));
    } else if !mode.referenced() {
        let merged = Profile {
            sni: Some(SniTrafficPolicy {
                rules: profiles
                    .iter()
                    .flat_map(|p| p.sni.as_ref().unwrap().rules.clone())
                    .collect(),
            }),
            tcp: Some(TcpPolicy {
                rules: profiles
                    .iter()
                    .flat_map(|p| p.tcp.as_ref().unwrap().rules.clone())
                    .collect(),
            }),
            ..Default::default()
        };
        if mode == Mode::InlineUnified {
            extensions.push(Extension {
                name: "security-policy".into(),
                config: Some(pack(SP, merged)),
            });
        } else {
            extensions.push(Extension {
                name: "sni-traffic-policy".into(),
                config: Some(pack(SNI, merged.sni.unwrap())),
            });
            extensions.push(Extension {
                name: "agentio.tcp.policy".into(),
                config: Some(pack(TCP, merged.tcp.unwrap())),
            });
        }
    }
    extensions.push(Extension {
        name: "metadata".into(),
        config: Some(pack(
            "type.googleapis.com/agentio.extensions.WorkloadMetadata",
            WorkloadMetadata {
                labels: (0..20)
                    .map(|i| (format!("label-{i}"), format!("value-{i}")))
                    .collect(),
                ..Default::default()
            },
        )),
    });
    pack(
        WDS,
        Workload {
            uid: workload_name(index),
            name: format!("pod-{index:05}"),
            namespace: "bench".into(),
            service_account: "default".into(),
            trust_domain: "cluster.local".into(),
            hostname: if revision > 0 && !changed {
                "identity-update".into()
            } else {
                String::new()
            },
            extensions,
            ..Default::default()
        },
    )
}

struct Plan {
    packets: Vec<Vec<u8>>,
    resources: usize,
    bytes: usize,
}

fn plan(case: Case, mode: Mode, stage: &str, revision: usize) -> Plan {
    let mut by_type: BTreeMap<String, Vec<ads::Resource>> = BTreeMap::new();
    let mut add = |name: String, body: Any| {
        by_type
            .entry(body.type_url.clone())
            .or_default()
            .push(ads::Resource {
                name,
                version: revision.to_string(),
                resource: Some(body),
                ..Default::default()
            });
    };
    if mode.referenced() && stage != "identity" {
        for group in 0..case.groups {
            for p in 0..case.profiles {
                if stage == "policy" && (group != 0 || p != 0) {
                    continue;
                }
                let value = profile(case, group, p, revision);
                let name = value.name.clone();
                if mode.split() {
                    add(name.clone(), pack(SNI, value.sni.unwrap()));
                    add(name, pack(TCP, value.tcp.unwrap()));
                } else {
                    add(name, pack(SP, value));
                }
            }
        }
    }
    if !mode.referenced() || stage != "policy" {
        for i in 0..case.workloads {
            if stage == "policy" && i % case.groups != 0 {
                continue;
            }
            if stage == "identity" && i != 0 {
                continue;
            }
            add(
                workload_name(i),
                workload(case, mode, i, revision, stage == "policy"),
            );
        }
    }
    let resources = by_type.values().map(Vec::len).sum();
    let mut packets = Vec::new();
    // Normalize arrival order: demand discovers policy references from Workload first.
    let mut by_type: Vec<_> = by_type.into_iter().collect();
    by_type.sort_by_key(|(type_url, _)| type_url != WDS);
    for (type_url, values) in by_type {
        // Real Delta envelopes; bounded batches avoid measuring a giant synthetic frame.
        for chunk in values.chunks(32) {
            packets.push(
                ads::DeltaDiscoveryResponse {
                    type_url: type_url.clone(),
                    nonce: revision.to_string(),
                    resources: chunk.to_vec(),
                    ..Default::default()
                }
                .encode_to_vec(),
            );
        }
    }
    let bytes = packets.iter().map(Vec::len).sum();
    Plan {
        packets,
        resources,
        bytes,
    }
}

#[derive(Clone)]
struct Segment {
    sni: Arc<Vec<SniRule>>,
    tcp: Arc<tcp::Policy>,
}

fn compile_sni(value: SniTrafficPolicy) -> Result<Arc<Vec<SniRule>>> {
    for rule in &value.rules {
        ensure!(
            SniAction::try_from(rule.action)? != SniAction::Unspecified,
            "invalid SNI action"
        );
    }
    Ok(Arc::new(value.rules))
}
fn compile_profile(value: Profile) -> Result<Segment> {
    let tcp = value.tcp.context("missing TCP policy")?;
    Ok(Segment {
        sni: compile_sni(value.sni.unwrap_or_default())?,
        tcp: Arc::new(tcp::Policy::compile(tcp)?),
    })
}

struct Binding {
    identity: Workload,
    names: Vec<String>,
    segments: Option<Vec<Segment>>,
}
// Keep the real wire Workload inline in the bounded, temporary decode batch.
#[allow(clippy::large_enum_variant)]
enum Decoded {
    Workload(String, Binding),
    Profile(String, Segment),
    Sni(String, Arc<Vec<SniRule>>),
    Tcp(String, Arc<tcp::Policy>),
}

#[derive(Default)]
struct Cache {
    workloads: HashMap<String, Arc<Binding>>,
    profiles: HashMap<String, Segment>,
    sni: HashMap<String, Arc<Vec<SniRule>>>,
    tcp: HashMap<String, Arc<tcp::Policy>>,
    dependents: HashMap<String, HashSet<String>>,
    tcp_compiles: usize,
    rebindings: usize,
}

impl Cache {
    fn resolve_names(&self, mode: Mode, names: &[String]) -> Option<Vec<Segment>> {
        names
            .iter()
            .map(|name| {
                if mode.split() {
                    Some(Segment {
                        sni: self.sni.get(name)?.clone(),
                        tcp: self.tcp.get(name)?.clone(),
                    })
                } else {
                    self.profiles.get(name).cloned()
                }
            })
            .collect()
    }
    fn rebind(&mut self, mode: Mode, name: &str) {
        let affected: Vec<_> = self
            .dependents
            .get(name)
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        for key in affected {
            let old = &self.workloads[&key];
            let binding = Binding {
                identity: old.identity.clone(),
                names: old.names.clone(),
                segments: self.resolve_names(mode, &old.names),
            };
            self.workloads.insert(key, Arc::new(binding));
            self.rebindings += 1;
        }
    }
    fn decode(mode: Mode, response: ads::DeltaDiscoveryResponse) -> Result<Vec<Decoded>> {
        let mut decoded = Vec::new();
        for resource in response.resources {
            let body = resource.resource.unwrap();
            ensure!(body.type_url == response.type_url, "wrong resource type");
            decoded.push(match body.type_url.as_str() {
                WDS => {
                    let mut identity = Workload::decode(body.value.as_slice())?;
                    let mut names = vec![];
                    let mut segments = vec![];
                    let mut sni = None;
                    let mut tcp = None;
                    for extension in std::mem::take(&mut identity.extensions) {
                        let value = extension.config.unwrap();
                        match value.type_url.as_str() {
                            REFS => {
                                names = PolicyReference::decode(value.value.as_slice())?
                                    .resources
                                    .into_iter()
                                    .map(|r| r.name)
                                    .collect()
                            }
                            SP => segments
                                .push(compile_profile(Profile::decode(value.value.as_slice())?)?),
                            SNI => {
                                sni = Some(compile_sni(SniTrafficPolicy::decode(
                                    value.value.as_slice(),
                                )?)?)
                            }
                            TCP => {
                                let value = TcpPolicy::decode(value.value.as_slice())?;
                                tcp = Some(Arc::new(tcp::Policy::compile(value)?));
                            }
                            _ => {}
                        }
                    }
                    if mode == Mode::InlineSplit {
                        segments.push(Segment {
                            sni: sni.unwrap(),
                            tcp: tcp.unwrap(),
                        });
                    }
                    Decoded::Workload(
                        resource.name,
                        Binding {
                            identity,
                            names,
                            segments: (!mode.referenced()).then_some(segments),
                        },
                    )
                }
                SP => Decoded::Profile(
                    resource.name,
                    compile_profile(Profile::decode(body.value.as_slice())?)?,
                ),
                SNI => Decoded::Sni(
                    resource.name,
                    compile_sni(SniTrafficPolicy::decode(body.value.as_slice())?)?,
                ),
                TCP => {
                    let value = TcpPolicy::decode(body.value.as_slice())?;
                    Decoded::Tcp(resource.name, Arc::new(tcp::Policy::compile(value)?))
                }
                _ => bail!("unsupported type"),
            });
        }
        Ok(decoded)
    }
    fn publish(&mut self, mode: Mode, decoded: Vec<Decoded>) {
        for value in decoded {
            match value {
                Decoded::Workload(name, mut value) => {
                    if mode.bound() {
                        if let Some(old) = self.workloads.get(&name) {
                            for key in &old.names {
                                self.dependents.get_mut(key).unwrap().remove(&name);
                            }
                        }
                        for key in &value.names {
                            self.dependents
                                .entry(key.clone())
                                .or_default()
                                .insert(name.clone());
                        }
                        value.segments = self.resolve_names(mode, &value.names);
                    }
                    if !mode.referenced() {
                        self.tcp_compiles += value.segments.as_ref().unwrap().len();
                    }
                    self.workloads.insert(name, Arc::new(value));
                }
                Decoded::Profile(name, value) => {
                    self.tcp_compiles += 1;
                    self.profiles.insert(name.clone(), value);
                    if mode.bound() {
                        self.rebind(mode, &name);
                    }
                }
                Decoded::Sni(name, value) => {
                    self.sni.insert(name.clone(), value);
                    if mode.bound() {
                        self.rebind(mode, &name);
                    }
                }
                Decoded::Tcp(name, value) => {
                    self.tcp_compiles += 1;
                    self.tcp.insert(name.clone(), value);
                    if mode.bound() {
                        self.rebind(mode, &name);
                    }
                }
            }
        }
    }
    fn capture(&self, mode: Mode, name: &str) -> Option<Snapshot> {
        let binding = self.workloads.get(name)?;
        if !mode.referenced() || mode.bound() {
            binding.segments.as_ref()?;
            Some(Snapshot::Bound(binding.clone()))
        } else {
            Some(Snapshot::Lookup(self.resolve_names(mode, &binding.names)?))
        }
    }
    fn remove(&mut self, mode: Mode, type_url: &str, name: &str) {
        match type_url {
            SP => {
                self.profiles.remove(name);
            }
            SNI => {
                self.sni.remove(name);
            }
            TCP => {
                self.tcp.remove(name);
            }
            _ => panic!("test policy removal only"),
        }
        if mode.bound() {
            self.rebind(mode, name);
        }
    }
}

enum Snapshot {
    Bound(Arc<Binding>),
    Lookup(Vec<Segment>),
}
impl Snapshot {
    fn segments(&self) -> &[Segment] {
        match self {
            Self::Bound(value) => value.segments.as_ref().unwrap(),
            Self::Lookup(value) => value,
        }
    }
    fn tcp_projection(&self) -> Vec<Value> {
        self.segments().iter().map(|p| p.tcp.project()).collect()
    }
    fn response(&self) -> Vec<u8> {
        let profiles = self
            .segments()
            .iter()
            .enumerate()
            .map(|(index, p)| {
                view::object([
                    ("uid".into(), view::string(index.to_string())),
                    ("tcpPolicy".into(), p.tcp.project()),
                    (
                        "sniPolicy".into(),
                        view::object([(
                            "rules".into(),
                            view::list(view::project_rules(&p.sni).collect()),
                        )]),
                    ),
                ])
            })
            .collect();
        let metadata = view::object([(
            "connection".into(),
            view::object([(
                "policy".into(),
                view::object([("profiles".into(), view::list(profiles))]),
            )]),
        )]);
        extproc::ProcessingResponse {
            response: Some(extproc::processing_response::Response::RequestHeaders(
                extproc::HeadersResponse {
                    response: Some(extproc::CommonResponse {}),
                },
            )),
            dynamic_metadata: Some(Struct {
                fields: BTreeMap::from([("agentio".into(), metadata)]),
            }),
        }
        .encode_to_vec()
    }
}

fn apply(cache: &Mutex<Cache>, mode: Mode, input: &Plan) -> Result<Duration> {
    let mut publication = Duration::ZERO;
    for packet in &input.packets {
        let decoded = Cache::decode(
            mode,
            ads::DeltaDiscoveryResponse::decode(packet.as_slice())?,
        )?;
        let start = Instant::now();
        cache.lock().unwrap().publish(mode, decoded);
        publication += start.elapsed();
    }
    Ok(publication)
}

fn timed(milliseconds: u64, mut op: impl FnMut()) -> serde_json::Value {
    for _ in 0..16 {
        op();
    }
    let start = Instant::now();
    let mut count = 0_u64;
    while start.elapsed().as_millis() < u128::from(milliseconds) {
        for _ in 0..16 {
            op();
        }
        count += 16;
    }
    let elapsed = start.elapsed().as_secs_f64();
    serde_json::json!({ "operations": count, "seconds": elapsed, "us_per_op": elapsed * 1e6 / count as f64, "ops_per_s": count as f64 / elapsed })
}

fn emit(case: Case, mode: Mode, stage: &str, values: serde_json::Value) {
    println!(
        "{}",
        serde_json::json!({"case": case.name, "mode": mode.name(), "stage": stage, "values": values})
    );
}

#[test]
fn delivery_semantics_self_check() {
    let case = Case {
        name: "self-check",
        workloads: 2,
        groups: 1,
        profiles: 1,
        tcp: 2,
        sni: 2,
    };
    let mut expected = None;
    for mode in Mode::ALL {
        let cache = Mutex::new(Cache::default());
        let initial = plan(case, mode, "initial", 0);
        apply(&cache, mode, &initial).unwrap();
        let snapshot = cache
            .lock()
            .unwrap()
            .capture(mode, &workload_name(0))
            .unwrap();
        let original_tcp = snapshot.tcp_projection();
        let response = snapshot.response();
        assert_eq!(expected.get_or_insert_with(|| response.clone()), &response);
        if mode == Mode::InlineSplit {
            let packet =
                ads::DeltaDiscoveryResponse::decode(initial.packets[0].as_slice()).unwrap();
            let workload = Workload::decode(
                packet.resources[0]
                    .resource
                    .as_ref()
                    .unwrap()
                    .value
                    .as_slice(),
            )
            .unwrap();
            let mut profile = agentio_porter::wire::agentio::security::SecurityProfile::default();
            for config in workload.extensions.into_iter().filter_map(|e| e.config) {
                if config.type_url.ends_with(".TCPPolicy") {
                    profile.tcp_policy = Some(TcpPolicy::decode(config.value.as_slice()).unwrap());
                }
                if config.type_url.ends_with(".SniTrafficPolicy") {
                    profile.sni_policy =
                        Some(SniTrafficPolicy::decode(config.value.as_slice()).unwrap());
                }
            }
            let view::View::SecurityProfile(real) = view::decode(
                view::ResourceKind::SecurityProfile,
                &Any {
                    type_url: view::SECURITY_PROFILE.into(),
                    value: profile.encode_to_vec(),
                },
            )
            .unwrap() else {
                unreachable!()
            };
            assert_eq!(real.rules, *snapshot.segments()[0].sni);
            assert_eq!(
                real.tcp_policy.project(),
                snapshot.segments()[0].tcp.project()
            );
        }
        apply(&cache, mode, &plan(case, mode, "policy", 1)).unwrap();
        let after = cache
            .lock()
            .unwrap()
            .capture(mode, &workload_name(0))
            .unwrap();
        assert_ne!(after.tcp_projection(), original_tcp);
        // An in-flight request retains the old complete snapshot.
        assert_eq!(snapshot.tcp_projection(), original_tcp);
        if mode.referenced() {
            cache.lock().unwrap().remove(
                mode,
                if mode.split() { TCP } else { SP },
                &profile_name(0, 0),
            );
            assert!(
                cache
                    .lock()
                    .unwrap()
                    .capture(mode, &workload_name(0))
                    .is_none()
            );
            apply(&cache, mode, &plan(case, mode, "policy", 1)).unwrap();
            assert!(
                cache
                    .lock()
                    .unwrap()
                    .capture(mode, &workload_name(0))
                    .is_some()
            );
            // Workload-first delivery must remain unavailable until every body arrives.
            let mut reversed = plan(case, mode, "initial", 0);
            reversed.packets.sort_by_key(|p| {
                ads::DeltaDiscoveryResponse::decode(p.as_slice())
                    .unwrap()
                    .type_url
                    != WDS
            });
            let empty = Mutex::new(Cache::default());
            let first = Plan {
                packets: vec![reversed.packets[0].clone()],
                resources: 0,
                bytes: 0,
            };
            apply(&empty, mode, &first).unwrap();
            assert!(
                empty
                    .lock()
                    .unwrap()
                    .capture(mode, &workload_name(0))
                    .is_none()
            );
            apply(&empty, mode, &reversed).unwrap();
            assert!(
                empty
                    .lock()
                    .unwrap()
                    .capture(mode, &workload_name(0))
                    .is_some()
            );
            // Compilation failure rejects a complete packet and keeps the last good value.
            let type_url = if mode.split() { TCP } else { SP };
            let mut value = profile(case, 0, 0, 2);
            value.tcp.as_mut().unwrap().rules[0].r#match[0].cidrs = vec!["invalid".into()];
            let bad = if mode.split() {
                pack(TCP, value.tcp.unwrap())
            } else {
                pack(SP, value)
            };
            let packet = ads::DeltaDiscoveryResponse {
                type_url: type_url.into(),
                resources: vec![ads::Resource {
                    name: profile_name(0, 0),
                    resource: Some(bad),
                    ..Default::default()
                }],
                ..Default::default()
            }
            .encode_to_vec();
            assert!(
                apply(
                    &cache,
                    mode,
                    &Plan {
                        packets: vec![packet],
                        resources: 1,
                        bytes: 0
                    }
                )
                .is_err()
            );
            assert_eq!(
                cache
                    .lock()
                    .unwrap()
                    .capture(mode, &workload_name(0))
                    .unwrap()
                    .tcp_projection(),
                after.tcp_projection()
            );
        }
        if mode.split() {
            let before = Mutex::new(Cache::default());
            apply(&before, mode, &initial).unwrap();
            let updated = plan(case, mode, "policy", 1);
            let sni_only: Vec<_> = updated
                .packets
                .into_iter()
                .filter(|p| {
                    ads::DeltaDiscoveryResponse::decode(p.as_slice())
                        .unwrap()
                        .type_url
                        == SNI
                })
                .collect();
            apply(
                &before,
                mode,
                &Plan {
                    packets: sni_only,
                    resources: 1,
                    bytes: 0,
                },
            )
            .unwrap();
            let mixed = before
                .lock()
                .unwrap()
                .capture(mode, &workload_name(0))
                .unwrap();
            assert_eq!(mixed.tcp_projection(), original_tcp);
            assert_eq!(mixed.segments()[0].sni[0].action, SniAction::Deny as i32);
        }
        let layered = Case {
            profiles: 2,
            ..case
        };
        let cache = Mutex::new(Cache::default());
        apply(&cache, mode, &plan(layered, mode, "initial", 0)).unwrap();
        let snapshot = cache
            .lock()
            .unwrap()
            .capture(mode, &workload_name(0))
            .unwrap();
        let tcp_rules: usize = snapshot
            .tcp_projection()
            .iter()
            .map(|value| {
                let Some(prost_types::value::Kind::StructValue(policy)) = &value.kind else {
                    panic!("invalid policy")
                };
                let Some(prost_types::value::Kind::ListValue(rules)) = &policy.fields["rules"].kind
                else {
                    panic!("invalid rules")
                };
                rules.values.len()
            })
            .sum();
        assert_eq!(tcp_rules, layered.profiles * layered.tcp);
        assert_eq!(
            snapshot
                .segments()
                .iter()
                .map(|p| p.sni.len())
                .sum::<usize>(),
            4
        );
    }
    assert!(compile_profile(Profile::default()).is_err());
    let empty = compile_profile(Profile {
        tcp: Some(TcpPolicy::default()),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        empty.tcp.project(),
        tcp::Policy::compile(TcpPolicy::default())
            .unwrap()
            .project()
    );
}

#[test]
#[ignore = "opt-in component benchmark, release build only"]
fn policy_delivery_benchmark() {
    let case_name = std::env::var("PORTER_DELIVERY_CASE").unwrap();
    let mode_name = std::env::var("PORTER_DELIVERY_MODE").unwrap();
    let case = *CASES.iter().find(|c| c.name == case_name).unwrap();
    let mode = Mode::ALL
        .into_iter()
        .find(|m| m.name() == mode_name)
        .unwrap();
    let milliseconds = std::env::var("PORTER_DELIVERY_MS")
        .unwrap_or_else(|_| "100".into())
        .parse()
        .unwrap();
    let start = Instant::now();
    let initial = plan(case, mode, "initial", 0);
    let encode_ms = start.elapsed().as_secs_f64() * 1e3;
    let cache = Mutex::new(Cache::default());
    let start = Instant::now();
    let publish = apply(&cache, mode, &initial).unwrap();
    emit(
        case,
        mode,
        "initial",
        serde_json::json!({"encode_ms": encode_ms, "apply_ms": start.elapsed().as_secs_f64()*1e3, "publish_ms": publish.as_secs_f64()*1e3, "wire_bytes": initial.bytes, "resources": initial.resources, "packets": initial.packets.len(), "tcp_compiles": cache.lock().unwrap().tcp_compiles}),
    );
    drop(initial);
    if std::env::var_os("PORTER_DELIVERY_MEMORY").is_some() {
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .unwrap();
        assert!(output.status.success());
        let rss_kib: usize = std::str::from_utf8(&output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        emit(
            case,
            mode,
            "memory",
            serde_json::json!({"rss_kib": rss_kib, "workloads": case.workloads, "unique_profiles": case.groups*case.profiles}),
        );
        black_box(&cache);
        return;
    }
    let name = workload_name(0);
    for (stage, payload) in [("hot_tcp_projection", false), ("hot_metadata", true)] {
        emit(
            case,
            mode,
            stage,
            timed(milliseconds, || {
                let snapshot = cache.lock().unwrap().capture(mode, &name).unwrap();
                if payload {
                    black_box(snapshot.response());
                } else {
                    black_box(snapshot.tcp_projection());
                }
            }),
        );
    }
    for stage in ["identity", "policy"] {
        let start = Instant::now();
        let update = plan(case, mode, stage, 1);
        let encode_ms = start.elapsed().as_secs_f64() * 1e3;
        let before = {
            let value = cache.lock().unwrap();
            (value.tcp_compiles, value.rebindings)
        };
        let start = Instant::now();
        let publish = apply(&cache, mode, &update).unwrap();
        let apply_ms = start.elapsed().as_secs_f64() * 1e3;
        let after = {
            let value = cache.lock().unwrap();
            (value.tcp_compiles, value.rebindings)
        };
        emit(
            case,
            mode,
            stage,
            serde_json::json!({"encode_ms": encode_ms, "apply_ms": apply_ms, "publish_ms": publish.as_secs_f64()*1e3, "wire_bytes": update.bytes, "resources": update.resources, "tcp_compiles": after.0-before.0, "rebindings": after.1-before.1}),
        );
    }
    // Shared cache mutex contention, not full ext_proc/ADS throughput.
    for threads in [1, 8] {
        let stop = AtomicBool::new(false);
        let started = Instant::now();
        let operations = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..threads)
                .map(|_| {
                    scope.spawn(|| {
                        let mut count = 0_u64;
                        while !stop.load(Ordering::Relaxed) {
                            for _ in 0..16 {
                                let snapshot = cache.lock().unwrap().capture(mode, &name).unwrap();
                                black_box(snapshot.response());
                            }
                            count += 16;
                        }
                        count
                    })
                })
                .collect();
            std::thread::sleep(Duration::from_millis(milliseconds));
            stop.store(true, Ordering::Relaxed);
            workers.into_iter().map(|w| w.join().unwrap()).sum::<u64>()
        });
        emit(
            case,
            mode,
            "concurrent_metadata",
            serde_json::json!({"threads": threads, "operations": operations, "seconds": started.elapsed().as_secs_f64(), "ops_per_s": operations as f64 / started.elapsed().as_secs_f64()}),
        );
    }
    let update = plan(case, mode, "policy", 2);
    let stop = AtomicBool::new(false);
    let (mut latencies, update_ms, publish_ms) = std::thread::scope(|scope| {
        let readers: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    let mut latencies = Vec::new();
                    while !stop.load(Ordering::Relaxed) {
                        let start = Instant::now();
                        let snapshot = cache.lock().unwrap().capture(mode, &name).unwrap();
                        black_box(snapshot.response());
                        latencies.push(start.elapsed().as_secs_f64() * 1e6);
                    }
                    latencies
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(20));
        let start = Instant::now();
        let publication = apply(&cache, mode, &update).unwrap();
        let update_ms = start.elapsed().as_secs_f64() * 1e3;
        std::thread::sleep(Duration::from_millis(milliseconds));
        stop.store(true, Ordering::Relaxed);
        (
            readers
                .into_iter()
                .flat_map(|r| r.join().unwrap())
                .collect::<Vec<_>>(),
            update_ms,
            publication.as_secs_f64() * 1e3,
        )
    });
    latencies.sort_unstable_by(f64::total_cmp);
    emit(
        case,
        mode,
        "update_under_load",
        serde_json::json!({"threads": 4, "operations": latencies.len(), "p50_us": latencies[latencies.len()/2], "p99_us": latencies[latencies.len()*99/100], "max_us": latencies.last().unwrap(), "apply_ms": update_ms, "publish_ms": publish_ms}),
    );
}
