// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

//! Opt-in ingestion prototype; JSON is not yet supported by production Porter.
//! Reference protobufs come from the real Go SecurityProfile compiler.

use agentio_porter::{
    tcp, view,
    wire::agentio::security::{
        SniAction, SniMatch, SniPolicy as SniTrafficPolicy, SniRule, TcpAction, TcpMatch,
        TcpPolicy, TcpRule,
    },
};
use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use prost::Message;
use serde::Deserialize;
use std::{hint::black_box, time::Instant};

#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Deserialize)]
struct Fixture {
    name: String,
    source: String,
    sni: String,
    tcp: String,
}

#[derive(Default, Deserialize)]
struct Profile {
    #[serde(default)]
    spec: Spec,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Spec {
    #[serde(default)]
    rules: Vec<ApplicationRule>,
    #[serde(default)]
    tcp_rules: Vec<TcpRuleInput>,
}

#[derive(Deserialize)]
struct ApplicationRule {
    r#match: Vec<ApplicationMatch>,
    actions: Actions,
}

#[derive(Deserialize)]
struct ApplicationMatch {
    domains: Vec<String>,
    #[serde(default)]
    ports: Vec<u32>,
    #[serde(default)]
    schemes: Vec<String>,
}

#[derive(Deserialize)]
struct Actions {
    tls: Option<Tls>,
}

#[derive(Deserialize)]
struct Tls {
    action: TlsAction,
}

#[derive(Clone, Copy, Deserialize)]
enum TlsAction {
    Deny,
    Passthrough,
}

#[derive(Deserialize)]
struct TcpRuleInput {
    name: String,
    r#match: Vec<TcpMatchInput>,
    action: TcpActionInput,
}

#[derive(Deserialize)]
struct TcpMatchInput {
    #[serde(default)]
    cidrs: Vec<String>,
    #[serde(default)]
    ports: Vec<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum TcpActionInput {
    Allow,
    Deny,
}

struct Compiled {
    tcp: tcp::Policy,
    sni: Vec<SniRule>,
}

// Benchmark projection for valid generated fixtures, not a production SP validator.
fn compile_json(input: Profile) -> Result<Compiled> {
    let tcp = TcpPolicy {
        rules: input
            .spec
            .tcp_rules
            .into_iter()
            .map(|rule| TcpRule {
                name: rule.name,
                action: match rule.action {
                    TcpActionInput::Allow => TcpAction::Allow,
                    TcpActionInput::Deny => TcpAction::Deny,
                } as i32,
                r#match: rule
                    .r#match
                    .into_iter()
                    .map(|clause| TcpMatch {
                        cidrs: clause.cidrs,
                        ports: clause.ports,
                    })
                    .collect(),
            })
            .collect(),
    };
    let mut sni = Vec::new();
    for rule in input.spec.rules {
        let tls = rule.actions.tls.map(|tls| tls.action);
        let action = match tls {
            Some(TlsAction::Deny) => SniAction::Deny,
            Some(TlsAction::Passthrough) => SniAction::Passthrough,
            None => SniAction::TlsTermination,
        };
        for matched in rule.r#match {
            if tls.is_none()
                && !matched.schemes.is_empty()
                && !matched
                    .schemes
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case("https"))
            {
                continue;
            }
            let mut domains = Vec::new();
            for domain in matched.domains {
                let domain = domain.strip_suffix('.').unwrap_or(&domain).to_lowercase();
                if !domains.contains(&domain) {
                    domains.push(domain);
                }
            }
            if !domains.is_empty() {
                sni.push(SniRule {
                    r#match: Some(SniMatch {
                        sni: domains,
                        ports: matched.ports,
                    }),
                    action: action as i32,
                });
            }
        }
    }
    Ok(Compiled {
        tcp: tcp::Policy::compile(tcp)?,
        sni,
    })
}

fn protobuf(sni: &[u8], tcp: &[u8]) -> Compiled {
    Compiled {
        sni: SniTrafficPolicy::decode(sni).unwrap().rules,
        tcp: tcp::Policy::compile(TcpPolicy::decode(tcp).unwrap()).unwrap(),
    }
}

fn selective(source: &str) -> Compiled {
    compile_json(serde_json::from_str(source).unwrap()).unwrap()
}

fn full_value(source: &str) -> Compiled {
    let value: serde_json::Value = serde_json::from_str(source).unwrap();
    compile_json(serde_json::from_value(value).unwrap()).unwrap()
}

fn hot(policy: &Compiled) -> (prost_types::Value, Vec<prost_types::Value>) {
    (
        policy.tcp.project(),
        view::project_rules(&policy.sni).collect(),
    )
}

fn measure<T>(case: &str, mode: &str, stage: &str, mut f: impl FnMut() -> T) {
    for _ in 0..32 {
        black_box(f());
    }
    let milliseconds: u64 = std::env::var("PORTER_SP_BENCH_MS")
        .unwrap_or_else(|_| "100".into())
        .parse()
        .unwrap();
    assert!(milliseconds > 0);
    let start = Instant::now();
    let mut iterations = 0_u64;
    while start.elapsed().as_millis() < u128::from(milliseconds) {
        for _ in 0..16 {
            black_box(f());
        }
        iterations += 16;
    }
    let elapsed = start.elapsed();
    println!(
        "{}",
        serde_json::json!({"case":case,"mode":mode,"stage":stage,
            "iterations":iterations,"elapsed_s":elapsed.as_secs_f64(),
            "us_per_op":elapsed.as_secs_f64()*1e6/iterations as f64,
            "ops_per_s":iterations as f64/elapsed.as_secs_f64()})
    );
}

#[test]
#[ignore = "ingestion prototype benchmark; generate fixtures and run release build"]
fn security_profile_json_benchmark() {
    let path =
        std::env::var("PORTER_SP_FIXTURES").expect("generate fixtures with sp_json_fixtures.go");
    let fixtures: Vec<Fixture> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    if let Ok(mode) = std::env::var("PORTER_SP_MEMORY_MODE") {
        assert_eq!(fixtures.len(), 1, "memory run needs one isolated fixture");
        let fixture = &fixtures[0];
        let count: usize = std::env::var("PORTER_SP_RETAIN")
            .unwrap_or_else(|_| "128".into())
            .parse()
            .unwrap();
        let sni = STANDARD.decode(&fixture.sni).unwrap();
        let tcp = STANDARD.decode(&fixture.tcp).unwrap();
        let mut retained = Vec::with_capacity(count);
        for _ in 0..count {
            let (compiled, source) = match mode.as_str() {
                "protobuf" => (protobuf(&sni, &tcp), None),
                "json_selective" => (selective(&fixture.source), None),
                "json_value" => (full_value(&fixture.source), None),
                "json_value_retained" => {
                    let value: serde_json::Value = serde_json::from_str(&fixture.source).unwrap();
                    let compiled =
                        compile_json(serde_json::from_value(value.clone()).unwrap()).unwrap();
                    (compiled, Some(value))
                }
                _ => panic!("unknown memory mode {mode}"),
            };
            retained.push((compiled, source));
        }
        println!(
            "{}",
            serde_json::json!({"stage":"memory","case":fixture.name,"mode":mode,"retained":retained.len()})
        );
        black_box(&retained);
        return;
    }
    let reverse = std::env::var_os("PORTER_SP_REVERSE").is_some();
    let mut modes = ["protobuf", "json_selective", "json_value"];
    if reverse {
        modes.reverse();
    }
    for fixture in fixtures {
        let sni_bytes = STANDARD.decode(&fixture.sni).unwrap();
        let tcp_bytes = STANDARD.decode(&fixture.tcp).unwrap();
        let reference = protobuf(&sni_bytes, &tcp_bytes);
        let selected = selective(&fixture.source);
        let full = full_value(&fixture.source);
        assert_eq!(reference.sni, selected.sni, "{} SNI parity", fixture.name);
        assert_eq!(reference.sni, full.sni, "{} SNI parity", fixture.name);
        assert_eq!(hot(&reference), hot(&selected));
        assert_eq!(hot(&reference), hot(&full));
        if fixture.name == "small" {
            let mut invalid: serde_json::Value = serde_json::from_str(&fixture.source).unwrap();
            invalid["spec"]["tcpRules"][0]["match"][0]["cidrs"][0] = "bad-cidr".into();
            assert!(compile_json(serde_json::from_value(invalid).unwrap()).is_err());
        }
        println!(
            "{}",
            serde_json::json!({"stage":"input","case":fixture.name,
                "json_bytes":fixture.source.len(),"protobuf_bytes":sni_bytes.len()+tcp_bytes.len(),
                "sni_rules":reference.sni.len(),"tcp_rules":TcpPolicy::decode(tcp_bytes.as_slice()).unwrap().rules.len()})
        );
        for mode in modes {
            measure(&fixture.name, mode, "ingest", || match mode {
                "protobuf" => protobuf(black_box(&sni_bytes), black_box(&tcp_bytes)),
                "json_selective" => selective(black_box(&fixture.source)),
                "json_value" => full_value(black_box(&fixture.source)),
                _ => unreachable!(),
            });
            let compiled = match mode {
                "protobuf" => &reference,
                "json_selective" => &selected,
                "json_value" => &full,
                _ => unreachable!(),
            };
            measure(&fixture.name, mode, "hot_tcp_and_sni_metadata", || {
                hot(black_box(compiled))
            });
        }
    }
}
