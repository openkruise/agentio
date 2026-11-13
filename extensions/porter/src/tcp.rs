// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::wire::agentio::security::{TcpAction, TcpPolicy};
use anyhow::{Context, Result, ensure};
use std::net::IpAddr;

#[derive(Debug)]
pub struct Policy {
    rules: Vec<Rule>,
}
#[derive(Debug)]
struct Rule {
    name: String,
    allow: bool,
    clauses: Vec<Clause>,
}
#[derive(Debug)]
struct Clause {
    networks: Vec<(IpAddr, u8)>,
    ports: Vec<u32>,
}

impl Policy {
    pub fn compile(value: TcpPolicy) -> Result<Self> {
        let mut rules = Vec::new();
        for rule in value.rules {
            let action = TcpAction::try_from(rule.action)?;
            ensure!(action != TcpAction::Unspecified, "unspecified TCP action");
            ensure!(!rule.r#match.is_empty(), "TCP rule requires match");
            let mut clauses = Vec::new();
            for clause in rule.r#match {
                ensure!(
                    clause.ports.iter().all(|p| (1..=65535).contains(p)),
                    "invalid TCP port"
                );
                let mut networks = Vec::new();
                for cidr in clause.cidrs {
                    let (ip, length) = cidr.split_once('/').context("invalid CIDR")?;
                    let ip: IpAddr = ip.parse()?;
                    let length: u8 = length.parse()?;
                    ensure!(
                        length <= if ip.is_ipv4() { 32 } else { 128 },
                        "invalid prefix length"
                    );
                    ensure!(ip.to_canonical() == ip, "IPv4-mapped CIDR is unsupported");
                    networks.push((ip, length));
                }
                clauses.push(Clause {
                    networks,
                    ports: clause.ports,
                });
            }
            rules.push(Rule {
                name: rule.name,
                allow: action == TcpAction::Allow,
                clauses,
            });
        }
        Ok(Self { rules })
    }

    pub fn project(&self) -> prost_types::Value {
        use crate::view::{list, object, string};
        use prost_types::{Value, value::Kind};
        object([(
            "rules".into(),
            list(
                self.rules
                    .iter()
                    .map(|rule| {
                        object([
                            ("name".into(), string(&rule.name)),
                            (
                                "action".into(),
                                string(if rule.allow {
                                    "TCP_ACTION_ALLOW"
                                } else {
                                    "TCP_ACTION_DENY"
                                }),
                            ),
                            (
                                "match".into(),
                                list(
                                    rule.clauses
                                        .iter()
                                        .map(|clause| {
                                            object([
                                                (
                                                    "cidrs".into(),
                                                    list(
                                                        clause
                                                            .networks
                                                            .iter()
                                                            .map(|(ip, bits)| {
                                                                string(format!("{ip}/{bits}"))
                                                            })
                                                            .collect(),
                                                    ),
                                                ),
                                                (
                                                    "ports".into(),
                                                    list(
                                                        clause
                                                            .ports
                                                            .iter()
                                                            .map(|p| Value {
                                                                kind: Some(Kind::NumberValue(
                                                                    f64::from(*p),
                                                                )),
                                                            })
                                                            .collect(),
                                                    ),
                                                ),
                                            ])
                                        })
                                        .collect(),
                                ),
                            ),
                        ])
                    })
                    .collect(),
            ),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::agentio::security::{TcpMatch, TcpRule};
    #[test]
    fn validates_and_projects_tcp_rules() {
        let rules = vec![
            TcpRule {
                name: "allow".into(),
                action: TcpAction::Allow as i32,
                r#match: vec![TcpMatch {
                    cidrs: vec!["10.1.0.0/16".into()],
                    ports: vec![443],
                }],
            },
            TcpRule {
                name: "deny".into(),
                action: TcpAction::Deny as i32,
                r#match: vec![TcpMatch {
                    cidrs: vec!["10.0.0.0/8".into(), "fc00::/7".into()],
                    ports: vec![],
                }],
            },
        ];
        let policy = Policy::compile(TcpPolicy {
            rules: rules.clone(),
        })
        .unwrap();
        let expected = crate::view::object([("rules".into(), crate::view::list(vec![]))]);
        assert_eq!(
            Policy::compile(TcpPolicy::default()).unwrap().project(),
            expected
        );
        let projected = policy.project();
        let prost_types::value::Kind::StructValue(fields) = projected.kind.unwrap() else {
            panic!("policy must be an object")
        };
        let prost_types::value::Kind::ListValue(rules_value) =
            fields.fields["rules"].kind.as_ref().unwrap()
        else {
            panic!("rules must be a list")
        };
        assert_eq!(rules_value.values.len(), 2);
        for (value, source) in rules_value.values.iter().zip(&rules) {
            let Some(prost_types::value::Kind::StructValue(rule)) = &value.kind else {
                panic!("invalid rule")
            };
            assert_eq!(rule.fields["name"], crate::view::string(&source.name));
            assert_eq!(
                rule.fields["action"],
                crate::view::string(TcpAction::try_from(source.action).unwrap().as_str_name())
            );
            let Some(prost_types::value::Kind::ListValue(clauses)) = &rule.fields["match"].kind
            else {
                panic!("invalid clauses")
            };
            assert_eq!(clauses.values.len(), source.r#match.len());
            for (value, source) in clauses.values.iter().zip(&source.r#match) {
                let Some(prost_types::value::Kind::StructValue(clause)) = &value.kind else {
                    panic!("invalid clause")
                };
                assert_eq!(
                    clause.fields["cidrs"],
                    crate::view::list(source.cidrs.iter().map(crate::view::string).collect())
                );
                assert_eq!(
                    clause.fields["ports"],
                    crate::view::list(
                        source
                            .ports
                            .iter()
                            .map(|port| prost_types::Value {
                                kind: Some(prost_types::value::Kind::NumberValue(f64::from(*port)))
                            })
                            .collect()
                    )
                );
            }
        }
        for cidr in ["invalid", "10.0.0.0/33", "::ffff:10.0.0.0/120"] {
            let mut bad = rules.clone();
            bad[0].r#match[0].cidrs = vec![cidr.into()];
            assert!(Policy::compile(TcpPolicy { rules: bad }).is_err());
        }
    }
}
