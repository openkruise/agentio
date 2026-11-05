// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

//! CONNECT-time egress policy evaluation. Bindings supply the evaluation order.

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result, ensure};

use crate::wire::agentio::security::{TrafficPolicy, traffic_policy as proto};

#[derive(Clone, Copy, Debug)]
pub struct Target {
    pub address: SocketAddr,
    pub protocol: proto::Protocol,
}

impl Target {
    pub fn parse(authority: &str, udp: bool) -> Result<Self> {
        // Do not resolve a hostname independently of Envoy's eventual dial.
        let mut address: SocketAddr = authority.parse().context("expected numeric IP:port")?;
        ensure!(address.port() != 0, "target port must be in 1..65535");
        address.set_ip(address.ip().to_canonical());
        Ok(Self {
            address,
            protocol: if udp {
                proto::Protocol::Udp
            } else {
                proto::Protocol::Tcp
            },
        })
    }
}

#[derive(Debug)]
pub struct Policy {
    egress: Option<Vec<Rule>>,
}

#[derive(Debug)]
struct Rule {
    allow: bool,
    destinations: Vec<Network>,
    fqdns: Vec<String>,
    ports: Vec<Port>,
}

#[derive(Debug)]
enum Network {
    V4 { address: u32, mask: u32 },
    V6 { address: u128, mask: u128 },
}

impl Network {
    fn compile(value: proto::Address) -> Result<Self> {
        match value.address.as_slice() {
            [a, b, c, d] => {
                ensure!(value.length <= 32, "invalid IPv4 prefix length");
                let mask = u32::MAX.checked_shl(32 - value.length).unwrap_or(0);
                Ok(Self::V4 {
                    address: u32::from_be_bytes([*a, *b, *c, *d]) & mask,
                    mask,
                })
            }
            bytes if bytes.len() == 16 => {
                ensure!(value.length <= 128, "invalid IPv6 prefix length");
                let mask = u128::MAX.checked_shl(128 - value.length).unwrap_or(0);
                Ok(Self::V6 {
                    address: u128::from_be_bytes(bytes.try_into().unwrap()) & mask,
                    mask,
                })
            }
            _ => anyhow::bail!("invalid IP address length"),
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { address, mask }, IpAddr::V4(ip)) => u32::from(ip) & mask == *address,
            (Self::V6 { address, mask }, IpAddr::V6(ip)) => u128::from(ip) & mask == *address,
            _ => false,
        }
    }
}

#[derive(Debug)]
struct Port {
    protocol: proto::Protocol,
    start: u16,
    end: u16,
}

impl Port {
    fn compile(value: proto::PortMatch) -> Result<Self> {
        let protocol = proto::Protocol::try_from(value.protocol)?;
        ensure!(
            protocol != proto::Protocol::Icmp || (value.port.is_none() && value.end_port.is_none()),
            "ICMP cannot have a port constraint"
        );
        let start = u16::try_from(value.port.unwrap_or(1))?;
        let end = u16::try_from(value.end_port.or(value.port).unwrap_or(65535))?;
        ensure!(start > 0 && end >= start, "invalid port range");
        Ok(Self {
            protocol,
            start,
            end,
        })
    }

    fn matches(&self, target: Target) -> bool {
        (self.protocol == proto::Protocol::All || self.protocol == target.protocol)
            && (self.start..=self.end).contains(&target.address.port())
    }
}

impl Policy {
    pub fn compile(value: TrafficPolicy) -> Result<Self> {
        // Validate the complete wire resource, even though CONNECT evaluates egress only.
        if let Some(ingress) = value.ingress {
            ensure!(
                ingress.rules.iter().all(|rule| rule
                    .r#match
                    .as_ref()
                    .is_none_or(|m| m.destination_fqdns.is_empty())),
                "destination FQDNs are egress-only"
            );
            compile_rules(ingress)?;
        }
        Ok(Self {
            egress: value.egress.map(compile_rules).transpose()?,
        })
    }
}

fn compile_rules(value: proto::RuleSet) -> Result<Vec<Rule>> {
    value
        .rules
        .into_iter()
        .map(|rule| {
            let action = proto::Action::try_from(rule.action)?;
            let matched = rule
                .r#match
                .context("TrafficPolicy rule requires match presence")?;
            for source in matched.source_ips {
                Network::compile(source)?;
            }
            let fqdns = matched
                .destination_fqdns
                .into_iter()
                .map(|name| {
                    let name = name.strip_suffix('.').unwrap_or(&name).to_ascii_lowercase();
                    ensure!(
                        !name.is_empty()
                            && name.len() <= 253
                            && name.split('.').all(|label| !label.is_empty()
                                && label.len() <= 63
                                && !label.starts_with('-')
                                && !label.ends_with('-')
                                && label.bytes().all(|b| b.is_ascii_lowercase()
                                    || b.is_ascii_digit()
                                    || b == b'-')),
                        "invalid destination FQDN"
                    );
                    Ok(name)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Rule {
                fqdns,
                allow: action == proto::Action::Allow,
                destinations: matched
                    .destination_ips
                    .into_iter()
                    .map(Network::compile)
                    .collect::<Result<_>>()?,
                ports: matched
                    .ports
                    .into_iter()
                    .map(Port::compile)
                    .collect::<Result<_>>()?,
            })
        })
        .collect()
}

/// One ordered stage: first match wins; configured but unmatched means deny.
/// Callers must resolve every reference before invoking this function.
pub fn evaluate<'a>(
    policies: impl IntoIterator<Item = &'a Policy>,
    target: Target,
    dns_candidates: &[String],
) -> Evaluation {
    let mut configured = false;
    for (policy_index, policy) in policies.into_iter().enumerate() {
        let Some(rules) = &policy.egress else {
            continue;
        };
        configured = true;
        for (rule_index, rule) in rules.iter().enumerate() {
            if ((rule.destinations.is_empty() && rule.fqdns.is_empty())
                || (target.protocol == proto::Protocol::Tcp
                    && dns_candidates.iter().any(|name| {
                        rule.fqdns.iter().any(|fqdn| {
                            fqdn.eq_ignore_ascii_case(name.strip_suffix('.').unwrap_or(name))
                        })
                    }))
                || rule
                    .destinations
                    .iter()
                    .any(|net| net.contains(target.address.ip())))
                && (rule.ports.is_empty() || rule.ports.iter().any(|port| port.matches(target)))
            {
                return Evaluation {
                    allowed: rule.allow,
                    matched_rule: Some((policy_index, rule_index)),
                    reason: "rule_match",
                };
            }
        }
    }
    Evaluation {
        allowed: !configured,
        matched_rule: None,
        reason: if configured {
            "no_matching_rule"
        } else {
            "no_egress_policy"
        },
    }
}

#[derive(Debug, PartialEq)]
pub struct Evaluation {
    pub allowed: bool,
    /// Zero-based indexes in the ordered policy bindings and the matched rule set.
    pub matched_rule: Option<(usize, usize)>,
    pub reason: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allows<'a>(policies: impl IntoIterator<Item = &'a Policy>, target: Target) -> bool {
        evaluate(policies, target, &[]).allowed
    }

    fn rule(
        action: proto::Action,
        destinations: Vec<proto::Address>,
        ports: Vec<proto::PortMatch>,
    ) -> proto::Rule {
        proto::Rule {
            action: action as i32,
            r#match: Some(proto::Match {
                destination_ips: destinations,
                ports,
                ..Default::default()
            }),
        }
    }

    fn policy(rules: Vec<proto::Rule>) -> Policy {
        Policy::compile(TrafficPolicy {
            egress: Some(proto::RuleSet { rules }),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn fqdn_and_ip_are_alternatives_without_a_wildcard() {
        let target = Target::parse("192.0.2.1:443", false).unwrap();
        let mut matched = proto::Match {
            destination_fqdns: vec!["API.EXAMPLE.COM.".into()],
            ..Default::default()
        };
        let build = |matched| {
            policy(vec![proto::Rule {
                action: proto::Action::Allow as i32,
                r#match: Some(matched),
            }])
        };
        let dns = build(matched.clone());
        assert!(!evaluate([&dns], target, &[]).allowed);
        assert!(evaluate([&dns], target, &["api.example.com".into()]).allowed);
        assert!(
            !evaluate(
                [&dns],
                Target::parse("192.0.2.1:443", true).unwrap(),
                &["api.example.com".into()]
            )
            .allowed
        );
        matched.destination_ips.push(proto::Address {
            address: vec![192, 0, 2, 1],
            length: 32,
        });
        let both = build(matched);
        assert!(evaluate([&both], target, &[]).allowed);
        let denied = policy(vec![rule(proto::Action::Deny, vec![], vec![])]);
        assert!(!evaluate([&denied, &dns], target, &["api.example.com".into()]).allowed);
        assert!(
            Policy::compile(TrafficPolicy {
                egress: Some(proto::RuleSet {
                    rules: vec![proto::Rule {
                        action: 0,
                        r#match: Some(proto::Match {
                            destination_fqdns: vec!["*.example.com".into()],
                            ..Default::default()
                        })
                    }]
                }),
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn evaluation_identifies_the_deciding_rule_and_default_reason() {
        let target = Target::parse("192.0.2.1:443", false).unwrap();
        let absent = Policy::compile(TrafficPolicy::default()).unwrap();
        let empty = policy(vec![]);
        let matched = policy(vec![
            rule(
                proto::Action::Deny,
                vec![],
                vec![proto::PortMatch {
                    port: Some(80),
                    ..Default::default()
                }],
            ),
            rule(proto::Action::Allow, vec![], vec![]),
        ]);
        assert_eq!(
            evaluate([&absent, &empty, &matched], target, &[]),
            Evaluation {
                allowed: true,
                matched_rule: Some((2, 1)),
                reason: "rule_match",
            }
        );
        assert_eq!(
            evaluate([&empty], target, &[]),
            Evaluation {
                allowed: false,
                matched_rule: None,
                reason: "no_matching_rule",
            }
        );
        assert_eq!(
            evaluate([&absent], target, &[]),
            Evaluation {
                allowed: true,
                matched_rule: None,
                reason: "no_egress_policy",
            }
        );
    }

    #[test]
    fn ordered_stages_and_direction_presence() {
        let target = Target::parse("192.0.2.1:443", false).unwrap();
        let absent = Policy::compile(TrafficPolicy::default()).unwrap();
        let empty = policy(vec![]);
        let allow = policy(vec![rule(proto::Action::Allow, vec![], vec![])]);
        let deny = policy(vec![rule(proto::Action::Deny, vec![], vec![])]);
        assert!(allows([], target));
        assert!(allows([&absent], target));
        assert!(!allows([&empty], target));
        assert!(allows([&empty, &allow, &deny], target));
        assert!(!allows([&deny, &allow], target));
        assert!(!allows([&empty, &absent], target));
        let ingress_only = Policy::compile(TrafficPolicy {
            ingress: Some(proto::RuleSet {
                rules: vec![rule(proto::Action::Deny, vec![], vec![])],
            }),
            ..Default::default()
        })
        .unwrap();
        assert!(allows([&ingress_only], target));
        let ordered = policy(vec![
            rule(proto::Action::Allow, vec![], vec![]),
            rule(proto::Action::Deny, vec![], vec![]),
        ]);
        assert!(allows([&ordered], target));
    }

    #[test]
    fn cidrs_ports_and_protocols() {
        let p = policy(vec![rule(
            proto::Action::Allow,
            vec![
                proto::Address {
                    address: vec![192, 0, 2, 127],
                    length: 24,
                },
                proto::Address {
                    address: "2001:db8::"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .to_vec(),
                    length: 32,
                },
            ],
            vec![
                proto::PortMatch {
                    protocol: proto::Protocol::Tcp as i32,
                    port: Some(443),
                    end_port: Some(445),
                },
                proto::PortMatch {
                    protocol: proto::Protocol::Udp as i32,
                    port: Some(53),
                    end_port: None,
                },
            ],
        )]);
        for (authority, udp, allowed) in [
            ("192.0.2.1:443", false, true),
            ("192.0.2.255:445", false, true),
            ("192.0.3.1:443", false, false),
            ("192.0.2.1:446", false, false),
            ("192.0.2.1:53", true, true),
            ("192.0.2.1:53", false, false),
            ("192.0.2.1:443", true, false),
            ("[2001:db8::1]:443", false, true),
            ("[2001:db9::1]:443", false, false),
            ("[::ffff:192.0.2.1]:443", false, true),
        ] {
            assert_eq!(
                allows([&p], Target::parse(authority, udp).unwrap()),
                allowed,
                "{authority} udp={udp}"
            );
        }
        // Egress must ignore an otherwise non-matching source IP constraint.
        let mut r = rule(proto::Action::Allow, vec![], vec![]);
        r.r#match.as_mut().unwrap().source_ips = vec![proto::Address {
            address: vec![10, 0, 0, 1],
            length: 32,
        }];
        assert!(allows(
            [&policy(vec![r])],
            Target::parse("192.0.2.1:443", false).unwrap()
        ));
    }

    #[test]
    fn wildcard_prefixes_and_open_port_bounds() {
        for (port, end_port, authority, allowed) in [
            (None, Some(100), "192.0.2.1:100", true),
            (None, Some(100), "192.0.2.1:101", false),
            (Some(443), None, "192.0.2.1:444", false),
            (None, None, "192.0.2.1:65535", true),
        ] {
            let p = policy(vec![rule(
                proto::Action::Allow,
                vec![proto::Address {
                    address: vec![0, 0, 0, 0],
                    length: 0,
                }],
                vec![proto::PortMatch {
                    protocol: proto::Protocol::All as i32,
                    port,
                    end_port,
                }],
            )]);
            assert_eq!(
                allows([&p], Target::parse(authority, true).unwrap()),
                allowed
            );
        }
        for protocol in [proto::Protocol::Icmp, proto::Protocol::Sctp] {
            let p = policy(vec![rule(
                proto::Action::Allow,
                vec![],
                vec![proto::PortMatch {
                    protocol: protocol as i32,
                    ..Default::default()
                }],
            )]);
            assert!(!allows(
                [&p],
                Target::parse("192.0.2.1:443", false).unwrap()
            ));
        }
    }

    #[test]
    fn malformed_wire_policies_are_rejected() {
        let valid = rule(proto::Action::Allow, vec![], vec![]);
        let mut invalid = vec![
            proto::Rule {
                action: 100,
                ..valid.clone()
            },
            proto::Rule {
                action: 0,
                r#match: None,
            },
        ];
        for address in [
            proto::Address {
                address: vec![1, 2, 3],
                length: 24,
            },
            proto::Address {
                address: vec![1, 2, 3, 4],
                length: 33,
            },
            proto::Address {
                address: vec![0; 16],
                length: 129,
            },
        ] {
            invalid.push(rule(proto::Action::Allow, vec![address], vec![]));
        }
        for (protocol, port, end_port) in [
            (100, None, None),
            (proto::Protocol::Tcp as i32, Some(0), None),
            (proto::Protocol::Tcp as i32, None, Some(65536)),
            (proto::Protocol::Tcp as i32, Some(443), Some(80)),
            (proto::Protocol::Icmp as i32, Some(80), None),
        ] {
            invalid.push(rule(
                proto::Action::Allow,
                vec![],
                vec![proto::PortMatch {
                    protocol,
                    port,
                    end_port,
                }],
            ));
        }
        for r in invalid {
            for ingress in [false, true] {
                let mut wire = TrafficPolicy::default();
                *if ingress {
                    &mut wire.ingress
                } else {
                    &mut wire.egress
                } = Some(proto::RuleSet {
                    rules: vec![r.clone()],
                });
                assert!(Policy::compile(wire).is_err());
            }
        }
    }

    #[test]
    fn targets_require_numeric_ip_and_nonzero_port() {
        for authority in [
            "example.com:443",
            "192.0.2.1",
            "192.0.2.1:0",
            "192.0.2.1:65536",
            "2001:db8::1:443",
            "[fe80::1%eth0]:443",
            "192.0.2.1:443/path",
        ] {
            assert!(Target::parse(authority, false).is_err(), "{authority}");
        }
    }
}
