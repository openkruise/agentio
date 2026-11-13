// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Deserializer, de::Error};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    #[serde(default)]
    name: String,
    r#match: Vec<Clause>,
    action: Action,
}

#[derive(Debug, Deserialize)]
enum Action {
    #[serde(rename = "TCP_ACTION_ALLOW")]
    Allow,
    #[serde(rename = "TCP_ACTION_DENY")]
    Deny,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Clause {
    #[serde(default)]
    cidrs: Vec<Prefix>,
    #[serde(default)]
    ports: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct Prefix(IpAddr, u32);

impl<'de> Deserialize<'de> for Prefix {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let (ip, bits) = value
            .split_once('/')
            .ok_or_else(|| D::Error::custom("missing CIDR prefix"))?;
        let ip: IpAddr = ip.parse().map_err(D::Error::custom)?;
        let bits = bits.parse().map_err(D::Error::custom)?;
        if ip.to_canonical() != ip || bits > if ip.is_ipv4() { 32 } else { 128 } {
            return Err(D::Error::custom("invalid CIDR prefix"));
        }
        Ok(Self(ip, bits))
    }
}

impl Prefix {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.0, ip.to_canonical()) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let mask = u32::MAX.checked_shl(32 - self.1).unwrap_or(0);
                u32::from(a) & mask == u32::from(b) & mask
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let mask = u128::MAX.checked_shl(128 - self.1).unwrap_or(0);
                u128::from(a) & mask == u128::from(b) & mask
            }
            _ => false,
        }
    }
}

impl Policy {
    pub fn valid(&self) -> bool {
        self.rules.iter().all(|rule| {
            !rule.name.is_empty()
                && !rule.r#match.is_empty()
                && rule
                    .r#match
                    .iter()
                    .all(|clause| clause.ports.iter().all(|p| (1..=65535).contains(p)))
        })
    }

    pub fn evaluate(&self, target: SocketAddr) -> Option<bool> {
        self.rules
            .iter()
            .find(|rule| {
                rule.r#match.iter().any(|clause| {
                    (clause.ports.is_empty() || clause.ports.contains(&u32::from(target.port())))
                        && (clause.cidrs.is_empty()
                            || clause.cidrs.iter().any(|p| p.contains(target.ip())))
                })
            })
            .map(|rule| matches!(rule.action, Action::Allow))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_go_rust_conformance() {
        #[derive(Deserialize)]
        struct Case {
            name: String,
            policy: Policy,
            targets: Vec<Target>,
        }
        #[derive(Deserialize)]
        struct Target {
            address: String,
            decision: String,
        }
        let cases: Vec<Case> = serde_json::from_str(include_str!(
            "../../../../pkg/policy/testdata/tcp_rules.json"
        ))
        .unwrap();
        for case in cases {
            assert!(case.policy.valid());
            for target in case.targets {
                let got = match case.policy.evaluate(target.address.parse().unwrap()) {
                    Some(true) => "allow",
                    Some(false) => "deny",
                    None => "no_match",
                };
                assert_eq!(got, target.decision, "{} {}", case.name, target.address);
            }
        }
    }

    #[test]
    fn ordered_ipv4_ipv6_ports_and_no_match() {
        let policy: Policy = serde_json::from_str(r#"{"rules":[
          {"name":"allow","match":[{"cidrs":["10.1.0.0/16"],"ports":[443]}],"action":"TCP_ACTION_ALLOW"},
          {"name":"deny","match":[{"cidrs":["10.0.0.0/8","fc00::/7"]}],"action":"TCP_ACTION_DENY"}
        ]}"#).unwrap();
        assert!(policy.valid());
        for (target, expected) in [
            ("10.1.0.1:443", Some(true)),
            ("10.1.0.1:80", Some(false)),
            ("[fd00::1]:443", Some(false)),
            ("192.0.2.1:443", None),
            ("[::ffff:10.1.0.1]:443", Some(true)),
        ] {
            assert_eq!(
                policy.evaluate(target.parse().unwrap()),
                expected,
                "{target}"
            );
        }
    }

    #[test]
    fn zero_prefix_and_bad_cidr() {
        let prefix: Prefix = serde_json::from_str(r#""0.0.0.0/0""#).unwrap();
        assert!(prefix.contains("203.0.113.9".parse().unwrap()));
        for cidr in ["bad", "10.0.0.0/33", "::ffff:10.0.0.0/120"] {
            assert!(serde_json::from_value::<Prefix>(serde_json::json!(cidr)).is_err());
        }
    }
}
