// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    policy::{self, Action},
    tcp,
};
use serde::Deserialize;
use std::net::SocketAddr;

pub const START_KEY: &[u8] = b"agentio.policy.start";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub profiles: Vec<Profile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Profile {
    pub uid: String,
    #[serde(default)]
    sni_policy: policy::Policy,
    #[serde(default)]
    pub tcp_policy: tcp::Policy,
}

impl Policy {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let policy: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if policy
            .profiles
            .iter()
            .any(|p| p.uid.is_empty() || !p.tcp_policy.valid())
        {
            return Err("invalid connection policy".into());
        }
        Ok(policy)
    }

    pub fn start(&self, uid: &str) -> Result<usize, String> {
        self.profiles
            .iter()
            .position(|p| p.uid == uid)
            .ok_or_else(|| "policy continuation is unavailable".into())
    }

    pub fn evaluate_sni(
        &self,
        name: Option<&str>,
        target: SocketAddr,
    ) -> Result<(Action, Option<&str>), &'static str> {
        for profile in &self.profiles {
            let action = profile
                .sni_policy
                .evaluate(name, Some(u32::from(target.port())));
            if action == Action::Deny {
                return Err("sni_policy_denied");
            }
            if action != Action::Fallthrough {
                return Ok((action, Some(&profile.uid)));
            }
            if let Some(allow) = profile.tcp_policy.evaluate(target) {
                return if allow {
                    Ok((Action::Fallthrough, None))
                } else {
                    Err("tcp_policy_denied")
                };
            }
        }
        Ok((Action::Fallthrough, None))
    }

    pub fn permits(&self, target: SocketAddr, end: usize) -> bool {
        self.profiles[..end]
            .iter()
            .find_map(|p| p.tcp_policy.evaluate(target))
            .unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_priority_and_sni_bypass_are_profile_scoped() {
        for (action, expected) in [
            ("TCP_ACTION_DENY", Err("tcp_policy_denied")),
            ("TCP_ACTION_ALLOW", Ok((Action::Fallthrough, None))),
        ] {
            let value = serde_json::json!({"profiles":[
                {"uid":"a","tcpPolicy":{"rules":[{"name":"first","match":[{"cidrs":["10.0.0.0/8"]}],"action":action}]}},
                {"uid":"b","sniPolicy":{"rules":[{"match":{"sni":["*"]},"action":"SNI_ACTION_PASSTHROUGH"}]},
                 "tcpPolicy":{"rules":[{"name":"own-deny","match":[{}],"action":"TCP_ACTION_DENY"}]}}
            ]});
            let p = Policy::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
            assert_eq!(
                p.evaluate_sni(Some("api.test"), "10.1.2.3:443".parse().unwrap()),
                expected
            );
            assert_eq!(
                p.evaluate_sni(Some("api.test"), "203.0.113.8:443".parse().unwrap()),
                Ok((Action::Passthrough, Some("b")))
            );
            assert_eq!(
                p.evaluate_sni(None, "10.1.2.3:443".parse().unwrap()),
                expected
            );
            assert_eq!(
                p.evaluate_sni(None, "203.0.113.8:443".parse().unwrap()),
                Ok((Action::Passthrough, Some("b")))
            );
            // SNI changed the address: recheck A, while bypassing only B's TCP rules.
            assert_eq!(
                p.permits("10.1.2.3:443".parse().unwrap(), 1),
                action == "TCP_ACTION_ALLOW"
            );
        }
    }
}
