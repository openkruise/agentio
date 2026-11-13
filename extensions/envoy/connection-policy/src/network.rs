// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::{connection, dns, store, tcp::Prefix};
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyNetworkFilter, EnvoyNetworkFilterConfig, NetworkFilter, NetworkFilterConfig,
    abi::envoy_dynamic_module_type_network_connection_close_type as CloseType,
    abi::envoy_dynamic_module_type_on_network_filter_data_status as Status, envoy_log_error,
};
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};

const FILTER_NAME: &str = "envoy_agentio_tcp_policy";
const PIN_KEY: &[u8] = b"envoy.network.transport_socket.original_dst_address";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Settings {
    #[serde(default)]
    resolve_sni: bool,
    #[serde(default)]
    denied_cidrs: Vec<Prefix>,
    #[serde(default)]
    skip_matched_profile: bool,
}

struct Config {
    settings: Settings,
    dns: Option<Arc<dns::Resolver>>,
}

pub fn new_config<C: EnvoyNetworkFilterConfig, N: EnvoyNetworkFilter>(
    _: &mut C,
    name: &str,
    bytes: &[u8],
) -> Option<Box<dyn NetworkFilterConfig<N>>> {
    if name != FILTER_NAME {
        return None;
    }
    let result = (|| -> Result<Config, String> {
        let settings: Settings = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let dns = if settings.resolve_sni {
            Some(Arc::new(dns::Resolver::new()?))
        } else {
            None
        };
        Ok(Config { settings, dns })
    })();
    match result {
        Ok(config) => Some(Box::new(config)),
        Err(error) => {
            envoy_log_error!("invalid TCP policy filter config: {}", error);
            None
        }
    }
}

struct Filter {
    dns: Option<Arc<dns::Resolver>>,
    denied_cidrs: Vec<Prefix>,
    policy: Option<store::SharedPolicy>,
    end: usize,
    original: Option<SocketAddr>,
    resolution: Option<dns::PendingResolution>,
    permitted: bool,
    skip_matched_profile: bool,
}

impl<N: EnvoyNetworkFilter> NetworkFilterConfig<N> for Config {
    fn new_network_filter(&self, _: &mut N) -> Box<dyn NetworkFilter<N>> {
        Box::new(Filter {
            dns: self.dns.clone(),
            denied_cidrs: self.settings.denied_cidrs.clone(),
            policy: None,
            end: 0,
            original: None,
            resolution: None,
            permitted: false,
            skip_matched_profile: self.settings.skip_matched_profile,
        })
    }
}

fn deny(envoy: &mut impl EnvoyNetworkFilter, reason: &str) -> Status {
    envoy.close_with_details(CloseType::NoFlush, reason);
    Status::StopIteration
}

impl Filter {
    fn authorize(
        &mut self,
        envoy: &mut impl EnvoyNetworkFilter,
        candidates: Vec<SocketAddr>,
    ) -> Status {
        let policy = self
            .policy
            .as_ref()
            .expect("policy installed before authorization")
            .policy()
            .expect("policy validated on connection initialization");
        let original = self
            .original
            .expect("target installed before authorization");
        let candidates = if candidates.contains(&original) {
            vec![original]
        } else {
            candidates
        };
        let selected = candidates.into_iter().find(|target| {
            (!self.denied_cidrs.iter().any(|p| p.contains(target.ip())))
                && policy.permits(*target, self.end)
        });
        let Some(selected) = selected else {
            return deny(envoy, "agentio_tcp_policy_denied");
        };
        if !envoy.set_filter_state_typed(PIN_KEY, selected.to_string().as_bytes()) {
            return deny(envoy, "agentio_tcp_destination_write_failed");
        }
        if self.dns.is_some()
            && !envoy.set_filter_state_typed(
                b"envoy.upstream.dynamic_host",
                selected.ip().to_string().as_bytes(),
            )
        {
            return deny(envoy, "agentio_tcp_destination_write_failed");
        }
        self.permitted = true;
        Status::Continue
    }
}

impl<N: EnvoyNetworkFilter> NetworkFilter<N> for Filter {
    fn on_new_connection(&mut self, envoy: &mut N) -> Status {
        let Some(bytes) = envoy.get_filter_state_bytes(store::HASH_KEY) else {
            return deny(envoy, "agentio_tcp_policy_missing");
        };
        let Some(shared) = store::SharedPolicy::lookup(bytes.as_slice()) else {
            return deny(envoy, "agentio_tcp_policy_unavailable");
        };
        let policy = match shared.policy() {
            Ok(policy) => policy,
            Err(error) => {
                envoy_log_error!("invalid TCP policy: {}", error);
                return deny(envoy, "agentio_tcp_policy_invalid");
            }
        };
        let (ip, port) = envoy.get_local_address();
        let target = match ip
            .parse::<std::net::IpAddr>()
            .ok()
            .zip(u16::try_from(port).ok())
        {
            Some((ip, port)) if port > 0 => SocketAddr::new(ip.to_canonical(), port),
            _ => return deny(envoy, "agentio_tcp_destination_invalid"),
        };
        let start = envoy
            .get_filter_state_bytes(connection::START_KEY)
            .map(|b| String::from_utf8(b.as_slice().to_vec()))
            .transpose();
        let start = match start {
            Ok(Some(uid)) => match policy.start(&uid) {
                Ok(index) => Some(index),
                Err(_) => return deny(envoy, "agentio_tcp_policy_unavailable"),
            },
            Ok(None) => None,
            Err(_) => return deny(envoy, "agentio_tcp_policy_invalid"),
        };
        // Explicit SNI passthrough skips its profile; post-termination TCP checks the full chain.
        self.end = if self.skip_matched_profile {
            start.unwrap_or(policy.profiles.len())
        } else {
            policy.profiles.len()
        };
        self.policy = Some(shared);
        self.original = Some(target);
        let Some(dns) = &self.dns else {
            return self.authorize(envoy, vec![target]);
        };
        let name = envoy
            .get_filter_state_bytes(b"envoy.upstream.dynamic_host")
            .or_else(|| envoy.get_requested_server_name());
        let name = match name
            .as_ref()
            .map(|b| std::str::from_utf8(b.as_slice()))
            .transpose()
        {
            Ok(Some(name)) if !name.is_empty() => name.to_owned(),
            Ok(_) => return self.authorize(envoy, vec![target]),
            Err(_) => return deny(envoy, "agentio_tcp_sni_invalid"),
        };
        if let Ok(ip) = name.parse::<std::net::IpAddr>() {
            return self.authorize(envoy, vec![SocketAddr::new(ip, target.port())]);
        }
        self.resolution = Some(dns.resolve(name, target.port(), envoy.new_scheduler()));
        Status::StopIteration
    }

    fn on_read(&mut self, _: &mut N, _: usize, _: bool) -> Status {
        if self.permitted {
            Status::Continue
        } else {
            Status::StopIteration
        }
    }

    fn on_scheduled(&mut self, envoy: &mut N, _: u64) {
        let result = self
            .resolution
            .take()
            .expect("DNS query scheduled")
            .finish();
        match result {
            Ok(candidates) => {
                if self.authorize(envoy, candidates) == Status::Continue {
                    envoy.continue_reading();
                }
            }
            Err(error) => {
                envoy_log_error!("TCP DNS resolution failed: {}", error);
                deny(envoy, "agentio_tcp_dns_failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoy_proxy_dynamic_modules_rust_sdk::{EnvoyBuffer, MockEnvoyNetworkFilter};

    fn filter() -> Filter {
        Filter {
            dns: None,
            denied_cidrs: Vec::new(),
            policy: None,
            end: 0,
            original: None,
            resolution: None,
            permitted: false,
            skip_matched_profile: false,
        }
    }

    #[test]
    fn resolved_destination_is_pinned_and_termination_keeps_the_matching_profile() {
        for skip_matched_profile in [true, false] {
            let owner = store::SharedPolicy::intern(br#"{"profiles":[
                {"uid":"first","tcpPolicy":{"rules":[{"name":"private","match":[{"cidrs":["10.0.0.0/8"]}],"action":"TCP_ACTION_DENY"}]}},
                {"uid":"matched","tcpPolicy":{"rules":[{"name":"deny","match":[{}],"action":"TCP_ACTION_DENY"}]}}
            ]}"#).unwrap();
            let hash = owner.hash().to_string();
            let mut filter = filter();
            filter.dns = Some(Arc::new(dns::Resolver::new().unwrap()));
            filter.skip_matched_profile = skip_matched_profile;
            let mut envoy = MockEnvoyNetworkFilter::new();
            envoy
                .expect_get_filter_state_bytes()
                .returning(move |key| match key {
                    store::HASH_KEY => Some(EnvoyBuffer::new(hash.as_bytes())),
                    connection::START_KEY => Some(EnvoyBuffer::new(b"matched")),
                    b"envoy.upstream.dynamic_host" => Some(EnvoyBuffer::new(b"203.0.113.8")),
                    _ => panic!("unexpected filter state key"),
                });
            envoy
                .expect_get_local_address()
                .return_const(("192.0.2.1".to_owned(), 443));
            if skip_matched_profile {
                envoy
                    .expect_set_filter_state_typed()
                    .withf(|key, value| key == PIN_KEY && value == b"203.0.113.8:443")
                    .times(1)
                    .return_const(true);
                envoy
                    .expect_set_filter_state_typed()
                    .withf(|key, value| {
                        key == b"envoy.upstream.dynamic_host" && value == b"203.0.113.8"
                    })
                    .times(1)
                    .return_const(true);
            } else {
                envoy
                    .expect_close_with_details()
                    .withf(|_, reason| reason == "agentio_tcp_policy_denied")
                    .times(1)
                    .return_const(());
            }
            assert_eq!(
                filter.on_new_connection(&mut envoy),
                if skip_matched_profile {
                    Status::Continue
                } else {
                    Status::StopIteration
                }
            );
        }
    }

    #[test]
    fn raw_tcp_is_authorized_and_pinned_before_proxy_initialization() {
        const P:&[u8]=br#"{"profiles":[{"uid":"a","tcpPolicy":{"rules":[{"name":"deny-private","match":[{"cidrs":["10.0.0.0/8"]}],"action":"TCP_ACTION_DENY"}]}}]}"#;
        for (ip, allowed) in [("203.0.113.8", true), ("10.1.2.3", false)] {
            let mut filter = filter();
            let owner = store::SharedPolicy::intern(P).unwrap();
            let hash = owner.hash().to_string();
            let mut envoy = MockEnvoyNetworkFilter::new();
            envoy
                .expect_get_filter_state_bytes()
                .withf(|k| k == store::HASH_KEY)
                .returning(move |_| Some(EnvoyBuffer::new(hash.as_bytes())));
            envoy
                .expect_get_filter_state_bytes()
                .withf(|k| k == connection::START_KEY)
                .returning(|_| None);
            envoy
                .expect_get_local_address()
                .return_const((ip.to_owned(), 443));
            if allowed {
                envoy
                    .expect_set_filter_state_typed()
                    .withf(|k, v| k == PIN_KEY && v == b"203.0.113.8:443")
                    .times(1)
                    .return_const(true);
            } else {
                envoy
                    .expect_close_with_details()
                    .withf(|_, reason| reason == "agentio_tcp_policy_denied")
                    .times(1)
                    .return_const(());
            }
            assert_eq!(
                filter.on_new_connection(&mut envoy),
                if allowed {
                    Status::Continue
                } else {
                    Status::StopIteration
                }
            );
            assert_eq!(
                filter.on_read(&mut envoy, 100, false),
                if allowed {
                    Status::Continue
                } else {
                    Status::StopIteration
                }
            );
        }
    }

    #[test]
    fn missing_and_released_hashes_fail_before_destination_selection() {
        let owner = store::SharedPolicy::intern(br#"{"profiles":[]}"#).unwrap();
        let hash = owner.hash().to_string();
        drop(owner);
        for value in [None, Some("invalid".to_owned()), Some(hash)] {
            let mut filter = filter();
            let mut envoy = MockEnvoyNetworkFilter::new();
            envoy
                .expect_get_filter_state_bytes()
                .withf(|key| key == store::HASH_KEY)
                .returning(move |_| value.as_ref().map(|s| EnvoyBuffer::new(s.as_bytes())));
            envoy.expect_close_with_details().times(1).return_const(());
            assert_eq!(filter.on_new_connection(&mut envoy), Status::StopIteration);
            assert_eq!(filter.on_read(&mut envoy, 10, false), Status::StopIteration);
        }
    }

    #[test]
    fn resolved_target_rechecks_prefix_and_does_not_fall_back_from_original() {
        let p=store::SharedPolicy::intern(br#"{"profiles":[
          {"uid":"a","tcpPolicy":{"rules":[{"name":"deny","match":[{"cidrs":["10.0.0.0/8"]}],"action":"TCP_ACTION_DENY"}]}},
          {"uid":"b","tcpPolicy":{"rules":[{"name":"own","match":[{}],"action":"TCP_ACTION_DENY"}]}}
        ]}"#).unwrap();
        let mut filter = filter();
        filter.policy = Some(p);
        filter.end = 1;
        filter.original = Some("10.1.2.3:443".parse().unwrap());
        let mut envoy = MockEnvoyNetworkFilter::new();
        envoy.expect_close_with_details().times(1).return_const(());
        assert_eq!(
            filter.authorize(
                &mut envoy,
                vec![
                    "10.1.2.3:443".parse().unwrap(),
                    "203.0.113.8:443".parse().unwrap()
                ]
            ),
            Status::StopIteration
        );
        filter.original = Some("192.0.2.1:443".parse().unwrap());
        envoy
            .expect_set_filter_state_typed()
            .withf(|k, v| k == PIN_KEY && v == b"203.0.113.8:443")
            .times(1)
            .return_const(true);
        assert_eq!(
            filter.authorize(
                &mut envoy,
                vec![
                    "10.1.2.3:443".parse().unwrap(),
                    "203.0.113.8:443".parse().unwrap()
                ]
            ),
            Status::Continue
        );
    }
}
