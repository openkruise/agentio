// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::{connection, dns, store, tcp::Prefix};
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyNetworkFilter, EnvoyNetworkFilterConfig, EnvoyNetworkFilterScheduler, NetworkFilter,
    NetworkFilterConfig, abi::envoy_dynamic_module_type_network_connection_close_type as CloseType,
    abi::envoy_dynamic_module_type_on_network_filter_data_status as Status, envoy_log_error,
};
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};

const FILTER_NAME: &str = "envoy_agentio_tcp_policy";
const PIN_KEY: &[u8] = b"envoy.network.transport_socket.original_dst_address";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    mode: Mode,
    #[serde(default)]
    dns: dns::Settings,
    #[serde(default)]
    denied_cidrs: Vec<Prefix>,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Mode {
    OriginalDst,
    DynamicForward,
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
        let dns = if matches!(settings.mode, Mode::DynamicForward) {
            Some(dns::Resolver::shared(&settings.dns)?)
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
    policy: Option<store::TcpPolicyView>,
    original: Option<SocketAddr>,
    resolution: Option<dns::PendingResolution>,
    permitted: bool,
}

impl<N: EnvoyNetworkFilter> NetworkFilterConfig<N> for Config {
    fn new_network_filter(&self, _: &mut N) -> Box<dyn NetworkFilter<N>> {
        Box::new(Filter {
            dns: self.dns.clone(),
            denied_cidrs: self.settings.denied_cidrs.clone(),
            policy: None,
            original: None,
            resolution: None,
            permitted: false,
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
            .expect("policy installed before authorization");
        let original = self
            .original
            .expect("target installed before authorization");
        let candidates = if candidates.contains(&original) {
            vec![original]
        } else {
            candidates
        };
        let selected = crate::destination::select(candidates, &self.denied_cidrs, |target| {
            policy.permits(target)
        });
        let Some(selected) = selected else {
            return deny(envoy, "agentio_tcp_policy_denied");
        };
        if !envoy.set_filter_state_typed(PIN_KEY, selected.to_string().as_bytes()) {
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
        let end_before = envoy.get_filter_state_bytes(connection::TCP_END_BEFORE_KEY);
        self.policy = match shared.tcp_view(end_before.as_ref().map(|b| b.as_slice())) {
            Ok(policy) => Some(policy),
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
        self.original = Some(target);
        let Some(dns) = &self.dns else {
            return self.authorize(envoy, vec![target]);
        };
        let name = envoy
            .get_filter_state_bytes(b"agentio.tls.outer_sni")
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
        let scheduler = envoy.new_scheduler();
        match dns.resolve(name, target.port(), move || scheduler.commit(0)) {
            dns::Lookup::Ready(Ok(candidates)) => self.authorize(envoy, candidates),
            dns::Lookup::Ready(Err(error)) => {
                envoy_log_error!("TCP DNS resolution failed: {}", error);
                deny(envoy, "agentio_tcp_dns_failed")
            }
            dns::Lookup::Pending(pending) => {
                self.resolution = Some(pending);
                Status::StopIteration
            }
        }
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
            original: None,
            resolution: None,
            permitted: false,
        }
    }

    #[test]
    fn resolved_destination_uses_the_supplied_policy_view() {
        for prefix_only in [true, false] {
            let owner = store::SharedPolicy::intern(br#"{"profiles":[
                {"uid":"first","tcpPolicy":{"rules":[{"name":"private","match":[{"cidrs":["10.0.0.0/8"]}],"action":"TCP_ACTION_DENY"}]}},
                {"uid":"matched","tcpPolicy":{"rules":[{"name":"deny","match":[{}],"action":"TCP_ACTION_DENY"}]}}
            ]}"#).unwrap();
            let hash = owner.hash().to_string();
            let mut filter = filter();
            filter.dns = Some(dns::Resolver::shared(&dns::Settings::default()).unwrap());
            let mut envoy = MockEnvoyNetworkFilter::new();
            envoy
                .expect_get_filter_state_bytes()
                .returning(move |key| match key {
                    store::HASH_KEY => Some(EnvoyBuffer::new(hash.as_bytes())),
                    connection::TCP_END_BEFORE_KEY => {
                        prefix_only.then(|| EnvoyBuffer::new(b"matched"))
                    }
                    b"agentio.tls.outer_sni" => Some(EnvoyBuffer::new(b"203.0.113.8")),
                    _ => panic!("unexpected filter state key"),
                });
            envoy
                .expect_get_local_address()
                .return_const(("192.0.2.1".to_owned(), 443));
            if prefix_only {
                envoy
                    .expect_set_filter_state_typed()
                    .withf(|key, value| key == PIN_KEY && value == b"203.0.113.8:443")
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
                if prefix_only {
                    Status::Continue
                } else {
                    Status::StopIteration
                }
            );
        }
    }

    #[test]
    fn mode_is_explicit_and_legacy_settings_are_rejected() {
        for mode in ["ORIGINAL_DST", "DYNAMIC_FORWARD"] {
            let config: Settings = serde_json::from_value(
                serde_json::json!({"mode":mode,"denied_cidrs":["10.0.0.0/8"]}),
            )
            .unwrap();
            assert_eq!(config.denied_cidrs.len(), 1);
        }
        for json in [
            r#"{}"#,
            r#"{"mode":"AUTO"}"#,
            r#"{"mode":"ORIGINAL_DST","resolveSni":false}"#,
            r#"{"mode":"ORIGINAL_DST","skipMatchedProfile":true}"#,
            r#"{"mode":"ORIGINAL_DST","denied_cidrs":["invalid"]}"#,
        ] {
            assert!(serde_json::from_str::<Settings>(json).is_err(), "{json}");
        }
    }

    #[test]
    fn denied_cidrs_override_even_an_empty_profile_view() {
        let owner = store::SharedPolicy::intern(br#"{"profiles":[{"uid":"pass"}]}"#).unwrap();
        let mut filter = filter();
        filter.policy = Some(owner.tcp_view(Some(b"pass")).unwrap());
        filter.original = Some("192.0.2.1:8443".parse().unwrap());
        filter.denied_cidrs = serde_json::from_str(r#"["203.0.113.0/24"]"#).unwrap();
        let mut envoy = MockEnvoyNetworkFilter::new();
        envoy.expect_close_with_details().times(1).return_const(());
        assert_eq!(
            filter.authorize(&mut envoy, vec!["203.0.113.8:8443".parse().unwrap()]),
            Status::StopIteration
        );
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
                .withf(|k| k == connection::TCP_END_BEFORE_KEY)
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
        filter.policy = Some(p.tcp_view(Some(b"b")).unwrap());
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
