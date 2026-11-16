// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::{destination, dns, tcp::Prefix};
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, EnvoyHttpFilterConfig, EnvoyHttpFilterScheduler, HttpFilter, HttpFilterConfig,
    abi::envoy_dynamic_module_type_on_http_filter_request_headers_status as Status,
    envoy_log_error,
};
use serde::Deserialize;
use std::{
    cell::RefCell,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

pub const FILTER_NAME: &str = "envoy_agentio_egress_authorization";
const SNI_KEY: &[u8] = b"agentio.tls.outer_sni";
const ORIGINAL_KEY: &[u8] = b"envoy.filters.listener.original_dst.local_ip";
use crate::destination::{PIN_KEY, UPSTREAM_KEY};

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Mode {
    OriginalDst,
    DynamicForward,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    mode: Mode,
    #[serde(default)]
    dns: dns::Settings,
    #[serde(default)]
    denied_cidrs: Vec<Prefix>,
    // The generated configuration supplies the upstream transport's default port.
    #[serde(default = "default_port")]
    default_port: u16,
}
fn default_port() -> u16 {
    80
}

struct Config;
struct RouteConfig {
    settings: Settings,
    dns: Option<Arc<dns::Resolver>>,
}
struct Filter {
    route: RefCell<Option<Arc<RouteConfig>>>,
    resolution: RefCell<Option<dns::PendingResolution>>,
}

pub fn new_config<C: EnvoyHttpFilterConfig, H: EnvoyHttpFilter>(
    _: &mut C,
    bytes: &[u8],
) -> Option<Box<dyn HttpFilterConfig<H>>> {
    bytes
        .is_empty()
        .then(|| Box::new(Config) as Box<dyn HttpFilterConfig<H>>)
}

pub fn new_route_config(name: &str, bytes: &[u8]) -> Option<Box<dyn std::any::Any>> {
    if name != FILTER_NAME {
        return None;
    }
    let result = (|| -> Result<RouteConfig, String> {
        let settings: Settings = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if settings.default_port == 0 {
            return Err("default_port must be between 1 and 65535".into());
        }
        let dns = match settings.mode {
            Mode::OriginalDst => None,
            Mode::DynamicForward => Some(dns::Resolver::shared(&settings.dns)?),
        };
        Ok(RouteConfig { settings, dns })
    })();
    match result {
        Ok(config) => Some(Box::new(Arc::new(config))),
        Err(error) => {
            envoy_log_error!("invalid egress authorization route config: {}", error);
            None
        }
    }
}
impl<H: EnvoyHttpFilter> HttpFilterConfig<H> for Config {
    fn new_http_filter(&self, _: &mut H) -> Box<dyn HttpFilter<H>> {
        Box::new(Filter {
            route: RefCell::new(None),
            resolution: RefCell::new(None),
        })
    }
}

fn reject(envoy: &mut impl EnvoyHttpFilter, status: u32, reason: &str) -> Status {
    envoy.send_response(status, &[], None, Some(reason));
    Status::StopIteration
}

// Embedded ports override the fallback, matching DFP's host normalization.
fn target(value: &str, fallback: u16) -> Result<(String, u16), &'static str> {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok((ip.to_string(), fallback));
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        if addr.port() == 0 {
            return Err("zero port");
        }
        return Ok((addr.ip().to_string(), addr.port()));
    }
    if let Some(ip) = value.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return ip
            .parse::<std::net::Ipv6Addr>()
            .map(|ip| (ip.to_string(), fallback))
            .map_err(|_| "invalid IPv6 address");
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse::<u16>()
                .ok()
                .filter(|p| *p > 0)
                .ok_or("invalid port")?,
        ),
        None => (value, fallback),
    };
    if host.is_empty()
        || host
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !b"-._".contains(&b))
    {
        return Err("invalid hostname");
    }
    Ok((host.into(), port))
}

impl Filter {
    fn authorize(&self, envoy: &mut impl EnvoyHttpFilter, candidates: Vec<SocketAddr>) -> Status {
        let route = self.route.borrow();
        let route = route
            .as_ref()
            .expect("route installed before authorization");
        let Some(selected) =
            destination::select(candidates, &route.settings.denied_cidrs, |_| true)
        else {
            return reject(envoy, 403, "agentio_egress_denied");
        };
        if !envoy.set_filter_state_typed(PIN_KEY, selected.to_string().as_bytes()) {
            return reject(envoy, 500, "agentio_egress_destination_write_failed");
        }
        Status::Continue
    }
}

impl RouteConfig {
    fn target(&self, envoy: &impl EnvoyHttpFilter) -> Result<(String, u16), &'static str> {
        if self.dns.is_none() {
            let value = envoy
                .get_filter_state_typed(ORIGINAL_KEY)
                .ok_or("missing original destination")?;
            let addr: SocketAddr = std::str::from_utf8(value.as_slice())
                .map_err(|_| "invalid address")?
                .parse()
                .map_err(|_| "invalid address")?;
            if addr.port() == 0 {
                return Err("zero port");
            }
            return Ok((addr.ip().to_string(), addr.port()));
        }

        if let Some(value) = envoy.get_filter_state_bytes(UPSTREAM_KEY) {
            let addr: SocketAddr = std::str::from_utf8(value.as_slice())
                .map_err(|_| "invalid upstream address")?
                .parse()
                .map_err(|_| "invalid upstream address")?;
            if addr.port() == 0 {
                return Err("zero port");
            }
            return Ok((addr.ip().to_string(), addr.port()));
        }
        if envoy
            .get_request_header_value(":method")
            .is_some_and(|v| v.as_slice() == b"CONNECT")
        {
            let original = envoy
                .get_filter_state_typed(ORIGINAL_KEY)
                .ok_or("missing proxy address")?;
            let original: SocketAddr = std::str::from_utf8(original.as_slice())
                .map_err(|_| "invalid proxy address")?
                .parse()
                .map_err(|_| "invalid proxy address")?;
            let sni = envoy
                .get_filter_state_typed(SNI_KEY)
                .ok_or("missing proxy SNI")?;
            return target(
                std::str::from_utf8(sni.as_slice()).map_err(|_| "invalid proxy SNI")?,
                original.port(),
            );
        }
        let authority = envoy
            .get_request_header_value(":authority")
            .ok_or("missing authority")?;
        target(
            std::str::from_utf8(authority.as_slice()).map_err(|_| "invalid authority")?,
            self.settings.default_port,
        )
    }
}
impl<H: EnvoyHttpFilter> HttpFilter<H> for Filter {
    fn on_request_headers(&self, envoy: &mut H, _: bool) -> Status {
        let Some(route) = envoy.get_most_specific_route_config() else {
            return reject(envoy, 403, "agentio_egress_policy_missing");
        };
        let route = route
            .downcast_ref::<Arc<RouteConfig>>()
            .expect("egress route config type")
            .clone();
        // Snapshot the accepted RDS policy once per request, including async DNS completion.
        self.route.replace(Some(route.clone()));
        let (host, port) = match route.target(envoy) {
            Ok(target) => target,
            Err(_) => return reject(envoy, 400, "agentio_egress_destination_invalid"),
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.authorize(envoy, vec![SocketAddr::new(ip, port)]);
        }
        let scheduler = envoy.new_scheduler();
        match route
            .dns
            .as_ref()
            .expect("hostname requires dynamic forwarding")
            .resolve(host, port, move || scheduler.commit(0))
        {
            dns::Lookup::Ready(Ok(candidates)) => self.authorize(envoy, candidates),
            dns::Lookup::Ready(Err(_)) => reject(envoy, 503, "agentio_egress_dns_failed"),
            dns::Lookup::Pending(pending) => {
                self.resolution.replace(Some(pending));
                Status::StopAllIterationAndWatermark
            }
        }
    }
    fn on_scheduled(&self, envoy: &mut H, _: u64) {
        let result = self
            .resolution
            .borrow_mut()
            .take()
            .expect("DNS query scheduled")
            .finish();
        match result {
            Ok(candidates) => {
                if self.authorize(envoy, candidates) == Status::Continue {
                    envoy.continue_decoding();
                }
            }
            Err(_) => {
                reject(envoy, 503, "agentio_egress_dns_failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoy_proxy_dynamic_modules_rust_sdk::{EnvoyBuffer, MockEnvoyHttpFilter};

    #[test]
    fn missing_route_policy_fails_closed() {
        let filter = Filter {
            route: RefCell::new(None),
            resolution: RefCell::new(None),
        };
        let mut envoy = MockEnvoyHttpFilter::new();
        envoy
            .expect_get_most_specific_route_config()
            .returning(|| None);
        envoy
            .expect_send_response()
            .withf(|code, _, _, detail| {
                *code == 403 && *detail == Some("agentio_egress_policy_missing")
            })
            .times(1)
            .return_const(());
        assert_eq!(
            filter.on_request_headers(&mut envoy, true),
            Status::StopIteration
        );
    }

    #[test]
    fn route_updates_do_not_mutate_existing_request_snapshots() {
        let allowed = new_route_config(FILTER_NAME, br#"{"mode":"ORIGINAL_DST"}"#).unwrap();
        let denied = new_route_config(
            FILTER_NAME,
            br#"{"mode":"ORIGINAL_DST","denied_cidrs":["127.0.0.0/8"]}"#,
        )
        .unwrap();
        let old = Filter {
            route: RefCell::new(Some(
                allowed.downcast_ref::<Arc<RouteConfig>>().unwrap().clone(),
            )),
            resolution: RefCell::new(None),
        };
        let current = Filter {
            route: RefCell::new(Some(
                denied.downcast_ref::<Arc<RouteConfig>>().unwrap().clone(),
            )),
            resolution: RefCell::new(None),
        };
        let mut envoy = MockEnvoyHttpFilter::new();
        envoy
            .expect_set_filter_state_typed()
            .withf(|key, value| key == PIN_KEY && value == b"127.0.0.1:80")
            .times(1)
            .return_const(true);
        envoy
            .expect_send_response()
            .withf(|code, _, _, detail| *code == 403 && *detail == Some("agentio_egress_denied"))
            .times(1)
            .return_const(());
        assert_eq!(
            current.authorize(&mut envoy, vec!["127.0.0.1:80".parse().unwrap()]),
            Status::StopIteration
        );
        assert_eq!(
            old.authorize(&mut envoy, vec!["127.0.0.1:80".parse().unwrap()]),
            Status::Continue
        );
    }

    #[test]
    fn explicit_endpoint_overrides_authority_and_default_port() {
        let mut envoy = MockEnvoyHttpFilter::new();
        envoy
            .expect_get_filter_state_bytes()
            .withf(|key| key == UPSTREAM_KEY)
            .returning(|_| Some(EnvoyBuffer::new(b"127.0.0.1:8443")));
        let route = new_route_config(FILTER_NAME, br#"{"mode":"DYNAMIC_FORWARD"}"#).unwrap();
        assert_eq!(
            route
                .downcast_ref::<Arc<RouteConfig>>()
                .unwrap()
                .target(&envoy),
            Ok(("127.0.0.1".into(), 8443))
        );
    }

    #[test]
    fn original_destination_mode_ignores_the_tunnel_target() {
        let mut envoy = MockEnvoyHttpFilter::new();
        envoy
            .expect_get_filter_state_typed()
            .withf(|key| key == ORIGINAL_KEY)
            .returning(|_| Some(EnvoyBuffer::new(b"192.0.2.1:8443")));
        let route = new_route_config(FILTER_NAME, br#"{"mode":"ORIGINAL_DST"}"#).unwrap();
        assert_eq!(
            route
                .downcast_ref::<Arc<RouteConfig>>()
                .unwrap()
                .target(&envoy),
            Ok(("192.0.2.1".into(), 8443))
        );
    }

    #[test]
    fn connect_uses_outer_proxy_name_and_original_port() {
        let mut envoy = MockEnvoyHttpFilter::new();
        envoy
            .expect_get_filter_state_bytes()
            .withf(|key| key == UPSTREAM_KEY)
            .returning(|_| None);
        envoy
            .expect_get_filter_state_typed()
            .returning(|key| match key {
                ORIGINAL_KEY => Some(EnvoyBuffer::new(b"192.0.2.1:8443")),
                SNI_KEY => Some(EnvoyBuffer::new(b"proxy.test")),
                _ => panic!("unexpected filter state"),
            });
        envoy
            .expect_get_request_header_value()
            .withf(|key| key == ":method")
            .returning(|_| Some(EnvoyBuffer::new(b"CONNECT")));
        let route = new_route_config(FILTER_NAME, br#"{"mode":"DYNAMIC_FORWARD"}"#).unwrap();
        assert_eq!(
            route
                .downcast_ref::<Arc<RouteConfig>>()
                .unwrap()
                .target(&envoy),
            Ok(("proxy.test".into(), 8443))
        );
    }

    #[test]
    fn invalid_route_configuration_is_rejected() {
        for value in [
            br#"{"mode":"TYPO"}"#.as_slice(),
            br#"{"mode":"DYNAMIC_FORWARD","default_port":0}"#,
            br#"{"mode":"ORIGINAL_DST","denied_cidrs":["bad"]}"#,
        ] {
            assert!(new_route_config(FILTER_NAME, value).is_none());
        }
    }

    #[test]
    fn parses_authorities_and_override_endpoints() {
        for (input, host, port) in [
            ("example.test", "example.test", 443),
            ("example.test:8080", "example.test", 8080),
            ("[2001:db8::1]:8443", "2001:db8::1", 8443),
            ("[::1]", "::1", 443),
            ("192.0.2.1", "192.0.2.1", 443),
        ] {
            assert_eq!(target(input, 443), Ok((host.into(), port)));
        }
        for invalid in [
            "",
            "example.test:0",
            "example.test:65536",
            "example.test:abc",
            "http://example.test",
            "user@example.test",
            "[::1]:0",
            "example.test/path",
        ] {
            assert!(target(invalid, 80).is_err(), "{invalid}");
        }
    }
}
