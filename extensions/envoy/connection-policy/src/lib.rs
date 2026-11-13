// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

mod connection;
mod dns;
mod http;
mod network;
mod policy;
mod store;
mod tcp;

use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyListenerFilter, EnvoyListenerFilterConfig, ListenerFilter, ListenerFilterConfig,
    abi::envoy_dynamic_module_type_on_listener_filter_status as Status, declare_all_init_functions,
    envoy_log_debug,
};
use policy::Action;

const FILTER_NAME: &str = "envoy_agentio_sni_policy";
const ACTION_KEY: &[u8] = b"agentio.tls.action";
const DENIAL_REASON_KEY: &[u8] = b"agentio.egress.denial_reason";

struct Config;
struct Filter;

impl<ELF: EnvoyListenerFilter> ListenerFilterConfig<ELF> for Config {
    fn new_listener_filter(&self, _: &mut ELF) -> Box<dyn ListenerFilter<ELF>> {
        Box::new(Filter)
    }
}

fn decide(envoy: &mut impl EnvoyListenerFilter) -> Result<Action, &'static str> {
    match envoy
        .get_detected_transport_protocol()
        .as_ref()
        .map(|b| b.as_slice())
    {
        None | Some(b"raw_buffer") => return Ok(Action::Cleartext),
        Some(b"tls") => {}
        _ => return Err("connection_protocol_unsupported"),
    }
    let Some(bytes) = envoy.get_filter_state_bytes(store::HASH_KEY) else {
        return Err("connection_policy_missing");
    };
    let Some(shared) = store::SharedPolicy::lookup(bytes.as_slice()) else {
        return Err("connection_policy_unavailable");
    };
    let policy = match shared.policy() {
        Ok(policy) => policy,
        Err(error) => {
            envoy_log_debug!("invalid connection policy: {}", error);
            return Err("connection_policy_invalid");
        }
    };
    let Some((ip, port)) = envoy.get_local_address() else {
        return Err("connection_destination_invalid");
    };
    let target = match ip
        .parse::<std::net::IpAddr>()
        .ok()
        .zip(u16::try_from(port).ok())
    {
        Some((ip, port)) if port > 0 => std::net::SocketAddr::new(ip.to_canonical(), port),
        _ => return Err("connection_destination_invalid"),
    };
    let sni = envoy.get_requested_server_name();
    let name = match sni
        .as_ref()
        .map(|b| std::str::from_utf8(b.as_slice()))
        .transpose()
    {
        Ok(name) => name,
        Err(_) => return Err("sni_invalid"),
    };
    let (action, start) = policy.evaluate_sni(name, target)?;
    if let Some(start) = start {
        let start = start.to_owned();
        if !envoy.set_filter_state_bytes(connection::START_KEY, start.as_bytes()) {
            return Err("policy_continuation_write_failed");
        }
    }
    Ok(action)
}

impl<ELF: EnvoyListenerFilter> ListenerFilter<ELF> for Filter {
    fn on_accept(&mut self, envoy: &mut ELF) -> Status {
        // The old CONNECT action capture must be removed on this path. The SDK
        // setter does not report attempts to overwrite a read-only state object.
        if envoy.get_filter_state_bytes(ACTION_KEY).is_some() {
            envoy.close_socket(Some("agentio_sni_action_already_set"));
            return Status::StopIteration;
        }
        // Runs once, after Envoy's inspectors. No buffering or ClientHello parser.
        let action = match decide(envoy) {
            Ok(action) => action,
            Err(reason) => {
                if !envoy.set_filter_state_bytes(DENIAL_REASON_KEY, reason.as_bytes()) {
                    envoy.close_socket(Some("agentio_denial_reason_write_failed"));
                    return Status::StopIteration;
                }
                Action::Deny
            }
        };
        if !envoy.set_filter_state_bytes(ACTION_KEY, action.as_bytes()) {
            envoy.close_socket(Some("agentio_sni_action_write_failed"));
            return Status::StopIteration;
        }
        Status::Continue
    }
}

declare_all_init_functions!(init, http: http::new_config, listener: new_config, network: network::new_config);

fn init() -> bool {
    true
}

fn new_config<EC: EnvoyListenerFilterConfig, ELF: EnvoyListenerFilter>(
    _: &mut EC,
    name: &str,
    config: &[u8],
) -> Option<Box<dyn ListenerFilterConfig<ELF>>> {
    (name == FILTER_NAME && config.is_empty())
        .then(|| Box::new(Config) as Box<dyn ListenerFilterConfig<ELF>>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoy_proxy_dynamic_modules_rust_sdk::{
        EnvoyBuffer, MockEnvoyListenerFilter, MockEnvoyListenerFilterConfig,
    };

    const POLICY: &[u8] = br#"{"profiles":[{"uid":"profile","sniPolicy":{"rules":[{"match":{"sni":["*.example.com"]},"action":"SNI_ACTION_TLS_TERMINATION"}]}}]}"#;

    fn tls_filter(
        policy: Option<&'static [u8]>,
        sni: Option<&'static [u8]>,
    ) -> MockEnvoyListenerFilter {
        let shared = policy.map(|p| {
            let owner = store::SharedPolicy::intern(p).unwrap();
            let hash = owner.hash().to_string();
            (owner, hash)
        });
        let mut envoy = MockEnvoyListenerFilter::new();
        envoy
            .expect_get_filter_state_bytes()
            .withf(|key| key == ACTION_KEY)
            .times(1)
            .returning(|_| None);
        envoy
            .expect_get_detected_transport_protocol()
            .returning(|| Some(EnvoyBuffer::new(b"tls")));
        envoy
            .expect_get_filter_state_bytes()
            .withf(|key| key == store::HASH_KEY)
            .returning_st(move |_| {
                shared
                    .as_ref()
                    .map(|(_, hash)| EnvoyBuffer::new(hash.as_bytes()))
            });
        envoy
            .expect_set_filter_state_bytes()
            .withf(|key, value| key == connection::START_KEY && value == b"profile")
            .return_const(true);
        envoy
            .expect_get_requested_server_name()
            .returning(move || sni.map(EnvoyBuffer::new));
        envoy
            .expect_get_local_address()
            .returning(|| Some(("192.0.2.1".into(), 8443)));
        envoy
    }

    #[test]
    fn callback_uses_inspector_sni_and_canonical_policy() {
        for (policy, name, want) in [
            (
                Some(POLICY),
                Some(b"A.B.EXAMPLE.COM.".as_slice()),
                Action::Terminate,
            ),
            (
                Some(POLICY),
                Some(b"example.org".as_slice()),
                Action::Fallthrough,
            ),
            (Some(POLICY), None, Action::Fallthrough),
            (
                Some(br#"{"profiles":[{"uid":"profile","sniPolicy":{"rules":[{"match":{"sni":["*"],"ports":[8443]},"action":"SNI_ACTION_DENY"}]}}]}"#.as_slice()),
                Some(b"api.example.com".as_slice()),
                Action::Deny,
            ),
            (
                Some(br#"{"profiles":[{"uid":"profile","sniPolicy":{"rules":[{"match":{"sni":["*"],"ports":[443]},"action":"SNI_ACTION_DENY"}]}}]}"#.as_slice()),
                Some(b"api.example.com".as_slice()),
                Action::Fallthrough,
            ),
            (
                Some(POLICY),
                Some(b"\xff.example.com".as_slice()),
                Action::Deny,
            ),
            (
                Some(br#"{"profiles":[]}"#.as_slice()),
                Some(b"api.example.com".as_slice()),
                Action::Fallthrough,
            ),
            (
                Some(br#"{"rules":[]}"#.as_slice()),
                Some(b"api.example.com".as_slice()),
                Action::Deny,
            ),
            (
                Some(b"not-json".as_slice()),
                Some(b"api.example.com".as_slice()),
                Action::Deny,
            ),
            (None, Some(b"api.example.com".as_slice()), Action::Deny),
        ] {
            let mut envoy = tls_filter(policy, name);
            if want == Action::Deny {
                envoy
                    .expect_set_filter_state_bytes()
                    .withf(|key, _| key == DENIAL_REASON_KEY)
                    .times(1)
                    .return_const(true);
            }
            envoy
                .expect_set_filter_state_bytes()
                .withf(move |k, v| k == ACTION_KEY && v == want.as_bytes())
                .times(1)
                .return_const(true);
            assert_eq!(Filter.on_accept(&mut envoy), Status::Continue);
            // Data callbacks never reread policy or rewrite the action.
            assert_eq!(Filter.on_data(&mut envoy, 10), Status::Continue);
        }
    }

    #[test]
    fn old_sni_policy_cannot_replace_missing_connection_policy() {
        let mut envoy = tls_filter(None, Some(b"api.example.com"));
        envoy
            .expect_get_filter_state_bytes()
            .withf(|key| key == b"agentio.sni.policy")
            .returning(|_| Some(EnvoyBuffer::new(br#"{"rules":[]}"#)));
        envoy
            .expect_set_filter_state_bytes()
            .withf(|key, value| key == DENIAL_REASON_KEY && value == b"connection_policy_missing")
            .times(1)
            .return_const(true);
        envoy
            .expect_set_filter_state_bytes()
            .withf(|key, value| key == ACTION_KEY && value == Action::Deny.as_bytes())
            .times(1)
            .return_const(true);
        assert_eq!(Filter.on_accept(&mut envoy), Status::Continue);
    }

    #[test]
    fn non_tls_does_not_read_policy() {
        for (protocol, action) in [
            (None, Action::Cleartext),
            (Some(b"raw_buffer".as_slice()), Action::Cleartext),
            (Some(b"quic".as_slice()), Action::Deny),
        ] {
            let mut envoy = MockEnvoyListenerFilter::new();
            envoy
                .expect_get_filter_state_bytes()
                .withf(|key| key == ACTION_KEY)
                .times(1)
                .returning(|_| None);
            envoy
                .expect_get_detected_transport_protocol()
                .returning(move || protocol.map(EnvoyBuffer::new));
            if action == Action::Deny {
                envoy
                    .expect_set_filter_state_bytes()
                    .withf(|key, value| {
                        key == DENIAL_REASON_KEY && value == b"connection_protocol_unsupported"
                    })
                    .times(1)
                    .return_const(true);
            }
            envoy
                .expect_set_filter_state_bytes()
                .withf(move |k, v| k == ACTION_KEY && v == action.as_bytes())
                .times(1)
                .return_const(true);
            assert_eq!(Filter.on_accept(&mut envoy), Status::Continue);
        }
    }

    #[test]
    fn denial_reason_distinguishes_sni_tcp_and_policy_errors() {
        const RULES: &[u8] = br#"{"profiles":[{"uid":"profile","sniPolicy":{"rules":[{"match":{"sni":["baidu.com"]},"action":"SNI_ACTION_DENY"}]},"tcpPolicy":{"rules":[{"name":"reject-other-tcp","match":[{"cidrs":["0.0.0.0/0","::/0"]}],"action":"TCP_ACTION_DENY"}]}}]}"#;
        for (policy, name, reason) in [
            (Some(RULES), b"baidu.com".as_slice(), "sni_policy_denied"),
            (Some(RULES), b"google.com".as_slice(), "tcp_policy_denied"),
            (None, b"google.com".as_slice(), "connection_policy_missing"),
            (
                Some(b"invalid".as_slice()),
                b"google.com".as_slice(),
                "connection_policy_invalid",
            ),
            (Some(RULES), b"\xff.test".as_slice(), "sni_invalid"),
        ] {
            let mut envoy = tls_filter(policy, Some(name));
            envoy
                .expect_set_filter_state_bytes()
                .withf(move |key, value| key == DENIAL_REASON_KEY && value == reason.as_bytes())
                .times(1)
                .return_const(true);
            envoy
                .expect_set_filter_state_bytes()
                .withf(|key, value| key == ACTION_KEY && value == b"deny")
                .times(1)
                .return_const(true);
            assert_eq!(Filter.on_accept(&mut envoy), Status::Continue);
        }
    }

    #[test]
    fn failed_denial_reason_write_closes_connection() {
        let mut envoy = tls_filter(None, Some(b"google.com"));
        envoy
            .expect_set_filter_state_bytes()
            .withf(|key, _| key == DENIAL_REASON_KEY)
            .times(1)
            .return_const(false);
        envoy
            .expect_close_socket()
            .withf(|reason| *reason == Some("agentio_denial_reason_write_failed"))
            .times(1)
            .return_const(());
        assert_eq!(Filter.on_accept(&mut envoy), Status::StopIteration);
    }

    #[test]
    fn failed_action_write_closes_connection() {
        let mut envoy = tls_filter(Some(POLICY), Some(b"api.example.com"));
        envoy.expect_set_filter_state_bytes().return_const(false);
        envoy
            .expect_close_socket()
            .withf(|reason| *reason == Some("agentio_sni_action_write_failed"))
            .times(1)
            .return_const(());
        assert_eq!(Filter.on_accept(&mut envoy), Status::StopIteration);
    }

    #[test]
    fn old_connect_action_cannot_override_the_module() {
        let mut envoy = MockEnvoyListenerFilter::new();
        envoy
            .expect_get_filter_state_bytes()
            .withf(|key| key == ACTION_KEY)
            .times(1)
            .returning(|_| Some(EnvoyBuffer::new(b"passthrough")));
        envoy
            .expect_close_socket()
            .withf(|reason| *reason == Some("agentio_sni_action_already_set"))
            .times(1)
            .return_const(());
        assert_eq!(Filter.on_accept(&mut envoy), Status::StopIteration);
    }

    #[test]
    fn config_rejects_unknown_name_and_unused_config() {
        let mut envoy = MockEnvoyListenerFilterConfig::new();
        assert!(new_config::<_, MockEnvoyListenerFilter>(&mut envoy, FILTER_NAME, b"").is_some());
        assert!(new_config::<_, MockEnvoyListenerFilter>(&mut envoy, "typo", b"").is_none());
        assert!(new_config::<_, MockEnvoyListenerFilter>(&mut envoy, FILTER_NAME, b"{}").is_none());
    }
}
