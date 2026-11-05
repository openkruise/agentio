// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

mod policy;

use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyListenerFilter, EnvoyListenerFilterConfig, ListenerFilter, ListenerFilterConfig,
    abi::envoy_dynamic_module_type_on_listener_filter_status as Status,
    declare_listener_filter_init_functions, envoy_log_debug,
};
use policy::{Action, Policy};

const FILTER_NAME: &str = "envoy_agentio_sni_policy";
const POLICY_KEY: &[u8] = b"agentio.sni.policy";
const ACTION_KEY: &[u8] = b"agentio.tls.action";

struct Config;
struct Filter;

impl<ELF: EnvoyListenerFilter> ListenerFilterConfig<ELF> for Config {
    fn new_listener_filter(&self, _: &mut ELF) -> Box<dyn ListenerFilter<ELF>> {
        Box::new(Filter)
    }
}

fn decide(envoy: &impl EnvoyListenerFilter) -> Action {
    match envoy
        .get_detected_transport_protocol()
        .as_ref()
        .map(|b| b.as_slice())
    {
        None | Some(b"raw_buffer") => return Action::Cleartext,
        Some(b"tls") => {}
        _ => return Action::Deny,
    }
    let Some(bytes) = envoy.get_filter_state_bytes(POLICY_KEY) else {
        return Action::Deny;
    };
    let policy = match serde_json::from_slice::<Policy>(bytes.as_slice()) {
        Ok(policy) => policy,
        Err(error) => {
            envoy_log_debug!("invalid agentio SNI policy: {}", error);
            return Action::Deny;
        }
    };
    let sni = envoy.get_requested_server_name();
    let name = match sni
        .as_ref()
        .map(|b| std::str::from_utf8(b.as_slice()))
        .transpose()
    {
        Ok(name) => name,
        Err(_) => return Action::Deny,
    };
    // original_dst restores the CONNECT destination before this filter runs.
    let port = envoy.get_local_address().map(|(_, port)| port);
    policy.evaluate(name, port)
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
        let action = decide(envoy);
        if !envoy.set_filter_state_bytes(ACTION_KEY, action.as_bytes()) {
            envoy.close_socket(Some("agentio_sni_action_write_failed"));
            return Status::StopIteration;
        }
        Status::Continue
    }
}

declare_listener_filter_init_functions!(init, new_config);

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

    const POLICY: &[u8] =
        br#"{"rules":[{"match":{"sni":["*.example.com"]},"action":"SNI_ACTION_TLS_TERMINATION"}]}"#;

    fn tls_filter(
        policy: Option<&'static [u8]>,
        sni: Option<&'static [u8]>,
    ) -> MockEnvoyListenerFilter {
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
            .withf(|key| key == POLICY_KEY)
            .returning(move |_| policy.map(EnvoyBuffer::new));
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
                Action::Passthrough,
            ),
            (Some(POLICY), None, Action::Passthrough),
            (
                Some(br#"{"rules":[{"match":{"sni":["*"],"ports":[8443]},"action":"SNI_ACTION_DENY"}]}"#.as_slice()),
                Some(b"api.example.com".as_slice()),
                Action::Deny,
            ),
            (
                Some(br#"{"rules":[{"match":{"sni":["*"],"ports":[443]},"action":"SNI_ACTION_DENY"}]}"#.as_slice()),
                Some(b"api.example.com".as_slice()),
                Action::Passthrough,
            ),
            (
                Some(POLICY),
                Some(b"\xff.example.com".as_slice()),
                Action::Deny,
            ),
            (
                Some(b"{}".as_slice()),
                Some(b"api.example.com".as_slice()),
                Action::Passthrough,
            ),
            (
                Some(b"not-json".as_slice()),
                Some(b"api.example.com".as_slice()),
                Action::Deny,
            ),
            (None, Some(b"api.example.com".as_slice()), Action::Deny),
        ] {
            let mut envoy = tls_filter(policy, name);
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
            envoy
                .expect_set_filter_state_bytes()
                .withf(move |k, v| k == ACTION_KEY && v == action.as_bytes())
                .times(1)
                .return_const(true);
            assert_eq!(Filter.on_accept(&mut envoy), Status::Continue);
        }
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
