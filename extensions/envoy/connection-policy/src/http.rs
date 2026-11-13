// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::store::{JSON_KEY, SharedPolicy};
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, EnvoyHttpFilterConfig, HttpFilter, HttpFilterConfig,
    abi::envoy_dynamic_module_type_on_http_filter_request_headers_status as Status,
};

use std::cell::RefCell;

const FILTER_NAME: &str = "envoy_agentio_connection_policy_store";
struct Config;
struct Filter {
    policy: RefCell<Option<SharedPolicy>>,
}

impl<H: EnvoyHttpFilter> HttpFilterConfig<H> for Config {
    fn new_http_filter(&self, _: &mut H) -> Box<dyn HttpFilter<H>> {
        Box::new(Filter {
            policy: RefCell::new(None),
        })
    }
}

impl<H: EnvoyHttpFilter> HttpFilter<H> for Filter {
    fn on_request_headers(&self, envoy: &mut H, _: bool) -> Status {
        let policy = match envoy.get_filter_state_bytes(JSON_KEY) {
            Some(json) => SharedPolicy::intern(json.as_slice()),
            None => Err("connection policy is missing"),
        };
        let policy = match policy {
            Ok(policy) => policy,
            Err(error) => {
                envoy.send_response(
                    403,
                    &[],
                    Some(error.as_bytes()),
                    Some("agentio_policy_unavailable"),
                );
                return Status::StopIteration;
            }
        };
        // Keep only the shared entry, not another JSON string and protobuf tree per CONNECT.
        if !envoy.set_filter_state_bytes(JSON_KEY, b"") {
            envoy.send_response(500, &[], None, Some("agentio_policy_state_write_failed"));
            return Status::StopIteration;
        }
        envoy.set_dynamic_metadata_string("agentio", "connection", "");
        envoy.set_dynamic_metadata_string(
            "agentio.connection",
            "policy_hash",
            &policy.hash().to_string(),
        );
        self.policy.replace(Some(policy));
        Status::Continue
    }
}

pub fn new_config<C: EnvoyHttpFilterConfig, H: EnvoyHttpFilter>(
    _: &mut C,
    name: &str,
    config: &[u8],
) -> Option<Box<dyn HttpFilterConfig<H>>> {
    (name == FILTER_NAME && config.is_empty())
        .then(|| Box::new(Config) as Box<dyn HttpFilterConfig<H>>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SharedPolicy;
    use envoy_proxy_dynamic_modules_rust_sdk::{EnvoyBuffer, MockEnvoyHttpFilter};

    #[test]
    fn connect_owns_the_policy_and_releases_the_unshared_input() {
        let filter = Filter {
            policy: RefCell::new(None),
        };
        let mut envoy = MockEnvoyHttpFilter::new();
        envoy
            .expect_get_filter_state_bytes()
            .withf(|key| key == JSON_KEY)
            .returning(|_| Some(EnvoyBuffer::new(br#"{"profiles":[]}"#)));
        envoy
            .expect_set_filter_state_bytes()
            .withf(|key, value| key == JSON_KEY && value.is_empty())
            .times(1)
            .return_const(true);
        envoy
            .expect_set_dynamic_metadata_string()
            .withf(|ns, key, value| ns == "agentio" && key == "connection" && value.is_empty())
            .times(1)
            .return_const(());
        envoy
            .expect_set_dynamic_metadata_string()
            .withf(|ns, key, value| {
                ns == "agentio.connection"
                    && key == "policy_hash"
                    && SharedPolicy::lookup(value.as_bytes()).is_some()
            })
            .times(1)
            .return_const(());
        assert_eq!(
            filter.on_request_headers(&mut envoy, false),
            Status::Continue
        );
        let hash = filter.policy.borrow().as_ref().unwrap().hash().to_string();
        let tcp = SharedPolicy::lookup(hash.as_bytes()).unwrap();
        drop(filter);
        assert!(SharedPolicy::lookup(hash.as_bytes()).is_some());
        drop(tcp);
        assert!(SharedPolicy::lookup(hash.as_bytes()).is_none());
    }

    #[test]
    fn missing_policy_and_failed_input_release_stop_connect() {
        for present in [false, true] {
            let filter = Filter {
                policy: RefCell::new(None),
            };
            let mut envoy = MockEnvoyHttpFilter::new();
            envoy
                .expect_get_filter_state_bytes()
                .returning(move |_| present.then(|| EnvoyBuffer::new(br#"{"profiles":[]}"#)));
            if present {
                envoy.expect_set_filter_state_bytes().return_const(false);
            }
            envoy
                .expect_send_response()
                .withf(move |status, _, _, _| *status == if present { 500 } else { 403 })
                .times(1)
                .return_const(());
            assert_eq!(
                filter.on_request_headers(&mut envoy, false),
                Status::StopIteration
            );
            assert!(filter.policy.borrow().is_none());
        }
    }
}
