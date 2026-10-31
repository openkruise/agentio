// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

mod bandwidth;
mod concurrency;
mod descriptor;
mod streams;

use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, EnvoyHttpFilterConfig, HttpFilterConfig, declare_init_functions,
    envoy_log_error,
};

declare_init_functions!(init, new_config);

fn init() -> bool {
    true
}

fn new_config<C: EnvoyHttpFilterConfig, E: EnvoyHttpFilter>(
    envoy: &mut C,
    name: &str,
    bytes: &[u8],
) -> Option<Box<dyn HttpFilterConfig<E>>> {
    let result: Result<Box<dyn HttpFilterConfig<E>>, String> = match name {
        "envoy_agentio_bandwidth" => bandwidth::FilterConfig::parse(bytes)
            .map(|config| Box::new(config) as Box<dyn HttpFilterConfig<E>>),
        "envoy_agentio_connect_concurrency" => concurrency::FilterConfig::parse(bytes)
            .map(|config| Box::new(config) as Box<dyn HttpFilterConfig<E>>),
        _ => return None,
    };
    match result {
        Ok(config) => {
            // Publish on the main dispatcher after construction has returned. Rejected
            // candidates are destroyed before this weakly-owned callback can run.
            envoy.new_scheduler().commit(0);
            Some(config)
        }
        Err(error) => {
            envoy_log_error!("{} config rejected: {}", name, error);
            None
        }
    }
}
