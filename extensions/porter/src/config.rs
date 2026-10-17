// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, env, net::SocketAddr, time::Duration};

use agentio_porter::{
    discovery::{CacheConfig, TransportConfig},
    view,
    wire::ads::Node,
};
use anyhow::{Context, Result, bail};
use clap::Parser;

use crate::telemetry;

pub struct Config {
    pub grpc_address: SocketAddr,
    pub health_address: SocketAddr,
    pub metrics_address: SocketAddr,
    pub transport: TransportConfig,
    pub cache: CacheConfig,
    pub cluster_id: String,
    pub request_timeout: Duration,
    pub worker_threads: usize,
    pub logging: telemetry::Config,
}

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Connection identity and policy discovery for Agentio gateways"
)]
struct Args {
    #[arg(long, default_value_t = 9002)]
    grpc_port: u16,
    #[arg(long, default_value_t = 9003)]
    grpc_health_port: u16,
    #[arg(long, default_value_t = 9004)]
    metrics_port: u16,
    #[arg(long)]
    xds_address: String,
    #[arg(long, default_value = "")]
    xds_node_id: String,
    #[arg(long, default_value = "")]
    domain: String,
    #[arg(long, default_value = "/var/run/secrets/agentio/root-cert.pem")]
    xds_root_path: String,
    #[arg(long, default_value = "/var/run/secrets/tokens/agentio-token")]
    xds_token_path: String,
    #[arg(long, default_value = "Kubernetes")]
    cluster_id: String,
    #[arg(long, default_value = "4s", value_parser = duration)]
    request_timeout: Duration,
    #[arg(long, default_value = "1m", value_parser = duration)]
    xds_cache_idle_ttl: Duration,
    #[arg(long, default_value_t = 10000)]
    xds_cache_max_entries: usize,
}

fn duration(value: &str) -> Result<Duration, String> {
    if value == "0" {
        Ok(Duration::ZERO)
    } else {
        humantime::parse_duration(value).map_err(|error| error.to_string())
    }
}

pub fn parse() -> Result<Config> {
    construct(Args::parse(), |name| match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error).with_context(|| format!("invalid {name}")),
    })
}

fn construct(args: Args, read_env: impl Fn(&str) -> Result<Option<String>>) -> Result<Config> {
    if args.request_timeout.is_zero() {
        bail!("--request-timeout must be positive");
    }
    if args.cluster_id.is_empty() {
        bail!("--cluster-id must not be empty");
    }
    let name = read_env("POD_NAME")?.context("POD_NAME is required")?;
    let namespace = read_env("POD_NAMESPACE")?.context("POD_NAMESPACE is required")?;
    if name.is_empty() || namespace.is_empty() {
        bail!("POD_NAME and POD_NAMESPACE must not be empty");
    }
    let worker_threads = match read_env("TOKIO_WORKER_THREADS")? {
        Some(value) => value
            .parse::<usize>()
            .context("invalid TOKIO_WORKER_THREADS: expected a positive integer")?,
        None => std::thread::available_parallelism()
            .context("determine available worker threads")?
            .get(),
    };
    if worker_threads == 0 {
        bail!("TOKIO_WORKER_THREADS must be positive");
    }
    let logging = telemetry::Config::new(
        read_env("AGENTIO_LOG_LEVEL")?.as_deref().unwrap_or("info"),
        read_env("AGENTIO_LOG_FORMAT")?.as_deref().unwrap_or("text"),
    )?;
    let domain = if args.domain.is_empty() {
        format!("{namespace}.svc.cluster.local")
    } else {
        args.domain
    };
    let node_id = if args.xds_node_id.is_empty() {
        let ip = read_env("POD_IP")?.unwrap_or_default();
        format!("agentio-porter~{ip}~{name}.{namespace}~{domain}")
    } else {
        args.xds_node_id
    };
    let node = Node {
        id: node_id,
        metadata: Some(prost_types::Struct {
            fields: BTreeMap::from([
                ("POD_NAME".into(), view::string(name)),
                ("POD_NAMESPACE".into(), view::string(namespace)),
                (
                    "POD_UID".into(),
                    view::string(read_env("POD_UID")?.unwrap_or_default()),
                ),
            ]),
        }),
    };
    Ok(Config {
        grpc_address: SocketAddr::from(([127, 0, 0, 1], args.grpc_port)),
        health_address: SocketAddr::from(([0, 0, 0, 0], args.grpc_health_port)),
        metrics_address: SocketAddr::from(([0, 0, 0, 0], args.metrics_port)),
        transport: TransportConfig {
            address: args.xds_address,
            root_path: args.xds_root_path,
            token_path: args.xds_token_path,
            node,
        },
        cache: CacheConfig {
            idle_ttl: args.xds_cache_idle_ttl,
            max_entries: args.xds_cache_max_entries,
        },
        cluster_id: args.cluster_id,
        request_timeout: args.request_timeout,
        worker_threads,
        logging,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(arguments: &[&str], overrides: &[(&str, &str)]) -> Result<Config> {
        let args = Args::try_parse_from(
            ["porter", "--xds-address", "control-plane:15012"]
                .into_iter()
                .chain(arguments.iter().copied()),
        )?;
        let mut environment = BTreeMap::from([
            ("POD_NAME", "gateway"),
            ("POD_NAMESPACE", "agentio"),
            ("POD_IP", "10.0.0.1"),
            ("TOKIO_WORKER_THREADS", "2"),
        ]);
        environment.extend(overrides.iter().copied());
        construct(args, |name| {
            Ok(environment.get(name).map(|value| value.to_string()))
        })
    }

    #[test]
    fn resolves_node_identity_and_cache_defaults() {
        let config = config(&[], &[]).unwrap();
        assert_eq!(
            config.transport.node.id,
            "agentio-porter~10.0.0.1~gateway.agentio~agentio.svc.cluster.local"
        );
        assert_eq!(config.cache.idle_ttl, Duration::from_secs(60));
        assert_eq!(config.cache.max_entries, 10_000);
        assert_eq!(config.worker_threads, 2);
        assert_eq!(config.grpc_address.to_string(), "127.0.0.1:9002");
    }

    #[test]
    fn preserves_explicit_node_id_and_disabled_cache_limits() {
        let config = config(
            &[
                "--xds-node-id",
                "custom-node",
                "--xds-cache-idle-ttl",
                "0",
                "--xds-cache-max-entries",
                "0",
            ],
            &[],
        )
        .unwrap();
        assert_eq!(config.transport.node.id, "custom-node");
        assert!(config.cache.idle_ttl.is_zero());
        assert_eq!(config.cache.max_entries, 0);
    }

    #[test]
    fn reports_invalid_configuration_source() {
        for (arguments, overrides, expected) in [
            (vec!["--request-timeout", "0"], vec![], "--request-timeout"),
            (vec!["--cluster-id", ""], vec![], "--cluster-id"),
            (
                vec![],
                vec![("TOKIO_WORKER_THREADS", "many")],
                "TOKIO_WORKER_THREADS",
            ),
            (
                vec![],
                vec![("TOKIO_WORKER_THREADS", "0")],
                "TOKIO_WORKER_THREADS",
            ),
            (vec![], vec![("POD_NAMESPACE", "")], "POD_NAMESPACE"),
            (
                vec![],
                vec![("AGENTIO_LOG_FORMAT", "yaml")],
                "AGENTIO_LOG_FORMAT",
            ),
        ] {
            let error = config(&arguments, &overrides).err().unwrap();
            assert!(error.to_string().contains(expected), "{error:#}");
        }
    }
}
