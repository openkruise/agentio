// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

//! ADS transport and reconnect lifecycle. Cache and subscription state live in
//! the parent module; sending requests never blocks incoming responses.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};
use tracing::{Instrument, info, info_span, warn};

use crate::{
    metrics::ResourceType,
    view::ResourceKind,
    wire::ads::{self, Node},
};

use super::Client;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct TransportConfig {
    pub address: String,
    pub root_path: String,
    pub token_path: String,
    pub node: Node,
}

impl Client {
    async fn stream(self: &Arc<Self>, transport: &TransportConfig) -> Result<()> {
        let roots = tokio::fs::read(&transport.root_path)
            .await
            .with_context(|| format!("read ADS roots {}", transport.root_path))?;
        let token = tokio::fs::read_to_string(&transport.token_path)
            .await
            .with_context(|| format!("read ADS token {}", transport.token_path))?;
        if token.trim().is_empty() {
            bail!("empty ADS token");
        }
        let channel = Endpoint::from_shared(format!("https://{}", transport.address))
            .context("invalid ADS address")?
            .connect_timeout(CONNECT_TIMEOUT)
            .tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(roots)))
            .context("configure ADS TLS")?
            .connect()
            .await
            .context("connect to ADS server")?;
        let client = self.clone();
        let node = transport.node.clone();
        let cancel = CancellationToken::new();
        let _guard = cancel.clone().drop_guard();
        let outbound = async_stream::stream! {
            // Construct retained subscriptions when the request body is polled,
            // instead of preparing them before initiating the RPC.
            let mut sent_generations = Default::default();
            for request in client.initial(&node, &mut sent_generations) {
                yield request;
            }
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = client.wake.notified() => {},
                }
                for request in client.outgoing(&mut sent_generations) {
                    yield request;
                }
            }
        };
        let mut request = tonic::Request::new(outbound);
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", token.trim())
                .parse()
                .context("invalid ADS token metadata")?,
        );
        let mut responses =
            ads::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient::new(
                channel,
            )
            // Match Go xdsclient: a large batch of pending demands may arrive
            // in one delta, well above tonic's default 4 MiB.
            .max_decoding_message_size(i32::MAX as usize)
            .delta_aggregated_resources(request)
            .await
            .context("establish ADS stream")?
            .into_inner();
        self.metrics.connected.set(1);
        info!("ADS stream established");
        while let Some(response) = responses.message().await.context("receive ADS response")? {
            let Some(kind) = ResourceKind::from_type_url(&response.type_url) else {
                bail!("unexpected discovery type {}", response.type_url);
            };
            let error = self.apply(kind, &response).err().map(|error| {
                self.metrics
                    .nacks
                    .get_or_create(&ResourceType {
                        resource_type: kind.type_url(),
                    })
                    .inc();
                warn!(
                    error = %format_args!("{error:#}"),
                    resource_type = %response.type_url,
                    nonce = %response.nonce,
                    "rejected ADS response"
                );
                ads::Status {
                    code: 3,
                    message: format!("{error:#}"),
                }
            });
            self.state.lock().unwrap().types[kind.index()].ack = Some((response.nonce, error));
            self.wake.notify_one();
        }
        bail!("ADS stream closed")
    }

    pub async fn run(self: Arc<Self>, transport: TransportConfig, stop: CancellationToken) {
        let mut delay = INITIAL_BACKOFF;
        let mut connection_id = 0_u64;
        let mut retry = false;
        loop {
            if stop.is_cancelled() {
                break;
            }
            if retry {
                self.metrics.reconnects.inc();
            }
            retry = true;
            connection_id += 1;
            let span = info_span!("xds", connection_id, address = %transport.address);
            let started = Instant::now();
            let result = tokio::select! {
                _ = stop.cancelled() => break,
                result = self.stream(&transport).instrument(span.clone()) => result,
            };
            let received = self
                .state
                .lock()
                .unwrap()
                .types
                .iter()
                .any(|type_state| type_state.synced);
            self.reset();
            if received && started.elapsed() > Duration::from_secs(1) {
                delay = INITIAL_BACKOFF;
            }
            if let Err(error) = result {
                warn!(
                    parent: &span,
                    error = %format_args!("{error:#}"),
                    retry_ms = delay.as_millis(),
                    "ADS disconnected"
                );
            }
            let jitter =
                Duration::from_secs_f64(delay.as_secs_f64() * rand::random_range(0.0..0.2));
            tokio::select! {
                _ = stop.cancelled() => break,
                _ = tokio::time::sleep(delay + jitter) => {},
            }
            delay = (delay * 2).min(MAX_BACKOFF);
        }
        self.reset();
    }
}
