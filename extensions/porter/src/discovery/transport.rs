// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

//! ADS transport and reconnect lifecycle. Cache and subscription state live in
//! the parent module; sending requests never blocks incoming responses.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};
use tracing::{Instrument, debug, info, info_span, warn};

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

// Match gateway-agent's logging policy without changing reconnect behavior.
fn expected_ads_closure(error: &anyhow::Error) -> bool {
    let Some(status) = error.downcast_ref::<tonic::Status>() else {
        return false;
    };
    if status.code() == tonic::Code::Cancelled {
        return true;
    }
    let message = status.message();
    // An abnormal GOAWAY takes precedence over an accompanying EOF or close.
    if let Some((_, goaway)) = message.split_once("received prior goaway: code: ") {
        return goaway.split(',').next() == Some("NO_ERROR");
    }
    let h2_message = message
        .strip_prefix("h2 protocol error: ")
        .unwrap_or(message);
    if let Some(reason) = h2_message
        .strip_prefix("connection error received: ")
        .or_else(|| h2_message.strip_prefix("stream error received: "))
        .or_else(|| h2_message.strip_prefix("protocol error: "))
    {
        return reason.split(" (").next() == Some("not a result of an error");
    }
    if status.code() == tonic::Code::Unavailable
        && [
            "client disconnected",
            "error reading from server: EOF",
            "transport is closing",
        ]
        .iter()
        .any(|closed| message.contains(closed))
    {
        return true;
    }
    message.contains("stream terminated by RST_STREAM with error code: NO_ERROR")
}

impl Client {
    async fn stream(
        self: &Arc<Self>,
        transport: &TransportConfig,
        received: &mut bool,
    ) -> Result<()> {
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
            // The RPC polls this body before confirming the stream. Only pending
            // demands may be sent while the old cache is still in its grace period.
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
        self.established();
        info!("ADS stream established");
        while let Some(response) = responses.message().await.context("receive ADS response")? {
            let Some(kind) = ResourceKind::from_type_url(&response.type_url) else {
                bail!("unexpected discovery type {}", response.type_url);
            };
            let applied = self.apply(kind, &response);
            *received |= applied.is_ok();
            let error = applied.err().map(|error| {
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
        Ok(())
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
            // Cached sync state may belong to the previous stream during grace.
            // Only accepted responses on this attempt can reset its backoff.
            let mut received = false;
            let result = tokio::select! {
                _ = stop.cancelled() => break,
                result = self.stream(&transport, &mut received).instrument(span.clone()) => result,
            };
            self.disconnected();
            if received && started.elapsed() > Duration::from_secs(1) {
                delay = INITIAL_BACKOFF;
            }
            match result {
                Ok(()) => debug!(
                    parent: &span,
                    retry_ms = delay.as_millis() as u64,
                    "ADS stream closed"
                ),
                Err(error) if expected_ads_closure(&error) => debug!(
                    parent: &span,
                    error = %format_args!("{error:#}"),
                    retry_ms = delay.as_millis() as u64,
                    "ADS stream closed"
                ),
                Err(error) => warn!(
                    parent: &span,
                    error = %format_args!("{error:#}"),
                    retry_ms = delay.as_millis() as u64,
                    "ADS disconnected"
                ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::{Code, Status};

    #[test]
    fn closure_classification_matches_gateway_agent() {
        for (code, message, expected) in [
            (Code::Cancelled, "closed", true),
            (
                Code::Unavailable,
                "received prior goaway: code: NO_ERROR",
                true,
            ),
            (
                Code::Unavailable,
                "error reading from server: EOF, received prior goaway: code: NO_ERROR, debug data: max_age",
                true,
            ),
            (Code::Unavailable, "error reading from server: EOF", true),
            (Code::Unavailable, "transport is closing", true),
            (Code::Unavailable, "client disconnected", true),
            (
                Code::Internal,
                "stream terminated by RST_STREAM with error code: NO_ERROR",
                true,
            ),
            (
                Code::Internal,
                "h2 protocol error: stream error received: not a result of an error",
                true,
            ),
            (
                Code::Internal,
                "h2 protocol error: connection error received: not a result of an error (b\"max_age\")",
                true,
            ),
            (Code::Unavailable, "connection refused", false),
            (Code::Unavailable, "connection reset by peer", false),
            (
                Code::Unavailable,
                "error reading from server: EOF, received prior goaway: code: ENHANCE_YOUR_CALM, debug data: too_many_pings",
                false,
            ),
            (
                Code::Unavailable,
                "transport is closing, received prior goaway: code: INTERNAL_ERROR",
                false,
            ),
            (
                Code::Internal,
                "h2 protocol error: connection error received: internal error (b\"transport is closing\")",
                false,
            ),
            (Code::Internal, "transport is closing", false),
            (Code::DeadlineExceeded, "context deadline exceeded", false),
            (
                Code::Unknown,
                "h2 protocol error: error reading a body from connection: stream closed because of a broken pipe",
                false,
            ),
            (
                Code::Unknown,
                "protocol error: missing grpc-status trailer",
                false,
            ),
        ] {
            let error =
                anyhow::Error::new(Status::new(code, message)).context("receive ADS response");
            assert_eq!(
                expected_ads_closure(&error),
                expected,
                "{code:?}: {message}"
            );
        }
        assert!(!expected_ads_closure(&anyhow::anyhow!("read ADS token")));
    }
}
