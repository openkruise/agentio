// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, future::Future, net::SocketAddr, sync::Arc, time::Duration};

use agentio_porter::{
    discovery::Client, metrics::Metrics, processor::Processor,
    wire::extproc::external_processor_server::ExternalProcessorServer,
};
use anyhow::{Context, Result, anyhow};
use tokio::{
    signal::unix::{SignalKind, signal},
    task::{Id, JoinSet},
};
use tokio_util::sync::CancellationToken;
use tonic_health::ServingStatus;
use tracing::{debug, error, info, warn};

use crate::config::Config;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const READINESS_SERVICES: [&str; 3] = [
    "",
    "readiness",
    "envoy.service.ext_proc.v3.ExternalProcessor",
];

pub async fn run(config: Config) -> Result<()> {
    // Install handlers before starting services so failures cannot leave an unsupervised process.
    let mut terminate = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
    info!(
        node_id = %config.transport.node.id,
        xds_address = %config.transport.address,
        grpc_address = %config.grpc_address,
        health_address = %config.health_address,
        metrics_address = %config.metrics_address,
        worker_threads = config.worker_threads,
        request_timeout = ?config.request_timeout,
        cache_idle_ttl = ?config.cache.idle_ttl,
        cache_max_entries = config.cache.max_entries,
        "starting Porter"
    );
    let metrics = Metrics::new();
    let client = Client::new(config.cache, metrics.clone());
    let processor = Processor {
        client: client.clone(),
        cluster_id: config.cluster_id,
        timeout: config.request_timeout,
    };
    let stop = CancellationToken::new();
    let (health, service) = tonic_health::server::health_reporter();
    health
        .set_service_status("liveness", ServingStatus::Serving)
        .await;
    let mut ready = client.readiness();
    for name in READINESS_SERVICES {
        health
            .set_service_status(name, ServingStatus::NotServing)
            .await;
    }
    let mut tasks = Tasks::new();
    let discovery = client.clone();
    let token = stop.clone();
    tasks.spawn("ads", async move {
        discovery.run(config.transport, token).await;
        Ok(())
    });
    let token = stop.clone();
    tasks.spawn("cache-expiry", async move {
        client.expire(token).await;
        Ok(())
    });
    let token = stop.clone();
    tasks.spawn("readiness", async move {
        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                result = ready.changed() => {
                    result.context("watch discovery readiness")?;
                    let serving = *ready.borrow_and_update();
                    for name in READINESS_SERVICES {
                        health.set_service_status(
                            name,
                            if serving { ServingStatus::Serving } else { ServingStatus::NotServing },
                        ).await;
                    }
                }
            }
        }
        Ok(())
    });
    let token = stop.clone();
    tasks.spawn("ext-proc", async move {
        tonic::transport::Server::builder()
            .add_service(ExternalProcessorServer::new(processor))
            .serve_with_shutdown(config.grpc_address, token.cancelled_owned())
            .await
            .context("serve ext_proc")?;
        Ok(())
    });
    let token = stop.clone();
    tasks.spawn("health", async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_shutdown(config.health_address, token.cancelled_owned())
            .await
            .context("serve gRPC health")?;
        Ok(())
    });
    let token = stop.clone();
    tasks.spawn("metrics", async move {
        serve_metrics(metrics, config.metrics_address, token).await
    });
    let result = tokio::select! {
        _ = terminate.recv() => {
            info!(signal = "SIGTERM", "starting shutdown");
            Ok(())
        }
        _ = interrupt.recv() => {
            info!(signal = "SIGINT", "starting shutdown");
            Ok(())
        }
        outcome = tasks.join_next() => {
            let (task, result) = outcome.expect("services have been started");
            let error = result.err().unwrap_or_else(|| anyhow!("task {task} exited unexpectedly"));
            error!(task, error = %format_args!("{error:#}"), "service stopped; starting shutdown");
            Err(error)
        }
    };
    stop.cancel();
    tasks.shutdown(result).await?;
    info!("Porter stopped");
    Ok(())
}

// The name map also identifies tasks that panic, whose normal return value is unavailable.
struct Tasks {
    running: JoinSet<Result<()>>,
    names: HashMap<Id, &'static str>,
}

impl Tasks {
    fn new() -> Self {
        Self {
            running: JoinSet::new(),
            names: HashMap::new(),
        }
    }

    fn spawn(
        &mut self,
        name: &'static str,
        future: impl Future<Output = Result<()>> + Send + 'static,
    ) {
        let handle = self.running.spawn(future);
        self.names.insert(handle.id(), name);
    }

    async fn join_next(&mut self) -> Option<(&'static str, Result<()>)> {
        let outcome = self.running.join_next_with_id().await?;
        let (id, result) = match outcome {
            Ok((id, result)) => (id, result),
            Err(error) => (error.id(), Err(error.into())),
        };
        let name = self.names.remove(&id).expect("spawned task has a name");
        Some((name, result.with_context(|| format!("task {name} failed"))))
    }

    async fn shutdown(&mut self, mut result: Result<()>) -> Result<()> {
        // Bound shutdown even when a peer keeps an HTTP/2 stream open.
        if tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
            while let Some((task, outcome)) = self.join_next().await {
                match outcome {
                    Ok(()) => debug!(task, "task stopped"),
                    Err(error) => {
                        error!(task, error = %format_args!("{error:#}"), "task failed during shutdown");
                        if result.is_ok() {
                            result = Err(error);
                        }
                    }
                }
            }
        })
        .await
        .is_err()
        {
            warn!(remaining_tasks = self.running.len(),
                tasks = ?self.names, timeout = ?SHUTDOWN_TIMEOUT, "shutdown timed out; aborting tasks");
            self.running.abort_all();
            // Observe panics/errors already racing with cancellation; expected aborts are silent.
            while let Some(outcome) = self.running.join_next_with_id().await {
                let (id, outcome) = match outcome {
                    Ok((id, result)) => (id, result),
                    Err(error) if error.is_cancelled() => {
                        self.names.remove(&error.id());
                        continue;
                    }
                    Err(error) => (error.id(), Err(error.into())),
                };
                let task = self.names.remove(&id).expect("spawned task has a name");
                if let Err(error) = outcome {
                    error!(task, error = %format_args!("{error:#}"), "task failed while aborting");
                    if result.is_ok() {
                        result = Err(error).with_context(|| format!("task {task} failed"));
                    }
                }
            }
        }
        result
    }
}

async fn serve_metrics(
    metrics: Arc<Metrics>,
    address: SocketAddr,
    stop: CancellationToken,
) -> Result<()> {
    let app = axum::Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let metrics = metrics.clone();
            async move {
                match metrics.encode() {
                    Ok(body) => Ok((
                        [(
                            "content-type",
                            "application/openmetrics-text; version=1.0.0; charset=utf-8",
                        )],
                        body,
                    )),
                    Err(error) => {
                        error!(%error, "encode metrics response");
                        Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("bind metrics listener at {address}"))?;
    axum::serve(listener, app)
        .with_graceful_shutdown(stop.cancelled_owned())
        .await
        .context("serve metrics")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn observes_failure_after_another_task_has_stopped() {
        let mut tasks = Tasks::new();
        let (release, wait) = tokio::sync::oneshot::channel();
        tasks.spawn("health", async { Ok(()) });
        tasks.spawn("metrics", async move {
            wait.await?;
            anyhow::bail!("listener failed")
        });
        assert_eq!(tasks.join_next().await.unwrap().0, "health");
        release.send(()).unwrap();
        let error = tasks.shutdown(Ok(())).await.unwrap_err();
        assert!(format!("{error:#}").contains("task metrics failed: listener failed"));
    }

    #[tokio::test]
    async fn identifies_panicking_task_and_preserves_first_error() {
        let mut tasks = Tasks::new();
        tasks.spawn("ads", async { panic!("unexpected ADS panic") });
        let (name, result) = tasks.join_next().await.unwrap();
        assert_eq!(name, "ads");
        let error = result.unwrap_err();
        assert!(format!("{error:#}").contains("unexpected ADS panic"));
        tasks.spawn("metrics", async { anyhow::bail!("later failure") });
        let error = tasks.shutdown(Err(error)).await.unwrap_err();
        assert!(format!("{error:#}").contains("unexpected ADS panic"));
    }

    #[tokio::test(start_paused = true)]
    async fn bounds_shutdown_and_joins_aborted_tasks() {
        let mut tasks = Tasks::new();
        tasks.spawn("ext-proc", std::future::pending());
        let start = tokio::time::Instant::now();
        tasks.shutdown(Ok(())).await.unwrap();
        assert_eq!(start.elapsed(), SHUTDOWN_TIMEOUT);
        assert!(tasks.running.is_empty());
        assert!(tasks.names.is_empty());
    }
}
