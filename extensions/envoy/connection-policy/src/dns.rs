// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use envoy_proxy_dynamic_modules_rust_sdk::{EnvoyNetworkFilterScheduler, envoy_log_error};
use hickory_resolver::{TokioResolver, config::LookupIpStrategy};
use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{runtime::Runtime, task::JoinHandle};

pub struct Resolver {
    runtime: Arc<Runtime>,
    resolver: TokioResolver,
}

impl Resolver {
    pub fn new() -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let guard = runtime.enter();
        let mut builder = TokioResolver::builder_tokio().map_err(|e| e.to_string())?;
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        let resolver = builder.build().map_err(|e| e.to_string())?;
        drop(guard);
        Ok(Self {
            runtime: Arc::new(runtime),
            resolver,
        })
    }

    pub fn resolve(
        &self,
        name: String,
        port: u16,
        scheduler: impl EnvoyNetworkFilterScheduler + 'static,
    ) -> PendingResolution {
        let resolver = self.resolver.clone();
        PendingResolution::spawn(
            self.runtime.clone(),
            async move {
                match tokio::time::timeout(Duration::from_secs(5), resolver.lookup_ip(name)).await {
                    Ok(Ok(answer)) => Ok(answer
                        .iter()
                        .filter(|ip| ip.is_ipv4())
                        .map(|ip| SocketAddr::new(ip, port))
                        .collect()),
                    Ok(Err(error)) => Err(error.to_string()),
                    Err(error) => Err(error.to_string()),
                }
            },
            scheduler,
        )
    }
}

type Resolution = Arc<Mutex<Option<Result<Vec<SocketAddr>, String>>>>;

pub struct PendingResolution {
    runtime: Arc<Runtime>,
    result: Resolution,
    task: Option<JoinHandle<()>>,
}

impl PendingResolution {
    fn spawn(
        runtime: Arc<Runtime>,
        query: impl Future<Output = Result<Vec<SocketAddr>, String>> + Send + 'static,
        scheduler: impl EnvoyNetworkFilterScheduler + 'static,
    ) -> Self {
        let result = Arc::new(Mutex::new(None));
        let output = result.clone();
        let task = runtime.spawn(async move {
            let answer = query.await;
            *output.lock().expect("resolution lock") = Some(answer);
            scheduler.commit(0);
        });
        Self {
            runtime,
            result,
            task: Some(task),
        }
    }

    pub fn finish(mut self) -> Result<Vec<SocketAddr>, String> {
        self.join(false)
            .map_err(|error| format!("DNS task failed: {error}"))?;
        self.result
            .lock()
            .expect("resolution lock")
            .take()
            .expect("DNS completion")
    }

    fn join(&mut self, cancel: bool) -> Result<(), tokio::task::JoinError> {
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        if cancel {
            task.abort();
        }
        // Quiesce scheduler callbacks before Envoy can destroy the worker dispatcher.
        self.runtime.block_on(task)
    }
}

impl Drop for PendingResolution {
    fn drop(&mut self) {
        if let Err(error) = self.join(true)
            && !error.is_cancelled()
        {
            envoy_log_error!("TCP DNS task failed during close: {}", error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoy_proxy_dynamic_modules_rust_sdk::MockEnvoyNetworkFilterScheduler;
    use std::sync::mpsc;

    #[test]
    fn resolution_preserves_port_and_notifies_envoy() {
        let resolver = Resolver::new().unwrap();
        let (notify, ready) = mpsc::channel();
        let mut scheduler = MockEnvoyNetworkFilterScheduler::new();
        scheduler
            .expect_commit()
            .withf(|id| *id == 0)
            .times(1)
            .returning(move |_| notify.send(()).unwrap());
        let query = resolver.resolve("127.0.0.1".into(), 8443, scheduler);
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            query.finish().unwrap(),
            vec!["127.0.0.1:8443".parse().unwrap()]
        );
    }

    #[test]
    fn lookup_errors_reach_the_caller() {
        let resolver = Resolver::new().unwrap();
        let (notify, ready) = mpsc::channel();
        let mut scheduler = MockEnvoyNetworkFilterScheduler::new();
        scheduler
            .expect_commit()
            .times(1)
            .returning(move |_| notify.send(()).unwrap());
        let query = PendingResolution::spawn(
            resolver.runtime.clone(),
            async { Err("lookup failed".into()) },
            scheduler,
        );
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(query.finish().unwrap_err(), "lookup failed");
    }

    #[test]
    fn dropping_pending_resolution_aborts_and_joins_the_task() {
        let resolver = Resolver::new().unwrap();
        let (started, running) = mpsc::channel();
        let (lifetime, finished) = mpsc::channel::<()>();
        let mut scheduler = MockEnvoyNetworkFilterScheduler::new();
        scheduler.expect_commit().times(0);
        let query = PendingResolution::spawn(
            resolver.runtime.clone(),
            async move {
                let _lifetime = lifetime;
                started.send(()).unwrap();
                std::future::pending().await
            },
            scheduler,
        );
        running.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(query);
        assert_eq!(finished.try_recv(), Err(mpsc::TryRecvError::Disconnected));
    }

    #[test]
    fn dropping_resolution_waits_for_an_inflight_scheduler_callback() {
        let resolver = Resolver::new().unwrap();
        let (entered, running) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let mut scheduler = MockEnvoyNetworkFilterScheduler::new();
        scheduler.expect_commit().times(1).returning(move |_| {
            entered.send(()).unwrap();
            resume.recv().unwrap();
        });
        let query = PendingResolution::spawn(
            resolver.runtime.clone(),
            async { Ok(Vec::new()) },
            scheduler,
        );
        running.recv_timeout(Duration::from_secs(5)).unwrap();
        let (done, stopped) = mpsc::channel();
        let closer = std::thread::spawn(move || {
            drop(query);
            done.send(()).unwrap();
        });
        let early = stopped.recv_timeout(Duration::from_millis(20));
        release.send(()).unwrap();
        closer.join().unwrap();
        assert_eq!(early, Err(mpsc::RecvTimeoutError::Timeout));
        stopped.recv_timeout(Duration::from_secs(5)).unwrap();
    }
}
