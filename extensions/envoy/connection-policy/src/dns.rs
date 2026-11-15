// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use envoy_proxy_dynamic_modules_rust_sdk::envoy_log_error;
use hickory_resolver::{TokioResolver, config::LookupIpStrategy};
use serde::Deserialize;
use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{runtime::Runtime, sync::Semaphore, task::JoinHandle};

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub max_hosts: usize,
    pub max_pending_requests: usize,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            max_hosts: 16384,
            max_pending_requests: 4096,
        }
    }
}

pub struct Resolver {
    runtime: Arc<Runtime>,
    resolver: TokioResolver,
    settings: Settings,
    pending: Arc<Semaphore>,
}

// Policy updates share raw DNS answers; authorization remains with each caller.
static SHARED_RESOLVER: Mutex<Option<Arc<Resolver>>> = Mutex::new(None);

impl Resolver {
    pub fn shared(settings: &Settings) -> Result<Arc<Self>, String> {
        let mut shared = SHARED_RESOLVER.lock().expect("shared DNS resolver lock");
        if let Some(resolver) = shared.as_ref() {
            if &resolver.settings != settings {
                return Err("DNS cache settings changed; restart the gateway to apply them".into());
            }
            return Ok(resolver.clone());
        }
        let resolver = Arc::new(Self::new(settings.clone())?);
        *shared = Some(resolver.clone());
        Ok(resolver)
    }

    fn new(settings: Settings) -> Result<Self, String> {
        if settings.max_hosts == 0
            || settings.max_pending_requests == 0
            || settings.max_pending_requests > Semaphore::MAX_PERMITS
        {
            return Err("DNS cache limits must be positive and within supported capacity".into());
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let guard = runtime.enter();
        let mut builder = TokioResolver::builder_tokio().map_err(|e| e.to_string())?;
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        builder.options_mut().cache_size = settings.max_hosts as u64;
        let resolver = builder.build().map_err(|e| e.to_string())?;
        drop(guard);
        Ok(Self {
            runtime: Arc::new(runtime),
            resolver,
            pending: Arc::new(Semaphore::new(settings.max_pending_requests)),
            settings,
        })
    }

    pub fn resolve(
        &self,
        name: String,
        port: u16,
        notify: impl FnOnce() + Send + 'static,
    ) -> Lookup {
        let resolver = self.resolver.clone();
        let mut query = Box::pin(async move {
            match tokio::time::timeout(Duration::from_secs(5), resolver.lookup_ip(name)).await {
                Ok(Ok(answer)) => Ok(answer
                    .iter()
                    .filter(|ip| ip.is_ipv4())
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect()),
                Ok(Err(error)) => Err(error.to_string()),
                Err(error) => Err(error.to_string()),
            }
        });
        // Cached answers complete inline; only network waits need a scheduler round trip.
        let ready = {
            let _guard = self.runtime.enter();
            query.as_mut().poll(&mut Context::from_waker(Waker::noop()))
        };
        match ready {
            Poll::Ready(result) => Lookup::Ready(result),
            Poll::Pending => {
                let Ok(permit) = self.pending.clone().try_acquire_owned() else {
                    return Lookup::Ready(Err("DNS pending request limit exceeded".into()));
                };
                Lookup::Pending(PendingResolution::spawn(
                    self.runtime.clone(),
                    async move {
                        let _permit = permit;
                        query.await
                    },
                    notify,
                ))
            }
        }
    }
}

pub enum Lookup {
    Ready(Result<Vec<SocketAddr>, String>),
    Pending(PendingResolution),
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
        notify: impl FnOnce() + Send + 'static,
    ) -> Self {
        let result = Arc::new(Mutex::new(None));
        let output = result.clone();
        let task = runtime.spawn(async move {
            let answer = query.await;
            *output.lock().expect("resolution lock") = Some(answer);
            notify();
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
        // Quiesce completion callbacks before the caller destroys their destination.
        self.runtime.block_on(task)
    }
}

impl Drop for PendingResolution {
    fn drop(&mut self) {
        if let Err(error) = self.join(true)
            && !error.is_cancelled()
        {
            envoy_log_error!("DNS task failed during close: {}", error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn concurrent_callers_and_replacements_share_one_resolver() {
        let callers: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(|| Resolver::shared(&Settings::default()).unwrap()))
            .collect();
        let resolvers: Vec<_> = callers.into_iter().map(|c| c.join().unwrap()).collect();
        for resolver in &resolvers {
            assert!(Arc::ptr_eq(&resolvers[0], resolver));
        }
        let previous = Arc::downgrade(&resolvers[0]);
        drop(resolvers);
        let replacement = Resolver::shared(&Settings::default()).unwrap();
        assert!(Arc::ptr_eq(&previous.upgrade().unwrap(), &replacement));
    }

    #[test]
    fn immediately_available_lookup_preserves_port_without_scheduling() {
        let resolver = Resolver::new(Settings::default()).unwrap();
        let result = resolver.resolve("localhost".into(), 8443, || {
            panic!("ready lookup scheduled")
        });
        let Lookup::Ready(result) = result else {
            panic!("localhost must complete inline")
        };
        assert_eq!(result.unwrap(), vec!["127.0.0.1:8443".parse().unwrap()]);
    }

    #[test]
    fn pending_budget_is_shared_released_on_cancel_and_bypassed_by_cache_hits() {
        use hickory_resolver::{
            config::{NameServerConfig, ResolverConfig},
            net::runtime::TokioRuntimeProvider,
        };
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut server = NameServerConfig::udp("127.0.0.1".parse().unwrap());
        server.connections[0].port = socket.local_addr().unwrap().port();
        let mut resolver = Resolver::new(Settings {
            max_pending_requests: 1,
            ..Settings::default()
        })
        .unwrap();
        {
            let _guard = resolver.runtime.enter();
            resolver.resolver = TokioResolver::builder_with_config(
                ResolverConfig::from_name_servers(vec![server]),
                TokioRuntimeProvider::default(),
            )
            .build()
            .unwrap();
        }
        let first = resolver.resolve("pending.test.".into(), 80, || {
            panic!("cancelled query notified")
        });
        assert!(matches!(&first, Lookup::Pending(_)));
        assert!(matches!(
            resolver.resolve("pending.test.".into(), 443, || panic!("overflow notified")),
            Lookup::Ready(Err(_))
        ));
        assert!(matches!(
            resolver.resolve("localhost".into(), 80, || panic!("cache hit notified")),
            Lookup::Ready(Ok(_))
        ));
        drop(first);
        let next = resolver.resolve("next.test.".into(), 443, || {
            panic!("cancelled query notified")
        });
        assert!(matches!(&next, Lookup::Pending(_)));
        drop(next);
        assert_eq!(resolver.pending.available_permits(), 1);
    }

    #[test]
    fn incompatible_dns_settings_require_restart() {
        let current = Resolver::shared(&Settings::default()).unwrap();
        let changed = Settings {
            max_pending_requests: 1,
            ..Settings::default()
        };
        assert!(Resolver::shared(&changed).is_err());
        assert!(Arc::ptr_eq(
            &current,
            &Resolver::shared(&Settings::default()).unwrap()
        ));
    }

    #[test]
    fn lookup_errors_reach_the_caller() {
        let resolver = Resolver::new(Settings::default()).unwrap();
        let (notify, ready) = mpsc::channel();
        let query = PendingResolution::spawn(
            resolver.runtime.clone(),
            async { Err("lookup failed".into()) },
            move || notify.send(()).unwrap(),
        );
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(query.finish().unwrap_err(), "lookup failed");
    }

    #[test]
    fn dropping_pending_resolution_aborts_and_joins_the_task() {
        let resolver = Resolver::new(Settings::default()).unwrap();
        let (started, running) = mpsc::channel();
        let (lifetime, finished) = mpsc::channel::<()>();
        let query = PendingResolution::spawn(
            resolver.runtime.clone(),
            async move {
                let _lifetime = lifetime;
                started.send(()).unwrap();
                std::future::pending().await
            },
            || panic!("cancelled query must not notify"),
        );
        running.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(query);
        assert_eq!(finished.try_recv(), Err(mpsc::TryRecvError::Disconnected));
    }

    #[test]
    fn dropping_resolution_waits_for_an_inflight_scheduler_callback() {
        let resolver = Resolver::new(Settings::default()).unwrap();
        let (entered, running) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let query = PendingResolution::spawn(
            resolver.runtime.clone(),
            async { Ok(Vec::new()) },
            move || {
                entered.send(()).unwrap();
                resume.recv().unwrap();
            },
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
