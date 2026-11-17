// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use envoy_proxy_dynamic_modules_rust_sdk::envoy_log_error;
use hickory_resolver::{TokioResolver, config::LookupIpStrategy};
use moka::sync::Cache;
use serde::Deserialize;
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tokio::{runtime::Runtime, sync::Semaphore, task::JoinHandle};

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub resolver: String,
    pub max_hosts: usize,
    pub max_pending_requests: usize,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            resolver: "agentio_dns_cache".into(),
            max_hosts: 16384,
            max_pending_requests: 4096,
        }
    }
}

#[derive(Clone)]
struct Answer {
    ips: Arc<[IpAddr]>,
    valid_until: Instant,
}

pub struct Resolver {
    runtime: Arc<Runtime>,
    resolver: TokioResolver,
    // Reuse immutable answers without rebuilding queries or cloning DNS response messages.
    answers: Cache<String, Answer>,
    settings: Settings,
    pending: Arc<Semaphore>,
}

// Configuration snapshots own generations; the registry must not keep retired caches alive.
static SHARED_RESOLVERS: Mutex<Vec<Weak<Resolver>>> = Mutex::new(Vec::new());

impl Resolver {
    pub fn shared(settings: &Settings) -> Result<Arc<Self>, String> {
        let mut shared = SHARED_RESOLVERS.lock().expect("shared DNS resolver lock");
        shared.retain(|resolver| resolver.strong_count() > 0);
        let mut runtime = None;
        for resolver in shared.iter().filter_map(Weak::upgrade) {
            if &resolver.settings == settings {
                return Ok(resolver);
            }
            if resolver.settings.resolver == settings.resolver {
                runtime = Some(resolver.runtime.clone());
            }
        }
        let runtime = match runtime {
            Some(runtime) => runtime,
            None => new_runtime()?,
        };
        let resolver = Arc::new(Self::new(settings.clone(), runtime)?);
        shared.push(Arc::downgrade(&resolver));
        Ok(resolver)
    }

    fn new(settings: Settings, runtime: Arc<Runtime>) -> Result<Self, String> {
        if settings.resolver.is_empty() {
            return Err("DNS resolver name must not be empty".into());
        }
        if settings.max_hosts == 0
            || settings.max_pending_requests == 0
            || settings.max_pending_requests > Semaphore::MAX_PERMITS
        {
            return Err("DNS cache limits must be positive and within supported capacity".into());
        }
        let guard = runtime.enter();
        let mut builder = TokioResolver::builder_tokio().map_err(|e| e.to_string())?;
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
        builder.options_mut().cache_size = settings.max_hosts as u64;
        let resolver = builder.build().map_err(|e| e.to_string())?;
        drop(guard);
        Ok(Self {
            runtime,
            resolver,
            answers: Cache::new(settings.max_hosts as u64),
            pending: Arc::new(Semaphore::new(settings.max_pending_requests)),
            settings,
        })
    }

    pub fn resolve<N: FnOnce() + Send + 'static>(
        &self,
        name: String,
        port: u16,
        make_notify: impl FnOnce() -> N,
    ) -> Lookup {
        if let Some(answer) = self.answers.get(&name)
            && answer.valid_until > Instant::now()
        {
            return Lookup::Ready(Ok(socket_addresses(&answer, port)));
        }
        let answers = self.answers.clone();
        let resolver = self.resolver.clone();
        let query_name = name.clone();
        let mut query = Box::pin(async move {
            match tokio::time::timeout(
                Duration::from_secs(5),
                resolver.lookup_ip(query_name.as_str()),
            )
            .await
            {
                Ok(Ok(answer)) => {
                    let answer = Answer {
                        ips: answer.iter().filter(|ip| ip.is_ipv4()).collect(),
                        valid_until: answer.valid_until(),
                    };
                    Ok(answer)
                }
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
            // Hickory rounds cached TTLs to seconds; do not cache them again and extend expiry.
            Poll::Ready(result) => {
                Lookup::Ready(result.map(|answer| socket_addresses(&answer, port)))
            }
            Poll::Pending => {
                let Ok(permit) = self.pending.clone().try_acquire_owned() else {
                    return Lookup::Ready(Err("DNS pending request limit exceeded".into()));
                };
                Lookup::Pending(PendingResolution::spawn(
                    self.runtime.clone(),
                    async move {
                        let _permit = permit;
                        let answer = query.await?;
                        let addresses = socket_addresses(&answer, port);
                        answers.insert(name, answer);
                        Ok(addresses)
                    },
                    make_notify(),
                ))
            }
        }
    }
}

fn new_runtime() -> Result<Arc<Runtime>, String> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map(Arc::new)
        .map_err(|e| e.to_string())
}

fn socket_addresses(answer: &Answer, port: u16) -> Vec<SocketAddr> {
    answer
        .ips
        .iter()
        .copied()
        .map(|ip| SocketAddr::new(ip, port))
        .collect()
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
        let original = Resolver::shared(&Settings::default()).unwrap();
        let callers: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(|| Resolver::shared(&Settings::default()).unwrap()))
            .collect();
        let resolvers: Vec<_> = callers.into_iter().map(|c| c.join().unwrap()).collect();
        for resolver in &resolvers {
            assert!(Arc::ptr_eq(&resolvers[0], resolver));
        }
        drop(resolvers);
        let replacement = Resolver::shared(&Settings::default()).unwrap();
        assert!(Arc::ptr_eq(&original, &replacement));
    }

    #[test]
    fn immediately_available_lookup_preserves_port_without_scheduling() {
        let resolver = Resolver::new(Settings::default(), new_runtime().unwrap()).unwrap();
        let result = resolver.resolve("localhost".into(), 8443, || -> fn() {
            panic!("ready lookup scheduled")
        });
        let Lookup::Ready(result) = result else {
            panic!("localhost must complete inline")
        };
        assert_eq!(result.unwrap(), vec!["127.0.0.1:8443".parse().unwrap()]);
    }

    #[test]
    fn hosts_aliases_preserve_request_ports() {
        let mut hosts = hickory_resolver::Hosts::default();
        hosts
            .read_hosts_conf(
                b"192.0.2.1 service.test alias.test\n2001:db8::1 service.test alias.test\n"
                    .as_slice(),
            )
            .unwrap();
        let mut resolver = Resolver::new(Settings::default(), new_runtime().unwrap()).unwrap();
        resolver.resolver.set_hosts(Arc::new(hosts));
        for (name, port) in [
            ("service.test", 80),
            ("service.test", 443),
            ("ALIAS.test.", 443),
        ] {
            let Lookup::Ready(result) = resolver.resolve(name.into(), port, || -> fn() {
                panic!("hosts lookup scheduled")
            }) else {
                panic!("hosts must complete inline")
            };
            assert_eq!(
                result.unwrap(),
                vec![SocketAddr::from(([192, 0, 2, 1], port))]
            );
        }
    }

    #[test]
    fn expired_answer_is_never_used() {
        let resolver = Resolver::new(Settings::default(), new_runtime().unwrap()).unwrap();
        for (deadline, expected) in [
            (Instant::now() + Duration::from_secs(60), [192, 0, 2, 1]),
            (Instant::now(), [127, 0, 0, 1]),
        ] {
            resolver.answers.insert(
                "localhost".into(),
                Answer {
                    ips: Arc::from([IpAddr::from([192, 0, 2, 1])]),
                    valid_until: deadline,
                },
            );
            let Lookup::Ready(result) = resolver.resolve("localhost".into(), 443, || -> fn() {
                panic!("cached or localhost lookup scheduled")
            }) else {
                panic!("lookup must complete inline")
            };
            assert_eq!(result.unwrap(), vec![SocketAddr::from((expected, 443))]);
        }
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
        let mut resolver = Resolver::new(
            Settings {
                max_pending_requests: 1,
                ..Settings::default()
            },
            new_runtime().unwrap(),
        )
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
            || panic!("cancelled query notified")
        });
        assert!(matches!(&first, Lookup::Pending(_)));
        assert!(matches!(
            resolver.resolve("pending.test.".into(), 443, || -> fn() {
                panic!("overflow scheduler created")
            }),
            Lookup::Ready(Err(_))
        ));
        assert!(matches!(
            resolver.resolve("localhost".into(), 80, || -> fn() {
                panic!("cache hit scheduler created")
            }),
            Lookup::Ready(Ok(_))
        ));
        drop(first);
        let next = resolver.resolve("next.test.".into(), 443, || {
            || panic!("cancelled query notified")
        });
        assert!(matches!(&next, Lookup::Pending(_)));
        drop(next);
        assert_eq!(resolver.pending.available_permits(), 1);
    }

    #[test]
    fn changed_settings_use_isolated_generations_on_the_same_runtime() {
        let settings = Settings {
            resolver: "hot-update".into(),
            ..Settings::default()
        };
        let current = Resolver::shared(&settings).unwrap();
        current.answers.insert(
            "service.test".into(),
            Answer {
                ips: Arc::from([IpAddr::from([192, 0, 2, 1])]),
                valid_until: Instant::now() + Duration::from_secs(60),
            },
        );
        let changed = Settings {
            max_hosts: 128,
            max_pending_requests: 1,
            ..settings.clone()
        };
        let next = Resolver::shared(&changed).unwrap();
        assert!(!Arc::ptr_eq(&current, &next));
        assert!(Arc::ptr_eq(&current.runtime, &next.runtime));
        assert_eq!(next.answers.policy().max_capacity(), Some(128));
        assert!(next.answers.get("service.test").is_none());
        assert!(current.answers.get("service.test").is_some());
        let _permit = current.pending.clone().try_acquire_owned().unwrap();
        assert_eq!(next.pending.available_permits(), 1);
        assert!(Arc::ptr_eq(&current, &Resolver::shared(&settings).unwrap()));
        assert!(Arc::ptr_eq(&next, &Resolver::shared(&changed).unwrap()));
        assert!(
            Resolver::shared(&Settings {
                max_hosts: 0,
                ..changed
            })
            .is_err()
        );
        assert!(Arc::ptr_eq(&current, &Resolver::shared(&settings).unwrap()));
    }

    #[test]
    fn named_resolvers_are_isolated_and_retired_generations_are_reclaimed() {
        let settings = Settings {
            resolver: "retirement".into(),
            ..Settings::default()
        };
        let current = Resolver::shared(&settings).unwrap();
        let other = Resolver::shared(&Settings {
            resolver: "other-resolver".into(),
            ..settings.clone()
        })
        .unwrap();
        assert!(!Arc::ptr_eq(&current, &other));
        assert!(!Arc::ptr_eq(&current.runtime, &other.runtime));
        for capacity in 1..=40 {
            let next = Resolver::shared(&Settings {
                max_hosts: capacity,
                ..settings.clone()
            })
            .unwrap();
            assert!(Arc::ptr_eq(&current.runtime, &next.runtime));
            let retired = Arc::downgrade(&next);
            drop(next);
            assert!(retired.upgrade().is_none());
        }
        let retired = Arc::downgrade(&current);
        let runtime = Arc::downgrade(&current.runtime);
        drop(current);
        assert!(retired.upgrade().is_none());
        assert!(runtime.upgrade().is_none());
        assert!(
            Resolver::shared(&Settings {
                resolver: String::new(),
                ..settings
            })
            .is_err()
        );
    }

    #[test]
    fn omitted_dns_fields_use_defaults() {
        let settings: Settings = serde_json::from_str("{}").unwrap();
        assert_eq!(settings, Settings::default());
        let current = Resolver::shared(&settings).unwrap();
        assert!(Arc::ptr_eq(
            &current,
            &Resolver::shared(&Settings::default()).unwrap(),
        ));
    }

    #[test]
    fn pending_lookup_completes_in_its_original_generation_after_update() {
        use hickory_resolver::{
            config::{NameServerConfig, ResolverConfig},
            net::runtime::TokioRuntimeProvider,
        };
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let settings = Settings {
            resolver: "pending-generation".into(),
            ..Settings::default()
        };
        let mut original = Resolver::new(settings.clone(), new_runtime().unwrap()).unwrap();
        let mut server = NameServerConfig::udp("127.0.0.1".parse().unwrap());
        server.connections[0].port = socket.local_addr().unwrap().port();
        {
            let _guard = original.runtime.enter();
            let mut builder = TokioResolver::builder_with_config(
                ResolverConfig::from_name_servers(vec![server]),
                TokioRuntimeProvider::default(),
            );
            builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
            original.resolver = builder.build().unwrap();
        }
        let original = Arc::new(original);
        SHARED_RESOLVERS
            .lock()
            .unwrap()
            .push(Arc::downgrade(&original));
        let (notify, ready) = mpsc::channel();
        let Lookup::Pending(query) =
            original.resolve("pending-generation.test.".into(), 443, || {
                move || notify.send(()).unwrap()
            })
        else {
            panic!("lookup must wait for DNS response")
        };
        let mut request = [0u8; 512];
        let (_, peer) = socket.recv_from(&mut request).unwrap();
        let replacement = Resolver::shared(&Settings {
            max_hosts: 128,
            max_pending_requests: 2,
            ..settings
        })
        .unwrap();
        assert!(Arc::ptr_eq(&original.runtime, &replacement.runtime));
        let mut question_end = 12;
        while request[question_end] != 0 {
            question_end += request[question_end] as usize + 1;
        }
        question_end += 5;
        let mut response = request[..2].to_vec();
        response.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        response.extend_from_slice(&request[12..question_end]);
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        socket.send_to(&response, peer).unwrap();
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            query.finish().unwrap(),
            vec!["192.0.2.1:443".parse().unwrap()]
        );
        assert!(original.answers.get("pending-generation.test.").is_some());
        assert!(
            replacement
                .answers
                .get("pending-generation.test.")
                .is_none()
        );
        let retired = Arc::downgrade(&original);
        drop(original);
        assert!(retired.upgrade().is_none());
    }

    #[test]
    fn lookup_errors_reach_the_caller() {
        let resolver = Resolver::new(Settings::default(), new_runtime().unwrap()).unwrap();
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
        let resolver = Resolver::new(Settings::default(), new_runtime().unwrap()).unwrap();
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
        let resolver = Resolver::new(Settings::default(), new_runtime().unwrap()).unwrap();
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
