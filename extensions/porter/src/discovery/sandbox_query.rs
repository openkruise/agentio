// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use moka::{Expiry, future::Cache};
use tokio::sync::Notify;
use tonic::{Code, Request, transport::Channel};

use super::{DemandError, TransportConfig};
use crate::{
    metrics::{Metrics, SandboxResult},
    view::{self, View},
    wire::agentio::sandbox::{
        GetSandboxRequest, sandbox_query_service_client::SandboxQueryServiceClient,
    },
};

// Bounded stale-on-error window. Serving the last good view keeps the data plane
// usable through a control-plane outage; the revocation risk is the same one the
// fail-closed ADS path already accepts while disconnected.
const STALE_WINDOW: Duration = Duration::from_secs(300);
const BACKOFF_BASE: Duration = Duration::from_millis(100);
const BACKOFF_MAX: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct Cached {
    value: Option<Arc<View>>,
    ttl: Duration,
}

struct PolicyExpiry;
impl Expiry<String, Cached> for PolicyExpiry {
    fn expire_after_create(&self, _: &String, value: &Cached, _: Instant) -> Option<Duration> {
        Some(value.ttl)
    }
}

struct BackoffExpiry;
impl Expiry<String, u32> for BackoffExpiry {
    fn expire_after_create(&self, _: &String, failures: &u32, _: Instant) -> Option<Duration> {
        Some(
            BACKOFF_BASE
                .saturating_mul(1u32 << (*failures).min(31))
                .min(BACKOFF_MAX),
        )
    }
}

struct StaleExpiry;
impl Expiry<String, Arc<View>> for StaleExpiry {
    fn expire_after_create(&self, _: &String, _: &Arc<View>, _: Instant) -> Option<Duration> {
        Some(STALE_WINDOW)
    }
}

struct Flight {
    done: Notify,
    result: OnceLock<Result<Cached, DemandError>>,
}

pub(super) struct SandboxQuery {
    transport: TransportConfig,
    channel: Mutex<Option<Channel>>,
    cache: Cache<String, Cached>,
    flights: Mutex<HashMap<String, Arc<Flight>>>,
    backoff: Cache<String, u32>,
    stale: Cache<String, Arc<View>>,
    metrics: Arc<Metrics>,
}

impl SandboxQuery {
    pub(super) fn new(
        transport: TransportConfig,
        max_entries: usize,
        metrics: Arc<Metrics>,
    ) -> Self {
        let mut builder = Cache::builder().expire_after(PolicyExpiry);
        let mut stale_builder = Cache::builder().expire_after(StaleExpiry);
        if max_entries != 0 {
            builder = builder.max_capacity(max_entries as u64);
            stale_builder = stale_builder.max_capacity(max_entries as u64);
        }
        Self {
            transport,
            channel: Mutex::new(None),
            cache: builder.build(),
            flights: Mutex::new(HashMap::new()),
            backoff: Cache::builder().expire_after(BackoffExpiry).build(),
            stale: stale_builder.build(),
            metrics,
        }
    }

    pub(super) fn connected(&self, channel: Channel) {
        *self.channel.lock().unwrap() = Some(channel);
    }

    fn record(&self, result: &'static str) {
        self.metrics
            .sandbox_queries
            .get_or_create(&SandboxResult { result })
            .inc();
    }

    pub(super) async fn get(self: &Arc<Self>, name: &str) -> Result<Arc<View>, DemandError> {
        if let Some(entry) = self.cache.get(name).await {
            return self.serve(entry, false);
        }
        // The backend recently failed; do not hammer it. A retained last good view
        // keeps callers serving while the backoff window runs.
        if self.backoff.get(name).await.is_some() {
            if let Some(value) = self.stale.get(name).await {
                self.record("stale");
                return Ok(value);
            }
            self.record("backoff");
            return Err(DemandError::Query(Code::Unavailable));
        }
        let flight = {
            let mut flights = self.flights.lock().unwrap();
            match flights.get(name) {
                Some(flight) => flight.clone(),
                None => {
                    let flight = Arc::new(Flight {
                        done: Notify::new(),
                        result: OnceLock::new(),
                    });
                    flights.insert(name.to_owned(), flight.clone());
                    self.spawn_fetch(name.to_owned(), flight.clone());
                    flight
                }
            }
        };
        // WHY: the fetch runs in a detached task so a canceled caller (request
        // timeout or invalidation) drops only its own wait. The shared RPC still
        // completes for every other waiter, matching Go's context.WithoutCancel;
        // moka's shared init future would instead abort the RPC for everyone.
        let notified = flight.done.notified();
        tokio::pin!(notified);
        // Register before reading the result so a notify racing with this check
        // cannot leave us waiting on an already-completed flight.
        notified.as_mut().enable();
        if flight.result.get().is_none() {
            notified.await;
        }
        // Re-check the cache: a concurrent refresh may have published a newer value
        // than the snapshot this flight carried.
        if let Some(entry) = self.cache.get(name).await {
            return self.serve(entry, true);
        }
        match flight
            .result
            .get()
            .expect("flight result is published before notify")
        {
            Ok(entry) => self.serve(entry.clone(), true),
            Err(err) => {
                if let Some(value) = self.stale.get(name).await {
                    self.record("stale");
                    return Ok(value);
                }
                self.record("error");
                Err(*err)
            }
        }
    }

    // One counter per call: a value reached through a flight is a miss even when
    // the publication landed in the cache before this waiter observed it.
    fn serve(&self, entry: Cached, fetched: bool) -> Result<Arc<View>, DemandError> {
        match entry.value {
            Some(value) => {
                self.record(if fetched { "miss" } else { "hit" });
                Ok(value)
            }
            None => {
                self.record("not_found");
                Err(DemandError::NotFound)
            }
        }
    }

    fn spawn_fetch(self: &Arc<Self>, name: String, flight: Arc<Flight>) {
        let query = self.clone();
        tokio::spawn(async move {
            let result = query.fetch(&name).await;
            let _ = flight.result.set(result);
            query.flights.lock().unwrap().remove(&name);
            flight.done.notify_waiters();
        });
    }

    async fn fetch(&self, name: &str) -> Result<Cached, DemandError> {
        // A completing flight can publish between a caller's cache miss and its
        // flight insert; reuse that value instead of issuing a redundant RPC.
        if let Some(entry) = self.cache.get(name).await {
            return Ok(entry);
        }
        let result = self.query_backend(name).await;
        match &result {
            Ok(entry) => {
                self.cache.insert(name.to_owned(), entry.clone()).await;
                if let Some(value) = &entry.value {
                    self.stale.insert(name.to_owned(), value.clone()).await;
                }
                self.backoff.invalidate(name).await;
            }
            // Closed means the channel is not ready yet, not a backend failure;
            // backing off would delay the first query after connected().
            Err(DemandError::Closed) => {}
            Err(err) => {
                let failures = self.backoff.get(name).await.unwrap_or(0) + 1;
                self.backoff.insert(name.to_owned(), failures).await;
                tracing::warn!(error=%err, sandbox=%name, "Sandbox query failed");
            }
        }
        result
    }

    async fn query_backend(&self, name: &str) -> Result<Cached, DemandError> {
        let channel = self
            .channel
            .lock()
            .unwrap()
            .clone()
            .ok_or(DemandError::Closed)?;
        let node = &self.transport.node;
        let mut req = Request::new(GetSandboxRequest {
            name: name.to_owned(),
            node_id: node.id.clone(),
            node_metadata: node.metadata.clone(),
        });
        let token = self.transport.bearer().await.map_err(|err| {
            tracing::warn!(error=%err, "read Sandbox query credential");
            DemandError::Query(Code::Unauthenticated)
        })?;
        req.metadata_mut().insert("authorization", token);
        // The detached fetch bounds its own RPC; callers only bound their wait.
        req.set_timeout(Duration::from_secs(4));
        let reply = SandboxQueryServiceClient::new(channel)
            .max_decoding_message_size(i32::MAX as usize)
            .get_sandbox(req)
            .await
            .map_err(|s| DemandError::Query(s.code()))?
            .into_inner();
        let ttl: Duration = reply
            .cache_ttl
            .filter(|t| {
                (0..=315_576_000_000).contains(&t.seconds) && (0..1_000_000_000).contains(&t.nanos)
            })
            .ok_or(DemandError::Query(Code::DataLoss))?
            .try_into()
            .map_err(|_| DemandError::Query(Code::DataLoss))?;
        // Jitter desynchronizes expiries across instances so refresh load does not
        // align on the server's TTL boundary.
        let ttl = Duration::from_secs_f64(ttl.as_secs_f64() * rand::random_range(0.9..1.1));
        let value = reply
            .sandbox
            .map(|s| {
                if s.uid.is_empty() {
                    return Err(DemandError::Query(Code::DataLoss));
                }
                view::sandbox_view(s).map(Arc::new).map_err(|err| {
                    tracing::warn!(error=%err, "invalid Sandbox query response");
                    DemandError::Query(Code::DataLoss)
                })
            })
            .transpose()?;
        Ok(Cached { value, ttl })
    }
}
