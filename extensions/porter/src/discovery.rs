// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

//! Demand-only Delta ADS with bounded retained interests. A generation survives
//! concurrent waiters; deletion ends that generation even if a new one is acquired.
//! Network backpressure never holds the state lock or stops receiving responses.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use lru::LruCache;
use tokio::{
    sync::{Notify, watch},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{
    metrics::{DemandResult, Eviction, Metrics, ResourceType},
    view::{self, ResourceKind, View},
    wire::ads::{self, DeltaDiscoveryRequest as Request, DeltaDiscoveryResponse as Response, Node},
};

mod transport;
pub use transport::TransportConfig;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
enum Outcome {
    Pending,
    Ready(Arc<View>),
    Missing,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DemandError {
    #[error("invalid resource name")]
    InvalidName,
    #[error("resource not found")]
    NotFound,
    #[error("resource alias is ambiguous")]
    Ambiguous,
    #[error("resource watch closed")]
    Closed,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct ResourceKey {
    kind: ResourceKind,
    name: String,
}

struct Generation {
    id: u64,
    // The epoch invalidates values still held by in-flight callers after disconnect.
    value: watch::Sender<(u64, Outcome)>,
}

struct Entry {
    generation: Arc<Generation>,
    users: usize,
}

struct Resource {
    value: Arc<View>,
    aliases: Vec<String>,
}

#[derive(Default)]
struct TypeState {
    // Set only after the first accepted response on the current ADS stream.
    synced: bool,
    resources: HashMap<String, Resource>,
    aliases: HashMap<String, HashSet<String>>,
    entries: HashMap<String, Entry>,
    dirty: HashSet<String>,
    ack: Option<(String, Option<ads::Status>)>,
}

impl TypeState {
    fn interested(&self, name: &str, aliases: &[String]) -> bool {
        self.entries.contains_key(name) || aliases.iter().any(|a| self.entries.contains_key(a))
    }

    fn resolve(&self, name: &str) -> Outcome {
        if !self.synced {
            return Outcome::Pending;
        }
        let canonical = match self.aliases.get(name) {
            Some(owners) if owners.len() != 1 => return Outcome::Ambiguous,
            Some(owners) => owners.iter().next().unwrap().as_str(),
            None => name,
        };
        self.resources
            .get(canonical)
            .map(|resource| Outcome::Ready(resource.value.clone()))
            .unwrap_or(Outcome::Pending)
    }

    fn remove_resource(&mut self, name: &str) -> Option<Resource> {
        let resource = self.resources.remove(name)?;
        for alias in &resource.aliases {
            if let Some(owners) = self.aliases.get_mut(alias) {
                owners.remove(name);
                if owners.is_empty() {
                    self.aliases.remove(alias);
                }
            }
        }
        Some(resource)
    }

    fn release(&mut self, name: &str) {
        let owners = self
            .aliases
            .get(name)
            .map(|owners| owners.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_else(|| vec![name.into()]);
        for owner in owners {
            if self
                .resources
                .get(&owner)
                .is_some_and(|resource| !self.interested(&owner, &resource.aliases))
            {
                self.remove_resource(&owner);
            }
        }
    }
}

struct State {
    types: [TypeState; 2],
    idle: LruCache<ResourceKey, Instant>,
    next_generation: u64,
}

#[derive(Clone, Copy)]
pub struct CacheConfig {
    pub idle_ttl: Duration,
    pub max_entries: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            idle_ttl: Duration::from_secs(60),
            max_entries: 10000,
        }
    }
}

pub struct Client {
    state: Mutex<State>,
    epoch: AtomicU64,
    config: CacheConfig,
    wake: Notify,
    expiry: Notify,
    ready: watch::Sender<bool>,
    pub metrics: Arc<Metrics>,
}

impl Client {
    pub fn new(config: CacheConfig, metrics: Arc<Metrics>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                types: Default::default(),
                idle: LruCache::unbounded(),
                next_generation: 0,
            }),
            epoch: AtomicU64::new(0),
            config,
            wake: Notify::new(),
            expiry: Notify::new(),
            ready: watch::channel(false).0,
            metrics,
        })
    }

    pub fn readiness(&self) -> watch::Receiver<bool> {
        self.ready.subscribe()
    }

    fn size(state: &State) -> usize {
        state
            .types
            .iter()
            .map(|type_state| type_state.entries.len())
            .sum()
    }

    fn publish_size(&self, state: &State) {
        self.metrics.cache.set(if self.retained() {
            Self::size(state) as i64
        } else {
            0
        });
    }

    fn retained(&self) -> bool {
        self.config.max_entries > 0 || !self.config.idle_ttl.is_zero()
    }

    fn remove(&self, state: &mut State, key: &ResourceKey) {
        state.idle.pop(key);
        let type_state = &mut state.types[key.kind.index()];
        type_state.entries.remove(&key.name);
        type_state.dirty.insert(key.name.clone());
        type_state.release(&key.name);
        self.wake.notify_one();
    }

    fn prune(&self, state: &mut State, now: Instant) {
        while let Some((key, last)) = state.idle.peek_lru() {
            let capacity =
                self.config.max_entries > 0 && Self::size(state) > self.config.max_entries;
            let expired = !self.config.idle_ttl.is_zero()
                && now.duration_since(*last) >= self.config.idle_ttl;
            if !capacity && !expired {
                break;
            }
            let key = key.clone();
            self.metrics
                .cache_evictions
                .get_or_create(&Eviction {
                    resource_type: key.kind.type_url(),
                    reason: if expired { "idle_ttl" } else { "capacity" },
                })
                .inc();
            self.remove(state, &key);
        }
        self.publish_size(state);
    }

    fn acquire(self: &Arc<Self>, kind: ResourceKind, name: &str) -> Result<Lease, DemandError> {
        if name.is_empty() || name == "*" {
            return Err(DemandError::InvalidName);
        }
        let key = ResourceKey {
            kind,
            name: name.into(),
        };
        let mut state = self.state.lock().unwrap();
        self.prune(&mut state, Instant::now());
        state.idle.pop(&key);
        if !state.types[kind.index()].entries.contains_key(name) {
            state.next_generation += 1;
            let generation = Arc::new(Generation {
                id: state.next_generation,
                value: watch::channel((
                    self.epoch.load(Ordering::Relaxed),
                    state.types[kind.index()].resolve(name),
                ))
                .0,
            });
            state.types[kind.index()].entries.insert(
                name.into(),
                Entry {
                    generation,
                    users: 0,
                },
            );
            state.types[kind.index()].dirty.insert(name.into());
            self.wake.notify_one();
        }
        let entry = state.types[kind.index()].entries.get_mut(name).unwrap();
        entry.users += 1;
        let generation = entry.generation.clone();
        self.prune(&mut state, Instant::now());
        Ok(Lease {
            client: self.clone(),
            key,
            generation,
            success: false,
        })
    }

    /// Wait for a resource within the caller's shared request budget.
    ///
    /// The caller enforces the timeout. `request_deadline` only classifies a
    /// dropped pending demand as a timeout rather than another cancellation.
    pub async fn demand(
        self: &Arc<Self>,
        kind: ResourceKind,
        name: &str,
        request_deadline: Option<Instant>,
    ) -> Result<Arc<View>, DemandError> {
        let mut lease = self.acquire(kind, name)?;
        let mut receiver = lease.generation.value.subscribe();
        self.metrics
            .cache_lookups
            .get_or_create(&DemandResult {
                resource_type: kind.type_url(),
                result: if matches!(self.current(&receiver.borrow()), Outcome::Ready(_)) {
                    "hit"
                } else {
                    "miss"
                },
            })
            .inc();
        let mut measurement: Option<WaitMeasurement> = None;
        loop {
            let outcome = self.current(&receiver.borrow_and_update()).clone();
            let result = match outcome {
                Outcome::Ready(value) => Some(Ok(value)),
                Outcome::Missing => Some(Err(DemandError::NotFound)),
                Outcome::Ambiguous => Some(Err(DemandError::Ambiguous)),
                Outcome::Pending => None,
            };
            if let Some(result) = result {
                lease.success = result.is_ok();
                if let Some(m) = measurement.as_mut() {
                    m.result = match &result {
                        Ok(_) => "success",
                        Err(DemandError::NotFound) => "not_found",
                        Err(_) => "error",
                    };
                }
                return result;
            }
            if measurement.is_none() {
                measurement = Some(WaitMeasurement::new(
                    self.metrics.clone(),
                    kind,
                    request_deadline,
                ));
            }
            if receiver.changed().await.is_err() {
                measurement.as_mut().unwrap().result = "error";
                return Err(DemandError::Closed);
            }
        }
    }

    // The epoch invalidates outcomes held by callers across disconnects.
    // Missing ends a generation and remains terminal even if its removed entry
    // is no longer in the cache.
    fn current<'a>(&self, value: &'a (u64, Outcome)) -> &'a Outcome {
        if matches!(value.1, Outcome::Missing) || value.0 == self.epoch.load(Ordering::Acquire) {
            &value.1
        } else {
            &Outcome::Pending
        }
    }

    pub async fn expire(self: Arc<Self>, stop: CancellationToken) {
        loop {
            let deadline = {
                let mut state = self.state.lock().unwrap();
                self.prune(&mut state, Instant::now());
                if self.config.idle_ttl.is_zero() {
                    None
                } else {
                    state
                        .idle
                        .peek_lru()
                        .map(|(_, t)| *t + self.config.idle_ttl)
                }
            };
            tokio::select! {
                _ = stop.cancelled() => break,
                _ = self.expiry.notified() => {},
                _ = async {
                    match deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                } => {},
            }
        }
    }

    fn reset(&self) {
        let started = Instant::now();
        let mut state = self.state.lock().unwrap();
        let mut retired_types = std::mem::take(&mut state.types);
        let retired_idle = std::mem::replace(&mut state.idle, LruCache::unbounded());
        for (type_state, retired) in state.types.iter_mut().zip(&mut retired_types) {
            // Preserve generations owned by waiting callers. Idle interests are
            // rediscovered on demand instead of replaying the historical cache.
            type_state
                .entries
                .extend(retired.entries.extract_if(|_, entry| entry.users > 0));
        }
        self.epoch.fetch_add(1, Ordering::Release);
        self.publish_size(&state);
        self.metrics.connected.set(0);
        self.ready.send_replace(false);
        drop(state);
        // Resource views and idle generations can be large; release them without
        // holding the mutex needed by newly arriving demands.
        drop(retired_types);
        drop(retired_idle);
        self.expiry.notify_one();
        tracing::debug!(
            reset_us = started.elapsed().as_micros() as u64,
            "invalidated ADS cache"
        );
    }

    fn initial(
        &self,
        node: &Node,
        sent_generations: &mut [HashMap<String, u64>; 2],
    ) -> Vec<Request> {
        let mut state = self.state.lock().unwrap();
        ResourceKind::ALL
            .into_iter()
            .map(|kind| {
                let type_state = &mut state.types[kind.index()];
                let mut request = Request {
                    node: Some(node.clone()),
                    type_url: kind.type_url().into(),
                    ..Default::default()
                };
                for (name, entry) in &type_state.entries {
                    request.resource_names_subscribe.push(name.clone());
                    sent_generations[kind.index()].insert(name.clone(), entry.generation.id);
                }
                type_state.dirty = HashSet::new();
                type_state.ack = None;
                if request.resource_names_subscribe.is_empty() {
                    request.resource_names_subscribe.push("*".into());
                    request.resource_names_unsubscribe.push("*".into());
                }
                request
            })
            .collect()
    }

    fn outgoing(&self, sent_generations: &mut [HashMap<String, u64>; 2]) -> Vec<Request> {
        let mut state = self.state.lock().unwrap();
        let mut requests = Vec::new();
        for kind in ResourceKind::ALL {
            let type_state = &mut state.types[kind.index()];
            let mut request = Request {
                type_url: kind.type_url().into(),
                ..Default::default()
            };
            for name in std::mem::take(&mut type_state.dirty) {
                match type_state.entries.get(&name) {
                    Some(entry)
                        if sent_generations[kind.index()].get(&name)
                            != Some(&entry.generation.id) =>
                    {
                        sent_generations[kind.index()].insert(name.clone(), entry.generation.id);
                        request.resource_names_subscribe.push(name);
                    }
                    None if sent_generations[kind.index()].remove(&name).is_some() => {
                        request.resource_names_unsubscribe.push(name)
                    }
                    _ => {}
                }
            }
            let ack = type_state.ack.take();
            if ack.is_some()
                || !request.resource_names_subscribe.is_empty()
                || !request.resource_names_unsubscribe.is_empty()
            {
                if let Some((nonce, error)) = ack {
                    request.response_nonce = nonce;
                    request.error_detail = error;
                }
                requests.push(request);
            }
        }
        requests
    }

    fn apply(&self, kind: ResourceKind, response: &Response) -> Result<()> {
        let started = Instant::now();
        let mut seen = HashSet::new();
        for resource in &response.resources {
            if resource.name.is_empty() {
                bail!("empty resource name");
            }
            if resource
                .resource
                .as_ref()
                .is_none_or(|value| value.type_url != response.type_url)
            {
                bail!(
                    "resource {} has a missing or incorrect payload type",
                    resource.name
                );
            }
            if resource.ttl.is_some() {
                bail!("resource {} uses unsupported resource TTL", resource.name);
            }
            if !seen.insert(&resource.name) {
                bail!("duplicate resource {}", resource.name);
            }
            if resource
                .aliases
                .iter()
                .any(|alias| alias.is_empty() || alias == "*")
            {
                bail!("resource {} has an invalid alias", resource.name);
            }
        }
        for name in &response.removed_resources {
            if name.is_empty() || !seen.insert(name) {
                bail!("invalid or conflicting removal {name}");
            }
        }

        // Decode before publication, outside the lock. Reject the entire delta
        // on a projection error. Late updates for released interests are ignored.
        let selected = {
            let state = self.state.lock().unwrap();
            response
                .resources
                .iter()
                .filter(|resource| {
                    state.types[kind.index()].interested(&resource.name, &resource.aliases)
                })
                .collect::<Vec<_>>()
        };
        let selected_at = Instant::now();
        let values = selected
            .into_iter()
            .map(|resource| {
                Ok((
                    resource.name.clone(),
                    Arc::new(
                        view::decode(kind, resource.resource.as_ref().unwrap())
                            .with_context(|| format!("decode resource {}", resource.name))?,
                    ),
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;
        let decoded_at = Instant::now();
        let mut state = self.state.lock().unwrap();
        let type_state = &mut state.types[kind.index()];
        let mut touched = HashSet::new();
        let mut vanished = HashSet::new();
        if !type_state.synced {
            for name in &response.removed_resources {
                if let Some(old) = type_state.resources.get(name) {
                    vanished.extend(old.aliases.iter().cloned());
                }
            }
            type_state.resources.clear();
            type_state.aliases.clear();
        }
        for resource in &response.resources {
            touched.insert(resource.name.clone());
            touched.extend(resource.aliases.iter().cloned());
            if let Some(old) = type_state.remove_resource(&resource.name) {
                vanished.extend(old.aliases);
            }
            if type_state.interested(&resource.name, &resource.aliases) {
                if let Some(value) = values.get(&resource.name) {
                    for alias in &resource.aliases {
                        type_state
                            .aliases
                            .entry(alias.clone())
                            .or_default()
                            .insert(resource.name.clone());
                    }
                    type_state.resources.insert(
                        resource.name.clone(),
                        Resource {
                            value: value.clone(),
                            aliases: resource.aliases.clone(),
                        },
                    );
                } else {
                    // Acquired while decoding an unsolicited update: its pending
                    // subscribe will request a fresh response.
                }
            }
        }
        for name in &response.removed_resources {
            if let Some(old) = type_state.remove_resource(name) {
                vanished.extend(old.aliases);
            }
            vanished.insert(name.clone());
        }
        type_state.synced = true;
        let epoch = self.epoch.load(Ordering::Relaxed);
        touched.extend(vanished.iter().cloned());
        let mut deleted = Vec::new();
        for name in touched {
            if let Some(entry) = type_state.entries.get(&name) {
                let outcome = type_state.resolve(&name);
                if vanished.contains(&name) && matches!(outcome, Outcome::Pending) {
                    entry
                        .generation
                        .value
                        .send_replace((epoch, Outcome::Missing));
                    deleted.push(name);
                } else {
                    entry.generation.value.send_replace((epoch, outcome));
                }
            }
        }
        for name in deleted {
            self.remove(&mut state, &ResourceKey { kind, name });
        }
        self.publish_size(&state);
        let ready = state.types.iter().all(|type_state| type_state.synced);
        self.ready.send_if_modified(|old| {
            if *old == ready {
                false
            } else {
                *old = ready;
                true
            }
        });
        tracing::debug!(
            resource_type = kind.type_url(),
            resources = response.resources.len(),
            select_us = (selected_at - started).as_micros() as u64,
            transform_us = (decoded_at - selected_at).as_micros() as u64,
            publish_us = decoded_at.elapsed().as_micros() as u64,
            total_us = started.elapsed().as_micros() as u64,
            "applied ADS response"
        );
        Ok(())
    }
}

struct Lease {
    client: Arc<Client>,
    key: ResourceKey,
    generation: Arc<Generation>,
    success: bool,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self.client.state.lock().unwrap();
        if let Some(entry) = state.types[self.key.kind.index()]
            .entries
            .get_mut(&self.key.name)
        {
            if entry.generation.id != self.generation.id {
                return;
            }
            entry.users -= 1;
            // Both bounds disabled bypass the retention manager, as in Go:
            // the underlying demand subscription remains until server deletion.
            if entry.users == 0 && self.client.retained() {
                if !self.success {
                    self.client.remove(&mut state, &self.key);
                } else {
                    state.idle.put(self.key.clone(), Instant::now());
                    self.client.prune(&mut state, Instant::now());
                }
            }
        }
        self.client.publish_size(&state);
        self.client.expiry.notify_one();
    }
}

struct WaitMeasurement {
    metrics: Arc<Metrics>,
    kind: ResourceKind,
    start: Instant,
    result: &'static str,
    request_deadline: Option<Instant>,
}

impl WaitMeasurement {
    fn new(metrics: Arc<Metrics>, kind: ResourceKind, request_deadline: Option<Instant>) -> Self {
        metrics
            .waiters
            .get_or_create(&ResourceType {
                resource_type: kind.type_url(),
            })
            .inc();
        Self {
            metrics,
            kind,
            start: Instant::now(),
            result: "canceled",
            request_deadline,
        }
    }
}

impl Drop for WaitMeasurement {
    fn drop(&mut self) {
        if self.result == "canceled" && self.request_deadline.is_some_and(|d| Instant::now() >= d) {
            self.result = "timeout";
        }
        self.metrics
            .waiters
            .get_or_create(&ResourceType {
                resource_type: self.kind.type_url(),
            })
            .dec();
        self.metrics
            .wait
            .get_or_create(&DemandResult {
                resource_type: self.kind.type_url(),
                result: self.result,
            })
            .observe(self.start.elapsed().as_secs_f64());
    }
}
