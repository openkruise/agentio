// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::{
    config::{BandwidthLimit, Config},
    timer::Timer,
};
use crate::descriptor::Key;
use crate::streams::Streams;
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyHttpFilterScheduler;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, hash_map::Entry},
    num::NonZeroU64,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

pub struct Ledger {
    pub config: Config,
    pub streams: Streams,
    buckets: HashMap<Key, Bucket>,
    dynamic_buckets: usize,
    expirations: BTreeSet<(Instant, Key)>,
    pub waiters: HashMap<u64, Arc<dyn EnvoyHttpFilterScheduler>>,
    pending_batches: HashMap<(u64, usize), Batch>,
    next_ticket: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    Turn,
    Until(Instant),
}

struct Batch {
    ticket: u64,
    keys: Vec<Key>,
}

struct Bucket {
    queued: [BTreeMap<u64, u64>; 2],
    limits: BandwidthLimit,
    dynamic: bool,
    users: usize,
    // Time when all consumed credit has refilled, not the next batch's admission time.
    // Keeping idle buckets until then prevents reconnects from replenishing burst credit.
    ready: [Instant; 2],
    debt_rates: [Option<NonZeroU64>; 2],
}

pub struct Budget {
    pub ledger: Arc<Mutex<Ledger>>,
    pub timer: Arc<Timer>,
    reaper_id: u64,
}

// Config construction is staged; only accepted configurations publish a policy.
// Stream/config destruction never restores an older policy.
pub struct Registration {
    pub budget: Arc<Budget>,
}

impl Budget {
    pub fn new(config: Config) -> Result<Self, String> {
        let ledger = Arc::new(Mutex::new(Ledger::new(config)));
        let timer = Timer::shared().map_err(|e| e.to_string())?;
        let reaper_id = timer.id();
        Ok(Self {
            ledger,
            timer,
            reaper_id,
        })
    }

    pub fn reap_at(&self, due: Option<Instant>) {
        if let Some(due) = due {
            self.timer.reap_at(self.reaper_id, due, self.ledger.clone());
        }
    }

    pub fn shared(config: Config) -> Result<Registration, String> {
        static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<Budget>>>> = OnceLock::new();
        let mut registry = REGISTRY.get_or_init(Mutex::default).lock().unwrap();
        let now = Instant::now();
        registry.retain(|_, budget| {
            Arc::strong_count(budget) > 1 || !budget.ledger.lock().unwrap().idle(now)
        });
        let budget = match registry.entry(config.budget_name.clone()) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => entry.insert(Arc::new(Self::new(config.clone())?)).clone(),
        };
        let mut ledger = budget.ledger.lock().unwrap();
        ledger.update(config, now);
        let due = ledger.next_expiration();
        drop(ledger);
        budget.reap_at(due);
        Ok(Registration { budget })
    }
}

impl Ledger {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            streams: Streams::default(),
            buckets: HashMap::new(),
            dynamic_buckets: 0,
            expirations: BTreeSet::new(),
            waiters: HashMap::new(),
            pending_batches: HashMap::new(),
            next_ticket: 0,
        }
    }

    fn idle(&self, now: Instant) -> bool {
        self.buckets
            .values()
            .all(|b| b.users == 0 && b.ready.iter().all(|t| *t <= now))
    }

    fn update(&mut self, config: Config, now: Instant) {
        let layout_changed = self.streams.generation == 0
            || self.config.enabled != config.enabled
            || !self.config.same_layout(&config)
            || self.config.buffer_limit_bytes != config.buffer_limit_bytes;
        let changed = layout_changed || self.config.descriptors != config.descriptors;
        if changed {
            self.expirations.clear();
            for (key, bucket) in &mut self.buckets {
                let descriptor = config.descriptor(key);
                let new = descriptor
                    .map(|d| d.bandwidth_limit.clone())
                    .unwrap_or_default();
                if let Some(descriptor) = descriptor {
                    bucket.dynamic = descriptor.dynamic();
                }
                bucket.limits = new.clone();
                for (direction, new) in [new.upload_bytes_per_second, new.download_bytes_per_second]
                    .into_iter()
                    .enumerate()
                {
                    // Preserve existing debt while unlimited, including across candidate rollback.
                    let old = bucket.debt_rates[direction];
                    if new.is_some() && old != new {
                        let remaining = bucket.ready[direction].saturating_duration_since(now);
                        let delay = match (old, new) {
                            (Some(old), Some(new)) => {
                                let nanos = (remaining.as_nanos() * old.get() as u128)
                                    .div_ceil(new.get() as u128);
                                Duration::new(
                                    (nanos / 1_000_000_000) as u64,
                                    (nanos % 1_000_000_000) as u32,
                                )
                            }
                            _ => Duration::ZERO,
                        };
                        bucket.ready[direction] = now + delay;
                        bucket.debt_rates[direction] = new;
                    }
                }
                if bucket.users == 0 {
                    self.expirations
                        .insert((*bucket.ready.iter().max().unwrap(), key.clone()));
                }
            }
        }
        self.config = config;
        self.dynamic_buckets = self.buckets.values().filter(|b| b.dynamic).count();
        if layout_changed {
            self.streams.changed();
        }
        if changed {
            // Drop removes waiters under this lock, quiescing posts before worker teardown.
            for scheduler in self.waiters.values() {
                scheduler.commit(0);
            }
        }
    }

    pub fn rebind(&mut self, id: u64, old: &[Key], new: &[Key], now: Instant) -> Option<Instant> {
        let added: Vec<_> = new.iter().filter(|k| !old.contains(k)).cloned().collect();
        let removed: Vec<_> = old.iter().filter(|k| !new.contains(k)).cloned().collect();
        self.acquire_inner(&added, now, false).unwrap();
        if old != new {
            for direction in 0..2 {
                if let Some(mut batch) = self.take_batch(id, direction) {
                    batch.keys = new.to_vec();
                    self.insert_batch(id, direction, batch);
                }
            }
        }
        self.release(&removed, now)
    }

    pub fn acquire(&mut self, keys: &[Key], now: Instant) -> Result<(), ()> {
        self.acquire_inner(keys, now, true)
    }
    fn acquire_inner(&mut self, keys: &[Key], now: Instant, admission: bool) -> Result<(), ()> {
        self.reap(now);
        let needed = keys
            .iter()
            .filter(|k| {
                self.config.descriptor(k).unwrap().dynamic() && !self.buckets.contains_key(*k)
            })
            .count();
        if admission
            && needed > 0
            && self.dynamic_buckets + needed > self.config.max_dynamic_buckets
        {
            return Err(());
        }
        self.dynamic_buckets += needed;
        for key in keys {
            let descriptor = self.config.descriptor(key).unwrap();
            let bucket = self.buckets.entry(key.clone()).or_insert(Bucket {
                queued: Default::default(),
                limits: descriptor.bandwidth_limit.clone(),
                dynamic: descriptor.dynamic(),
                users: 0,
                ready: [now; 2],
                debt_rates: [None; 2],
            });
            if bucket.users == 0 {
                self.expirations
                    .remove(&(*bucket.ready.iter().max().unwrap(), key.clone()));
            }
            bucket.users += 1;
        }
        Ok(())
    }

    pub fn release(&mut self, keys: &[Key], now: Instant) -> Option<Instant> {
        for key in keys {
            let bucket = self.buckets.get_mut(key).unwrap();
            bucket.users -= 1;
            if bucket.users == 0 {
                let due = *bucket.ready.iter().max().unwrap();
                if due <= now {
                    self.remove_bucket(key);
                } else {
                    self.expirations.insert((due, key.clone()));
                }
            }
        }
        self.next_expiration()
    }

    fn remove_bucket(&mut self, key: &Key) {
        let bucket = self.buckets.remove(key).unwrap();
        self.dynamic_buckets -= usize::from(bucket.dynamic);
    }

    fn next_expiration(&self) -> Option<Instant> {
        self.expirations.first().map(|(due, _)| *due)
    }

    pub fn reap(&mut self, now: Instant) -> Option<Instant> {
        // Bound time under the shared ledger lock; the timer continues any remaining batch.
        for _ in 0..64 {
            if self.next_expiration().is_none_or(|due| due > now) {
                break;
            }
            let (_, key) = self.expirations.pop_first().unwrap();
            self.remove_bucket(&key);
        }
        self.next_expiration()
    }

    // Tickets order whole buffered batches, independently in each direction. A stream
    // that just made progress rejoins at the tail rather than racing all waiters.
    // The same ticket enters every applicable bucket, preventing cyclic waits when
    // a stream is constrained by both a tenant and a sandbox budget.
    pub fn admit_batch(
        &mut self,
        id: u64,
        keys: &[Key],
        direction: usize,
        bytes: usize,
        now: Instant,
    ) -> Option<Wait> {
        if bytes == 0 {
            self.take_batch(id, direction);
            return None;
        }
        let behind = keys.iter().any(|key| {
            let bucket = &self.buckets[key];
            let rate = if direction == 0 {
                bucket.limits.upload_bytes_per_second
            } else {
                bucket.limits.download_bytes_per_second
            };
            rate.is_some()
                && bucket.queued[direction]
                    .first_key_value()
                    .is_some_and(|(_, first)| *first != id)
        });
        let waiting = if behind {
            Some(Wait::Turn)
        } else {
            self.charge(keys, direction, bytes, now).map(Wait::Until)
        };
        if waiting.is_some() {
            if !self.pending_batches.contains_key(&(id, direction)) {
                self.next_ticket += 1;
                self.insert_batch(
                    id,
                    direction,
                    Batch {
                        ticket: self.next_ticket,
                        keys: keys.to_vec(),
                    },
                );
            }
        } else {
            self.take_batch(id, direction);
        }
        waiting
    }

    fn insert_batch(&mut self, id: u64, direction: usize, batch: Batch) {
        for key in &batch.keys {
            self.buckets.get_mut(key).unwrap().queued[direction].insert(batch.ticket, id);
        }
        self.pending_batches.insert((id, direction), batch);
    }

    fn take_batch(&mut self, id: u64, direction: usize) -> Option<Batch> {
        let batch = self.pending_batches.remove(&(id, direction))?;
        for key in &batch.keys {
            self.buckets.get_mut(key).unwrap().queued[direction].remove(&batch.ticket);
        }
        // Wake only successors, not every contender. Non-head waiters have no timer.
        for key in &batch.keys {
            if let Some((_, next)) = self.buckets[key].queued[direction].first_key_value()
                && let Some(scheduler) = self.waiters.get(next)
            {
                scheduler.commit(0);
            }
        }
        Some(batch)
    }

    pub fn cancel_batches(&mut self, id: u64) {
        for direction in 0..2 {
            self.take_batch(id, direction);
        }
    }

    pub fn charge(
        &mut self,
        keys: &[Key],
        direction: usize,
        bytes: usize,
        now: Instant,
    ) -> Option<Instant> {
        if bytes == 0 {
            return None;
        }
        let limits = |key: &Key| {
            let limit = &self.buckets[key].limits;
            if direction == 0 {
                (limit.upload_bytes_per_second, limit.upload_burst_bytes)
            } else {
                (limit.download_bytes_per_second, limit.download_burst_bytes)
            }
        };
        let due = keys
            .iter()
            .filter_map(|k| {
                let (rate, burst) = limits(k);
                rate.map(|rate| {
                    let remaining = self.buckets[k].ready[direction].saturating_duration_since(now);
                    // Reserve enough credit for the whole batch. Oversized batches require a full
                    // bucket; they pass whole and their entire cost remains payable afterward.
                    let credit = burst.map_or(0, |b| b.get().saturating_sub(bytes as u64));
                    let slack = Duration::from_secs(credit / rate.get())
                        + Duration::from_nanos(
                            ((credit % rate.get()) as u128 * 1_000_000_000 / rate.get() as u128)
                                as u64,
                        );
                    now + remaining.saturating_sub(slack)
                })
            })
            .max();
        if let Some(due) = due.filter(|t| *t > now) {
            return Some(due);
        }
        // Check all budgets before charging any; a tenant and its sandbox must commit together.
        // shortcut: oversized callback batches can exceed burst capacity; strict caps need partial injection.
        for key in keys {
            let limit = &self.buckets[key].limits;
            let rate = if direction == 0 {
                limit.upload_bytes_per_second
            } else {
                limit.download_bytes_per_second
            };
            if let Some(rate) = rate {
                let bucket = self.buckets.get_mut(key).unwrap();
                bucket.debt_rates[direction] = Some(rate);
                let bytes = bytes as u64;
                let rate = rate.get();
                let delay = Duration::from_secs(bytes / rate)
                    + Duration::from_nanos(
                        ((bytes % rate) as u128 * 1_000_000_000).div_ceil(rate as u128) as u64,
                    );
                bucket.ready[direction] = bucket.ready[direction].max(now) + delay;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoy_proxy_dynamic_modules_rust_sdk::MockEnvoyHttpFilterScheduler;

    fn config() -> Config {
        Config::parse(br#"{"rate_limits":[{"actions":[{"filter_state":{"key":"id","descriptor_key":"id"}}]}],
            "descriptors":[{"entries":[{"key":"id"}],"bandwidth_limit":{"upload_bytes_per_second":100,"download_bytes_per_second":200}}]}"#).unwrap()
    }

    #[test]
    fn last_release_removes_settled_buckets_immediately() {
        let config = config();
        let keys = config.resolve(|_| Some("a".into())).unwrap();
        let mut ledger = Ledger::new(config);
        let now = Instant::now();
        ledger.acquire(&keys, now).unwrap();
        ledger.acquire(&keys, now).unwrap();
        ledger.charge(&keys, 0, 100, now);
        ledger.release(&keys, now + Duration::from_secs(1));
        assert_eq!(ledger.buckets[&keys[0]].users, 1);
        assert!(ledger.expirations.is_empty());
        ledger.release(&keys, now + Duration::from_secs(1));
        assert!(ledger.buckets.is_empty());
        assert_eq!(ledger.dynamic_buckets, 0);
    }

    #[test]
    fn partially_used_burst_survives_reconnect_until_fully_refilled() {
        let mut config = config();
        config.descriptors[0].bandwidth_limit.upload_burst_bytes = Some(1000.try_into().unwrap());
        let keys = config.resolve(|_| Some("a".into())).unwrap();
        let mut ledger = Ledger::new(config);
        let now = Instant::now();
        ledger.acquire(&keys, now).unwrap();
        for i in 1..=10 {
            assert_eq!(ledger.charge(&keys, 0, 100, now), None);
            assert_eq!(
                ledger.release(&keys, now),
                Some(now + Duration::from_secs(i))
            );
            ledger.acquire(&keys, now).unwrap();
        }
        assert_eq!(
            ledger.charge(&keys, 0, 100, now),
            Some(now + Duration::from_secs(1))
        );
        ledger.release(&keys, now);
        ledger.reap(now + Duration::from_secs(9));
        assert_eq!(ledger.dynamic_buckets, 1);
        ledger.reap(now + Duration::from_secs(10));
        assert_eq!(ledger.dynamic_buckets, 0);
        ledger
            .acquire(&keys, now + Duration::from_secs(10))
            .unwrap();
        assert_eq!(
            ledger.charge(&keys, 0, 1000, now + Duration::from_secs(10)),
            None
        );
    }

    #[test]
    fn burst_resize_and_rate_update_preserve_consumption_and_wake_waiters() {
        let mut config = config();
        config.descriptors[0].bandwidth_limit.upload_burst_bytes = Some(1000.try_into().unwrap());
        let original = config.clone();
        let keys = config.resolve(|_| Some("a".into())).unwrap();
        let mut ledger = Ledger::new(config.clone());
        let now = Instant::now();
        ledger.acquire(&keys, now).unwrap();
        assert_eq!(ledger.charge(&keys, 0, 1000, now), None);
        let mut scheduler = MockEnvoyHttpFilterScheduler::new();
        scheduler.expect_commit().times(4).return_const(());
        ledger.waiters.insert(1, Arc::new(scheduler));
        config.descriptors[0].bandwidth_limit.upload_burst_bytes = Some(500.try_into().unwrap());
        ledger.update(config.clone(), now);
        assert_eq!(
            ledger.charge(&keys, 0, 100, now),
            Some(now + Duration::from_secs(6))
        );
        config.descriptors[0].bandwidth_limit.upload_burst_bytes = Some(2000.try_into().unwrap());
        ledger.update(config, now);
        assert_eq!(ledger.charge(&keys, 0, 1000, now), None);
        ledger.update(original.clone(), now);
        assert_eq!(
            ledger.charge(&keys, 0, 100, now),
            Some(now + Duration::from_secs(11))
        );
        ledger.release(&keys, now);
        let mut faster = original;
        faster.descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second = Some(200.try_into().unwrap());
        ledger.update(faster, now + Duration::from_secs(2));
        assert_eq!(
            ledger.next_expiration(),
            Some(now + Duration::from_secs(11))
        );
        ledger.acquire(&keys, now + Duration::from_secs(2)).unwrap();
        assert_eq!(
            ledger.charge(&keys, 0, 100, now + Duration::from_secs(2)),
            Some(now + Duration::from_millis(6500))
        );
    }

    #[test]
    fn reconnect_cancels_expiration_without_resetting_debt() {
        let config = config();
        let keys = config.resolve(|_| Some("a".into())).unwrap();
        let mut ledger = Ledger::new(config);
        let now = Instant::now();
        ledger.acquire(&keys, now).unwrap();
        ledger.charge(&keys, 0, 100, now);
        ledger.charge(&keys, 1, 400, now);
        let due = now + Duration::from_secs(2);
        for _ in 0..100 {
            assert_eq!(ledger.release(&keys, now), Some(due));
            assert_eq!(ledger.expirations.len(), 1);
            ledger.acquire(&keys, now).unwrap();
            assert!(ledger.expirations.is_empty());
            assert_eq!(ledger.charge(&keys, 1, 1, now), Some(due));
        }
        ledger.reap(due);
        assert_eq!(ledger.buckets[&keys[0]].users, 1);
        ledger.release(&keys, due);
        assert!(ledger.buckets.is_empty());
        assert_eq!(ledger.dynamic_buckets, 0);
    }

    #[test]
    fn idle_expiration_tracks_rate_updates_and_rollback() {
        let mut config = config();
        let original = config.clone();
        let keys = config.resolve(|_| Some("a".into())).unwrap();
        let mut ledger = Ledger::new(config.clone());
        let now = Instant::now();
        ledger.acquire(&keys, now).unwrap();
        ledger.charge(&keys, 0, 1000, now);
        ledger.release(&keys, now);
        config.descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second = Some(200.try_into().unwrap());
        ledger.update(config, now + Duration::from_secs(2));
        assert_eq!(ledger.next_expiration(), Some(now + Duration::from_secs(6)));
        ledger.update(original, now + Duration::from_secs(3));
        assert_eq!(ledger.next_expiration(), Some(now + Duration::from_secs(9)));
        assert_eq!(ledger.expirations.len(), 1);
        ledger.reap(now + Duration::from_secs(6));
        assert_eq!(ledger.buckets.len(), 1);
        ledger.reap(now + Duration::from_secs(9));
        assert!(ledger.buckets.is_empty());
        assert_eq!(ledger.dynamic_buckets, 0);
    }

    #[test]
    fn expiration_reclaims_only_a_bounded_batch() {
        let config = config();
        let mut ledger = Ledger::new(config.clone());
        let now = Instant::now();
        for i in 0..130 {
            let keys = config.resolve(|_| Some(i.to_string())).unwrap();
            ledger.acquire(&keys, now).unwrap();
            ledger.charge(&keys, 0, 100, now);
            ledger.release(&keys, now);
        }
        let due = now + Duration::from_secs(1);
        assert_eq!(ledger.reap(due), Some(due));
        assert_eq!(ledger.buckets.len(), 66);
        assert_eq!(ledger.dynamic_buckets, 66);
        assert_eq!(ledger.reap(due), Some(due));
        assert_eq!(ledger.buckets.len(), 2);
        assert_eq!(ledger.reap(due), None);
        assert!(ledger.buckets.is_empty());
        assert_eq!(ledger.dynamic_buckets, 0);
    }

    #[test]
    fn timer_reclaims_idle_buckets_after_config_drop_without_new_traffic() {
        let mut config = config();
        config.budget_name = "idle-reaper-test".into();
        let registration = Budget::shared(config.clone()).unwrap();
        let budget = registration.budget.clone();
        assert!(Arc::ptr_eq(
            &budget.timer,
            &Budget::new(config.clone()).unwrap().timer
        ));
        let now = Instant::now();
        let mut ledger = budget.ledger.lock().unwrap();
        for i in 0..130 {
            let keys = config.resolve(|_| Some(i.to_string())).unwrap();
            ledger.acquire(&keys, now).unwrap();
            ledger.charge(&keys, 0, 10, now);
            ledger.release(&keys, now);
        }
        let due = ledger.next_expiration();
        assert_eq!(ledger.expirations.len(), 130);
        drop(ledger);
        budget.reap_at(due);
        let ledger = budget.ledger.clone();
        drop(registration);
        drop(budget);
        let timeout = Instant::now() + Duration::from_secs(2);
        loop {
            let ledger = ledger.lock().unwrap();
            if ledger.buckets.is_empty() {
                assert!(ledger.expirations.is_empty());
                assert_eq!(ledger.dynamic_buckets, 0);
                break;
            }
            assert!(Instant::now() < timeout, "idle bucket was not reclaimed");
            drop(ledger);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn rate_updates_preserve_unpaid_bytes_and_wake_waiters() {
        let mut config = Config::parse(br#"{"rate_limits":[{"actions":[{"filter_state":{"key":"id","descriptor_key":"id"}}]}],
            "descriptors":[{"entries":[{"key":"id"}],"bandwidth_limit":{"upload_bytes_per_second":100,"download_bytes_per_second":200}}]}"#).unwrap();
        let keys = config.resolve(|_| Some("a".into())).unwrap();
        let mut ledger = Ledger::new(config.clone());
        let now = Instant::now();
        ledger.acquire(&keys, now).unwrap();
        ledger.charge(&keys, 0, 1000, now);
        ledger.charge(&keys, 1, 2000, now);
        let mut scheduler = MockEnvoyHttpFilterScheduler::new();
        scheduler.expect_commit().times(4).return_const(());
        ledger.waiters.insert(1, Arc::new(scheduler));

        config.descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second = Some(200.try_into().unwrap());
        ledger.update(config.clone(), now + Duration::from_secs(2));
        assert_eq!(
            ledger.charge(&keys, 0, 1, now + Duration::from_secs(2)),
            Some(now + Duration::from_secs(6))
        );
        assert_eq!(
            ledger.charge(&keys, 1, 1, now + Duration::from_secs(2)),
            Some(now + Duration::from_secs(10))
        );
        config.descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second = Some(50.try_into().unwrap());
        ledger.update(config.clone(), now + Duration::from_secs(3));
        assert_eq!(
            ledger.charge(&keys, 0, 1, now + Duration::from_secs(3)),
            Some(now + Duration::from_secs(15))
        );
        config.descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second = None;
        ledger.update(config.clone(), now + Duration::from_secs(4));
        assert_eq!(
            ledger.charge(&keys, 0, 100, now + Duration::from_secs(4)),
            None
        );
        config.descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second = Some(50.try_into().unwrap());
        ledger.update(config, now + Duration::from_secs(5));
        assert_eq!(
            ledger.charge(&keys, 0, 1, now + Duration::from_secs(5)),
            Some(now + Duration::from_secs(15))
        );
    }
}
