// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    descriptor::{self, Entry, Key, MatchDescriptor, RateLimit},
    streams::Streams,
};
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, HttpFilter, HttpFilterConfig,
    abi::envoy_dynamic_module_type_on_http_filter_request_headers_status as Headers,
};
use serde::Deserialize;
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    num::NonZeroU32,
    sync::{Arc, Mutex, OnceLock},
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default = "enabled")]
    enabled: bool,
    #[serde(default = "descriptor::default_budget_name")]
    budget_name: String,
    #[serde(default)]
    rate_limits: Vec<RateLimit>,
    #[serde(default)]
    descriptors: Vec<Descriptor>,
    #[serde(default = "descriptor::default_capacity")]
    max_dynamic_buckets: usize,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    entries: Vec<Entry>,
    max_concurrent_streams: NonZeroU32,
}

impl MatchDescriptor for Descriptor {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
}

fn enabled() -> bool {
    true
}

impl Config {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let config: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if config.budget_name.is_empty() || config.max_dynamic_buckets == 0 {
            return Err("budget_name and capacity must be nonempty/positive".into());
        }
        if config.enabled {
            descriptor::validate_groups(&config.rate_limits, &config.descriptors)?;
        }
        Ok(config)
    }
}

struct Ledger {
    config: Config,
    active: HashMap<Key, u32>,
    dynamic_buckets: usize,
    streams: Streams,
}

#[derive(Debug, PartialEq)]
enum Rejection {
    Limit,
    Capacity,
}

impl Ledger {
    fn install(&mut self, config: Config) {
        let same = self.config.enabled == config.enabled
            && descriptor::same_layout(
                &self.config.rate_limits,
                &self.config.descriptors,
                &config.rate_limits,
                &config.descriptors,
            );
        self.config = config;
        if same && self.streams.generation != 0 {
            return;
        }
        self.active.clear();
        self.dynamic_buckets = 0;
        self.streams.changed();
    }
    fn count_existing(&mut self, keys: &[Key]) {
        for key in keys {
            if !self.active.contains_key(key)
                && descriptor::matching_descriptor(
                    &self.config.rate_limits,
                    &self.config.descriptors,
                    key,
                )
                .unwrap()
                .dynamic()
            {
                self.dynamic_buckets += 1;
            }
            *self.active.entry(key.clone()).or_default() += 1;
        }
    }
    fn acquire(&mut self, keys: &[Key]) -> Result<(), Rejection> {
        let mut new_dynamic = 0;
        for key in keys {
            let descriptor = descriptor::matching_descriptor(
                &self.config.rate_limits,
                &self.config.descriptors,
                key,
            )
            .unwrap();
            if self.active.get(key).copied().unwrap_or(0) >= descriptor.max_concurrent_streams.get()
            {
                return Err(Rejection::Limit);
            }
            if descriptor.dynamic() && !self.active.contains_key(key) {
                new_dynamic += 1;
            }
        }
        // A capacity decrease must not prevent admission to existing counters.
        if new_dynamic > 0 && self.dynamic_buckets + new_dynamic > self.config.max_dynamic_buckets {
            return Err(Rejection::Capacity);
        }
        for key in keys {
            *self.active.entry(key.clone()).or_default() += 1;
        }
        self.dynamic_buckets += new_dynamic;
        Ok(())
    }

    fn release(&mut self, keys: &[Key]) {
        for key in keys {
            let count = self.active.get_mut(key).unwrap();
            *count -= 1;
            if *count == 0 {
                self.active.remove(key);
                if descriptor::matching_descriptor(
                    &self.config.rate_limits,
                    &self.config.descriptors,
                    key,
                )
                .unwrap()
                .dynamic()
                {
                    self.dynamic_buckets -= 1;
                }
            }
        }
    }
}

struct Registration {
    ledger: Arc<Mutex<Ledger>>,
}

impl Registration {
    fn shared(config: Config) -> Result<Arc<Self>, String> {
        static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<Mutex<Ledger>>>>> = OnceLock::new();
        let mut registry = REGISTRY.get_or_init(Mutex::default).lock().unwrap();
        registry.retain(|_, ledger| Arc::strong_count(ledger) > 1);
        let ledger = registry
            .entry(config.budget_name.clone())
            .or_insert_with(|| {
                Arc::new(Mutex::new(Ledger {
                    config: config.clone(),
                    active: HashMap::new(),
                    dynamic_buckets: 0,
                    streams: Streams::default(),
                }))
            })
            .clone();
        let mut state = ledger.lock().unwrap();
        state.install(config);
        drop(state);
        Ok(Arc::new(Self { ledger }))
    }
}

pub struct FilterConfig {
    config: Config,
    registration: Mutex<Option<Arc<Registration>>>,
}

impl FilterConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            config: Config::parse(bytes)?,
            registration: Mutex::new(None),
        })
    }
    fn activate(&self) {
        let mut registration = self.registration.lock().unwrap();
        if registration.is_none() {
            *registration = Some(Registration::shared(self.config.clone()).unwrap());
        }
    }
}

impl<E: EnvoyHttpFilter> HttpFilterConfig<E> for FilterConfig {
    fn on_scheduled(&self, _: u64) {
        self.activate();
    }
    fn new_http_filter(&self, _: &mut E) -> Box<dyn HttpFilter<E>> {
        self.activate();
        Box::new(Filter {
            registration: self.registration.lock().unwrap().as_ref().unwrap().clone(),
            id: Streams::id(),
            keys: RefCell::new(Vec::new()),
            generation: Cell::new(0),
            admitted: Cell::new(false),
            waiting: Cell::new(false),
            registered: Cell::new(false),
        })
    }
}

struct Filter {
    registration: Arc<Registration>,
    id: u64,
    keys: RefCell<Vec<Key>>,
    generation: Cell<u64>,
    admitted: Cell<bool>,
    waiting: Cell<bool>,
    registered: Cell<bool>,
}

impl Filter {
    fn resolve(&self, ledger: &mut Ledger, envoy: &impl EnvoyHttpFilter) -> Result<(), ()> {
        if self.generation.get() == ledger.streams.generation {
            return Ok(());
        }
        let keys = if ledger.config.enabled {
            descriptor::resolve(
                &ledger.config.rate_limits,
                &ledger.config.descriptors,
                |key| {
                    envoy
                        .get_filter_state_bytes(key.as_bytes())
                        .and_then(|value| {
                            std::str::from_utf8(value.as_slice())
                                .ok()
                                .map(str::to_owned)
                        })
                },
            )
        } else {
            Ok(Vec::new())
        };
        self.generation.set(ledger.streams.generation);
        self.keys.borrow_mut().clear();
        if let Ok(keys) = &keys {
            if self.admitted.get() {
                ledger.count_existing(keys);
            }
            *self.keys.borrow_mut() = keys.clone();
        }
        ledger.streams.ready(self.id);
        keys.map(|_| ())
    }
    fn stop_tracking(&self) {
        self.registered.set(false);
        self.waiting.set(false);
        self.registration
            .ledger
            .lock()
            .unwrap()
            .streams
            .remove(self.id);
    }
    fn admit(&self, ledger: &mut Ledger) -> Result<bool, Rejection> {
        if self.admitted.get() {
            return Ok(true);
        }
        if ledger.config.enabled && !ledger.streams.pending.is_empty() {
            return Ok(false);
        }
        ledger.acquire(&self.keys.borrow())?;
        self.admitted.set(true);
        Ok(true)
    }
}

impl<E: EnvoyHttpFilter> HttpFilter<E> for Filter {
    fn on_request_headers(&self, envoy: &mut E, _: bool) -> Headers {
        let result = {
            let mut ledger = self.registration.ledger.lock().unwrap();
            ledger
                .streams
                .handles
                .insert(self.id, Arc::new(envoy.new_scheduler()));
            self.registered.set(true);
            // Generation zero is reserved for a stream not yet matched.
            self.resolve(&mut ledger, envoy)
                .map_err(|_| (403, "concurrency_missing_key"))
                .and_then(|_| {
                    self.admit(&mut ledger).map_err(|reason| match reason {
                        Rejection::Limit => (429, "concurrency_limit_exceeded"),
                        Rejection::Capacity => (503, "concurrency_capacity"),
                    })
                })
        };
        match result {
            Ok(true) => Headers::Continue,
            Ok(false) => {
                self.waiting.set(true);
                Headers::StopAllIterationAndWatermark
            }
            Err((status, detail)) => {
                self.stop_tracking();
                envoy.send_response(status, &[], Some(detail.as_bytes()), Some(detail));
                Headers::StopIteration
            }
        }
    }
    fn on_scheduled(&self, envoy: &mut E, _: u64) {
        if !self.registered.get() {
            return;
        }
        let result = {
            let mut ledger = self.registration.ledger.lock().unwrap();
            self.resolve(&mut ledger, envoy)
                .map_err(|_| (403, "concurrency_missing_key"))
                .and_then(|_| {
                    self.admit(&mut ledger).map_err(|reason| match reason {
                        Rejection::Limit => (429, "concurrency_limit_exceeded"),
                        Rejection::Capacity => (503, "concurrency_capacity"),
                    })
                })
        };
        match result {
            Ok(true) if self.waiting.replace(false) => envoy.continue_decoding(),
            Err((status, detail)) if !self.admitted.get() => {
                self.stop_tracking();
                envoy.send_response(status, &[], Some(detail.as_bytes()), Some(detail));
            },
            Err(_) => envoy.reset_stream(envoy_proxy_dynamic_modules_rust_sdk::abi::envoy_dynamic_module_type_http_filter_stream_reset_reason::LocalReset, "concurrency_missing_key"),
            _ => {},
        }
    }
}

impl Drop for Filter {
    fn drop(&mut self) {
        let mut ledger = self.registration.ledger.lock().unwrap();
        if self.admitted.get() && self.generation.get() == ledger.streams.generation {
            ledger.release(self.keys.get_mut());
        }
        ledger.streams.remove(self.id);
    }
}

#[cfg(test)]
mod tests;
