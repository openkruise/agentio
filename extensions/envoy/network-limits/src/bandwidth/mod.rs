// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

mod budget;
mod config;
mod timer;

use crate::descriptor::Key;
use budget::{Budget, Registration, Wait};
use config::Config;
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, EnvoyHttpFilterScheduler, HttpFilter, HttpFilterConfig,
    abi::{
        envoy_dynamic_module_type_on_http_filter_request_body_status as RequestBody,
        envoy_dynamic_module_type_on_http_filter_request_headers_status as Headers,
        envoy_dynamic_module_type_on_http_filter_request_trailers_status as RequestTrailers,
        envoy_dynamic_module_type_on_http_filter_response_body_status as ResponseBody,
        envoy_dynamic_module_type_on_http_filter_response_trailers_status as ResponseTrailers,
    },
};
use std::{
    cell::{Cell, RefCell},
    sync::{Arc, Mutex},
    time::Instant,
};
use timer::Timer;

pub struct FilterConfig {
    config: Config,
    registration: Mutex<Option<Registration>>,
    timer: Arc<Timer>,
}

impl FilterConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let config = Config::parse(bytes)?;
        let timer = Timer::shared().map_err(|e| e.to_string())?;
        Ok(Self {
            config,
            registration: Mutex::new(None),
            timer,
        })
    }
}

impl FilterConfig {
    fn activate(&self) {
        let mut registration = self.registration.lock().unwrap();
        if registration.is_none() {
            *registration = Some(Budget::shared(self.config.clone()).unwrap());
        }
    }
}

impl<E: EnvoyHttpFilter> HttpFilterConfig<E> for FilterConfig {
    fn on_scheduled(&self, _: u64) {
        self.activate();
    }
    fn new_http_filter(&self, envoy: &mut E) -> Box<dyn HttpFilter<E>> {
        self.activate();
        Box::new(Filter {
            budget: self
                .registration
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .budget
                .clone(),
            timer: self.timer.clone(),
            id: self.timer.id(),
            scheduler: Arc::new(envoy.new_scheduler()),
            keys: RefCell::new(Vec::new()),
            waiting: Cell::new([None; 2]),
            generation: Cell::new(0),
            registered: Cell::new(false),
        })
    }
}

fn read_identity(envoy: &impl EnvoyHttpFilter, key: &str) -> Option<String> {
    envoy
        .get_filter_state_bytes(key.as_bytes())
        .and_then(|value| {
            std::str::from_utf8(value.as_slice())
                .ok()
                .map(str::to_owned)
        })
}

struct Filter {
    budget: Arc<Budget>,
    timer: Arc<Timer>,
    id: u64,
    scheduler: Arc<dyn EnvoyHttpFilterScheduler>,
    keys: RefCell<Vec<Key>>,
    waiting: Cell<[Option<Wait>; 2]>,
    generation: Cell<u64>,
    registered: Cell<bool>,
}

impl Filter {
    fn refresh(&self, envoy: &mut impl EnvoyHttpFilter) -> bool {
        if !self.registered.get() {
            return true;
        }
        let mut ledger = self.budget.ledger.lock().unwrap();
        if self.generation.get() == ledger.streams.generation {
            return true;
        }
        let keys = ledger.config.resolve(|key| read_identity(envoy, key));
        let Ok(keys) = keys else {
            drop(ledger);
            envoy.reset_stream(envoy_proxy_dynamic_modules_rust_sdk::abi::envoy_dynamic_module_type_http_filter_stream_reset_reason::LocalReset, "bandwidth_missing_key");
            return false;
        };
        let due = ledger.rebind(self.id, &self.keys.borrow(), &keys, Instant::now());
        *self.keys.borrow_mut() = keys;
        self.generation.set(ledger.streams.generation);
        ledger.streams.ready(self.id);
        let buffer_limit = ledger.config.buffer_limit_bytes;
        drop(ledger);
        self.budget.reap_at(due);
        if !self.keys.borrow().is_empty() {
            envoy.set_buffer_limit(buffer_limit as u64);
        }
        true
    }

    fn charge(&self, direction: usize, bytes: usize) -> bool {
        let mut ledger = self.budget.ledger.lock().unwrap();
        let mut waiting = self.waiting.get();
        waiting[direction] = ledger.admit_batch(
            self.id,
            &self.keys.borrow(),
            direction,
            bytes,
            Instant::now(),
        );
        self.waiting.set(waiting);
        if self.waiting.get().iter().any(Option::is_some) {
            ledger.waiters.insert(self.id, self.scheduler.clone());
        } else {
            ledger.waiters.remove(&self.id);
        }
        drop(ledger);
        self.arm();
        self.waiting.get()[direction].is_none()
    }

    fn arm(&self) {
        let waiting = self.waiting.get();
        let due = waiting
            .iter()
            .flatten()
            .filter_map(|wait| match wait {
                Wait::Turn => None,
                Wait::Until(due) => Some(*due),
            })
            .min();
        if let Some(due) = due {
            self.timer.schedule(self.id, due, self.scheduler.clone());
        } else {
            self.timer.cancel(self.id);
        }
    }
}

impl<E: EnvoyHttpFilter> HttpFilter<E> for Filter {
    fn on_request_headers(&self, envoy: &mut E, _: bool) -> Headers {
        // Retry replay buffers share the filter-manager buffer used for pacing.
        if self.budget.ledger.lock().unwrap().config.enabled
            && ["x-envoy-retry-on", "x-envoy-retry-grpc-on"]
                .iter()
                .any(|header| envoy.get_request_header_value(header).is_some())
        {
            envoy.send_response(
                400,
                &[],
                Some(b"bandwidth shaping does not support router retries"),
                Some("bandwidth_retry_unsupported"),
            );
            return Headers::StopIteration;
        }
        let result = {
            let mut ledger = self.budget.ledger.lock().unwrap();
            let keys = ledger.config.resolve(|key| read_identity(envoy, key));
            match keys {
                Err(()) => Err((403, "bandwidth_missing_key")),
                Ok(keys) => match ledger.acquire(&keys, Instant::now()) {
                    Err(()) => Err((503, "bandwidth_capacity")),
                    Ok(()) => {
                        *self.keys.borrow_mut() = keys;
                        self.generation.set(ledger.streams.generation);
                        ledger
                            .streams
                            .handles
                            .insert(self.id, self.scheduler.clone());
                        self.registered.set(true);
                        Ok(ledger.config.buffer_limit_bytes)
                    }
                },
            }
        };
        match result {
            Err((status, detail)) => {
                envoy.send_response(status, &[], Some(detail.as_bytes()), Some(detail));
                return Headers::StopIteration;
            }
            Ok(buffer_limit) => {
                if !self.keys.borrow().is_empty() {
                    envoy.set_buffer_limit(buffer_limit as u64);
                }
            }
        }
        Headers::Continue
    }

    fn on_request_body(&self, envoy: &mut E, _: bool) -> RequestBody {
        if !self.refresh(envoy) {
            return RequestBody::StopIterationAndWatermark;
        }
        if self.keys.borrow().is_empty() {
            return RequestBody::Continue;
        }
        let mut bytes = envoy.get_received_request_body_size();
        if !envoy.received_buffered_request_body() {
            bytes += envoy.get_buffered_request_body_size();
        }
        if self.charge(0, bytes) {
            RequestBody::Continue
        } else {
            RequestBody::StopIterationAndWatermark
        }
    }

    fn on_response_body(&self, envoy: &mut E, _: bool) -> ResponseBody {
        if !self.refresh(envoy) {
            return ResponseBody::StopIterationAndWatermark;
        }
        if self.keys.borrow().is_empty() {
            return ResponseBody::Continue;
        }
        let mut bytes = envoy.get_received_response_body_size();
        if !envoy.received_buffered_response_body() {
            bytes += envoy.get_buffered_response_body_size();
        }
        if self.charge(1, bytes) {
            ResponseBody::Continue
        } else {
            ResponseBody::StopIterationAndWatermark
        }
    }

    fn on_request_trailers(&self, _: &mut E) -> RequestTrailers {
        if self.waiting.get()[0].is_some() {
            RequestTrailers::StopIteration
        } else {
            RequestTrailers::Continue
        }
    }

    fn on_response_trailers(&self, _: &mut E) -> ResponseTrailers {
        if self.waiting.get()[1].is_some() {
            ResponseTrailers::StopIteration
        } else {
            ResponseTrailers::Continue
        }
    }

    fn on_scheduled(&self, envoy: &mut E, _: u64) {
        if !self.refresh(envoy) {
            return;
        }
        if self.waiting.get()[0].is_some() && self.charge(0, envoy.get_buffered_request_body_size())
        {
            // A grouping update can make a timerless response queue eligible too.
            // Post before resuming: continue_decoding can synchronously destroy this filter.
            if self.waiting.get()[1] == Some(Wait::Turn) {
                self.scheduler.commit(0);
            }
            envoy.continue_decoding();
            return;
        }
        if self.waiting.get()[1].is_some()
            && self.charge(1, envoy.get_buffered_response_body_size())
        {
            envoy.continue_encoding();
        }
    }
}

impl Drop for Filter {
    fn drop(&mut self) {
        self.timer.cancel(self.id);
        let mut ledger = self.budget.ledger.lock().unwrap();
        ledger.waiters.remove(&self.id);
        ledger.cancel_batches(self.id);
        ledger.streams.remove(self.id);
        let due = ledger.release(self.keys.get_mut(), Instant::now());
        drop(ledger);
        self.budget.reap_at(due);
    }
}

#[cfg(test)]
mod tests;
