// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::{
    cell::Cell,
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};

use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, EnvoyListenerFilter, EnvoyListenerFilterConfig, EnvoyListenerFilterScheduler,
    ListenerFilter, ListenerFilterConfig,
    abi::{
        envoy_dynamic_module_type_filter_state_life_span as LifeSpan,
        envoy_dynamic_module_type_filter_state_stream_sharing as Sharing,
        envoy_dynamic_module_type_on_listener_filter_status as Status,
    },
    envoy_log_error,
};

use crate::bandwidth::timer::Timer;

const KEY: &[u8] = b"agentio.bandwidth.clock";
const TIMEOUT: Duration = Duration::from_secs(1);
type SharedClock = Arc<Mutex<Clock>>;

fn clocks() -> &'static Mutex<HashMap<u64, Weak<Mutex<Clock>>>> {
    static CLOCKS: OnceLock<Mutex<HashMap<u64, Weak<Mutex<Clock>>>>> = OnceLock::new();
    CLOCKS.get_or_init(Mutex::default)
}

#[derive(Default)]
struct Clock {
    paused: Option<Instant>,
    total: Duration,
    inspectors: HashMap<u64, Arc<dyn EnvoyListenerFilterScheduler>>,
}

impl Clock {
    fn stopped(&self, now: Instant) -> Duration {
        self.total + self.paused.map_or(Duration::ZERO, |start| now - start)
    }

    fn pause(&mut self, paused: bool, now: Instant) {
        match (paused, self.paused) {
            (true, None) => self.paused = Some(now),
            (false, Some(start)) => {
                self.total += now - start;
                self.paused = None;
            }
            _ => return,
        }
        // Wake on both transitions, so neither idle expiry nor resumed traffic polls.
        for scheduler in self.inspectors.values() {
            scheduler.commit(0);
        }
    }
}

// Only the HTTP pacing filter publishes this opaque clock; CONNECT headers cannot select it.
pub(crate) struct Pacing {
    id: u64,
    clock: SharedClock,
    paused: Cell<bool>,
}

impl Pacing {
    pub fn new(id: u64) -> Self {
        let clock = Arc::new(Mutex::new(Clock::default()));
        clocks().lock().unwrap().insert(id, Arc::downgrade(&clock));
        Self {
            id,
            clock,
            paused: Cell::new(false),
        }
    }

    pub fn publish(&self, envoy: &mut impl EnvoyHttpFilter) -> bool {
        envoy.set_filter_state_value(
            KEY,
            self.id.to_string().as_bytes(),
            LifeSpan::Request,
            Sharing::SharedWithUpstreamConnection,
        )
    }

    pub fn pause(&self, paused: bool) {
        if self.paused.replace(paused) != paused {
            self.clock.lock().unwrap().pause(paused, Instant::now());
        }
    }
}

impl Drop for Pacing {
    fn drop(&mut self) {
        self.pause(false);
        clocks().lock().unwrap().remove(&self.id);
    }
}

struct Config {
    timer: Arc<Timer>,
}

pub fn new_config<C: EnvoyListenerFilterConfig, E: EnvoyListenerFilter>(
    _: &mut C,
    name: &str,
    config: &[u8],
) -> Option<Box<dyn ListenerFilterConfig<E>>> {
    if name != "envoy_agentio_inspection_deadline" || !config.is_empty() {
        return None;
    }
    match Timer::shared() {
        Ok(timer) => Some(Box::new(Config { timer })),
        Err(error) => {
            envoy_log_error!("inspection timer unavailable: {}", error);
            None
        }
    }
}

struct Inspector {
    timer: Arc<Timer>,
    id: u64,
    clock: SharedClock,
    start: Instant,
    initial_stopped: Duration,
    scheduler: Option<Arc<dyn EnvoyListenerFilterScheduler>>,
}

impl<E: EnvoyListenerFilter> ListenerFilterConfig<E> for Config {
    fn new_listener_filter(&self, _: &mut E) -> Box<dyn ListenerFilter<E>> {
        Box::new(Inspector {
            timer: self.timer.clone(),
            id: self.timer.id(),
            clock: Arc::new(Mutex::new(Clock::default())),
            start: Instant::now(),
            initial_stopped: Duration::ZERO,
            scheduler: None,
        })
    }
}

impl Inspector {
    fn check(&self, envoy: &mut impl EnvoyListenerFilter) {
        let clock = self.clock.lock().unwrap();
        let now = Instant::now();
        let stopped = clock.stopped(now) - self.initial_stopped;
        let elapsed = (now - self.start).saturating_sub(stopped);
        if elapsed >= TIMEOUT {
            drop(clock);
            envoy.close_socket(Some("agentio_protocol_inspection_timeout"));
        } else if clock.paused.is_none() {
            self.timer.inspect(
                self.id,
                now + (TIMEOUT - elapsed),
                self.scheduler.as_ref().unwrap().clone(),
            );
        } else {
            self.timer.cancel(self.id);
        }
    }
}

impl<E: EnvoyListenerFilter> ListenerFilter<E> for Inspector {
    fn on_accept(&mut self, envoy: &mut E) -> Status {
        if let Some(value) = envoy.get_filter_state_bytes(KEY) {
            let clock = std::str::from_utf8(value.as_slice())
                .ok()
                .and_then(|id| id.parse::<u64>().ok())
                .and_then(|id| clocks().lock().unwrap().get(&id).and_then(Weak::upgrade));
            let Some(clock) = clock else {
                envoy.close_socket(Some("agentio_inspection_clock_unavailable"));
                return Status::StopIteration;
            };
            self.clock = clock;
        }
        self.scheduler = Some(Arc::new(envoy.new_scheduler()));
        self.start = Instant::now();
        let mut clock = self.clock.lock().unwrap();
        self.initial_stopped = clock.stopped(self.start);
        clock
            .inspectors
            .insert(self.id, self.scheduler.as_ref().unwrap().clone());
        drop(clock);
        self.check(envoy);
        Status::Continue
    }

    fn on_scheduled(&mut self, envoy: &mut E, _: u64) {
        self.check(envoy);
    }
}

impl Drop for Inspector {
    fn drop(&mut self) {
        self.clock.lock().unwrap().inspectors.remove(&self.id);
        self.timer.cancel(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoy_proxy_dynamic_modules_rust_sdk::{
        MockEnvoyListenerFilter, MockEnvoyListenerFilterScheduler,
    };

    #[test]
    fn only_pacing_time_is_subtracted_and_repeated_pause_does_not_reset_it() {
        let start = Instant::now();
        let mut clock = Clock::default();
        clock.pause(true, start + Duration::from_millis(200));
        clock.pause(true, start + Duration::from_secs(2));
        assert_eq!(
            clock.stopped(start + Duration::from_secs(5)),
            Duration::from_millis(4800)
        );
        clock.pause(false, start + Duration::from_secs(5));
        assert_eq!(
            clock.stopped(start + Duration::from_secs(7)),
            Duration::from_millis(4800)
        );
        clock.pause(true, start + Duration::from_secs(8));
        assert_eq!(
            clock.stopped(start + Duration::from_secs(9)),
            Duration::from_millis(5800)
        );
    }

    #[test]
    fn paused_inspection_waits_but_client_idle_time_still_expires() {
        let timer = Timer::shared().unwrap();
        let start = Instant::now() - Duration::from_secs(10);
        let clock = Arc::new(Mutex::new(Clock::default()));
        clock
            .lock()
            .unwrap()
            .pause(true, start + Duration::from_millis(200));
        let mut guard = Inspector {
            id: timer.id(),
            timer,
            clock: clock.clone(),
            start,
            initial_stopped: Duration::ZERO,
            scheduler: Some(Arc::new(MockEnvoyListenerFilterScheduler::new())),
        };
        let mut envoy = MockEnvoyListenerFilter::new();
        guard.check(&mut envoy);
        clock.lock().unwrap().pause(false, Instant::now());
        guard.check(&mut envoy);
        guard.start -= Duration::from_secs(2);
        envoy
            .expect_close_socket()
            .withf(|detail| *detail == Some("agentio_protocol_inspection_timeout"))
            .times(1)
            .return_const(());
        guard.check(&mut envoy);
    }

    #[test]
    fn pacing_registry_lifetime_matches_the_connect_filter() {
        let id = Timer::shared().unwrap().id();
        let pacing = Pacing::new(id);
        assert!(
            clocks()
                .lock()
                .unwrap()
                .get(&id)
                .unwrap()
                .upgrade()
                .is_some()
        );
        drop(pacing);
        assert!(!clocks().lock().unwrap().contains_key(&id));
    }
}
