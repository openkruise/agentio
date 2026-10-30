// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::budget::Ledger;
use super::*;
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyBuffer, MockEnvoyHttpFilter, MockEnvoyHttpFilterScheduler,
};
use std::{sync::Mutex, time::Duration};

const CONFIG: &str = r#"{
  "rate_limits":[{"actions":[
    {"filter_state":{"key":"tenant.id","descriptor_key":"tenant"}},
    {"filter_state":{"key":"sandbox.id","descriptor_key":"sandbox"}}
  ]}],
  "descriptors":[
    {"entries":[{"key":"tenant"},{"key":"sandbox"}],"bandwidth_limit":{"upload_bytes_per_second":100,"download_bytes_per_second":200}},
    {"entries":[{"key":"tenant","value":"vip"},{"key":"sandbox","value":"one"}],"bandwidth_limit":{"download_bytes_per_second":1000}}
  ]
}"#;

fn keys(config: &Config, tenant: &str, sandbox: &str) -> Vec<Key> {
    config
        .resolve(|k| Some(if k == "tenant.id" { tenant } else { sandbox }.into()))
        .unwrap()
}

#[test]
fn descriptors_are_ordered_combined_keys_with_exact_precedence() {
    let config = Config::parse(CONFIG.as_bytes()).unwrap();
    assert_eq!(
        config
            .descriptor(&keys(&config, "vip", "one")[0])
            .unwrap()
            .bandwidth_limit
            .download_bytes_per_second
            .unwrap()
            .get(),
        1000
    );
    assert_eq!(
        config
            .descriptor(&keys(&config, "vip", "two")[0])
            .unwrap()
            .bandwidth_limit
            .download_bytes_per_second
            .unwrap()
            .get(),
        200
    );
    assert_ne!(keys(&config, "a", "one"), keys(&config, "b", "one"));
    assert_ne!(keys(&config, "a", "one"), keys(&config, "a", "two"));
    assert!(config.resolve(|_| None).is_err());
    assert!(config.resolve(|_| Some(String::new())).is_err());
    let mut config = config;
    config.descriptors.remove(0);
    assert!(keys(&config, "a", "one").is_empty());
}

#[test]
fn invalid_configuration_fails_at_the_boundary() {
    for invalid in [
        CONFIG.replace(
            "\"upload_bytes_per_second\":100",
            "\"upload_bytes_per_second\":0",
        ),
        CONFIG.replace("\"key\":\"sandbox\"", "\"key\":\"unknown\""),
        CONFIG.replace("\"sandbox.id\"", "\"\""),
        CONFIG.replace("\"rate_limits\":", "\"typo\":"),
        CONFIG.replace(
            "\"rate_limits\":",
            "\"buffer_limit_bytes\":0,\"rate_limits\":",
        ),
        CONFIG.replace(
            "\"rate_limits\":",
            "\"max_dynamic_buckets\":0,\"rate_limits\":",
        ),
        "{}".into(),
    ] {
        assert!(Config::parse(invalid.as_bytes()).is_err(), "{invalid}");
    }
}

#[test]
fn shared_byte_budget_survives_reconnect_and_is_directional() {
    let config = Config::parse(CONFIG.as_bytes()).unwrap();
    let key = keys(&config, "a", "one");
    let other = keys(&config, "a", "two");
    let mut ledger = Ledger::new(config.clone());
    let now = Instant::now();
    ledger.acquire(&key, now).unwrap();
    ledger.acquire(&key, now).unwrap();
    ledger.acquire(&other, now).unwrap();
    assert_eq!(ledger.charge(&key, 0, 1000, now), None);
    assert_eq!(
        ledger.charge(&key, 0, 1, now),
        Some(now + Duration::from_secs(10))
    );
    assert_eq!(ledger.charge(&key, 1, 200, now), None);
    assert_eq!(ledger.charge(&other, 0, 100, now), None);
    ledger.release(&key, now);
    ledger.release(&key, now);
    ledger.acquire(&key, now).unwrap();
    assert_eq!(
        ledger.charge(&key, 0, 1, now),
        Some(now + Duration::from_secs(10))
    );
    assert_eq!(
        ledger.charge(&key, 0, 100, now + Duration::from_secs(10)),
        None
    );
}

#[test]
fn capacity_retains_live_and_unpaid_buckets() {
    let mut config = Config::parse(CONFIG.as_bytes()).unwrap();
    config.max_dynamic_buckets = 1;
    let first = keys(&config, "a", "one");
    let next = keys(&config, "a", "two");
    let exact = keys(&config, "vip", "one");
    let now = Instant::now();
    let mut ledger = Ledger::new(config.clone());
    ledger.acquire(&first, now).unwrap();
    ledger.acquire(&exact, now).unwrap();
    ledger.release(&exact, now);
    assert!(ledger.acquire(&next, now).is_err());
    ledger.acquire(&exact, now).unwrap();
    ledger.charge(&exact, 1, 100, now);
    ledger.release(&exact, now);
    ledger.reap(now + Duration::from_millis(100));
    assert!(
        ledger
            .acquire(&next, now + Duration::from_millis(100))
            .is_err()
    );
    ledger.charge(&first, 0, 100, now);
    ledger.release(&first, now);
    assert!(ledger.acquire(&next, now).is_err());
    ledger.acquire(&next, now + Duration::from_secs(1)).unwrap();
}

#[test]
fn multiple_descriptors_charge_atomically_and_deduplicate() {
    let json = r#"{"rate_limits":[
      {"actions":[{"filter_state":{"key":"tenant.id","descriptor_key":"tenant"}}]},
      {"actions":[{"filter_state":{"key":"sandbox.id","descriptor_key":"sandbox"}}]},
      {"actions":[{"filter_state":{"key":"tenant.id","descriptor_key":"tenant"}}]}
    ],"descriptors":[
      {"entries":[{"key":"tenant"}],"bandwidth_limit":{"upload_bytes_per_second":1000}},
      {"entries":[{"key":"sandbox"}],"bandwidth_limit":{"upload_bytes_per_second":100}}
    ]}"#;
    let config = Config::parse(json.as_bytes()).unwrap();
    let keys = keys(&config, "a", "one");
    assert_eq!(keys.len(), 2);
    let mut ledger = Ledger::new(config.clone());
    let now = Instant::now();
    ledger.acquire(&keys, now).unwrap();
    ledger.charge(&keys, 0, 100, now);
    assert_eq!(
        ledger.charge(&keys, 0, 1000, now + Duration::from_millis(500)),
        Some(now + Duration::from_secs(1))
    );
    assert_eq!(
        ledger.charge(&keys[..1], 0, 1, now + Duration::from_millis(500)),
        None
    );
}

#[test]
fn workers_cannot_multiply_the_budget() {
    let mut config = Config::parse(CONFIG.as_bytes()).unwrap();
    config.descriptors[0].bandwidth_limit.upload_burst_bytes = Some(400.try_into().unwrap());
    let config = Arc::new(config);
    let keys = keys(&config, "a", "one");
    let now = Instant::now();
    let ledger = Arc::new(Mutex::new(Ledger::new((*config).clone())));
    ledger.lock().unwrap().acquire(&keys, now).unwrap();
    let workers: Vec<_> = (0..16)
        .map(|_| {
            let (keys, ledger) = (keys.clone(), ledger.clone());
            std::thread::spawn(move || ledger.lock().unwrap().charge(&keys, 0, 100, now).is_none())
        })
        .collect();
    assert_eq!(
        workers
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>(),
        4
    );
}

#[test]
fn burst_credit_refills_without_accumulating_past_capacity() {
    let mut config = Config::parse(CONFIG.as_bytes()).unwrap();
    config.descriptors[0].bandwidth_limit.upload_burst_bytes = Some(400.try_into().unwrap());
    config.descriptors[0].bandwidth_limit.download_burst_bytes = Some(800.try_into().unwrap());
    let key = keys(&config, "a", "one");
    let other = keys(&config, "a", "two");
    let mut ledger = Ledger::new(config);
    let now = Instant::now();
    ledger.acquire(&key, now).unwrap();
    ledger.acquire(&other, now).unwrap();
    for _ in 0..4 {
        assert_eq!(ledger.charge(&key, 0, 100, now), None);
        assert_eq!(ledger.charge(&key, 1, 200, now), None);
    }
    let due = now + Duration::from_secs(1);
    assert_eq!(ledger.charge(&key, 0, 100, now), Some(due));
    assert_eq!(ledger.charge(&key, 1, 200, now), Some(due));
    assert_eq!(ledger.charge(&other, 0, 400, now), None);
    assert_eq!(ledger.charge(&key, 0, 100, due), None);
    assert_eq!(
        ledger.charge(&key, 0, 100, due),
        Some(due + Duration::from_secs(1))
    );
    let idle = now + Duration::from_secs(60);
    assert_eq!(ledger.charge(&key, 0, 400, idle), None);
    assert_eq!(
        ledger.charge(&key, 0, 100, idle),
        Some(idle + Duration::from_secs(1))
    );
}

#[test]
fn oversized_batches_wait_for_full_refill_and_are_charged_in_full() {
    let mut config = Config::parse(CONFIG.as_bytes()).unwrap();
    config.descriptors[0].bandwidth_limit.upload_burst_bytes = Some(100.try_into().unwrap());
    let key = keys(&config, "a", "one");
    let mut ledger = Ledger::new(config);
    let now = Instant::now();
    ledger.acquire(&key, now).unwrap();
    assert_eq!(ledger.charge(&key, 0, 50, now), None);
    let due = now + Duration::from_millis(500);
    assert_eq!(ledger.charge(&key, 0, 1000, now), Some(due));
    assert_eq!(ledger.charge(&key, 0, 1000, due), None);
    assert_eq!(
        ledger.charge(&key, 0, 100, due),
        Some(due + Duration::from_secs(10))
    );
    assert_eq!(ledger.charge(&key, 0, 0, due), None);
}

#[test]
fn burst_and_legacy_budgets_are_charged_together() {
    let mut config = Config::parse(CONFIG.as_bytes()).unwrap();
    config.descriptors[0].bandwidth_limit.upload_burst_bytes = Some(400.try_into().unwrap());
    config.descriptors[1]
        .bandwidth_limit
        .upload_bytes_per_second = Some(100.try_into().unwrap());
    let mut both = keys(&config, "a", "one");
    both.extend(keys(&config, "vip", "one"));
    let mut ledger = Ledger::new(config);
    let now = Instant::now();
    ledger.acquire(&both, now).unwrap();
    assert_eq!(ledger.charge(&both, 0, 100, now), None);
    assert_eq!(
        ledger.charge(&both, 0, 100, now),
        Some(now + Duration::from_secs(1))
    );
    // The rejected joint charge must not consume the first budget's remaining credit.
    assert_eq!(ledger.charge(&both[..1], 0, 300, now), None);
    assert_eq!(
        ledger.charge(&both[..1], 0, 100, now),
        Some(now + Duration::from_secs(1))
    );
}

#[test]
fn burst_configuration_accepts_protojson_and_requires_positive_matching_rates() {
    for value in ["500", "\"500\""] {
        let json = CONFIG.replace(
            "\"upload_bytes_per_second\":100",
            &format!("\"upload_bytes_per_second\":100,\"upload_burst_bytes\":{value}"),
        );
        let config = Config::parse(json.as_bytes()).unwrap();
        assert_eq!(
            config.descriptors[0]
                .bandwidth_limit
                .upload_burst_bytes
                .unwrap()
                .get(),
            500
        );
    }
    for value in ["0", "\"0\"", "-1", "1.5"] {
        let json = CONFIG.replace(
            "\"upload_bytes_per_second\":100",
            &format!("\"upload_bytes_per_second\":100,\"upload_burst_bytes\":{value}"),
        );
        assert!(Config::parse(json.as_bytes()).is_err(), "{json}");
    }
    for json in [
        CONFIG.replace(
            "\"upload_bytes_per_second\":100",
            "\"upload_burst_bytes\":500",
        ),
        CONFIG.replace(
            "\"download_bytes_per_second\":200",
            "\"download_burst_bytes\":500",
        ),
    ] {
        assert!(Config::parse(json.as_bytes()).is_err(), "{json}");
    }
}

#[test]
fn reload_reuses_budget_across_grouping_changes() {
    let mut config = Config::parse(CONFIG.as_bytes()).unwrap();
    config.budget_name = "reload-test".into();
    let first = Budget::shared(config.clone()).unwrap();
    config.buffer_limit_bytes *= 2;
    let second = Budget::shared(config.clone()).unwrap();
    assert!(Arc::ptr_eq(&first.budget, &second.budget));
    config.max_dynamic_buckets += 1;
    assert!(Budget::shared(config.clone()).is_ok());
    Arc::make_mut(&mut config.rate_limits[0].actions).reverse();
    for descriptor in &mut config.descriptors {
        descriptor.entries.reverse();
    }
    assert!(Budget::shared(config).is_ok());
}

#[test]
fn dropping_config_does_not_restore_previous_rates() {
    let mut config = Config::parse(CONFIG.as_bytes()).unwrap();
    config.budget_name = "rollback-test".into();
    let first = Budget::shared(config.clone()).unwrap();
    let key = keys(&config, "a", "one");
    let now = Instant::now();
    let mut ledger = first.budget.ledger.lock().unwrap();
    ledger.acquire(&key, now).unwrap();
    ledger.charge(&key, 0, 1000, now);
    drop(ledger);
    config.descriptors[0]
        .bandwidth_limit
        .upload_bytes_per_second = Some(200.try_into().unwrap());
    let candidate = Budget::shared(config).unwrap();
    assert!(Arc::ptr_eq(&first.budget, &candidate.budget));
    assert_eq!(
        first.budget.ledger.lock().unwrap().config.descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second
            .unwrap()
            .get(),
        200
    );
    drop(candidate);
    let mut ledger = first.budget.ledger.lock().unwrap();
    assert_eq!(
        ledger.config.descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second
            .unwrap()
            .get(),
        200
    );
    assert!(ledger.charge(&key, 0, 1, Instant::now()).is_some());
    ledger.release(&key, Instant::now());
}

#[test]
fn protojson_rates_accept_uint64_strings_and_reject_zero() {
    let config = CONFIG.replace(
        "\"upload_bytes_per_second\":100",
        "\"upload_bytes_per_second\":\"100\"",
    );
    assert_eq!(
        Config::parse(config.as_bytes()).unwrap().descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second
            .unwrap()
            .get(),
        100
    );
    assert!(Config::parse(config.replace("\"100\"", "\"0\"").as_bytes()).is_err());
}

fn filter() -> Filter {
    let budget = Arc::new(Budget::new(Config::parse(CONFIG.as_bytes()).unwrap()).unwrap());
    let timer = budget.timer.clone();
    Filter {
        budget,
        id: timer.id(),
        timer,
        scheduler: Arc::new(MockEnvoyHttpFilterScheduler::new()),
        keys: RefCell::new(Vec::new()),
        waiting: Cell::new([None; 2]),
        generation: Cell::new(0),
        registered: Cell::new(false),
    }
}

#[test]
fn callbacks_count_buffered_bytes_once_and_stop_trailers() {
    let filter = filter();
    let mut envoy = MockEnvoyHttpFilter::new();
    envoy.expect_get_request_header_value().returning(|_| None);
    envoy
        .expect_get_filter_state_bytes()
        .returning(|_| Some(EnvoyBuffer::new(b"a")));
    envoy
        .expect_set_buffer_limit()
        .withf(|n| *n == 65536)
        .times(1)
        .return_const(());
    assert_eq!(
        filter.on_request_headers(&mut envoy, false),
        Headers::Continue
    );
    // An earlier filter may deliver the filter-manager buffer itself.
    envoy
        .expect_get_received_request_body_size()
        .return_const(10000usize);
    envoy
        .expect_received_buffered_request_body()
        .return_const(true);
    assert_eq!(
        filter.on_request_body(&mut envoy, false),
        RequestBody::Continue
    );
    assert_eq!(
        filter.on_request_body(&mut envoy, true),
        RequestBody::StopIterationAndWatermark
    );
    assert_eq!(
        filter.on_request_trailers(&mut envoy),
        RequestTrailers::StopIteration
    );
    assert_eq!(
        filter.on_response_trailers(&mut envoy),
        ResponseTrailers::Continue
    );
}

#[test]
fn missing_identity_rejects_and_local_response_is_not_charged() {
    let filter = filter();
    let mut envoy = MockEnvoyHttpFilter::new();
    envoy.expect_get_request_header_value().returning(|_| None);
    envoy.expect_get_filter_state_bytes().returning(|_| None);
    envoy
        .expect_send_response()
        .withf(|status, _, _, details| *status == 403 && *details == Some("bandwidth_missing_key"))
        .times(1)
        .return_const(());
    assert_eq!(
        filter.on_request_headers(&mut envoy, false),
        Headers::StopIteration
    );
    assert_eq!(
        filter.on_response_body(&mut envoy, true),
        ResponseBody::Continue
    );
}

#[test]
fn retry_headers_are_rejected_before_acquiring_a_budget() {
    for header in ["x-envoy-retry-on", "x-envoy-retry-grpc-on"] {
        let filter = filter();
        let mut envoy = MockEnvoyHttpFilter::new();
        envoy
            .expect_get_request_header_value()
            .returning(move |key| (key == header).then(|| EnvoyBuffer::new(b"unavailable")));
        envoy
            .expect_send_response()
            .withf(|status, _, _, details| {
                *status == 400 && *details == Some("bandwidth_retry_unsupported")
            })
            .times(1)
            .return_const(());
        assert_eq!(
            filter.on_request_headers(&mut envoy, false),
            Headers::StopIteration
        );
        assert!(filter.keys.borrow().is_empty());
    }
}

#[test]
fn scheduled_resume_returns_before_touching_the_other_direction() {
    let mut filter = filter();
    let mut scheduler = MockEnvoyHttpFilterScheduler::new();
    scheduler.expect_commit().times(1).return_const(());
    filter.scheduler = Arc::new(scheduler);
    let now = Instant::now();
    let keys = keys(&filter.budget.ledger.lock().unwrap().config, "a", "one");
    filter
        .budget
        .ledger
        .lock()
        .unwrap()
        .acquire(&keys, now)
        .unwrap();
    *filter.keys.borrow_mut() = keys;
    // Future deadlines keep the real timer from racing this manually delivered event.
    filter.waiting.set([
        Some(Wait::Until(now + Duration::from_secs(60))),
        Some(Wait::Turn),
    ]);

    let mut request = MockEnvoyHttpFilter::new();
    request
        .expect_get_buffered_request_body_size()
        .times(1)
        .return_const(100usize);
    request.expect_continue_decoding().times(1).return_const(());
    // No further Envoy calls are allowed: continue_decoding may have destroyed the filter.
    filter.on_scheduled(&mut request, 0);
    assert!(filter.waiting.get()[0].is_none());
    assert!(filter.waiting.get()[1].is_some());
    assert!(
        filter
            .budget
            .ledger
            .lock()
            .unwrap()
            .waiters
            .contains_key(&filter.id)
    );

    // If the stream survived, its next scheduled event must still resume the response.
    let mut response = MockEnvoyHttpFilter::new();
    response
        .expect_get_buffered_response_body_size()
        .times(1)
        .return_const(200usize);
    response
        .expect_continue_encoding()
        .times(1)
        .return_const(());
    filter.on_scheduled(&mut response, 0);
    assert_eq!(filter.waiting.get(), [None; 2]);
    assert!(
        !filter
            .budget
            .ledger
            .lock()
            .unwrap()
            .waiters
            .contains_key(&filter.id)
    );
}

#[test]
fn descriptor_override_and_reorder_preserve_burst_consumption() {
    let mut config = Config::parse(CONFIG.as_bytes()).unwrap();
    config.budget_name = "descriptor-override".into();
    config.descriptors[0].bandwidth_limit.upload_burst_bytes = Some(100.try_into().unwrap());
    let registration = Budget::shared(config.clone()).unwrap();
    let key = keys(&config, "a", "one");
    let now = Instant::now();
    let mut ledger = registration.budget.ledger.lock().unwrap();
    ledger.acquire(&key, now).unwrap();
    assert_eq!(ledger.charge(&key, 0, 100, now), None);
    drop(ledger);
    let mut exact = config.descriptors[0].clone();
    exact.entries[0].value = "a".into();
    exact.entries[1].value = "one".into();
    config.descriptors.insert(0, exact);
    config.descriptors.reverse();
    let updated = Budget::shared(config.clone()).unwrap();
    assert_eq!(key, keys(&config, "a", "one"));
    let mut ledger = updated.budget.ledger.lock().unwrap();
    assert!(ledger.charge(&key, 0, 100, now).is_some());
    ledger.release(&key, now);
}

#[test]
fn shared_bucket_rotates_batches_without_blocking_other_keys_or_directions() {
    let config = Config::parse(CONFIG.as_bytes()).unwrap();
    let shared = keys(&config, "a", "one");
    let other = keys(&config, "b", "one");
    let mut ledger = Ledger::new(config);
    let now = Instant::now();
    for _ in 0..3 {
        ledger.acquire(&shared, now).unwrap();
    }
    ledger.acquire(&other, now).unwrap();
    assert_eq!(ledger.admit_batch(1, &shared, 0, 100, now), None);
    assert_eq!(
        ledger.admit_batch(1, &shared, 0, 100, now),
        Some(Wait::Until(now + Duration::from_secs(1)))
    );
    assert_eq!(
        ledger.admit_batch(2, &shared, 0, 100, now),
        Some(Wait::Turn)
    );
    assert_eq!(
        ledger.admit_batch(3, &shared, 0, 100, now),
        Some(Wait::Turn)
    );
    assert_eq!(ledger.admit_batch(4, &other, 0, 100, now), None);
    assert_eq!(ledger.admit_batch(2, &shared, 1, 100, now), None);
    for (second, winner) in [(1, 1), (2, 2), (3, 3), (4, 1), (5, 2)] {
        let time = now + Duration::from_secs(second);
        let loser = winner % 3 + 1;
        assert_eq!(
            ledger.admit_batch(loser, &shared, 0, 100, time),
            Some(Wait::Turn)
        );
        assert_eq!(ledger.admit_batch(winner, &shared, 0, 100, time), None);
        assert_eq!(
            ledger.admit_batch(winner, &shared, 0, 100, time),
            Some(Wait::Turn)
        );
    }
}

#[test]
fn queued_batch_rebind_and_cancellation_leave_no_stale_head() {
    let config = Config::parse(CONFIG.as_bytes()).unwrap();
    let shared = keys(&config, "a", "one");
    let other = keys(&config, "b", "one");
    let mut ledger = Ledger::new(config);
    let now = Instant::now();
    for _ in 0..3 {
        ledger.acquire(&shared, now).unwrap();
    }
    ledger.admit_batch(1, &shared, 0, 100, now);
    ledger.admit_batch(1, &shared, 0, 100, now);
    ledger.admit_batch(2, &shared, 0, 100, now);
    ledger.admit_batch(3, &shared, 0, 100, now);
    ledger.cancel_batches(1);
    ledger.release(&shared, now);
    ledger.rebind(2, &shared, &other, now);
    assert_eq!(ledger.admit_batch(2, &other, 0, 100, now), None);
    assert_eq!(
        ledger.admit_batch(3, &shared, 0, 100, now + Duration::from_secs(1)),
        None
    );
    ledger.release(&other, now + Duration::from_secs(2));
    ledger.release(&shared, now + Duration::from_secs(2));
}
