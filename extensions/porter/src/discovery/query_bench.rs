// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

//! Local hot-path benchmarks for the Sandbox query client.
//! Run: cargo test --release --lib query_bench -- --ignored --nocapture

use super::query_tests::QueryFixture;
use super::*;
use crate::wire::agentio::sandbox::Sandbox;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

fn percentile(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx] as f64 / 1e6
}

fn sample(name: &str, workers: usize, samples: &mut [u64], seconds: f64) {
    samples.sort_unstable();
    println!(
        "SAMPLE {} {}",
        name,
        json!({
            "workers": workers,
            "operations": samples.len(),
            "seconds": seconds,
            "ops_per_second": samples.len() as f64 / seconds,
            "p50_ms": percentile(samples, 0.50),
            "p99_ms": percentile(samples, 0.99),
        })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn query_hot_hit() {
    const KEYS: usize = 1000;
    const REQUESTS: usize = 200_000;
    let f = QueryFixture::new().await;
    let c = f.client();
    let names: Vec<String> = (0..KEYS).map(|i| format!("vm:{i:06}")).collect();
    for name in &names {
        f.put(name, Sandbox { uid: name.clone(), ..Default::default() });
        c.demand(ResourceKind::Sandbox, name, None).await.unwrap();
    }
    let mut samples = Vec::with_capacity(REQUESTS);
    let start = Instant::now();
    for i in 0..REQUESTS {
        let begin = Instant::now();
        c.demand(ResourceKind::Sandbox, &names[i % KEYS], None).await.unwrap();
        samples.push(begin.elapsed().as_nanos() as u64);
    }
    sample("hot-hit-sequential", 1, &mut samples, start.elapsed().as_secs_f64());

    for workers in [8, 64] {
        let mut set = JoinSet::new();
        let per = REQUESTS / workers;
        let start = Instant::now();
        for w in 0..workers {
            let (c, names) = (c.clone(), names.clone());
            set.spawn(async move {
                let mut samples = Vec::with_capacity(per);
                for i in 0..per {
                    let begin = Instant::now();
                    c.demand(ResourceKind::Sandbox, &names[(w * per + i) % KEYS], None)
                        .await
                        .unwrap();
                    samples.push(begin.elapsed().as_nanos() as u64);
                }
                samples
            });
        }
        let mut all = Vec::with_capacity(REQUESTS);
        while let Some(part) = set.join_next().await {
            all.extend(part.unwrap());
        }
        sample(
            &format!("hot-hit-parallel{workers}"),
            workers,
            &mut all,
            start.elapsed().as_secs_f64(),
        );
    }
    assert_eq!(f.calls(), KEYS);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn query_coalesced_wave() {
    const WORKERS: usize = 64;
    const WAVES: usize = 500;
    let f = QueryFixture::new().await;
    // Zero TTL makes every wave cold. The 1ms backend delay overlaps concurrent
    // arrivals into one flight; late arrivals legitimately start a new one, so
    // coalescing is reported as lookups/wave rather than asserted exactly.
    f.set_ttl(Duration::ZERO);
    f.set_delay(Duration::from_millis(1));
    f.put("vm:one", Sandbox { uid: "vm:one".into(), ..Default::default() });
    let c = f.client();
    let mut samples = Vec::with_capacity(WAVES);
    let start = Instant::now();
    for _ in 0..WAVES {
        let begin = Instant::now();
        let mut set = JoinSet::new();
        for _ in 0..WORKERS {
            let c = c.clone();
            set.spawn(async move { c.demand(ResourceKind::Sandbox, "vm:one", None).await.unwrap() });
        }
        while let Some(result) = set.join_next().await {
            result.unwrap();
        }
        samples.push(begin.elapsed().as_nanos() as u64);
    }
    sample("coalesced-wave", WORKERS, &mut samples, start.elapsed().as_secs_f64());
    let calls = f.calls();
    println!("coalesced-wave lookups/wave: {:.2}", calls as f64 / WAVES as f64);
    assert!(calls >= WAVES && calls <= WAVES * WORKERS, "calls = {calls}");
}