// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

//! Opt-in load test for the same Sandbox demand and wire projection as Porter.
use agentio_porter::{
    discovery::{CacheConfig, Client, TransportConfig},
    metrics::Metrics,
    view::{ResourceKind, View},
    wire::ads::Node,
};
use anyhow::{Result, ensure};
use serde::Deserialize;
use serde_json::json;
use std::{
    env,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    task::JoinSet,
    time::{Instant, sleep, sleep_until, timeout},
};
use tokio_util::sync::CancellationToken;

#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Config {
    mode: String,
    address: String,
    root: String,
    token: String,
    keys: usize,
    warm: usize,
    requests: usize,
    workers: usize,
    #[serde(default)]
    max_entries: usize,
    rate: usize,
    #[serde(rename = "PauseMS")]
    pause_ms: u64,
}

fn probe(phase: &str, when: &str) -> Result<()> {
    if let Some(path) = env::var_os("AGENTIO_QUERY_BENCH_PROBE") {
        let out = Command::new(path).output()?;
        ensure!(out.status.success(), "sampling {phase}-{when} failed");
        println!(
            "COUNTERS {phase}-{when} {}",
            std::str::from_utf8(&out.stdout)?.trim()
        );
    }
    Ok(())
}

async fn phase(
    client: &Arc<Client>,
    names: &Arc<Vec<String>>,
    c: &Config,
    warm: bool,
) -> Result<()> {
    let (name, keys, count, rate) = if warm {
        ("warm", c.warm, c.warm, 0)
    } else {
        ("measure", c.keys, c.requests, c.rate)
    };
    let next = Arc::new(AtomicUsize::new(0));
    let mut workers = JoinSet::new();
    probe(name, "start")?;
    let start = Instant::now();
    for _ in 0..c.workers {
        let (client, next, names) = (client.clone(), next.clone(), names.clone());
        workers.spawn(async move {
            let mut samples = Vec::new();
            let mut errors = 0;
            let mut first = None;
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= count {
                    break;
                }
                let arrival = if rate == 0 {
                    Instant::now()
                } else {
                    let due = start + Duration::from_secs_f64(i as f64 / rate as f64);
                    if due > Instant::now() {
                        sleep_until(due).await;
                    }
                    due
                };
                let begin = Instant::now();
                let uid = &names[i % keys];
                let result = timeout(
                    Duration::from_secs(4),
                    client.demand(ResourceKind::Sandbox, uid, None),
                )
                .await;
                let correct = match &result {
                    Ok(Ok(view)) => matches!(view.as_ref(), View::Sandbox(s)
                        if &s.uid == uid && s.workload_uid == "host"
                            && s.profile.as_ref().is_some_and(|p| &p.uid == uid)),
                    _ => false,
                };
                if !correct {
                    errors += 1;
                    first.get_or_insert_with(|| format!("{uid}: {result:?}"));
                }
                let finish = Instant::now();
                samples.push((
                    (finish - arrival).as_nanos() as u64,
                    (finish - begin).as_nanos() as u64,
                ));
            }
            (samples, errors, first)
        });
    }
    let mut batches = Vec::new();
    while let Some(batch) = workers.join_next().await {
        batches.push(batch?);
    }
    let seconds = start.elapsed().as_secs_f64();
    probe(name, "end")?;
    let mut total = Vec::with_capacity(count);
    let mut op = Vec::with_capacity(count);
    let mut errors = 0;
    let mut first = None;
    for (batch, nerr, err) in batches {
        errors += nerr;
        first = first.or(err);
        for (t, o) in batch {
            total.push(t);
            op.push(o);
        }
    }
    ensure!(total.len() == count);
    total.sort_unstable();
    op.sort_unstable();
    let ms = |a: &[u64], p: usize| a[(count * p / 100).min(count - 1)] as f64 / 1e6;
    println!(
        "SAMPLE {name} {}",
        json!({"operations":count,"unique_attempted":keys.min(count),
        "seconds":seconds,"ops_per_second":count as f64 / seconds,"p50_ms":ms(&total,50),
        "p95_ms":ms(&total,95),"p99_ms":ms(&total,99),"operation_p99_ms":ms(&op,99),
        "errors":errors,"first_error":first,"concurrency":c.workers,"offered_rate":rate})
    );
    ensure!(errors == 0, "{errors} failures: {first:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running policy benchmark fixture"]
async fn sandbox_policy_load() -> Result<()> {
    let c: Config = serde_json::from_str(&env::var("AGENTIO_SANDBOX_BENCH")?)?;
    ensure!(
        matches!(c.mode.as_str(), "rpc" | "xds")
            && c.keys > 0
            && c.warm <= c.keys
            && c.requests > 0
            && c.workers > 0
    );
    let transport = TransportConfig {
        address: c.address.clone(),
        root_path: c.root.clone(),
        token_path: c.token.clone(),
        node: Node {
            id: "porter".into(),
            ..Default::default()
        },
    };
    let client = Client::new_with_query(
        CacheConfig {
            max_entries: c.max_entries,
            ..CacheConfig::default()
        },
        Metrics::new(),
        true,
        (c.mode == "rpc").then(|| transport.clone()),
    );
    let stop = CancellationToken::new();
    let reader = tokio::spawn(client.clone().run(transport, stop.clone()));
    let expiry = tokio::spawn(client.clone().expire(stop.clone()));
    timeout(Duration::from_secs(8), client.readiness().wait_for(|v| *v)).await??;
    let names = Arc::new((0..c.keys).map(|i| format!("sandbox:{i:06}")).collect());
    if c.warm > 0 {
        phase(&client, &names, &c, true).await?;
    }
    sleep(Duration::from_millis(c.pause_ms)).await;
    let result = phase(&client, &names, &c, false).await;
    stop.cancel();
    reader.await?;
    expiry.await?;
    result
}
