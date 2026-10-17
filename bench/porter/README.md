# Porter scale tests

Reusable Porter image comparison against the repository's real ADS server, resource generators and Go WDS client. Requires Linux Kubernetes nodes, the repository's Go toolchain and permission to create/delete a **new disposable namespace**. The runner requires an explicit kubeconfig, refuses an existing namespace and cleans up its namespace on success or failure by default. Pass `--keep-namespace` to retain the final test environment for inspection; delete that namespace manually when finished. It records the original Pods and compares their UID, phase and restart counts after cleanup. If the runner is killed with SIGKILL or the host loses connectivity, delete the named test namespace manually.

The minimum inventory is 50,000 workloads. The default is 100,000 workloads, 100,000 Sandbox resources, 200 simulated nodes with 500 WDS resources each, two control planes and four Porters. These resources live in the real in-memory xDS Store, not in 100,000 Kubernetes Pods. Each workload has 20 labels and eight SNI rules. Node WDS uses real TLS ADS, wildcard subscriptions and the production reconnect logic. Porter receives real ext_proc RPCs with certificate instance claims and performs real cold demand requests, cache hits, eviction and resynchronization.

This is a component benchmark. Authentication of the simulated node is stubbed; it does **not** measure Kubernetes watches/compilation, token review, certificate issuance, Envoy/EPE forwarding or sandbox execution. Generated peer certificates model attributes already authenticated by Envoy. Test ADS certificates/token are generated per run and mounted from a temporary Secret, never baked into images or exported with results. No production credentials are required.

All components are implemented in Go. The [shared scheduler](../load/README.md) handles logical identities, concurrency, rate control and timing independently of Porter. `load/` supplies the Porter ext_proc adapter, simulated WDS clients and test ADS server. `run/` orchestrates Porter scenarios and analyzes saved results. Kubernetes resource creation/deletion, readiness polling, Pod exec and logs use client-go; certificate generation uses Go crypto. Neither orchestration nor analysis requires Python, kubectl or OpenSSL.

## Build

From the repository root (build for the Kubernetes node's architecture):

```sh
go build -o /tmp/porter-bench ./bench/porter/run
docker build -f bench/porter/Dockerfile --target bench -t porter-perf:dev .
docker build -f extensions/porter/docker/Dockerfile -t porter:dev .
kind load docker-image --name YOUR_KIND_CLUSTER porter-perf:dev porter:dev
kind get kubeconfig --name YOUR_KIND_CLUSTER > /tmp/porter-perf.kubeconfig
```

All variants must implement the same certificate-identity/metadata contract. Compare candidate images against a previously built baseline image; building the helper does not require a baseline implementation in this checkout.

The helper can also be built with `CGO_ENABLED=0 go build -o /tmp/porter-load ./bench/porter/load`. Its `server`, `watchers`, `client`, `get` and `idle` commands are used by the runner. Process CPU/RSS collection uses Linux `/proc` (CPU ticks assume Linux USER_HZ=100) and the load container shares its Porter's PID namespace. The Go module/toolchain and Rust lockfile determine dependency versions.

## Run

Do not run other builds or benchmarks on the host during a timed comparison. Allow roughly 12 CPU cores for the control planes, 12 for Porters, 12 for generators and 2 for WDS clients at configured limits; actual use varies by phase. The runner does not resize or remove existing workloads or kind clusters. Use a host with sufficient headroom; Kubernetes resource requests are deliberately smaller than limits.

```sh
/tmp/porter-bench run \
  --kubeconfig /tmp/porter-perf.kubeconfig \
  --namespace porter-perf-comparison \
  --output /tmp/porter-perf-comparison \
  --bench-image porter-perf:dev \
  --variant candidate=porter:dev \
  --workloads 100000 --gateways 4 --control-planes 2 \
  --suites reconnect,mixed,lifecycle,failover
# Reports are also generated automatically at the end of a run.
/tmp/porter-bench analyze /tmp/porter-perf-comparison
```

Add `--variant baseline=YOUR_BASELINE_IMAGE` to compare another image. Use `--variant-command baseline=/porter` for archived benchmark images with that executable path.

Variants run sequentially against fresh, identical inventories for each suite. `--variant-command` defaults to `/usr/local/bin/agentio-porter`; set it for images with a different binary path. Images default to `imagePullPolicy: Never`; use `--image-pull-policy IfNotPresent` for registry images. `--context` selects a context in the supplied kubeconfig. The output directory must be empty.

| Suite | Coverage |
| --- | --- |
| `reconnect` (default) | Full cold inventory, three hot-cache saturation trials, three forced ADS reconnects while serving 10,000 requests/s, full inventory verification afterward |
| `mixed` | Cold fill and rescan beyond the 10,000-entry per-Porter cache; disjoint hot and cold sets concurrently at 10,000 + 1,000 requests/s, default 60 seconds |
| `lifecycle` | Sandbox binding and combined SNI policy; update while serving traffic; revision verification; hot-subset reconnect; delete/reject/restore; 2-second idle TTL expiry and reload |
| `failover` | Delete one of at least two test control planes while serving simultaneous hot/cold requests through the shared ADS Service; verify WDS recovery and request outcomes |

The mixed suite also verifies the retained cache stays within its configured capacity after each workload. Request validation checks workload identity, instance alias, per-workload labels, expected revision and SNI rule count. Deleted identities must return 403; unexpected denial, stale revision after update convergence, timeout, incomplete request count or incorrect metadata fails the run. Updates in progress allow either revision, then the verification phase requires the new revision.

Porters use balanced, pinned control-plane addresses except in `failover`, which uses a Service. WDS clients use the shared Service. `reconnect` closes all ADS TCP connections on every test control plane, including the 200 WDS clients, then waits for fresh WDS transforms. Thus reconnect includes real stream admission competition and full cache resynchronization. WDS convergence time is **not** Porter recovery time.

Useful overrides (see `porter-bench run --help` for the full list):

- `--trials 5` for additional reconnect/hot repetitions; reverse variant order in a separate run to check order effects.
- `--mixed-seconds 180` to exercise longer sustained cache churn.
- `--cp-cpu 6 --porter-cpu 3 --load-cpu 3`, with `--cp-memory`/`--porter-memory` for limits.
- `--hot-rate`, `--cold-rate`, `--hot-requests`, `--reconnect-requests` for offered load and phase length. Counts/rates must divide evenly across gateways.
- `--prepare-seconds 20` if certificate/message preparation misses the common start. Such a miss fails explicitly rather than silently staggering clients.
- `--admission-rate 0` preserves the control plane's automatic stream-admission limit. A separate `--admission-rate 1000` experiment can isolate admission contention; this is an experimental setting, not a general production recommendation.

## Measurement and artifacts

Each worker prepares only its assigned certificates/messages before a common scheduled start. Fixed-rate latency includes waiting behind earlier requests to avoid hiding an overload queue. Saturation phases are closed-loop with fixed concurrency. The report's P99/max are the **worst worker's** values, not merged fleet quantiles; QPS is total completed operations divided by the common wall-clock interval.

`porter-bench analyze OUTPUT` produces `report.md`, `analysis.json`, `analysis.csv`, `admission-timings.json` and `apply-timings.json`. Raw worker results include completion counts per second, latency summaries, client CPU, Porter CPU/RSS and metrics before/after. Phase snapshots include both control planes' CPU/RSS, ADS messages/resources/bytes, admission rejections, WDS readiness/transforms and Porter metrics. Pod snapshots retain image IDs and resource limits. `config.json` records exact arguments; `cleanup.json` records namespace deletion or retention and any changes to original Pods. A failed run retains its partial results and `failure.txt`; both the runner and analyzer return a nonzero exit status for a failed run.

CPU per request is summed Porter process CPU delta divided by completed requests; its sampling window also includes the worker's final preparation/wait. CP mean CPU uses the wider phase snapshot interval, including preparation and snapshot collection. RSS is the sum of final process RSS, **not** live heap or a simultaneous peak; workers also report process VmHWM. For overlapping hot/cold phases the analyzer omits CPU, ADS wire and demand counter deltas rather than attributing the same counters twice. ADS byte counters use gRPC payload lengths, not NIC traffic including TLS/HTTP2 overhead. Raw snapshots remain available for whole-scenario analysis. These counters are not a replacement for a time-series cluster monitor.

The server logs `ads_first_request`: `before_recv_ms` includes admission, authentication and scheduling between RPC entry and first `Recv`; it is not a pure admission timer. `recv_ms` measures that first call. The analyzer filters historical logs to each phase's measured window.

For a separate Rust diagnostic run, enable:

```sh
# Add to porter-bench run arguments; keep normal performance runs at the default log level.
--variant-env 'candidate:AGENTIO_LOG_LEVEL=info,agentio_porter::discovery=debug' \
--variant-env candidate:AGENTIO_LOG_FORMAT=json
```

Rust logs cache invalidation time and ADS select/transform/publish/total durations. `publish_us` includes lock acquisition; `total_us` excludes destruction of remaining locals after return. Diagnostic logging can affect timings, so do not mix it into normal throughput comparisons. `apply-timings.json` is empty when debug logging is disabled or the tested binary predates these events.

Run local scheduling, client-go exec/cleanup, certificate and analyzer tests with `go test -race ./bench/load ./bench/porter/...`. These tests use a fake Kubernetes client and a local SPDY server; they do not create cluster resources. The scale suites themselves are the integration verification; no sub-50,000 synthetic smoke workload is required.

## Isolating control-plane regressions

Use `--control-plane-image` to select the ADS server independently of `--bench-image` (the fixed WDS/load clients) and `--variant` (the fixed Porter). Without this option ADS continues to use `--bench-image`. Build baseline and candidate servers from the same tree/toolchain with only the intended server patch changed; changing the entire helper image for every container would also change the clients.

```sh
/tmp/porter-bench run \
  --kubeconfig /tmp/porter-perf.kubeconfig \
  --namespace porter-cp-baseline --output /tmp/porter-cp-baseline \
  --bench-image porter-perf:fixed-clients \
  --control-plane-image porter-perf:baseline-server \
  --variant baseline=porter:fixed \
  --workloads 100000 --trials 1 --suites controlplane
```

Run the candidate with a fresh namespace/output and its server image. Alternate run order for repeated comparisons. The `controlplane` suite measures ordinary WDS updates (500, 5,000 and full-inventory batches), deletion/restoration, WDS-only reconnect, full cold demand, full-cache reconnect, bounded-cache fill/rescan, mixed hot/cold demand, three full-inventory updates during mixed demand, mixed reconnect, and single-replica failover. The inventory is always at least 50,000; a smaller update batch is not a smaller inventory.

WDS observers decode revisions and inspect client snapshots after change notifications. Each affected client's convergence time ends when its published snapshot contains the target revisions (or the intended deletions); reconnect additionally requires fresh resources. Timing starts when the observer is armed, before mutation/disconnect requests. It includes trigger delivery and resource construction/publication, not just network delivery. This instrumentation adds fixed client work to both A/B variants. Raw per-client timings are retained. The suite does not model Kubernetes watch/compilation or certificate issuance.

ADS `/stats` includes cumulative allocation, allocation count, GC count/pause time, heap and cgroup v2 CPU counters. Analysis additionally writes `controlplane-analysis.json` and `wds-convergence.json`. Use the parent mixed-scenario interval for control-plane totals, not the overlapping hot/cold worker intervals. A removed control plane marks an incomplete interval; surviving-replica CPU is not fleet total. Snapshot intervals include preparation and collection overhead, and RSS is an end sample rather than a simultaneous peak.

For local generator and subscription-churn microbenchmarks with 50,000/100,000-resource inventories:

```sh
go test ./pkg/xds -run '^$' \
  -bench '^BenchmarkControlPlane(Scale|DemandChurn)$' \
  -benchmem -benchtime=1s -count=3
```

These benchmarks isolate generator/handler cost with minimal valid resources. They complement the TLS ADS component suites; their time/op is not end-to-end request latency. Compare both revisions on the same machine, and keep profiling separate from timing runs.
