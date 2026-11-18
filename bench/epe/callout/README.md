# HTTPCallout Envoy integration and performance tests

The reusable [HTTPCallout test server](../../../test/fixtures/httpcallout/README.md) lives under `test/fixtures`; this directory owns the Envoy integration and load harness. Kubernetes fixture coverage lives in `test/e2e/suites/epe`.

## Tests

```sh
go test -race ./bench/epe/callout/... ./test/fixtures/httpcallout/... \
  ./extensions/epe/pkg/filters/httpcallout ./extensions/epe/pkg/extensionprovider
```

The Envoy integration test requires Linux with Docker host networking and a local Envoy image:

```sh
go test -v ./bench/epe/callout -run '^TestEnvoyE2E$' \
  -args -envoy-image envoyproxy/envoy:v1.39.4
```

The path is HTTP client → Envoy → real EPE ext_proc gRPC server → real provider HTTP client → callout server; allowed traffic also reaches a real HTTP echo upstream. EPE policy projection, engine, body buffering and mutations use production code. The fixture injects a static policy resolver and synthetic workload identity through Envoy filter state. It does **not** deploy agentiod, Kubernetes, xDS policy distribution, TLS, or a production EPE main process. Absent `-envoy-image`, Docker tests explicitly skip.

The e2e matrix covers both phases, fail-open/closed, all endpoint modes, exact call counts (no silent identity bypass or retries), upstream reachability, header and body mutations, and same-provider recovery after faults. Each invocation creates a named temporary Envoy container and removes it on completion. Other containers and clusters are untouched. Do not run concurrently with capacity measurements on the same machine.

## Performance and stability

Reuse `bench/load` for scheduling and latency measurement. The full proxy chain is exercised; the load generator, EPE, callout endpoint and echo upstream share one Go process, while Envoy runs with two worker threads. Memory/goroutine/FD samples describe that entire Go process, not isolated EPE memory. Latency includes request creation, proxy round trip, response read and validation. Positive rates also include scheduler queueing; zero rate uses closed-loop concurrency.

```sh
go test -v ./bench/epe/callout -run '^TestEnvoyLoad$' -timeout 15m -args \
  -envoy-image envoyproxy/envoy:v1.39.4 \
  -callout-concurrency 64 -callout-requests 30000 -callout-rate 1000 \
  -callout-rounds 10 -callout-body 1024
```

Each round must complete all requests, validate every expected response and observe exactly one callout per request. `RESULT` JSON records throughput, latency, error counts, per-second counts, post-GC heap, goroutines, FDs and active callouts. Heap samples include measurement arrays retained for reporting; compare rounds with identical sizes. A round has a 10-minute safety deadline; deadline expiry fails instead of reporting a partial run as success. Body sizes are 0..1 MiB, with the fixture policy limit set to 2 MiB.

`-callout-path` selects `/request/<mode>/<open|closed>`, `/response/<mode>/<open|closed>` or `/headers/<mode>/<open|closed>`. `/baseline` keeps Envoy and EPE but resolves no callout rule. Load validation supports unchanged echo bodies with HTTP 200, or an expected non-200 status via `-callout-status` (e.g. 500 for fault/fail-closed). Mutation and custom-response contents are checked by e2e, not the load mode.

For a remote host without Go, cross-compile locally and transfer these binaries alongside `run.sh` to a dedicated remote directory:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/callout-server ./test/fixtures/httpcallout/server
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/callout.test ./bench/epe/callout
```

`GOMAXPROCS=4 ENVOY_IMAGE=envoyproxy/envoy:v1.39.4 bash run.sh` runs the e2e, concurrency/baseline matrix, 64 KiB and 1 MiB bodies in both phases, concurrent fault loads, three 100,000-request baseline/callout pairs, and a 5-minute 1,000 RPS soak. It stops on a failure and retains raw logs under `results/`. Keep those logs outside the source tree or in an ignored local directory. To measure EPE CPU separately from network and fixture costs, use the existing `BenchmarkCalloutCPUPath` in `extensions/epe/pkg/filters/httpcallout`.

To compare forwarding headers alone versus headers plus body, add `-callout-forward-headers`. This selects `headers.mode: all` and sends the same 16 synthetic request headers (each value 64 ASCII bytes), in addition to normal HTTP/Envoy headers. Keep the original request body identical in both runs:

```sh
for phase in headers request; do
  GOMAXPROCS=4 go test -v ./bench/epe/callout -run '^TestEnvoyLoad$' -args \
    -envoy-image envoyproxy/envoy:v1.39.4 -callout-forward-headers \
    -callout-path "/$phase/continue/closed" -callout-body 1024 \
    -callout-concurrency 64 -callout-requests 100000
done
```

Without that flag, headers are not forwarded (`headers.mode: none`); the `/headers/` route then sends only request metadata, without buffering a body.

## Isolated EPE measurements

Use `-callout-isolated` with `TestEnvoyLoad` to run the generator, EPE, callout endpoint and echo upstream in separate processes. EPE CPU/RSS is then recorded as `epe_cpu_seconds` and `epe_rss_bytes`; endpoint CPU/RSS is recorded as `endpoint_cpu_seconds` and `endpoint_rss_bytes`. The heap/goroutine/FD fields still describe the load-generator process. In the default shared mode those per-process CPU/RSS fields are zero. The fixture allocates GOMAXPROCS 4 to EPE, 8 to the endpoint and 4 to upstream; set the parent process's GOMAXPROCS separately.

```sh
GOMAXPROCS=4 go test -v ./bench/epe/callout -run '^TestEnvoyLoad$' -timeout 15m -args \
  -envoy-image envoyproxy/envoy:v1.39.4 -callout-isolated \
  -callout-forward-headers -callout-body 1048576 \
  -callout-concurrency 64 -callout-requests 10000
```

`-callout-process-artifacts /absolute/directory` retains each child's logs and CPU, mutex and block profiles (with profiling overhead). Without it, child logs are temporary. All child processes and the test Envoy are stopped after the test.

## HTTP/1.1 versus HTTP/2 comparison

Build the Linux test binary with `bash bench/epe/callout/build-h2c.sh /tmp/agentio-h2c` from the repository root. Copy `callout.test` and `compare-h2c.py` to one directory on a Linux Docker host. Both modes use the production AgentioConfig API and transport; no compiler overlay is needed.

Run `python3 compare-h2c.py` there for three alternating-order comparisons with isolated generator/EPE/endpoint/upstream processes. The runner validates every response, protocol, call count and refused-stream count, and writes raw logs plus `results/summary.json`. HTTP/2 runs set `-callout-http2`, selecting production `protocol: HTTP2` and asserting h2c on every invocation. The default client limit is 32 streams per connection; `-callout-client-streams` overrides it. `-callout-max-connections` sets the provider connection cap (zero omits the override: HTTP2 defaults to 32 connections and 8 idle connections, AUTO/HTTP1 to 128 and 64). `-callout-max-idle` overrides idle retention; `-callout-timeout=` uses the production 500ms timeout instead of the harness default of 2s.

The endpoint accepts HTTP/1.1 and h2c. `transport` records HTTP/1 and HTTP/2 invocation counts, cumulative POST connection count, current and peak connections, peak total and per-connection handlers, and refused streams. Health/statistics connections are excluded. Handler counts exclude streams before handler entry or after handler return, so they are not exact protocol-level active-stream counts. The fixture's `/reset` aborts the HTTP/2 stream when invoked over h2c.

Run `python3 compare-h2c.py --stream-sweep` to compare HTTP/1.1 with HTTP/2 client and server stream limits of 16, 32, 64, 100 and 250, using 1 KiB and 1 MiB bodies at concurrency 64 and 256. Each of the 24 combinations runs three times with rotated variant order; results go to `stream-results/`. `-callout-max-streams` sets the endpoint's advertised stream limit (zero uses Go's default). The client respects the smaller of its configured cap and the peer's advertised cap, opening more connections up to `maxConnections` before queueing.

Run `go test -race ./bench/epe/callout -run '^TestCalloutHTTPProtocols$'` for production protocol selection and reset/recovery without Docker. For the full functional matrix, run `callout.test -test.run '^TestEnvoyE2E$' -envoy-image envoyproxy/envoy:v1.39.4 -callout-forward-headers` once without and once with `-callout-http2`.

For connection saturation, `python3 compare-h2c.py --slow-sweep` compares HTTP/1.1 capped at 128 connections, HTTP/2 with 250 streams per connection, and HTTP/1.1 capped at 512 connections. Each variant runs 4,096 requests at concurrency 64/128/256/512, repeated three times in rotated order. `-callout-response-delay=200ms` maps successful continue decisions to the fixture's `/delay` endpoint while keeping the provider timeout at 2 seconds. Results go to `slow-results/`. The runner verifies that default HTTP/1.1 reaches but never exceeds 128 simultaneous handlers at concurrency 256/512, while the other variants exceed 128.

For flow-control diagnosis, `-callout-connection-window` sets the endpoint's HTTP/2 connection receive window in bytes; zero uses Go's default. It propagates to isolated endpoint processes and leaves the per-stream window unchanged. EPE cannot enlarge a peer's receive window from its client configuration. A high stream cap sharing a small connection window can increase flow-control waits and lock contention when sending large bodies. Tune the server window independently from the client stream cap and measure both memory and tail latency.

See [capacity planning and measured results](../../../docs/reference/epe-configuration.md#capacity-planning-and-measured-defaults) for cold-start validation, the controlled 1 MiB comparison, default pool capacity and idle-retention tradeoffs. Keep generated JSON, raw logs and profiles outside the repository.

## Protocol default capacity matrix

Build with `bash bench/epe/callout/build-h2c.sh`, copy `callout.test` and `compare-defaults.py` into the same directory on the benchmark host, then run `python3 compare-defaults.py`.
The runner varies concurrency, offered RPS and endpoint delays from 5ms to 500ms, and compares HTTP2's 32/8 connection defaults with the former 128/64 values across cold and warm rounds.
It leaves connection settings omitted for default cases; calls with up to 200ms endpoint delay also omit the timeout to exercise the production 500ms default.
The 500ms endpoint and closed-loop capacity cases explicitly use a 2s timeout.
Raw logs and structured records go to `default-results/`; overloaded cases retain their nonzero test exit status and error counts rather than being treated as successful capacity measurements.
Fixed-rate latency includes waiting in the load generator, and reported throughput includes final draining; use successful completions, errors and the per-second bins together when judging whether a requested rate is sustainable.
The harness sets the EPE ext_proc cluster's `max_requests` and `max_pending_requests` to 8,192 so Envoy's default 1,024-request circuit breaker does not reject the high-concurrency cases before they reach the callout pool.
Use `--prefix capacity-` to select the 500ms HTTP2 capacity-boundary cases, or `--output <directory>` to retain a separate repeat.
The [configuration reference](../../../docs/reference/epe-configuration.md#capacity-planning-and-measured-defaults) summarizes the measured capacity boundaries, overload failures and idle-retention tradeoff.
