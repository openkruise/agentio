# Sandbox policy lookup benchmarks

Run the EPE hot-cache and TTL-refresh benchmarks and the Go query client's 64-caller cold wave from the repository root.

```sh
GOMAXPROCS=2 go test ./extensions/epe/cmd/epe -run '^$' -bench BenchmarkSandboxPolicyDelivery -benchmem -count=5
GOMAXPROCS=2 go test ./pkg/xdsclient -run '^$' -bench BenchmarkSandboxQueryColdWave -benchmem -count=5
```

The first benchmark uses the production gRPC service over TLS, EPE's retention cache, and its asynchronous policy admission path. It verifies the number of unary calls. The second parks every caller before allowing the backend to reply, with either one name or 64 distinct names. Its unit of work is a whole wave.

## Run against kind

On the Linux build host for your kind cluster, build the fixture and the two driver binaries. The fixture uses a temporary Go module file for its PostgreSQL dependency. The production module files are untouched.

```sh
bin=$(mktemp -d)
cp go.mod "$bin/fixture.mod"
cp go.sum "$bin/fixture.sum"
go mod edit -modfile="$bin/fixture.mod" -require=github.com/jackc/pgx/v5@v5.10.0
CGO_ENABLED=0 go build -mod=mod -modfile="$bin/fixture.mod" -o "$bin/backend" bench/sandbox/query/fixture.go
CGO_ENABLED=0 go test -c -o "$bin/epe.test" ./extensions/epe/cmd/epe
cargo test --manifest-path extensions/porter/Cargo.toml --locked --release --test sandbox_query_benchmark \
  --no-run --message-format=json > "$bin/cargo.jsonl"
cp "$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "sandbox_query_benchmark" and .executable != null) | .executable' "$bin/cargo.jsonl")" "$bin/porter.test"
```

Pass the existing kind cluster name and binary directory. Each invocation creates an isolated namespace, seeds 300,000 policies, runs the drivers sequentially, and deletes the namespace. The three pods each have a 2-CPU and 2-GiB limit. The driver uses the build host's glibc libraries to run the Rust binary inside Alpine. The fixture requires the repository's Go and Rust toolchains, a compatible `protoc`, and cgroup v2.

```sh
cluster=kind   # Use the name shown by kind get clusters.
bash bench/sandbox/query/kind.sh "$cluster" "$bin" db 120s
bash bench/sandbox/query/kind.sh "$cluster" "$bin" snapshot 120s
AGENTIO_SANDBOX_BENCH='{"Mode":"xds","Address":"api:9000","Root":"/tmp/ca.crt","Token":"/tmp/token","Keys":10000,"Warm":10000,"Requests":100000,"Workers":64,"Rate":0,"PauseMS":0}' \
  bash bench/sandbox/query/kind.sh "$cluster" "$bin" snapshot 120s
```

The `snapshot` backend precompiles the first 50,000 rows once (override with `QUERY_BENCH_INVENTORY`). Both protocols serve those same published resources. The `db` backend serves unary queries with one indexed SQL read, JSON decode and `CompileSandboxPayload` per lookup. The fixture uses the production delta and unary handlers with TLS and a fixed benchmark bearer identity. It exercises policy resolution inside Porter and EPE. Envoy traffic processing, Kubernetes attestation and control-plane controllers are outside the measurements.

| Driver field | Meaning |
| --- | --- |
| `Keys`, `Warm` | Size of the round-robin UID set and number of distinct keys fetched before the measured phase. Each driver starts with an empty cache. |
| `Requests`, `Workers` | Number of measured resolutions and maximum concurrent workers. |
| `Rate` | Zero uses closed-loop concurrency. A positive value schedules arrivals per second. The reported p99 includes queueing. `operation_p99_ms` starts when a worker begins the lookup. |
| `PauseMS` | Delay after warm-up. Use a value above the server TTL to exercise expiration. |
| `MaxEntries` | Optional client cache capacity. Zero uses the production default without an entry limit. |

`SAMPLE` lines report throughput, latency and errors for each phase. `COUNTERS` lines bracket those phases with cumulative SQL reads, unary calls, delta responses/resources and CPU seconds. The client CPU counter is in microseconds. RSS is in MiB. The fixture's stats endpoint samples PostgreSQL's cgroup CPU with a separate query which is excluded from the policy-read counter. Point `AGENTIO_QUERY_BENCH_HEAP` at a writable file when invoking the EPE driver directly to capture its live heap after GC, before its caches shut down.
