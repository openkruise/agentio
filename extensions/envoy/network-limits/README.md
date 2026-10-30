# Network limits dynamic module

Currently, this Rust HTTP dynamic module provides independent bandwidth and concurrency filters for CONNECT tunnels. Install them after trusted identity filters and before the router on `connect_terminate`. HTTP, TLS and other TCP payloads consume the same byte budget; inner TLS records count as bytes. Outer HBONE headers, HTTP/2 framing, outer TLS and IP overhead do not count. No Envoy source changes are needed.

`src/lib.rs` registers both filters. `src/bandwidth/` and `src/concurrency/` each contain their implementation in `mod.rs` and unit tests in `tests.rs`; `src/descriptor.rs` contains their shared descriptor matching and validation. The library is named `envoy_agentio_network_limits`; the individual filter names remain `envoy_agentio_bandwidth` and `envoy_agentio_connect_concurrency`. CONNECT establishment rate limiting still uses Envoy's native filter.

The gateway image includes `libenvoy_agentio_network_limits.so`. Enable it with `egressGateways[].bandwidthLimit` in [AgentioConfig](../../../docs/reference/agentio-configuration.md#connect-bandwidth-limits); see the [configuration example](../../../manifests/examples/gateway-bandwidth-config.yaml). The controller generates the filter placement, module path and stable `agentio/<namespace>/<name>/bandwidth` budget name. Gateway API parameters use the same settings. Do not derive production identity from arbitrary client headers. The module targets the community Envoy gateway, not legacy proxyv2.

This controller requires the matching gateway image with Envoy 1.40.2 and these updated modules, even when limits are disabled. Upgrade gateway images before rolling out the controller; older modules cannot parse the generated configuration.

Upgrading from the previous always-instantiated filters changes the HCM defaults once and follows Envoy's normal listener update/drain behavior. Subsequent policy enable/disable operations keep HCM unchanged.

The native gateway keeps fixed ECDS filter entries in HCM with `disabled: true`. RDS enables each entry on the TCP CONNECT route only when its corresponding public setting is present. With a setting absent, Envoy creates no instance of that filter for a new stream: there is no module stream registration or body callback. ECDS providers and module configuration still exist. Enabling or disabling a limit updates RDS and ECDS without replacing the listener or draining HTTP/2 connections; new CONNECT streams on an existing HTTP/2 connection use the updated route. All accounting remains local to one Envoy process.

Only streams created with a filter instance participate in its later policy updates. A CONNECT established while that filter was off remains outside its accounting and enforcement until it closes, even after the limit is enabled. Removing a setting stops creating new instances and disables restrictions on existing instances; those instances remain until stream destruction and can participate when the limit is enabled again. Thus activation does not establish a strict total concurrent-stream or bandwidth cap over tunnels that already existed without the filter. Drain or reconnect those tunnels if complete coverage is required. The two filters are enabled independently.

The controller sends ECDS before RDS, but this ordering is not an ACK barrier or an atomic activation. An accepted module configuration publishes shared policy through the main-dispatcher scheduler; worker callbacks apply it asynchronously. During convergence, route enablement and module policy may differ. Rejected configuration candidates do not publish; destroying old configuration objects never restores old policy. An ECDS ACK alone does not indicate that every existing instance has completed migration, and the two filters do not form one transaction.

## Independent concurrency filter

The same library also registers `envoy_agentio_connect_concurrency`. Enable it independently with `egressGateways[].connectConcurrencyLimit`; see the [configuration and lifecycle contract](../../../docs/reference/agentio-configuration.md#connect-concurrency-limits) and [combined example](../../../manifests/examples/gateway-concurrency-config.yaml). Agentio installs it after native CONNECT rate limiting and before bandwidth shaping. The concurrency filter uses the same descriptor matcher but has its own registry; an existing instance retains its worker scheduler handle when its policy is disabled, without per-body accounting or a pacing timer. Streams created while its route entry is disabled have no instance or scheduler handle.

For direct module configuration, use `filter_name: envoy_agentio_connect_concurrency`, keep `dynamic_module_config.name: envoy_agentio_network_limits`, the same library path and `do_not_close: true`. Its JSON has `budget_name` (default `default`), `rate_limits`, `descriptors` and `max_dynamic_buckets` (default 10000). Each descriptor contains `entries` and positive numeric uint32 `max_concurrent_streams`; byte rates and buffer watermarks are not accepted. Limits and grouping can update in place. For grouping changes, all tracked streams (including idle ones) resolve current filter state again. New admissions wait for that census; existing streams count even above the new quota/capacity and are not evicted merely for exceeding it. Closing a stream during migration removes it from the census. Standalone callers choose a shared budget name; Agentio generates `agentio/<namespace>/<name>/connect_concurrency`.

`tests/concurrency_test.go` checks both concurrency-only and all-three-filter chains with two workers: shared sandbox and gateway totals, request half-close, normal completion, reset, connection loss, upstream failure, LDS limit changes and rejected-candidate isolation. Run it using:

```sh
./bin/test_network_limits.sh agentio-network-limits:test
```

## Bandwidth module configuration

The module parses the JSON representation of `filter_config` (`google.protobuf.Struct`); these fields are not a new Agentio CRD or the native Envoy rate-limit protobuf. Descriptor terminology follows Envoy's local rate-limit configuration:

```yaml
budget_name: sandbox-bandwidth
rate_limits:
  - actions:
      - filter_state: {key: tenant.id, descriptor_key: tenant}
      - filter_state: {key: sandbox.id, descriptor_key: sandbox}
descriptors:
  - entries:
      - {key: tenant}
      - {key: sandbox}
    bandwidth_limit:
      upload_bytes_per_second: 10485760
      download_bytes_per_second: 52428800
      upload_burst_bytes: 1048576
      download_burst_bytes: 5242880
max_dynamic_buckets: 10000
buffer_limit_bytes: 65536
```

- Each action group produces one ordered descriptor. All entries form a composite key: `(tenant=A, sandbox=X)` is independent of `(tenant=B, sandbox=X)`. A `generic_key: {descriptor_key: ..., descriptor_value: ...}` action adds a fixed entry.
- Entries with omitted or empty `value` are wildcards: every distinct actual value combination gets its own budget. Nonempty `value` matches exactly. Full exact descriptors take priority; otherwise the first matching wildcard descriptor wins. Prefix matching is not supported.
- Multiple action groups can apply simultaneously, for example a tenant-wide budget and a tenant/sandbox budget. All applicable budgets must permit a batch before any are charged; duplicate matches are charged once.
- Upload means downstream to upstream; download means upstream to downstream. Directions have independent budgets. Rates are positive integer **bytes per second** (numbers or ProtoJSON uint64 strings). An omitted direction is unlimited; zero and a descriptor with neither rate are invalid.
- Optional `upload_burst_bytes` and `download_burst_bytes` set positive burst capacities (numbers or ProtoJSON uint64 strings) and require the matching rate. Credit starts full and refills at that rate, capped at the configured capacity, shared by all streams/workers using the key. Omission preserves legacy one-batch pacing; explicit zero is invalid. Burst capacity is separate from buffer watermarks and dynamic-bucket capacity.
- Required filter state is read at request headers and again on grouping changes, using its serialized UTF-8 string. Missing, empty or unserializable values reject new requests with 403; a new rule requiring unavailable identity resets an already accepted stream. Rule updates cannot reconstruct identity never stored by the trusted filters. Complete descriptors with no match are unlimited. Include a wildcard descriptor when every key must be limited.
- Unknown configuration fields, duplicate descriptors and entries that do not match an action group's ordered keys reject configuration loading.

## Sharing, buffering and lifecycle

For standalone module configuration, `budget_name` defaults to `default`. All filter instances with the same name in the loaded module share budgets across workers, listeners and connections in one Envoy process. Different replicas/processes do not share budgets. Use the same module path and `do_not_close: true`, as generated by Agentio, to retain the registry through configuration replacement.

Rate changes reuse the existing buckets. Remaining debt in bytes is preserved and converted to time at the new rate; waiting streams are notified on their workers. Omitting a direction makes it unlimited; previous debt continues expiring at its last rate so a quick rollback cannot refill the bucket. The latest accepted configuration supplies rates and capacity, including for streams using older filter configurations. Constructing a candidate does not mutate shared state; accepted policies publish through the configuration scheduler. Worker migration is asynchronous, and this is not an atomic multi-resource update.

Actions and descriptor entries/order may change while managed streams are active; see the update semantics below. Keep the budget name stable across updates. Disabling a policy wakes paused streams and retains their existing filter instances for later enablement. It does not add instances to streams that bypassed the filter at creation. Watermark changes also notify existing instances.

`max_dynamic_buckets` defaults to 10000 and bounds wildcard-derived buckets per budget name, across descriptor rules. Active buckets and buckets with unpaid byte debt cannot be evicted. A new distinct key that exceeds capacity receives 503. Lowering capacity preserves existing buckets and blocks new keys until capacity is available. Reconnecting never resets outstanding debt. Explicit exact descriptors do not consume this dynamic capacity.

When the last CONNECT stream using a bucket closes, a settled bucket is removed immediately. Otherwise, it is retained until both directions' debt expires, then reclaimed automatically even without new traffic. Reconnecting cancels that bucket's expiration; rate changes and rollback update its deadline. An ordered expiration index avoids scanning all buckets on admission, and cleanup releases the ledger lock after at most 64 removals. Cleanup and stream resumption share one module-wide timer thread. Removing entries releases their keys and capacity slots; the hash table allocation can retain its previous high-water capacity, so process RSS need not return to its initial level.

The module uses virtual-time token accounting: each bucket stores when its consumed bytes will have fully refilled. With burst configured, a batch waits until there is credit for its entire size. A callback batch larger than the burst capacity waits for all prior consumption to refill, passes whole, and is charged in full; this avoids permanently stalling oversized batches. Consequently the effective burst can exceed the configured capacity by callback granularity, and this is not a strict wire-level burst cap. Without burst, each batch waits for all prior consumption, preserving existing behavior. Neither mode accumulates unlimited credit while idle.

Changing burst capacity changes available credit without forgetting consumed bytes; rate changes convert that consumption at the new rate. Reconnects and rejected configurations do not reset credit. Idle buckets remain until fully refilled, even if they already have enough credit to admit another batch. Envoy owns the buffered bytes. A waiting stream returns `StopIterationAndWatermark`; a timer thread posts callbacks to the owning worker to resume it. Cancellation removes pending timers. Both directions use Envoy's streaming watermarks for source backpressure.

`buffer_limit_bytes` defaults to 65536 and sets the stream's **soft watermark**, not a hard allocation or burst cap. The callback batch size depends on Envoy, transport buffers and other filters. Short transfers can pass in the first batch; subsequent traffic, including reconnects, pays for it. The sustained cap is per key; waiting streams take FIFO turns for whole callback batches, independently per direction. A successful stream rejoins at the tail; cancellation and rule migration remove or move its queue entries. Only queue heads use pacing timers. This prevents the previous wake-and-race starvation, but does not promise equal byte shares for differently sized batches, minimum bandwidth, CPU isolation or global link capacity allocation. A batch subject to several budgets waits for the slowest one, which can delay successors sharing those budgets. Choose limits whose aggregate fits the available link.

Supported placement is the TCP CONNECT chain, immediately before the router and after trusted identity processing. **Do not enable router retries on this chain**, including route/virtual-host retry policies or retry-policy extensions. The module rejects `x-envoy-retry-on` and `x-envoy-retry-grpc-on` headers that reach it with 400 (`bandwidth_retry_unsupported`). Do not combine it with internal redirects, buffered request mirroring, or other filters that retain already-forwarded body data in the shared filter-manager buffer: resuming that buffer can send those bytes again. Agentio's generated CONNECT route has no retries; retries on the separate inner HTTP chain are unaffected. Manual gateway patches must preserve this restriction; the module cannot inspect route retry policies through the current ABI.

CONNECT-UDP, separately configured upgrade filter chains, and traffic bypassing this listener are outside this integration. The pinned SDK and the Envoy v1.40.2 HTTP dynamic-module SDK lack partial data injection for splitting a batch across resumptions, so this module retains batch pacing rather than a strict burst cap. The SDK and gateway image are pinned to Envoy v1.40.2.

**Envoy v1.39.4 limitation:** when a raw TCP upstream closes first while the HTTP/2 CONNECT request remains open and the response is blocked by the downstream HTTP/2 window, Envoy can reset the stream before delivering its final bytes. This also reproduces without this module. The runtime option `allow_multiplexed_upstream_half_close` does not fix the TCP-upstream case. The HTTP/2 transfer tests half-close the request after sending its payload; the HTTP/1 tests exercise upstream-first closure. Validate this close pattern with your actual HBONE client before production deployment; this module does not fix Envoy's CONNECT close semantics.

## Build and test

On Linux, install Rust 1.93+, Go (the version in `go.mod`), clang/libclang, curl, tar and Docker. Run from the repository root:

```sh
bash extensions/envoy/network-limits/build.sh
docker build --target runtime -t agentio-network-limits:test extensions/envoy/network-limits
./bin/test_network_limits.sh agentio-network-limits:test
```

`build.sh` checks formatting, runs Rust tests and builds the shared library. The SDK is pinned to Envoy tag `v1.40.2`, matching the repository's Envoy v1.40.2 image. Remove `.envoy-sdk` when changing the pin; the dynamic-module ABI must match the Envoy binary.

`bin/test_network_limits.sh IMAGE` builds a Go test binary in a temporary directory outside the repository and runs it as the gateway user against the given image. The image build workflow runs it on both native architectures before recording the candidate digest. No Python or OpenSSL executable is required.

The real-Envoy fixture runs two workers with local TCP/TLS origins and HTTP/1 CONNECT plus multiplexed HTTP/2 CONNECT clients. Test-only headers populate filter state. It checks aggregate upload/download, full-duplex resumption, retry-header rejection, independent composite keys, a fast stream beside a limited stream, shared HTTP/TLS budgets, missing identity, HTTP/2 half-close, source backpressure, Envoy RSS growth and cancellation. A Rust regression test ensures request resumption returns without touching the filter again and leaves the response scheduled; configuration tests keep inner HTTP retries off the outer CONNECT route. File-based LDS updates verify speed increases/decreases on an existing tunnel and rollback when a later filter rejects a candidate. Go tests cover watched AgentioConfig updates through generated xDS listeners, both configuration entry points, and TCP-only placement. Production identity discovery, mTLS/SDS and the full Agentio deployment require separate end-to-end testing.

## Performance benchmarks

Reusable Go load generation, Envoy/origin orchestration and result analysis live under [`bench/connect`](../../../bench/connect/README.md). Store generated binaries, logs, results and reports outside the repository. The benchmark supports bandwidth-only and combined concurrency/bandwidth comparisons and has no Python runtime dependency. The Go tests in this module share `bench/connect/fixture` with the benchmark.

## Updating rules on existing streams

Bucket identity consists of action sources and resolved values, independent of the descriptor array index. Adding an exact override, deleting it to fall back to a wildcard, or reordering descriptors preserves consumption for the same key. Changed action sources/grouping start new bandwidth scopes: historical bytes cannot be exactly redistributed after splitting or merging groups. Removed keys retain unpaid debt until expiration; new streams still respect distinct-key capacity. Migrating accepted streams may temporarily exceed that capacity.

`tests/hot_reload_test.go` exercises filesystem ECDS with Envoy 1.40.2: disabled-to-enabled idle-stream counting, changes of descriptor precedence and identity source on existing HTTP/2 connections, release after close, disable/re-enable, rejected updates, and bandwidth activation on an existing stream. These direct-module tests create filter instances even when the module JSON has `enabled: false`; they verify the lifecycle of managed streams. Agentio's default-disabled HCM entry instead omits the instance entirely until RDS enables it. `tests/route_gate_test.go` verifies independent RDS/ECDS activation on an existing HTTP/2 connection, unmanaged streams remaining outside the limits, recounting managed streams after re-enablement, and releasing a throttled download on disablement. Configuration tests verify independent TCP-only route gates and unchanged HCM across settings changes. The public AgentioConfig format is unchanged.

`TestEnvoySharedBucketProgress` covers 8 and 32 streams sharing 1 MiB/s in both directions, verifying every payload and bounding each stream's no-progress interval. Queue tests cover cancellation, key migration, direction isolation and repeat attempts by a stream that just consumed a batch. The reusable `bench/connect` fairness suite samples receiver progress over longer runs, including a separate fast sandbox beside throttled streams.
