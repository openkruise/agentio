# Agentio Porter

Porter is the Rust connection processor. It resolves the source Workload and its SNI policies for the gateway's outer HBONE CONNECT request. It implements standard Envoy ext_proc on `127.0.0.1:9002`; application HTTP processing remains with EPE or the configured HTTP ext_proc provider.

The gateway passes Envoy's TLS-verified peer certificate to Porter using `%DOWNSTREAM_PEER_CERT%` in CONNECT-local filter state. Porter reads the existing non-critical JSON instance extension (`1.3.6.1.4.1.57874.5.1`): `registry` names a trusted source registry and its installation/cluster scope, and `uid` is the immutable, non-reused instance key within that registry. Neither field assumes Kubernetes. The optional `role` is not part of the lookup key. For example, Kubernetes uses `kubernetes/<cluster-id>` plus the actual Pod UID; another runtime can use its own registry and instance UID. The issuer must attest these claims; a CSR cannot authorize its own identity.

Porter demands WDS through the instance alias `workload-instance/<registry>/<escaped-uid>`, using the control-plane-issued alias as the authoritative mapping to the workload. The xDS client resolves the requested alias and rejects ambiguous mappings; no duplicate instance identity is carried in the workload payload. The UID is percent-encoded using RFC 3986 unreserved characters; the registry retains its path separators. For example, registry `kubernetes/demo` and UID `pod-123` produce `workload-instance/kubernetes/demo/pod-123`. The WDS resource name remains unchanged. Deleted instances and mismatching replacements reject CONNECT, including when a new instance reuses the same workload name. Names and namespaces come from the resolved WDS resource; CONNECT name headers do not override certificate identity. The control plane publishes the instance alias independently of optional workload-label configuration.

Only certificates without the instance extension use physical peer IP plus certificate principal to resolve the Workload. Native gateways do not capture workload name/namespace CONNECT headers, and Porter does not consume those attributes. Unknown or ambiguous IPs, host-network workloads and identity mismatches reject that IP fallback. This fallback requires direct sidecar connections with the source Pod IP preserved; it does not resolve through SNAT or intermediate proxies. Malformed certificates/extensions, missing certified instances and instance mismatches never fall back. Shared ambient ztunnels still need per-instance certificate issuance and caching before they can stop relying on source-IP preservation. This change does not alter certificate issuance or migrate substrate's distinct ActorIdentity OID.

The certificate authenticates the Workload/attester, not each Sandbox. The optional `X-AGENTIO-SANDBOX-ID` CONNECT header selects the Sandbox for that tunnel. Porter requires its WDS attester binding to match the resolved Workload; an absent, unassigned or differently bound Sandbox is rejected. Multiple Sandboxes can share one Workload certificate, while each CONNECT selects exactly one Sandbox. `X-AGENTIO-SANDBOX-TOKEN` remains available to downstream EPE; it does not select or authenticate the Workload. Sandbox ID and token are hashable filter state shared once with the next internal listener so internal connection pools cannot reuse another Sandbox's context. Policies and workload labels come from discovery, not client assertions. Existing legacy waypoint behavior is unchanged. It does not evaluate an SNI supplied in request headers. The gateway exposes certificate principals as `agentio.peer.principal` and `agentio.local.principal`; Porter reads only `agentio.peer.principal`. Custom CEL expressions for the new gateway must use these keys. Legacy waypoint configurations retain `io.istio.peer_principal` and `io.istio.local_principal`.

Porter combines compiled Sandbox rules followed by Workload rules and returns canonical `SniTrafficPolicy` JSON in dynamic metadata under `agentio.sni.policy`. After ext_proc, the gateway copies the resolved workload name and namespace into hashable filter state shared once with the next internal listener for EPE and connection isolation, even when SNI policy is disabled. Porter also returns the WDS workload labels, subject to `sandboxIgnoredLabels`, as `agentio.workload_labels` dynamic metadata. The gateway writes these into hashable `agentio.workload.labels` filter state, with the same value also written to legacy `sandbox.labels` for older EPE instances; native gateways no longer capture `X-AGENTIO-SANDBOX-LABELS`. The canonical labels participate in internal pool isolation so concurrent CONNECTs with the same identity but different label snapshots cannot inherit each other's connection context. The duplicate `sandbox.labels` uses a non-hashable string. The EPE base64 `k=v,k2=v2` contract is retained. Labels remain a CONNECT-time snapshot; updates apply to new tunnels. After TLS termination, the gateway explicitly relays identity, labels and token once more to the final internal listener. These business fields remain readable by EPE and access logs there, but are not shared with external upstream connections and do not partition their pools. The peer certificate itself is not shared with inner connections. The gateway copies `%DYNAMIC_METADATA(agentio:sni:policy)%` into hashable `agentio.sni.policy` filter state before opening the internal connection. The Rust listener module evaluates Envoy TLS inspector's actual SNI and writes `agentio.tls.action` to select termination, passthrough or denial. Gateway exclusions take precedence. A valid empty policy selects passthrough; missing or malformed policy denies detected TLS.

Workload, Sandbox and TrafficPolicy subscriptions start with a subscribe/unsubscribe `*` handshake to disable wildcard discovery, then demand only named resources. The demand cache keeps subscriptions while retained and receives policy updates and removals. Disconnected ADS state is not used for new requests. The default processing budget is 4 seconds; Envoy allows 5 seconds and uses `failure_mode_allow: false`. Policy changes apply to new CONNECT requests. CONNECT-UDP also uses Porter once at tunnel establishment for Workload resolution and Sandbox binding checks, including the same IP fallback. Envoy presents it as `GET` with `Upgrade: connect-udp`. Porter evaluates UDP egress policy and returns only workload metadata for UDP; the gateway skips SNI policy transfer and forwards datagrams directly without inspection.

The projected gateway Pod token authenticates ADS. Agentiod verifies Pod identity and Gateway membership before accepting `agentio-porter~<Pod IP>~<Pod name>.<namespace>~<DNS domain>`; Envoy and Porter share the `ClientAgentioEgress` class, which allows Envoy xDS resources plus Workload, Sandbox and TrafficPolicy. Porter itself subscribes only to these three discovery types. No Kubernetes read RBAC is needed. `--cluster-id` must match Agentiod because Workload resource names use `<cluster-id>//Pod/<namespace>/<name>`.

Both static and Gateway API chart deployments include Porter with the gateway's token and CA volumes. Configure `egressGateway.porter.image`, `.resources` and `.cache` (`idleTTL: 10m`, `maxEntries: 0`; no entry-count limit, with idle subscriptions evicted after ten minutes). A manual deployment sets `POD_NAME`, `POD_NAMESPACE`, `POD_UID`, `POD_IP`, `--xds-address` and `--cluster-id`. The health listener on port 9003 serves gRPC `readiness` after all three discovery watches synchronize, and `liveness` for process health. Do not expose the processing port through a Service.

The gateway requires Kubernetes native sidecar support (`SidecarContainers`). Porter runs in `initContainers` with `restartPolicy: Always`; the gateway stays in `containers`. On normal Pod deletion, kubelet stops Porter only after the gateway exits, keeping discovery available to CONNECT requests already in progress during gateway drain. Porter readiness still gates Pod readiness. The Pod termination budget is shared: gateway-agent caps drain at the total budget minus ten seconds, reserving five seconds for gateway cleanup and five for Porter shutdown. With the default 30-second budget, drain is capped at 20 seconds. Force deletion, node failure and independent Porter restarts are outside this ordering guarantee.

Run the deletion regression against an existing Linux KinD cluster from the repository root:

```sh
bin/test_porter_shutdown.sh YOUR_KIND_CLUSTER YOUR_GATEWAY_IMAGE YOUR_PORTER_IMAGE
```

The supplied images must exist in local Docker and match the node architecture. The script requires Go, Helm, Docker and KinD. It borrows one node and creates only a temporary namespace, using the rendered production Deployment's container placement and termination budget. The test runs real gateway-agent, Envoy and Porter with test CA/ADS servers: it blocks a cold WDS response, deletes the Pod, checks Porter/ADS availability during drain, releases the response, completes the CONNECT tunnel and its HTTP response, then checks both container exit statuses and ordering. It also performs a fresh Porter demand during drain. The fixture replaces control-plane authentication and inventory; this is a shutdown regression, not a scale or full product test. Presubmit runs it in the existing `sidecar-auto` environment before the product suites.

## CONNECT TrafficPolicy authorization

Upgrade Agentiod before Porter: the native gateway client class must be authorized to subscribe to `agentio.security.TrafficPolicy`. Workloads must carry an explicit `PolicyReference` for this type, including an empty reference list when no policies apply. A missing binding denies CONNECT. Shared policy bodies are demanded concurrently in the same request budget and retained in the existing bounded discovery cache; they are decoded and validated once per accepted update. Policy cache entries count toward the same `maxEntries` limit as Workloads and Sandboxes.

CONNECT authority must be a numeric IPv4 `IP:port` or bracketed IPv6 `[IP]:port` with port 1–65535. Porter does not independently resolve hostnames. CONNECT-UDP uses the authority rewritten by Envoy from the validated MASQUE target, and is evaluated as UDP rather than TCP. The current gateway UDP path still restricts forwarding to IPv4.

A selected Sandbox's inline egress policy runs first. DENY or configured-but-unmatched rejects the tunnel; ALLOW only passes that stage. Workload policy references then run in control-plane order, with the first matching rule deciding the stage. If any policy configures egress but no rule matches, the stage denies. If none configures egress, it allows. Every referenced body must be available before an earlier ALLOW is accepted. An explicit missing resource returns 403; discovery errors/timeouts fail the ext_proc call and Envoy fails closed. Invalid updates are NACKed without replacing the previous accepted resource. Updates and removals affect new CONNECT requests, not already-established tunnels.

This is authorization of the declared CONNECT destination, not yet a complete gateway enforcement boundary. It does not restrict direct traffic bypassing the gateway, reauthorize destinations selected later by HTTP/SNI dynamic forwarding or target rewriting, or revoke established tunnels. It also preserves the current optional Sandbox selection contract: omitting the Sandbox ID evaluates Workload policy only; a shared attester does not prove which hosted Sandbox originated a request. Retain existing enforcement until external egress isolation, final-destination authorization and trusted Sandbox selection cover those paths. Ingress, ICMP and SCTP are not enforced by this CONNECT hook.

The opt-in [TrafficPolicy benchmark](tests/traffic_benchmark.rs) measures cold requests over local TLS ADS, hot handler execution, and hot ext_proc gRPC at concurrency 1 and 16. It uses actual certificate parsing, 20 workload labels, eight SNI rules and ordered TrafficPolicy sets whose last rule matches. The ADS inventory is synthetic; it does not measure Kubernetes, Agentiod compilation, Envoy forwarding or production network latency. Run a release build in isolation:

```sh
cargo test --release --locked --manifest-path extensions/porter/Cargo.toml \
  --test traffic_benchmark -- --ignored --nocapture
```

Copy the same benchmark source into a checkout without Porter TrafficPolicy authorization to compare identical inputs. This baseline measures the cost of adding authorization, not two implementations with equivalent enforcement. `PORTER_BENCH_REQUESTS` sets hot samples per scenario (default 5000); cold scenarios use 100 unique Workload/policy sets.

## Code organization

`config.rs` resolves CLI arguments and environment variables into a validated runtime configuration. `main.rs` initializes tracing and one Tokio runtime; `app.rs` assembles the services and supervises their named tasks, including signal handling and the five-second shutdown deadline. Business code receives configuration rather than reading environment variables.

`discovery.rs` owns demand subscriptions and cache state; `discovery/transport.rs` owns ADS connections, TLS/token loading and reconnects. `ResourceKind` identifies Workload, Sandbox and TrafficPolicy resources while the state remains array-backed. The caller enforces one CONNECT deadline across identity and policy demands; discovery uses that deadline only to classify canceled wait metrics. `identity.rs` parses the authenticated certificate claim, `processor.rs` resolves and checks the connection identity, and `view.rs` projects discovery resources into cached views and response metadata.

Lifecycle and ADS connection events use structured tracing fields. Each ADS attempt has an `xds` span with its connection ID and address. Retry/NACK/forced-shutdown events are warnings, service failures are errors, and request rejection reasons are debug events. Certificate contents and tokens are never logged. The existing `AGENTIO_LOG_LEVEL` and `AGENTIO_LOG_FORMAT=text|json` settings remain the configuration interface.

Logging writes synchronously to stderr. Text output contains no ANSI color or style escape sequences. Policy decisions are emitted at INFO for audit collection; a slow log sink can apply backpressure to request processing.

`POST /logging` on port 9004 follows ztunnel's logging API. It accepts only loopback connections; invoke it from the gateway Pod. A request without parameters returns `current log level is <filter>`. `level` merges directives into the current configuration; `reset` restores the startup configuration before applying any supplied `level`. Its value is ignored, as in ztunnel. Invalid levels return 400 without changing the filter; non-POST methods return 405. Startup `AGENTIO_LOG_LEVEL` now uses ztunnel's target filter semantics: a bare level applies globally, and more specific module directives override it. The existing `none` startup alias for `off` remains supported.

```sh
curl -X POST http://127.0.0.1:9004/logging
curl -X POST 'http://127.0.0.1:9004/logging?level=agentio_porter::policy=debug'
curl -X POST 'http://127.0.0.1:9004/logging?reset&level=warn'
curl -X POST 'http://127.0.0.1:9004/logging?reset'
```

Completed TrafficPolicy evaluations emit one INFO event, `CONNECT policy evaluated`, under the `agentio_porter::policy` target. These events are enabled by the default `AGENTIO_LOG_LEVEL=info`. Fields include `workload` (canonical WDS resource name), `sandbox_id`, `destination` (IP:port), `protocol`, the deciding `stage` (`sandbox` or `workload`), `action` (`allow` or `deny`), and `reason` (`rule_match`, `no_matching_rule`, or `no_egress_policy`). A matching Workload rule includes its xDS resource name in `policy`; `rule_index` is zero-based. Sandbox policies are inline and have no separate policy resource name. Unmatched/default decisions have no `policy` or `rule_index`. A Sandbox ALLOW proceeds to Workload evaluation; only a Sandbox DENY or the final Workload decision emits this event. Identity/discovery failures before evaluation retain their separate diagnostics. These events cover completed policy evaluations, not all CONNECT attempts: identity/discovery failures before evaluation are not included. Raising the policy target filter above INFO or setting it to off suppresses these audit events.

## Log format contract

`AGENTIO_LOG_FORMAT=json` emits one JSON object per line for both operational logs and policy decisions. The envelope follows [ztunnel's Istio JSON format](https://github.com/openkruise/ztunnel/blob/f4e7257075c7eb4d1c45abb4b9a20e549516a6d3/src/telemetry.rs). `AGENTIO_LOG_FORMAT=text` remains the default human-readable tracing format, with the same event fields and span context; its layout is not a machine parsing contract. Both formats write synchronously to stderr and respect the same dynamic level filter.

| JSON field | Type | Meaning |
|---|---|---|
| `time` | string | UTC RFC 3339 event timestamp |
| `level` | string | Lowercase `trace`, `debug`, `info`, `warn`, or `error` |
| `scope` | string | Full tracing target, e.g. `agentio_porter::policy` |
| `message` | string | Human-readable description; wording is not a stable query key |
| `event` | string, when defined | Stable machine event identifier; policy decisions use `traffic_policy_decision` |
| `spans` | array, when present | Context from root to leaf as `{ "name": ..., "fields": {...} }`; includes the xDS connection ID and address |

Business fields live at the top level, use snake_case and preserve JSON numeric/boolean types. `time`, `level`, `scope`, and `spans` are reserved for the formatter. Span fields stay inside `spans`, so they do not overwrite event fields. Unlike ztunnel's dynamic top-level span keys, the array preserves nested spans with the same name. Standard tracing JSON span fields support subsequent `span.record` updates.

Policy decisions retain `workload`, `sandbox_id`, `destination`, `protocol`, `stage`, `action`, and `reason`. `workload` is the canonical WDS resource name, not an immutable Kubernetes Pod UID. An empty `sandbox_id` means this request has no Sandbox identity. `stage` is `sandbox` or `workload`; `action` is `allow` or `deny`; `reason` is `rule_match`, `no_matching_rule`, or `no_egress_policy`. A matched rule in either stage includes `rule_index`, a zero-based integer within the deciding policy. A matched Workload rule also includes `policy`, its canonical xDS resource name. Sandbox rules are inline and have no independent `policy` name. Unmatched/default decisions omit both fields; missing values are not synthesized. This schema describes completed policy evaluation; it does not imply that identity/discovery errors are covered or that the destination connection succeeded. INFO decisions are not sampled. Raising the logging filter can suppress them.

```json
{"time":"2026-10-20T10:20:30.123456Z","level":"info","scope":"agentio_porter::policy","event":"traffic_policy_decision","workload":"cluster1//Pod/demo/client","sandbox_id":"","destination":"203.0.113.10:443","protocol":"tcp","stage":"workload","policy":"namespaces/demo/trafficPolicies/allow-egress","rule_index":0,"action":"allow","reason":"rule_match","message":"CONNECT policy evaluated"}
```

Operational events retain their descriptive `message` and diagnostic fields. Lifecycle events are INFO, retry/NACK events WARN, service failures ERROR, and detailed cache/processing diagnostics DEBUG. No duration or request ID is added to policy decisions: latency is available in metrics, and an Envoy correlation ID requires a verified propagation path. Certificate contents and tokens must never be logged.

### Operational events and error handling

| Event | Level | Trigger and fields |
|---|---|---|
| `log_level_changed` | INFO | A successful effective filter change. `previous_filter` and `current_filter` are canonical filter strings; `source_address` is the HTTP peer socket address; `reset` is a boolean indicating that startup defaults were used as the base. Reads, rejected requests and no-op updates emit no change event. |
| `porter_failed` | ERROR | A returned runtime/startup-service failure after logging initialization. `error` contains the full diagnostic chain, including the failing task when applicable. Porter exits with failure status. |

Filter updates merge atomically against the current configuration. The change event is emitted after the update and respects the new filter: for example, warn → info is visible, while info → warn normally suppresses this INFO event. `source_address` identifies the transport peer, not an authenticated human operator. This is an operational event, not an unfiltered administrative audit trail. The `/logging` HTTP behavior remains unchanged.

The process entry point reports the primary returned failure once, after bounded service shutdown. Additional failures encountered during shutdown are logged separately. Errors before logging is initialized (including invalid CLI/configuration) retain the CLI's stderr diagnostics. These, along with Rust panic-hook diagnostics, are outside the JSON tracing contract.

Startup configuration logs use numeric `request_timeout_seconds` and `cache_idle_ttl_seconds`, preserving fractional seconds. The forced-shutdown warning uses numeric `timeout_seconds`. These replace the former Debug strings in `request_timeout`, `cache_idle_ttl` and `timeout`. Existing diagnostic measurements retain their explicit units, such as `retry_ms` and `total_us`.

### Adding or extending a log event

- Give events intended for stable machine queries or auditing a constant, Porter-wide unique `event` name in snake_case. Keep the same meaning across module moves; do not embed workload names, policy names or other variable data in the identifier. Ordinary diagnostic events may use only `message`. Document a new machine event's trigger, required/optional fields, types and reason values alongside this contract.
- Use the module's default tracing target for operational logs. Use an explicit category target, such as `agentio_porter::policy`, when operators need to control that category independently. `scope` identifies the logging source/category; `event` identifies what occurred.
- Keep `message` readable. Use `reason` for a documented, event-specific machine reason and `error` for variable diagnostic text. Consumers must not parse `message` or `error` to classify decisions. Record only outcomes known at the emission point: a policy allow is not proof of a successful connection. Identity fields must distinguish verified identity from unverified claims when introducing events before identity validation.
- Record strings, bools, i64/u64 and finite f64 values directly. `%value` and `?value` produce text, even for numbers. The current visitor also represents i128/u128 through debug text; convert values that are known to fit, such as bounded retry milliseconds, to u64. Put units in numeric field names (`retry_ms`, `total_us`). Do not reuse formatter-reserved field names.
- Keep existing event identifiers, field meanings, types and reason values stable. Optional additive fields are allowed; incompatible semantics require a distinct event identifier and corresponding documentation. Omit unavailable optional fields and explain what their absence means; do not use fabricated values. Existing `sandbox_id=""` remains the explicit no-Sandbox convention.
- For a new machine event, test its actual emitted fields and important outcomes with the production JSON formatter, including absent optional fields. Reuse the existing formatter and span support rather than adding another logging abstraction.

For example, the existing operational reconnect warning needs no new event identifier: its message explains the failure, `error` provides diagnostic detail, `retry_ms` remains numeric, and the span identifies the ADS connection.

```json
{"time":"2026-10-20T10:20:30.123456Z","level":"warn","scope":"agentio_porter::discovery::transport","message":"ADS disconnected","error":"connection reset","retry_ms":100,"spans":[{"name":"xds","fields":{"connection_id":4,"address":"agentiod:15012"}}]}
```

This replaces the previous JSON layout: `timestamp` becomes `time`, uppercase `level` becomes lowercase, `target` becomes `scope`, and event `fields.*` move to the top level. The previous `span`/`spans` representations become a single `spans` array with explicit `name` and `fields`. Log collectors and queries must be updated together with this change; old and new fields are not emitted in parallel.

## Build and run

Rust 1.93+ and `protoc` with the standard protobuf include files are required (Debian: `protobuf-compiler libprotobuf-dev`). From the repository root:

```sh
cargo build --release --locked --manifest-path extensions/porter/Cargo.toml
cargo test --locked --manifest-path extensions/porter/Cargo.toml
cargo clippy --locked --manifest-path extensions/porter/Cargo.toml --all-targets -- -D warnings
docker build -f extensions/porter/docker/Dockerfile -t agentio-porter:dev .
```

`TOKIO_WORKER_THREADS`, when set, selects the worker count; otherwise Porter uses the available parallelism. ext_proc binds to localhost:9002, gRPC health to :9003, metrics to :9004. `AGENTIO_LOG_LEVEL` and `AGENTIO_LOG_FORMAT` configure text/JSON tracing. ADS trust roots and the projected token are reread when opening a new connection. The TLS server must present a leaf certificate; using a CA certificate as a server leaf is rejected.

The Dockerfile builds for its target platform with the Rust image's toolchain. Multi-platform builds require the normal Docker buildx target-platform builder/emulation; there is no cross-linker configured by this crate.

## Behavior

- Parse Envoy's authenticated peer certificate instance extension (`1.3.6.1.4.1.57874.5.1`), using opaque registry + UID. TLS authentication of the peer remains Envoy's responsibility. Only an absent extension permits the existing physical-IP + principal fallback. Invalid/missing certified identities do not fall back.
- Resolve a Sandbox separately and require its attester Workload UID to match. Preserve Sandbox-before-Workload SNI rules. CONNECT-UDP validates identity and binding but returns no SNI policy.
- Decode and validate discovered resources before publishing a delta atomically. Precompute labels and retain typed policy rules on discovery updates. Malformed resources and unsupported policy actions reject the entire update and preserve the last accepted state. Ambiguous aliases cannot resolve an identity; unregistered discovery types terminate the stream.
- Demand watches use the same `*` subscribe/unsubscribe initial handshake as the Go xDS client. Concurrent callers share a subscription generation. Deletion ends that generation; old canceled callers cannot release a newer subscription.
- One retained cache spans Workload and Sandbox. Idle TTL starts after the final caller finishes; in-flight entries are pinned. Both bounds at zero bypass the retention manager and keep xDS interests until server deletion or disconnect; the managed-cache gauge is zero in this mode. Cache hits read current published values; updates do not extend idle TTL. Errors release the entry when its final caller finishes.
- Expiration uses one timer and LRU eviction only visits idle entries. Alias indexes update incrementally. A separate outbound stream drains changed subscriptions and the latest ACK/NACK per type, so outbound flow control cannot stop receiving/applying deltas. Resources are never dropped to coalesce ACKs.
- Disconnect clears readiness and drops idle subscriptions and cached resources. In-flight callers keep their subscription generations; a connection epoch invalidates their old values so partial resynchronization cannot revalidate an older value. Reconnect subscribes only to pending demands, without claiming retained versions; later requests rediscover resources on demand. New requests wait within the same 4-second budget. Resource-level xDS TTL is rejected; the cache's idle TTL is separate.

The xDS and ext_proc proto files are narrow wire projections. Workload, Sandbox and extension messages compile from this repository’s authoritative proto definitions. `tests/fixtures.json` retains 28 serialized Envoy requests and expected responses captured before removing the Go processor (updated to numeric authorities and explicit empty TrafficPolicy bindings); the tests consume these fixtures directly, without a Go Porter dependency. Update contract fixtures and semantic tests together when intentionally changing the protocol.

## Validation and measurement

The corpus covers 28 wire contract cases, including non-Kubernetes identity, certificate wrappers, malformed claims, IP/principal fallback, host-network rejection, Sandbox binding, UDP, empty policy and ignored claimed metadata. Unit tests cover generations, cancellation, incremental aliases, atomic rejection, expiration, pinned eviction, reconnect and bounded pending ACKs. A real TLS ADS test verifies the wire handshake, token authentication/reload, not-found, expiry-driven unsubscribe and responses above 4 MiB. The ADS receive limit matches Go xdsclient (2 GiB minus one byte), since a large batch of pending demands can return in one response.

Metrics are served at `:9004/metrics` (`--metrics-port`). CONNECT duration measures handler completion, excluding response transmission, first-message wait and tunnel lifetime. Use external-client latency for implementation comparisons. Linux binaries use jemalloc with its default settings; other platforms use the system allocator. Cached policies retain typed rules and expand them into dynamic metadata only when producing a response.

| Metric | Labels | Meaning |
| --- | --- | --- |
| `agentio_porter_connect_duration_seconds` | `protocol` | Valid CONNECT handler duration, including failed and canceled attempts |
| `agentio_porter_connect_requests_total` | `protocol`, `result` | Handler outcomes: `allowed`, `denied`, `error`, `canceled`; malformed CONNECT headers are excluded |
| `agentio_porter_demand_cache_entries` | — | Retained subscriptions across Workload and Sandbox, including pending lookups; zero when retention management is disabled |
| `agentio_porter_demand_cache_lookups_total` | `resource_type`, `result` | One observation per valid demand call: `hit` when a ready value is initially available, otherwise `miss`; a miss may share an existing pending subscription and does not necessarily issue another ADS request |
| `agentio_porter_demand_cache_evictions_total` | `resource_type`, `reason` | Idle subscription eviction by `idle_ttl` or `capacity`; TTL takes precedence if both apply. Server deletions and failed lookup cleanup are excluded |
| `agentio_xds_client_connected` | — | ADS stream open, not resource synchronization/readiness |
| `agentio_xds_client_reconnects_total` | — | ADS retry attempts, including failed attempts; excludes the initial attempt |
| `agentio_xds_client_nacks_total` | `resource_type` | Rejected ADS responses generating NACKs; counts rejections even if pending NACKs are coalesced before transmission |
| `agentio_xds_client_demand_wait_duration_seconds` | `resource_type`, `result` | Calls that actually waited, across reconnects; results: `success`, `not_found`, `timeout`, `canceled`, `error` |
| `agentio_xds_client_demand_waiters` | `resource_type` | Concurrent waiting calls, including calls sharing a subscription |

`allowed` means a normal ext_proc response was produced; downstream SNI policy enforcement and tunnel establishment are outside this handler. `protocol` is `tcp` or `udp`; `resource_type` is the full Workload/Sandbox/TrafficPolicy TypeURL. No workload identities or user labels are metric dimensions. Labeled series appear on first use. Histograms expose `_bucket`, `_sum`, `_count` with finite boundaries 0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8 seconds. Cache lookup counters remain active with retention disabled because demand subscriptions still retain discovered resources. RSS and CPU should be collected by container monitoring; the production endpoint has no allocator diagnostics or forced-purge hooks.

Rust tracing provides lifecycle/discovery diagnostics. At debug level, discovery logs cache invalidation time and select/transform/publish/total durations for each accepted ADS response. Publication timing includes lock acquisition; timings exclude destruction of remaining locals after return. Use these logs in separate diagnostic runs because logging can affect performance.

The scale harness compares supplied Porter images with the same control plane, WDS clients, resource inventory, certificates and resource limits. The harness drives actual TLS ADS and ext_proc, not the full Envoy/EPE forwarding path. See the [reusable scale test framework](../../bench/porter/README.md) for build/run commands, scenarios, metrics and limitations.

Deployments declare a container port named `porter-metrics`. For Prometheus Operator, apply [the optional Porter PodMonitor](../../manifests/charts/agentio/addons/porter-podmonitor.yaml) and ensure your Prometheus instance selects it. Narrow its namespace and Pod selectors as needed. A separate Porter deployment can use the same named port. Existing gateway Prometheus annotations alone do not collect this endpoint.

Without Prometheus Operator, add a separate scrape job:

```yaml
- job_name: agentio-porter
  kubernetes_sd_configs:
    - role: pod
  relabel_configs:
    - source_labels: [__meta_kubernetes_pod_container_port_name]
      action: keep
      regex: porter-metrics
    - source_labels: [__meta_kubernetes_namespace]
      target_label: namespace
    - source_labels: [__meta_kubernetes_pod_name]
      target_label: pod
```

The Agentio Grafana dashboard includes CONNECT mean/P95/P99 duration, retained cache entries, ADS connection state, demand wait P95/P99 duration and current demand waiters.

### TrafficPolicy opt-in

Porter TrafficPolicy enforcement is disabled by default. Set `ENABLE_TRAFFIC_POLICY=true` on the Porter container and restart it to enable both Sandbox and Workload egress evaluation. The variable accepts `true` or `false`; invalid values fail startup. With the flag disabled, Porter retains identity checks, Workload/Sandbox discovery and metadata projection, but skips TrafficPolicy resource demands, binding requirements, target IP parsing and policy evaluation. Keep ztunnel enforcement enabled until Porter enforcement has been explicitly enabled on all gateways and verified.
