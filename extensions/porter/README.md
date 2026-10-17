# Agentio Porter

Porter is the Rust connection processor. It resolves the source Workload and its SNI policies for the gateway's outer HBONE CONNECT request. It implements standard Envoy ext_proc on `127.0.0.1:9002`; application HTTP processing remains with EPE or the configured HTTP ext_proc provider.

The gateway passes Envoy's TLS-verified peer certificate to Porter using `%DOWNSTREAM_PEER_CERT%` in CONNECT-local filter state. Porter reads the existing non-critical JSON instance extension (`1.3.6.1.4.1.57874.5.1`): `registry` names a trusted source registry and its installation/cluster scope, and `uid` is the immutable, non-reused instance key within that registry. Neither field assumes Kubernetes. The optional `role` is not part of the lookup key. For example, Kubernetes uses `kubernetes/<cluster-id>` plus the actual Pod UID; another runtime can use its own registry and instance UID. The issuer must attest these claims; a CSR cannot authorize its own identity.

Porter demands WDS through the instance alias `instance/<registry-byte-length>:<registry><uid>`, using the control-plane-issued alias as the authoritative mapping to the workload. The xDS client resolves the requested alias and rejects ambiguous mappings; no duplicate instance identity is carried in the workload payload. The WDS resource name remains unchanged. Deleted instances and mismatching replacements reject CONNECT, including when a new instance reuses the same workload name. Names and namespaces come from the resolved WDS resource; CONNECT name headers do not override certificate identity. The control plane publishes the instance alias independently of optional workload-label configuration.

Only certificates without the instance extension use physical peer IP plus certificate principal to resolve the Workload. Native gateways do not capture workload name/namespace CONNECT headers, and Porter does not consume those attributes. Unknown or ambiguous IPs, host-network workloads and identity mismatches reject that IP fallback. This fallback requires direct sidecar connections with the source Pod IP preserved; it does not resolve through SNAT or intermediate proxies. Malformed certificates/extensions, missing certified instances and instance mismatches never fall back. Shared ambient ztunnels still need per-instance certificate issuance and caching before they can stop relying on source-IP preservation. This change does not alter certificate issuance or migrate substrate's distinct ActorIdentity OID.

The certificate authenticates the Workload/attester, not each Sandbox. The optional `X-AGENTIO-SANDBOX-ID` CONNECT header selects the Sandbox for that tunnel. Porter requires its WDS attester binding to match the resolved Workload; an absent, unassigned or differently bound Sandbox is rejected. Multiple Sandboxes can share one Workload certificate, while each CONNECT selects exactly one Sandbox. `X-AGENTIO-SANDBOX-TOKEN` remains available to downstream EPE; it does not select or authenticate the Workload. Sandbox ID and token are hashable, transitively shared filter state so internal connection pools cannot reuse another Sandbox's context. Policies and workload labels come from discovery, not client assertions. Existing legacy waypoint behavior is unchanged. It does not evaluate an SNI supplied in request headers. The gateway exposes certificate principals as `agentio.peer.principal` and `agentio.local.principal`; Porter reads only `agentio.peer.principal`. Custom CEL expressions for the new gateway must use these keys. Legacy waypoint configurations retain `io.istio.peer_principal` and `io.istio.local_principal`.

Porter combines compiled Sandbox rules followed by Workload rules and returns canonical `SniTrafficPolicy` JSON in dynamic metadata under `agentio.sni.policy`. After ext_proc, the gateway copies the resolved workload name, namespace and certified instance alias into hashable, transitively shared filter state for EPE and connection isolation, even when SNI policy is disabled. Porter also returns the WDS workload labels, subject to `sandboxIgnoredLabels`, as `agentio.workload_labels` dynamic metadata. The gateway writes these into `agentio.workload.labels` filter state, with the same value also written to legacy `sandbox.labels` for older EPE instances; native gateways no longer capture `X-AGENTIO-SANDBOX-LABELS`. The EPE base64 `k=v,k2=v2` contract is retained. Labels are a CONNECT-time snapshot, and the label value participates in internal connection-pool isolation. The peer certificate itself is not shared with inner connections. The gateway copies `%DYNAMIC_METADATA(agentio:sni:policy)%` into hashable `agentio.sni.policy` filter state before opening the internal connection. The Rust listener module evaluates Envoy TLS inspector's actual SNI and writes `agentio.tls.action` to select termination, passthrough or denial. Gateway exclusions take precedence. A valid empty policy selects passthrough; missing or malformed policy denies detected TLS.

Workload and Sandbox subscriptions start with a subscribe/unsubscribe `*` handshake to disable wildcard discovery, then demand only named resources. The demand cache keeps subscriptions while retained and receives policy updates and removals. Disconnected ADS state is not used for new requests. The default processing budget is 4 seconds; Envoy allows 5 seconds and uses `failure_mode_allow: false`. Policy changes apply to new CONNECT requests. CONNECT-UDP also uses Porter once at tunnel establishment for Workload resolution and Sandbox binding checks, including the same IP fallback. Envoy presents it as `GET` with `Upgrade: connect-udp`. Porter returns only workload metadata for UDP; the gateway skips SNI policy transfer and forwards datagrams directly without inspection.

The projected gateway Pod token authenticates ADS. Agentiod verifies Pod identity and Gateway membership before accepting `agentio-porter~<Pod IP>~<Pod name>.<namespace>~<DNS domain>`; Envoy and Porter share the `ClientAgentioEgress` class, which allows Envoy xDS resources plus Workload and Sandbox. Porter itself subscribes only to Workload and Sandbox. No Kubernetes read RBAC is needed. `--cluster-id` must match Agentiod because Workload resource names use `<cluster-id>//Pod/<namespace>/<name>`.

Both static and Gateway API chart deployments include Porter with the gateway's token and CA volumes. Configure `egressGateway.porter.image`, `.resources` and `.cache` (`idleTTL: 1m`, `maxEntries: 10000`). A manual deployment sets `POD_NAME`, `POD_NAMESPACE`, `POD_UID`, `POD_IP`, `--xds-address` and `--cluster-id`. The health listener on port 9003 serves gRPC `readiness` after both discovery watches synchronize, and `liveness` for process health. Do not expose the processing port through a Service.

The gateway requires Kubernetes native sidecar support (`SidecarContainers`). Porter runs in `initContainers` with `restartPolicy: Always`; the gateway stays in `containers`. On normal Pod deletion, kubelet stops Porter only after the gateway exits, keeping discovery available to CONNECT requests already in progress during gateway drain. Porter readiness still gates Pod readiness. The Pod termination budget is shared: gateway-agent caps drain at the total budget minus ten seconds, reserving five seconds for gateway cleanup and five for Porter shutdown. With the default 30-second budget, drain is capped at 20 seconds. Force deletion, node failure and independent Porter restarts are outside this ordering guarantee.

Run the deletion regression against an existing Linux KinD cluster from the repository root:

```sh
bin/test_porter_shutdown.sh YOUR_KIND_CLUSTER YOUR_GATEWAY_IMAGE YOUR_PORTER_IMAGE
```

The supplied images must exist in local Docker and match the node architecture. The script requires Go, Helm, Docker and KinD. It borrows one node and creates only a temporary namespace, using the rendered production Deployment's container placement and termination budget. The test runs real gateway-agent, Envoy and Porter with test CA/ADS servers: it blocks a cold WDS response, deletes the Pod, checks Porter/ADS availability during drain, releases the response, completes the CONNECT tunnel and its HTTP response, then checks both container exit statuses and ordering. It also performs a fresh Porter demand during drain. The fixture replaces control-plane authentication and inventory; this is a shutdown regression, not a scale or full product test. Presubmit runs it in the existing `sidecar-auto` environment before the product suites.

## Code organization

`config.rs` resolves CLI arguments and environment variables into a validated runtime configuration. `main.rs` initializes tracing and one Tokio runtime; `app.rs` assembles the services and supervises their named tasks, including signal handling and the five-second shutdown deadline. Business code receives configuration rather than reading environment variables.

`discovery.rs` owns demand subscriptions and cache state; `discovery/transport.rs` owns ADS connections, TLS/token loading and reconnects. `ResourceKind` identifies Workload and Sandbox resources while the state remains array-backed. The caller enforces one CONNECT deadline across both demands; discovery uses that deadline only to classify canceled wait metrics. `identity.rs` parses the authenticated certificate claim, `processor.rs` resolves and checks the connection identity, and `view.rs` projects discovery resources into cached views and response metadata.

Lifecycle and ADS connection events use structured tracing fields. Each ADS attempt has an `xds` span with its connection ID and address. Retry/NACK/forced-shutdown events are warnings, service failures are errors, and request rejection reasons are debug events. Successful requests do not emit per-request logs. Certificate contents and tokens are never logged. The existing `AGENTIO_LOG_LEVEL` and `AGENTIO_LOG_FORMAT=text|json` settings remain the configuration interface.

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

The xDS and ext_proc proto files are narrow wire projections. Workload, Sandbox and extension messages compile from this repository’s authoritative proto definitions. `tests/fixtures.json` retains 28 serialized Envoy requests and expected responses captured before removing the Go processor; the tests consume these fixtures directly, without a Go Porter dependency. Update contract fixtures and semantic tests together when intentionally changing the protocol.

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

`allowed` means a normal ext_proc response was produced; downstream SNI policy enforcement and tunnel establishment are outside this handler. `protocol` is `tcp` or `udp`; `resource_type` is the full Workload/Sandbox TypeURL. No workload identities or user labels are metric dimensions. Labeled series appear on first use. Histograms expose `_bucket`, `_sum`, `_count` with finite boundaries 0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8 seconds. Cache lookup counters remain active with retention disabled because demand subscriptions still retain discovered resources. RSS and CPU should be collected by container monitoring; the production endpoint has no allocator diagnostics or forced-purge hooks.

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
