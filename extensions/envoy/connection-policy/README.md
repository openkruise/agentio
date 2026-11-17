# Agentio connection policy module

This dynamic library provides the gateway's CONNECT policy store, SNI listener filter, TCP network filter and HTTP destination authorization filter. Its module name is `envoy_agentio_connection_policy`; the filter entry points are `envoy_agentio_connection_policy_store`, `envoy_agentio_sni_policy` `envoy_agentio_tcp_policy` and `envoy_agentio_egress_authorization`. Porter supplies an ordered, per-SecurityProfile SNI/TCP view through `agentio:connection:policy` dynamic metadata. CONNECT registers the view in a worker-local store and shares only the hash as `agentio.connection.policy_hash` filter state. TLS termination relays the complete snapshot hash to the post-termination listener. Explicit SNI passthrough publishes an exclusive profile boundary in `agentio.tcp_policy.end_before`; it is local to that forwarding stage. The CONNECT HTTP filter and TCP network filter hold references to the same immutable snapshot; the final consumer removes it from the store. Identical JSON reuses an entry after a hash and content check. Parsing and validation happen once, on the first SNI/TCP consumer, so cleartext HTTP does not parse unused connection rules. The existing CONNECT identity capture also captures the temporary JSON; it needs no separate input filter. Temporary JSON filter state and policy metadata are cleared after registration. SNI evaluation uses the validated snapshot without revalidating its rules. Missing hashes or invalid policies fail closed; the module does not fall back to raw JSON or the flat SNI projection. Porter emits only the grouped connection policy; its flat SNI and precomputed TCP decision outputs have been removed.

For TLS, the listener filter evaluates each profile's SNI rules before its TCP rules against the restored original IP and port. SNI deny and TCP deny reject; TCP allow ends evaluation and forwards to the original address. SNI passthrough skips only that profile's TCP rules, resolves the SNI, rechecks the preceding profiles against the resolved candidates, and pins an authorized numerical address before TCP proxy can connect. After TLS termination, HTTP evaluation starts from the highest-priority profile and evaluates the complete HTTP/TCP chain. EPE starts with the complete chain. The TCP network filter receives a view of the selected profiles, backed by the same snapshot, and does not infer policy scope from TLS actions or destination mode. The native gateway requires a valid SNI hostname before TLS routing; absent or malformed SNI matches no filter chain and closes the connection, even when TCP rules allow it or TLS termination excludes it. This guard also applies with SNI policy disabled and to fixed endpoints. `*` matches every TLS connection admitted by this guard; exact names and suffix wildcards require a name. Unmatched TLS falls through to TCP rules for the original destination.

Raw TCP is authorized on connection initialization before initializing TCP proxy. Protocol inspection timeout closes the connection. The filter blocks incoming data until authorization completes. An empty ordered profile list permits traffic; missing or malformed connection policy closes the connection. Non-HTTP traffic after TLS termination also uses the network filter. EPE evaluates HTTP and TCP rules locally in profile order, including an explicit TCP allow before a lower-priority HTTP block.

TCP and HTTP DNS use one lazily initialized Hickory resolver per loaded module in each Envoy process, with two Tokio worker threads and TTL caching. All `DYNAMIC_FORWARD` filter configurations, including replacements after xDS updates, share it. A bounded answer cache reuses immutable IP lists until their original TTL deadline, avoiding Hickory query setup and DNS response copying on warm lookups. Only asynchronous lookup completions fill this cache; immediate Hickory cache hits are not cached again because their remaining TTL is rounded to whole seconds. Both this cache and Hickory's response cache are limited by `max_hosts`; the extra cached representation consumes additional memory. Negative answers remain in Hickory's cache. Cache hits complete on the calling Envoy worker; only pending network lookups schedule asynchronous completion. Resolver initialization failures reject the configuration and can be retried on a later update. The shared cache contains DNS answers only; each connection or HTTP request authorizes them against its own policy snapshot and `denied_cidrs`. Removing all filters retains the resolver until process exit; process replacement starts a new cache.

Hostname lookup is IPv4-only with a five-second query deadline, preserving the gateway's current hostname address-family behavior. Literal original destinations support both IP families. Resolved addresses pass the gateway's mandatory address exclusions. The authorized address is pinned in `envoy.network.transport_socket.original_dst_address`. HTTP and TCP both forward through ORIGINAL_DST using this numeric endpoint; native forwarding no longer uses DFP. Connection destruction cancels only its pending resolution and waits for its completion callback to finish.

DNS queries accept a completion callback, while `network.rs` and `egress_http.rs` adapt it to the Envoy network and HTTP schedulers. Both entry points use `destination.rs` to select a permitted address; TCP additionally evaluates the selected profile rules. Policy evaluation in `connection.rs`, `policy.rs` and `tcp.rs` remains independent of Envoy callbacks; new traffic entry points can reuse these modules without sharing authorization decisions.

ServiceEntry endpoint bindings retain their configured numeric destination and port and use ORIGINAL_DST clusters without DNS or a DFP filter. Post-termination endpoint TCP adds a TLS transport socket using the outer SNI for SNI/SAN validation. Other post-termination non-HTTP forwarding resolves the outer SNI and checks the complete TCP policy chain, including the terminating profile. TLS passthrough still leaves certificate verification to the client.

Native `tlsTermination.excludeHosts` only disables termination. It cannot override a SNI/TCP denial or invalid policy. A selected termination changed to passthrough uses the complete TCP chain; an explicit policy passthrough keeps only preceding profiles. Profile order and first-match semantics remain unchanged. The SNI listener has no filter configuration: it publishes the policy decision as `agentio.tls.action`. The Envoy matcher checks gateway exclusions only under the `terminate` branch. An excluded connection retains the `terminate` policy action but selects the TLS passthrough chain; no TCP scope boundary is added. Static TLS routing with SNI policy disabled uses the same hostname guard. Explicit `tcpPassthrough` routes skip HTTP/TLS inspection and retain opaque TCP forwarding; legacy proxyv2 keeps its existing routing behavior.

TCP module `filter_config` examples (the payload inside `google.protobuf.Struct`):

```yaml
# Raw TCP and fixed ServiceEntry endpoints; no DNS resolver is created.
mode: ORIGINAL_DST
denied_cidrs:
  - 100.100.100.200/32
```

```yaml
# Domain forwarding; resolve, authorize and pin the selected numerical address.
mode: DYNAMIC_FORWARD
denied_cidrs:
  - 100.100.100.200/32
```

`mode` is required and selects destination lookup only. `DYNAMIC_FORWARD` reads `agentio.tls.outer_sni` (or inspected SNI before termination), uses the original port, and falls back to the original address only for an empty target name. DNS failure denies the connection. `denied_cidrs` is an optional list of IP prefixes; it applies before profile authorization in both modes, including an empty profile view. The generator supplies mandatory gateway exclusions plus user entries. The user-facing Agentio configuration remains `egressAuthorization.deniedCIDRs`. The former `resolveSni`, `skipMatchedProfile` and `deniedCidrs` module fields are no longer accepted.

HTTP authorization runs after EPE and destination selection, before router. It checks each request, including requests on reused HTTP/1 connections and concurrent HTTP/2 streams. It authorizes EPE's final endpoint or resolves the selected hostname, then pins the full numerical IP:port without changing HTTP Host or TLS identity. EPE receives the selected numeric endpoint through `agentio.route.upstream` string filter state; the selected target returns through `agentio.route` metadata. Deploy the matching EPE build with the new gateway configuration. Plain HTTP proxy CONNECT checks the actual proxy endpoint with `ORIGINAL_DST`; it does not inspect the destination reached by that external proxy. HTTP profile rules and their interleaved TCP rules remain in EPE. ServiceEntry, EPE and Rust use request-scoped `agentio.route.upstream` for explicit targets; Rust writes `envoy.network.transport_socket.original_dst_address` only after authorization, adapting it for ORIGINAL_DST; EPE CONNECT decisions do not override the physical proxy destination.

The HTTP filter has no global `filter_config`. Its mode and restrictions are supplied through RDS, so a CIDR update applies to new requests on existing connections without replacing the listener. For example:

```yaml
# Inside HttpConnectionManager.http_filters, before router:
- name: agentio.egress_authorization
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter
    dynamic_module_config:
      name: envoy_agentio_connection_policy
      do_not_close: true
    filter_name: envoy_agentio_egress_authorization

# Inside RouteConfiguration; a route can override this for ORIGINAL_DST CONNECT:
typed_per_filter_config:
  agentio.egress_authorization:
    "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilterPerRoute
    dynamic_module_config:
      name: envoy_agentio_connection_policy
      do_not_close: true
    filter_name: envoy_agentio_egress_authorization
    filter_config:
      "@type": type.googleapis.com/google.protobuf.Struct
      value:
        mode: DYNAMIC_FORWARD
        default_port: 443
        denied_cidrs: [100.100.100.200/32]
```

`default_port` is the upstream transport's fallback (80 by default, 443 for TLS); explicit authority, dynamic port and endpoint port override it in that order. `ORIGINAL_DST` reads the original numerical endpoint and does not use DNS. Missing route policy denies the request. Invalid configuration is rejected by Envoy and the last accepted policy remains active. HTTP denial returns 403 (`agentio_egress_denied`), DNS failure returns 503, and malformed destination returns 400. TCP denial closes the connection before dialing upstream.

A request snapshots the accepted RDS policy when it reaches authorization. In-flight requests, including pending DNS queries, retain that snapshot; existing TCP connections retain their connection policy. Updates do not terminate active transfers. DNS caches contain answers rather than allow/deny decisions, so cached answers are rechecked against the current request's policy. A refreshed answer containing only forbidden IPs is denied, without falling back to a previously allowed address. CIDR changes do not replace the shared resolver. ORIGINAL_DST maintains its own host map and HTTP pools independently of the DNS cache.

Deploy the gateway image containing both the policy-store and HTTP authorization entry points before publishing their configuration. The gateway configuration and module must be upgraded together; missing policy hashes fail closed.

The production `docker/Dockerfile.gateway` includes this module with community Envoy. The control plane emits the extension only to authenticated `agentio-egress~` clients. The legacy proxyv2 image does not support the listener dynamic-module configuration and continues to receive its existing custom matcher during rolling upgrades.

Build on Linux with Rust 1.93+, clang/libclang, curl and tar:

```sh
cd extensions/envoy/connection-policy
bash build.sh
```

The build downloads the required subtree from pinned Envoy SDK tag `v1.40.2`, checks formatting, runs unit tests and builds `target/release/libenvoy_agentio_connection_policy.so`. The SDK cache is ignored; remove `.envoy-sdk` when changing the SDK pin.

The standalone smoke fixture uses test headers, static certificates and local origins to isolate module behavior. It exercises real TLS termination and relay, ordered matching, wildcard boundaries, normalization, denial, absent/invalid policies, cleartext, alternating policies and conflicting actions. Production HBONE, Porter discovery and on-demand SDS require the integrated gateway test as well.

```sh
docker build -t agentio-envoy-connection-policy:dev .
python3 tests/smoke.py
```

The TCP smoke fixture checks profile priority, scoped SNI passthrough, SNI destination changes, authorization before any origin connection, missing SNI, and server-first TCP. Its header-based policy producer is test-only.

```sh
python3 tests/tcp_smoke.py --image agentio-envoy-connection-policy:dev
```

Go and Rust TCP matchers share `pkg/policy/testdata/tcp_rules.json`; run `go test ./pkg/policy` and the module unit tests to check the same CIDR/port corpus in both implementations.

The kind fixture tests the module through real Envoy CONNECT and internal TCP listeners, with a counted DNS server and echo origin. It creates 16 independent `DYNAMIC_FORWARD` configurations and checks shared cache hits, 40 LDS replacements, per-configuration denial before origin connection, policy snapshot isolation, TTL expiry, cancellation and stable thread count. It uses test policy headers and bypasses Porter/EPE; it is not a full Agentio deployment test.

```sh
kind load docker-image --name <cluster> <baseline-image> <candidate-image> python:3.13-alpine
python3 tests/shared_dns_kind.py manifest \
  --baseline <baseline-image> --candidate <candidate-image> > /tmp/dns-sharing.json
kubectl --context kind-<cluster> apply -f /tmp/dns-sharing.json
kubectl --context kind-<cluster> -n agentio-dns-sharing wait --for=condition=Ready pod --all --timeout=60s
kubectl --context kind-<cluster> -n agentio-dns-sharing get pods -o wide
kubectl --context kind-<cluster> -n agentio-dns-sharing exec loadgen -- \
  python3 /scripts/shared_dns_kind.py verify --host <candidate-pod-ip>
kubectl --context kind-<cluster> -n agentio-dns-sharing exec loadgen -- \
  python3 /scripts/shared_dns_kind.py bench --host <candidate-pod-ip> \
  --mode warm --concurrency 32 --seconds 10
# Repeat bench against both pods in alternating order; modes: warm, many, cold, stream.
kubectl --context kind-<cluster> delete namespace agentio-dns-sharing
```

`bench` reports throughput, p50/p95/p99 latency, errors, DNS queries, Envoy CPU, RSS and thread count. `many` rotates through 1,024 names at concurrency 64, `cold` uses a unique name for each connection and asserts that each performs DNS resolution, and `stream` exchanges 16-KiB payloads over persistent connections. Both pods use two Envoy workers and a two-CPU Envoy limit. Short-connection benchmarks use server-initiated close with no HCM delayed close; synthetic targets partition internal connection pools to preserve their identity under concurrent load.

`egressGateways[].dnsCache.maxHosts` sizes each shared DNS cache: immutable IP lists and Hickory responses (default 16,384 entries per cache; eviction at capacity). `maxPendingRequests` limits waiting HTTP and TCP requests together (default 4,096); cache hits complete inline without consuming a slot, and completion/cancellation releases the slot. The generated module field is `dns: {max_hosts: 16384, max_pending_requests: 4096}` in HTTP route and TCP filter configuration. All configurations in one process must agree; changing these settings or DNS servers requires a restart. The retired `hostTtl` field is rejected in YAML/JSON configuration. Native answers expire according to DNS record TTL; legacy DFP uses a fixed 120-second idle lifetime.

The HTTP kind fixture compares Rust authorization followed by DFP (baseline) with Rust authorization followed by ORIGINAL_DST (candidate) using the same Envoy version and resources. It verifies literal and DNS targets, mixed answers, DNS rebinding, original-proxy CONNECT, port precedence, Host preservation, body buffering, per-request authorization, RDS replacements on existing HTTP/1 and HTTP/2 connections, rejection of invalid RDS, in-flight snapshots and cancellation.

```sh
python3 tests/http_egress_kind.py manifest \
  --baseline <previous-gateway-image> --candidate <candidate-image> > /tmp/egress-http.json
kubectl --context kind-<cluster> apply -f /tmp/egress-http.json
kubectl --context kind-<cluster> -n agentio-egress-http wait --for=condition=Ready pod --all --timeout=90s
kubectl --context kind-<cluster> -n agentio-egress-http exec loadgen -- \
  python3 /scripts/http_egress_kind.py verify --host <candidate-pod-ip>
kubectl --context kind-<cluster> -n agentio-egress-http exec loadgen -- pip install h2==4.3.0
kubectl --context kind-<cluster> -n agentio-egress-http exec loadgen -- \
  python3 /scripts/http_egress_kind.py verify-h2 --host <candidate-pod-ip>
kubectl --context kind-<cluster> -n agentio-egress-http exec loadgen -- \
  python3 /scripts/http_egress_kind.py bench --host <candidate-pod-ip> \
  --mode warm --concurrency 32 --seconds 10
# Alternate baseline/candidate; modes: literal, warm, many, cold, body (16-KiB POST).
kubectl --context kind-<cluster> delete namespace agentio-egress-http
```
