# Maintained pilot-agent extraction

Source baseline: `openkruise/agentio`, `release-0.1`, commit `169bad3c36783711989757cd907465b8fe9cfc3a`. Original code is Apache-2.0; copyright notices are retained. These are local sources, not an Istio Go library dependency. The gateway binary must have no `istio.io/*` package in its dependency tree, including indirect imports.

| Local code | Source and changes |
| --- | --- |
| `envoy/agent.go`, `envoy/proxy.go`, `envoy/admin.go` | Copied from `pkg/envoy`. Replace Istio logging, collections, HTTP and environment helpers with standard-library implementations. Remove FIPS, bootstrap overrides and permissive unknown-static-field handling. Bound Admin requests, reap the child on kill/skip-drain, and bound the optional active-connection drain loop. |
| `envoy/ready.go`, `envoy/stats.go` | Copied from `pilot/cmd/pilot-agent/status/ready/probe.go` and `status/util/stats.go`. Preserve initial CDS/LDS and LIVE/workers checks. Remove Istio startup metric and helper dependencies. |
| `../policy_ready.go` | Adapt the initial-sync gate from `pilot/cmd/pilot-agent/status/policyready/probe.go`. In legacy mode, require `policy_store.initial_sync_ready=1` once when the store is enabled; keep later policy changes out of readiness. |
| `../identity.go` | Adapt the `security/pkg/nodeagent/cache/secretcache.go` CSR/cache/rotation responsibilities and `caclient/providers/citadel/client.go` signing protocol. This is a reduced implementation, not a verbatim copy of the complete secret cache. Retain locally generated keys, SPIFFE CSR and actual certificate expiry; default to RSA-2048, 50% rotation grace and 1% jitter, with configurable key and renewal parameters. Use Go `crypto/x509`; reload token and roots per signing attempt, bound retries, validate returned identity/key/chain, and retain a valid cached certificate during CA failure. |
| `../sds.go` | Adapt `security/pkg/nodeagent/sds/sdsservice.go` resource generation and watch/push behavior. Replace the generic Istio xDS framework with a bounded SotW stream loop for `default` and `ROOTCA`; reject arbitrary file and domain secret requests. Local SDS remains SotW, as in pilot-agent. |
| `caproto/ca.proto`, generated Go | Vendor the CA wire schema from `istio/api` commit `f9b16f1f49ce`, the API dependency of the release baseline. Preserve protobuf service/message names for compatibility with agentiod. The local Go package owns the implementation; no Istio API Go import is used. |

Additional intentional differences:

- Projected workload trust roots come from the mounted ConfigMap or ClusterTrustBundle, not `istio.mesh.v1alpha1.ProxyConfig` discovery. A one-second poll follows projected-volume symlink swaps independently of CA signing requests. A signing attempt has a ten-second deadline. Malformed/missing replacements retain the last valid bundle. Root changes trigger renewal and an SDS push.
- Only Pod-token authentication and the existing CA signing protocol are retained. No cloud credential plugins, arbitrary file SDS, output-certificate files, private-key providers, CRL discovery, external SDS delegation or mesh bootstrap.
- `../xds.go` is an Agentio transparent ADS relay, not a copy of pilot-agent's generic proxy with DNS, Wasm download/config rewriting, health and trust-bundle subscription processing. Native Envoy Wasm/ECDS remains available. The relay retains the release baseline's gRPC keepalive defaults without importing its helpers.
- SDS and ADS stay alive until Envoy drain and process cleanup finish.

When updating from pilot-agent, review upstream fixes to these source paths and port applicable fixes explicitly. Do not restore a whole-agent dependency.

Regenerate the local CA message code with `protoc-gen-go v1.36.11`, staging `ca.proto` at `security/v1alpha1/ca.proto`, and passing `--go_opt=module=github.com/openkruise/agentio`. The vendored gRPC stubs retain the unchanged service definition. Protocol compatibility does not require importing the original Go module.

Legacy gateway compatibility:

- `gateway-agent --legacy` uses a separate bootstrap for the pinned custom Envoy (`LEGACY_ENVOY_IMAGE` in `docker/Dockerfile.gateway`). Build with `--target legacy`; its default command enables legacy mode. The default/community target is unchanged.
- The compatibility contract retains `waypoint~IP~pod.namespace~DNS-domain`, proxy version `1.29`, metadata discovery, and the release baseline runtime and statistics settings. Policy store loading and its latched initial-sync readiness follow `ENABLE_POLICY_STORE` or the explicit `policyStore` option. Active-connection statistics remain enabled for drain. Agent build metadata stays independent of the proxy compatibility version.
- Defaults use `/etc/istio/proxy`, `/var/run/secrets/istio/root-cert.pem` and `/var/run/secrets/tokens/istio-token`. Existing `AGENTIO_*` path overrides still work. `CA_ADDR` is also the discovery address when `AGENTIO_XDS_ADDRESS` is absent. `AGENTIO_DNS_DOMAIN` defaults to `<namespace>.svc.cluster.local`; `AGENTIO_SERVICE_CLUSTER` defaults to `<workload>.<namespace>`, using `ISTIO_META_WORKLOAD_NAME` when set and otherwise the Pod name.
- Mounted `/etc/istio/pod/labels` supplies policy selector metadata. Custom metadata still uses `AGENTIO_META_*` and `AGENTIO_METAJSON_*`; this does not emulate the pilot-agent CLI or its `PROXY_CONFIG` input. Deployments must change their args to `--legacy`, supply `POD_UID`, and explicitly wire worker/drain options as needed.
- Trust roots still come from projected files, not mesh ProxyConfig discovery. Switching the executable does not restore cloud credentials, DNS capture, or agent-side Wasm downloading. Existing deployment defaults are not switched.

Legacy bootstrap runtime and statistics values are adapted from `tools/packaging/common/envoy_bootstrap.json` and `pkg/bootstrap/config.go` at the source baseline above.

Deployment configuration:

`AGENTIO_GATEWAY_CONFIG` accepts the locally maintained options below. Legacy Pod statistics annotations from `/etc/istio/pod/annotations` (override with `AGENTIO_POD_ANNOTATIONS`) and legacy discovery/logging switches provide defaults; explicit JSON fields take precedence, followed by CLI flags. Metadata retains the existing `AGENTIO_META_*`/`AGENTIO_METAJSON_*` semantics. The agent does not parse Istio `PROXY_CONFIG`.

| Options | Behavior |
| --- | --- |
| `statsFlushInterval`, `statsEvictionInterval` | Go duration strings. Eviction must be a positive multiple of flush; omit eviction to retain the Envoy default. CLI equivalents are `--stats-flush-interval` and `--stats-eviction-interval`. |
| `statsMatcher` | `inclusionPrefixes`, `inclusionSuffixes`, `inclusionRegexps` arrays. Required readiness, drain and enabled legacy discovery/policy metrics are retained. `{pod_ip}` expands over `instanceIPs`. |
| `extraStatTags`, `histogramBuckets` | Additional Istio-style encoded metric tags and a map of metric prefixes to ordered nonnegative bucket boundaries. Existing legacy tags are retained. |
| `runtimeValues`, `maxDownstreamConnections` | Native runtime keys and a global downstream connection resource monitor. Empty string/null removes a default runtime key. Health and metrics listeners bypass overload management. |
| `policyStore`, `metadataDiscovery` | Legacy-only switches; discovery defaults on for a waypoint, policy store defaults off as in pilot-agent. Policy store requires discovery and waits for its initial sync before readiness. `--policy-store` overrides JSON. |
| `skipDeprecatedLogs`, `statsCompression` | Both default true. The former sets the Envoy flag (also `--skip-deprecated-logs`); the latter negotiates gzip for the complete combined metrics response, without buffering the full scrape. |
| `adminPort`, `statusPort`, `envoyStatusPort`, `prometheusPort`, `workloadSocket` | Default to 15000, 15020, 15021, 15090 and the standard workload SDS socket. Nondefault ports must be reflected in deployment probes and monitoring. |
| `instanceIPs`, `locality` | IP array starting with `INSTANCE_IP`; both families create additional health/metrics addresses. `locality` uses Envoy Node locality JSON (`region`, `zone`, `sub_zone`). |
| `metricsLocalhostOnly`, `statusProxyProtocol` | Restrict the Envoy metrics listener to loopback, or require PROXY protocol on the Envoy status listener. The latter requires a compatible health checker. |
| `xdsHeaders`, `caHeaders` | Lowercase ASCII gRPC headers. Authentication, cluster ID and gRPC-reserved headers cannot be overridden. Legacy `XDS_HEADER_*`/`CA_HEADER_*` are also accepted as defaults. |
| `rsaKeySize`, `eccCurve`, `pkcs8`, `certSigner`, `rotationGraceRatio`, `rotationJitter` | RSA 2048/3072/4096 or ECDSA P256/P384, optional PKCS8 and CA signer selection. Rotation defaults remain 0.5/0.01; expiry comes from the actual certificate. |
| `telemetryClusters` | Array of native Envoy Cluster JSON, including native TLS and HTTP/2 settings, for tracing/ALS/metrics backends. Duplicate or agent-owned names are rejected. Dynamic xDS can reference these clusters. |
| `statsSinks`, `tracing`, `loadStatsConfig`, `outlierEventLog` | Native Bootstrap stats sink array, tracing object, ClusterManager ApiConfigSource for LRS, and outlier event log path. StatsD, metrics service and tracing use the Envoy types directly; ALS filters remain in dynamic xDS. No Istio API translation layer is required. |
| `profiling` | Opt-in local-only pprof endpoints on the agent status port. `/metrics` aliases `/stats/prometheus`. |

`AGENTIO_ROOT_CA` is the workload trust bundle. `AGENTIO_XDS_ROOT_CA` and `AGENTIO_CA_ROOT_CA` independently select the TLS roots for the control-plane and signing connections, falling back to that bundle. Legacy `XDS_ROOT_CA`/`CA_ROOT_CA` are accepted when the corresponding new variable is absent. These files are reread on new streams/signing attempts. Legacy CPU fallback also accepts `ISTIO_CPU_LIMIT`; `AGENTIO_CPU_LIMIT` takes precedence.

Legacy drain defaults are 45s for Envoy and 5s for process termination, matching release-0.1. Community defaults remain 20s/25s. Explicit JSON/CLI durations override these defaults and the existing Pod termination-grace cap still applies.

Example statistics and resource configuration (valid in either mode):

```json
{
  "statsFlushInterval": "5s",
  "statsEvictionInterval": "1m",
  "statsMatcher": {"inclusionPrefixes": ["http.", "cluster."]},
  "histogramBuckets": {"http.": [1, 5, 10, 50, 100, 500]},
  "maxDownstreamConnections": 10000,
  "statsCompression": true
}
```

Telemetry resource objects are validated using Envoy protobuf JSON and the selected image must provide the referenced factories. They are configuration, not arbitrary bootstrap overrides: callers cannot replace the agent-owned ADS/SDS/health resources. Runtime tests validate configured resources against both pinned Envoy binaries; unsupported factories fail explicitly.
