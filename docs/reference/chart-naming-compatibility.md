# Chart naming compatibility

This change maps the remaining Istio names in the Agentio master chart to their
consumers on `release-0.1`. The audit used `upstream/master` at `beb0d2b9b2`;
`git grep -ni istio upstream/master -- manifests/charts/agentio` returned 85 lines.
The release chart has a different directory layout and still includes additional
Istio APIs and injection selectors that are outside this master-chart inventory.

## Configuration names migrated in this change

| Previous name | Agentio name | Consumer adaptation |
| --- | --- | --- |
| `traffic.sidecar.istio.io/*` | `traffic.sidecar.agentio.kruise.io/*` | Kebab-case suffixes; injector validation, template and CNI share alias precedence. See the [traffic annotation table](../getting-started/sidecar-mode.md#configure-traffic-capture). |
| `istio.io/reroute-virtual-interfaces` | `agentio.kruise.io/reroute-virtual-interfaces` | Injector and CNI retain the `-k` argument and deprecated kubevirt fallback. |
| `sidecar.istio.io/interceptionMode` | `sidecar.agentio.kruise.io/interception-mode` | Injector, proxy UID adjustment and CNI read the new key first. |
| `status.sidecar.istio.io/port` | `status.sidecar.agentio.kruise.io/port` | Injector, probe rewriting, pilot-agent configuration and CNI read the new key first. |
| `sidecar.istio.io/status` | `sidecar.agentio.kruise.io/status` | Agentio injections write the new key; reinjection, CNI enrollment/repair and revision readers accept both. Upstream injection templates retain their existing output. |
| `sidecar.istio.io/statsFlushInterval` | `sidecar.agentio.kruise.io/stats-flush-interval` | Gateway chart and Envoy bootstrap reader are updated. |
| `sidecar.istio.io/statsEvictionInterval` | `sidecar.agentio.kruise.io/stats-eviction-interval` | Gateway chart and Envoy bootstrap reader are updated. |
| `networking.istio.io/traffic-distribution` | `networking.agentio.kruise.io/traffic-distribution` | Gateway template and service conversion are updated; Kubernetes `spec.trafficDistribution` retains priority. |
| `cni.istio.io/uninitialized` | `cni.agentio.kruise.io/uninitialized` | Chart passes the configured label key to the repair controller. |
| `istio-iptables` | `agentio-iptables` | New pilot-agent subcommand alias; legacy invocation remains supported. |
| `/var/run/istio-cni` | `/var/run/agentio-cni` | Chart mount and host directory match the explicit `CNI_AGENT_RUN_DIR` setting. |
| Volume names `istio-token`, `istiod-ca-cert`, `istio-envoy`, `istio-data`, `istio-podinfo`, `istio-ca-crl` | `agentio-token`, `agentio-ca-certs`, `agentio-envoy`, `agentio-data`, `agentio-podinfo`, `agentio-ca-crl` | Volume declarations and mounts are updated together. The referenced CA ConfigMap and ClusterTrustBundle resource identities remain unchanged. |
| `/var/run/secrets/tokens/istio-token` | `/var/run/secrets/tokens/agentio-token` | Projected filename matches ztunnel `AUTH_TOKEN` and pilot-agent `JWT_PATH`. |
| `/var/run/secrets/istio/root-cert.pem` | `/var/run/secrets/agentio/root-cert.pem` | Both ztunnel and pilot-agent receive explicit `CA_ROOT_CA` and `XDS_ROOT_CA` paths. |
| `/var/run/secrets/istio/crl/ca-crl.pem` | `/var/run/secrets/agentio/crl/ca-crl.pem` | Optional CRL mount matches `CRL_PATH`; the missing CRL volume declaration is supplied. |

The `agentio-init` and `agentio-validation` names were already present in master;
this change also introduces them to the release chart. CNI skips Pods with
`agentio-init`, and the repair controller continues to recognize old
`istio-validation` Pods during an upgrade.

For each annotation alias, the Agentio value wins, including an explicit empty
value. Otherwise the previous annotation remains supported. Runtime rules,
port formats and virtual-interface semantics are unchanged.

## Credential paths

All Agentio sidecar, ambient ztunnel, Gateway API gateway, static gateway and
OpenKruise traffic-proxy templates project `agentio-token` under
`/var/run/secrets/tokens` and mount the CA under `/var/run/secrets/agentio`.
Ztunnel uses its existing `AUTH_TOKEN`, `CA_ROOT_CA` and `XDS_ROOT_CA`
configuration; the token setting names a file, not a literal token value.

Agentiod uses `JWT_PATH` for its own projected token when discovering the CA
token issuer and audience. Pilot-agent also accepts `JWT_PATH`. When unset,
it retains the legacy
`./var/run/secrets/tokens/istio-token` default. Explicit paths are read for each
credential request, so projected-token rotation continues to work. A missing
explicit path does not fall back to another token; an explicitly empty
`JWT_PATH` disables the JWT credential fetcher for certificate-only deployments.

The token audience remains `istio-ca`, as expected by this branch's CA. Renaming
volume names and filenames does not change token claims, CA ConfigMap names or
ClusterTrustBundle signer identities.

## Names retained for compatibility

Every other category in the master inventory has a runtime or attribution
contract. These are intentionally retained until their producer and consumer
can migrate together:

| Remaining names | Location in the master chart | Reason |
| --- | --- | --- |
| `istio_requests_total`, `istio_request_duration_milliseconds_bucket` | `addons/dashboards/agentio.json` | Actual metric names emitted by the gateway telemetry implementation. Renaming the queries alone would produce empty dashboards. |
| `ISTIO_META_SERVICE_ACCOUNT`, `ISTIO_META_NODE_NAME`, `ISTIO_META_CLUSTER_ID`, `ISTIO_META_NETWORK`, `ISTIO_META_INTERCEPTION_MODE`, `ISTIO_META_WORKLOAD_NAME`, `ISTIO_META_OWNER`, `ISTIO_META_MESH_ID`, `ISTIO_META_DNS_CAPTURE`, `ISTIO_META_ENABLE_HBONE`, `ISTIO_CPU_LIMIT` | Gateway templates, ztunnel injection and DaemonSet | Environment-variable and proxy-metadata contracts consumed by pilot-agent, proxy and external ztunnel images. No unverified `AGENTIO_*` names are emitted. |
| `/var/lib/istio/data`, `/etc/istio/proxy`, `/etc/istio/pod`, `/var/run/secrets/istio-dns` | Gateway and control-plane templates | Proxy data, bootstrap, pod metadata and control-plane DNS certificate paths remain aligned with the existing binary defaults. Credential paths are configured explicitly as described above. |
| `istioNamespace`, `pilotCertProvider: istiod`, `PILOT_CERT_PROVIDER=istiod` | Injector values and gateway configuration | Existing values-schema field and recognized certificate-provider identifier. These are configuration contracts rather than display text. |
| `Copyright Istio Authors`, adaptation provenance | `files/agentgateway.yaml` | Upstream attribution must remain. This master-only template has no release-chart counterpart. |

## Image and branch coordination

Deploy this chart with matching control-plane, proxy-init, gateway/proxy and CNI
images built with these adaptations. In particular, old proxy-init images do
not recognize `agentio-iptables`, and old gateway images do not read the new
stats annotations or the `JWT_PATH` setting. The gateway/proxy image must
therefore include the new token-path support before deploying these mounts.
Ztunnel credential paths use existing configuration and require no Rust code
change. Old CNI images do not understand the new traffic/status
annotations or skip `agentio-init` Pods.

Master consumes externally built data-plane images through immutable pins in
`agentio.deps`; it does not contain this branch's CNI or iptables source. Port the
injector changes into master's `pkg/inject`, update its chart and template test
fixture together, and update the CNI, proxy-init and gateway image pins after
publishing matching images. Do not copy the release chart wholesale into master.

Existing Pods keep their containers and programmed rules until recreated. This
change does not publish images, change dependency pins, or modify a cluster.
