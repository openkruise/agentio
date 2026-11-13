# Agentio Helm chart

Agentio is installed as one Helm release. The `profile` value selects the data plane, with independent Helm-managed gateway and Gateway controller switches; EPE uses an explicit mode.

**Sidecar mode is the default and recommended deployment mode. Ambient mode is in Alpha and does not yet have full feature parity with sidecar mode.** Keep the selected profile in your values file:

```yaml
profile: sidecar # recommended; ambient is in Alpha

sandbox:
  enabled: false # ordinary Workloads by default; true requires sidecar

egressGateway:
  enabled: false # Helm-managed Envoy gateway

agentiod:
  gatewayDeployer:
    enabled: false # Users create Gateway objects separately

epe:
  mode: disabled # disabled | managed | external
```

## Choose the installation and configuration entry point

For a standalone installation, start with sidecar mode and keep deployment settings in one values file. Enable a static gateway when egress routing is needed, then managed EPE when request policy is needed. Use that same file for upgrades:

```bash
cp manifests/charts/examples/complete-values.yaml values-prod.yaml
helm upgrade --install agentio manifests/charts/agentio \
  -n agentio-system --create-namespace \
  -f values-prod.yaml --atomic --wait
```

For the embedded OpenKruise installation, start with [OpenKruise chart integration](OPENKRUISE.md) instead. Agentio belongs to the sandbox-manager release, uses the `agentio.*` values prefix, and defaults to the `sandbox-system` namespace. Sandbox-controller owns traffic-proxy injection in a separate release.

| What to configure | Entry point | How changes take effect |
| --- | --- | --- |
| Components, images, resources and scheduling | Helm `profile`, `sandbox`, `global`, `agentiod`, `cni`, `ztunnel`, `egressGateway`, `epe` | Helm upgrade; Pod template changes roll out managed workloads. Existing injected Pods need recreation. |
| Egress routes, gateway policy and external processors | `agentiod.config.values` | Helm writes the base ConfigMap; Agentiod watches and distributes valid changes. |
| Operations-owned Agentio policy overrides | `agentio-config-primary` ConfigMap | Watched; overrides the Helm-managed base. Use only when another owner needs an override. |
| EPE extension providers | `epe.config` | Helm writes EPE's base ConfigMap; EPE watches it and its externally managed primary overlay. |
| Gateway agent process settings | Shared `egressGateway.agentConfig`; per-Gateway agent-config annotation | Both Envoy deployment paths use these defaults; annotations override them. See [Gateway agent configuration](../../docs/reference/gateway-agent-configuration.md). |
| Envoy patches and telemetry | `agentiod.config.sources` | Separate watched Kubernetes document stream; see [Envoy patches](../../docs/reference/envoy-patches.md). |
| Advanced process options | Component `env` maps | Pod rollout. Prefer named Helm settings when available; explicit env entries override generated entries. |

The policy layers have different merge rules: Helm deep-merges `agentiod.config.values` over generated maps; the runtime primary ConfigMap replaces supplied messages and lists. EPE merges providers by name. See [Agentio configuration](../../docs/reference/agentio-configuration.md#configuration-sources-and-precedence) and [EPE configuration](../../docs/reference/epe-configuration.md) before adding an overlay.

## Prerequisites

- Kubernetes and Helm 3.6 or later (Helm 4 is supported).
- Install the [Kubernetes Gateway API CRDs](https://gateway-api.sigs.k8s.io/guides/#installing-gateway-api) before selecting `agentiod.gatewayDeployer.enabled=true`.
- Install the [Kruise Agents API](https://github.com/openkruise/agents-api) `sandboxes.agents.kruise.io` CRD before using Sandbox-backed policy.

The chart installs the four Agentio policy CRDs. Helm retains resources from the chart's `crds/` directory when the release is uninstalled.

## Sidecar mode

### Sandbox support

Set `sandbox.enabled: true` to enable Kruise Sandbox discovery and xDS output
in Agentiod, Sandbox inline security rules in managed EPE, and the Sandbox
Manager in injected sidecars. Ordinary Workloads remain supported. The sidecar
gets a writable `/var/lib/ztunnel/sandbox` volume only when enabled.

The default, `false`, runs in ordinary Workload mode without those Sandbox
capabilities. `profile: ambient` with `sandbox.enabled: true` is rejected because
Ambient Sandbox Manager integration is not supported.

Replace existing `agentiod.env.AGENTIO_SANDBOX_MODE` and
`agentiod.env.AGENTIO_SANDBOX_RUNTIMES` overrides with this switch. Helm owns
`AGENTIO_SANDBOX_MODE` and rejects overrides; the runtime selection variable
has been removed. Managed EPE's `AGENTIO_SANDBOX_MODE` and Ambient ztunnel's
Sandbox settings are also chart-owned. External EPE must be configured separately.
Restart existing injected Pods after changing the switch; Helm updates the
injection template, not existing Pods.

Token reading still requires `SANDBOX_TOKEN_ENABLED=true` and a mounted token
directory supplied by the credential producer; see
[CredentialProvider](../../docs/reference/credential-provider.md).

Sidecar mode installs `agentiod` and its injection webhook, without the ambient CNI or node ztunnel:

```bash
helm upgrade --install agentio manifests/charts/agentio \
  --namespace agentio-system \
  --create-namespace \
  --set profile=sidecar \
  --atomic \
  --wait
```

Enable injection and recreate workloads:

```bash
kubectl label namespace demo agentio.kruise.io/dataplane-mode=sidecar --overwrite
kubectl rollout restart deployment -n demo
```

In this chart, `sidecar` means the existing Agentio per-Pod ztunnel injection path. It is not a traditional Envoy sidecar.

## Separate policy control plane

Keep the existing `agentiod` Deployment and Service for ztunnel, and optionally add an `agentiod-policy` Deployment and Service for gateway, Porter and EPE:

```yaml
agentiod:
  policyPool:
    # Deploy a separate backend for gateway/Porter/EPE; ztunnel keeps using agentiod.
    enabled: true
    replicaCount: 2
    resources:
      requests: {cpu: "2", memory: 4Gi}
```

The policy Pod label is `agentio.kruise.io/control-plane-pool: policy`. Its `app.kubernetes.io/name` is distinct so the original Deployment and Service do not select policy Pods. Existing agentiod Deployment selectors are unchanged. With a custom agentiod name, the policy name uses the same name plus `-policy`.

Enabling the option changes the default ADS endpoints for managed EPE, static gateways, and gateways generated by the Gateway API controller. Injected and ambient ztunnel keep their original address. Gateway and managed EPE CA requests also use the policy endpoint; an explicit EPE CA address keeps precedence. Both pools share configuration, the ServiceAccount, CA Secret and CA leader leases. Each instance issues a serving certificate for its own Service name. The policy pool does not run the injection webhook, client trust distributor or gateway deployment controller. It has a separate replica count and resource settings; other agentiod settings are inherited.

Deploy the policy backend and wait for readiness before restarting existing clients to switch endpoints. Existing ADS connections remain on their current backend until reconnect. Disabling this option removes the policy backend, so migrate its clients back to agentiod before disabling it. No automatic failover from the policy Service to the proxy pool is configured.

## Ambient mode

> **Alpha:** Ambient mode does not yet have full feature parity with sidecar mode. Prefer [sidecar mode](#sidecar-mode) for deployments.

Ambient mode installs `agentiod`, the Agentio CNI node agent, and the node ztunnel. Select it explicitly with `--set profile=ambient`:

```bash
helm upgrade --install agentio manifests/charts/agentio \
  --namespace agentio-system \
  --create-namespace \
  --set profile=ambient \
  --atomic \
  --wait
```

Enroll a workload namespace after the release is ready:

```bash
kubectl label namespace demo agentio.kruise.io/dataplane-mode=ambient --overwrite
kubectl rollout restart deployment -n demo
```

## Egress gateway

`egressGateway.enabled` defaults to `false`. Enabling it lets Helm own one static Envoy gateway workload in this release:

```yaml
egressGateway:
  enabled: true
  replicaCount: 2
```

```bash
helm upgrade --install agentio manifests/charts/agentio \
  -n agentio-system --create-namespace \
  -f values-prod.yaml --atomic --wait
```

`agentiod.gatewayDeployer.enabled` independently enables the Gateway controller:

```yaml
agentiod:
  gatewayDeployer:
    enabled: true
```

Install the external Gateway API CRDs, then create Gateways separately using
[the standalone example](examples/egress-gateway.yaml):

```bash
kubectl apply -f manifests/charts/examples/egress-gateway.yaml
kubectl wait -n agentio-system gateway/agentio-api-egress \
  --for=condition=Programmed --timeout=2m
```

The controller creates the built-in GatewayClasses and each Gateway's workloads.
The chart does not create or delete user Gateways or routes. Keep them in your
application chart or GitOps repository. To use a different namespace, edit the
example's namespace before applying it. Creating the Gateway alone does not
configure application traffic to use it; follow [egress routing](../../docs/tasks/route-traffic-through-egress-gateway.md).

### Gateway setting scope

Both switches can be enabled together. Use different names for Helm-managed and
controller-created gateways in the same namespace.

| Entry | Owns |
| --- | --- |
| `egressGateway.image`, `.resources`, `.agentConfig`, `.terminationGracePeriodSeconds` and scheduling fields | Shared defaults for Helm-managed and Gateway API Envoy gateways |
| `egressGateway.porter` | Shared Porter image/cache/resources for both Envoy paths and identity-enabled native gateways |
| `egressGateway.agentgateway` | Native image and CA bootstrap |
| `egressGateway.enabled` | Whether Helm creates its own gateway workload; common defaults remain effective when false |
| `egressGateway` name, replicas, Service/ServiceAccount, token audience, RBAC, HPA/PDB, NetworkPolicy, env, Pod metadata and statistics CLI fields | Helm-managed gateway only |
| `agentiod.gatewayDeployer` | Controller enablement and leader lease only |
| User GatewayClass defaults and Gateway parametersRef | Dynamic workload customizations applied after shared defaults |
| User Gateway agent-config annotation | Per-Gateway override of shared Envoy agent settings |
| `global.imagePullSecrets` | Pull secrets for both paths; the Secrets must exist in each workload namespace |

Configure a Gateway API Envoy gateway through the same entry point, while leaving
Helm-managed deployment disabled:

```yaml
agentiod:
  gatewayDeployer:
    enabled: true
egressGateway:
  enabled: false
  resources:
    requests: {cpu: 500m, memory: 512Mi}
  nodeSelector:
    pool: gateways
```

The common Envoy defaults apply to both deployment paths. Use [resource patches](../../docs/tasks/customize-gateway-resources.md)
for differences between dynamic gateways or GatewayClass defaults. Envoy defaults
request `500m` CPU and `512Mi` memory with no limits. Native main-container
defaults request `100m` and `128Mi`, with limits of `2` CPU and `1Gi`, independent
of Envoy settings. Both initially use a 30-second shutdown budget. Manage Gateway
API NetworkPolicies separately. Generated token audiences follow
`agentiod.tokenAudience`. Native file configuration comes from `parametersRef`.

CA ConfigMap mounts follow `agentiod.ca.configMapName`, falling back to `global.caCertConfigMap`. The trusted node account follows the deployed ztunnel ServiceAccount unless `agentiod.trustedNodeServiceAccount` is explicitly set.

Static gateway identity uses its ServiceAccount name. To reuse an existing
account, set `egressGateway.serviceAccount.create: false` and set
`egressGateway.fullnameOverride` to that account's name. An explicit
`egressGateway.serviceAccount.name` must match the gateway name; mismatches are
rejected before installation.

### Migrate existing gateway values

| Previous field | New field or owner |
| --- | --- |
| `egressGateway.mode: static` | `egressGateway.enabled: true` |
| `egressGateway.mode: gatewayAPI` or `gatewayAPI.enabled` | `agentiod.gatewayDeployer.enabled: true` |
| `egressGateway.mode: disabled` | Leave both switches `false` |
| `egressGateway.gatewayAPI.*` or `gatewayAPI.gateway.*` | User-owned Gateway YAML |
| Gateway API backend settings under `gatewayAPI` or `agentiod.gatewayDeployer` | Shared `egressGateway.image`, `.porter`, `.agentgateway` |
| Gateway API Envoy resources/scheduling/shutdown defaults | Shared `egressGateway` fields; GatewayClass or per-Gateway patches for differences |
| Gateway API Envoy agent defaults | Shared `egressGateway.agentConfig`; per-Gateway annotation for overrides |

Helm-managed gateway fields retain their location. Upgrade with `--reset-values
-f updated-values.yaml` so removed fields are not retained. If an old release
owns a Gateway, the upgrade removes that chart-owned object and may interrupt
traffic: export it first and reapply it separately after the upgrade, during a
maintenance window. Subsequent upgrades do not manage that user-owned Gateway.
Agentio and EPE configuration sources and base/primary merge rules are unchanged.

## EPE

Managed mode deploys EPE and automatically writes its endpoint into the control-plane Agentio configuration:

```yaml
epe:
  mode: managed
  auditWebhook:
    insecureSkipVerify: false
  credentialProvider:
    url: https://credentials.example.com
    mtls:
      source: none # none | secret
```

HTTPS audit webhooks verify the receiver certificate by default. Keep `epe.auditWebhook.insecureSkipVerify: false` in production.

The default `source: none` uses system trust roots without a client certificate. To watch a Secret directly for credential-provider TLS, configure `source: secret`:

```yaml
epe:
  mode: managed
  credentialProvider:
    url: https://credentials.example.com
    mtls:
      source: secret
      secret:
        namespace: credential-system
        name: epe-client
```

External mode deploys no EPE workload and points the control plane and static gateway at an existing endpoint:

```yaml
epe:
  mode: external
  external:
    address: epe.security-system.svc
    port: 9002
```

User settings under `agentiod.config.values` override the generated `sandboxExtProc` defaults when custom request or response behavior is needed.

## Logging

Agentiod emits structured logs through Go's `log/slog`. Text output at info level is the default; JSON is recommended for production log collectors:

```yaml
agentiod:
  logging:
    level: info # debug | info | warn | error
    format: json # text | json
```

The chart maps these values to `AGENTIO_LOG_LEVEL` and `AGENTIO_LOG_FORMAT`. Standard-library logs and Kubernetes `klog` output use the same handler and format.

## Upgrades and profile changes

Static gateway selectors now use only `gateway.networking.k8s.io/gateway-name`; the obsolete `networking.agents.kruise.io/sandbox-egress` label is no longer emitted. When upgrading an existing static gateway whose Deployment selector includes that label, recreate the gateway Deployment during a maintenance window because Kubernetes does not allow changing its selector. This also applies to the sandbox-manager integration and interrupts gateway traffic while the replacement starts.

To keep an existing ambient installation in ambient mode when upgrading, set `profile: ambient` in your release values. The chart now defaults to `sidecar`.

Keep release values in a file and use the same command for installation and upgrade:

```bash
helm upgrade --install agentio manifests/charts/agentio \
  -n agentio-system \
  -f values-prod.yaml \
  --atomic \
  --wait
```

This is one Helm release. Component image tags can be set independently, but the release has one values set and one rollback history. Helm does not wait for `agentiod` before creating the CNI, ztunnel, gateway, or EPE resources; readiness and client retries provide convergence, and `--wait` waits for the whole release.

Changing `profile` does not relabel namespaces or recreate business Pods. For sidecar to ambient, switch the dataplane-mode label and restart the workloads after the upgraded Agentio release is ready:

```bash
kubectl label namespace demo agentio.kruise.io/dataplane-mode=ambient --overwrite
kubectl rollout restart deployment -n demo
```

For ambient to sidecar, switch the label back and restart:

```bash
kubectl label namespace demo agentio.kruise.io/dataplane-mode=sidecar --overwrite
kubectl rollout restart deployment -n demo
```

Profile switching is not currently an ordered, zero-downtime migration.

## OpenKruise Agents integration

To embed Agentio in the sandbox-manager chart and provide sandbox-controller's
`traffic-proxy` runtime, follow [OpenKruise chart integration](OPENKRUISE.md).
The generated bundle uses the same component modes and release image digests as
this chart.

## Local verification

```bash
sh manifests/charts/verify.sh
```

This lints the unified chart, runs its render contract tests, and runs the complete Go test suite.
