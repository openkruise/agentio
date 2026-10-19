# OpenKruise Agents chart integration

Agentio generates two integration bundles for the OpenKruise charts repository:

- `sandbox-manager`: an optional Agentio control plane, static or Gateway API egress gateway, and managed or external EPE.
- `sandbox-controller`: the `traffic-proxy` entry in `ConfigMap/sandbox-injection-config`.

The source is the master Agentio chart. The reviewed generated files live in `agentio/integrations/openkruise/` and are included in the packaged Agentio chart. Edit the standalone chart or generator, then regenerate the bundle; do not edit the generated manager templates or controller values directly.

## Generate and verify

Run from the Agentio repository root with Go and Helm installed:

```bash
go run ./tools/agentio-chart-sync build --chart manifests/charts/agentio
go run ./tools/agentio-chart-sync verify \
  --bundle manifests/charts/agentio/integrations/openkruise
go test ./manifests/charts ./tools/agentio-chart-sync
```

The tests verify that the checked-in bundle matches the chart, render all gateway and EPE mode combinations, and check the bootstrap contract and immutable images in a packaged release. `build --output <directory>` writes to another directory.

## Apply to OpenKruise charts

In a local checkout of `openkruise/charts`, the destination charts are `versions/kruise-agents-sandbox-manager/next` and `versions/kruise-agents-sandbox-controller/next`. Set `CHARTS_REPO` to that checkout:

```bash
export CHARTS_REPO=/path/to/charts
helm pull oci://docker.io/openkruise/agentio --version 0.2.0 \
  --untar --untardir /tmp/agentio-release

go run ./tools/agentio-chart-sync apply \
  --bundle /tmp/agentio-release/agentio/integrations/openkruise \
  --manager-chart "$CHARTS_REPO/versions/kruise-agents-sandbox-manager/next" \
  --controller-chart "$CHARTS_REPO/versions/kruise-agents-sandbox-controller/next"

helm lint "$CHARTS_REPO/versions/kruise-agents-sandbox-manager/next" \
  --set e2b.adminApiKey=test --set ingress.className=test
helm lint "$CHARTS_REPO/versions/kruise-agents-sandbox-controller/next"
```

`apply` replaces the marked Agentio values and the manager's `templates/agentio/` and `files/agentio/` directories. In the controller, it updates only the `traffic-proxy` entry, its marked values, and an Agentio image helper; other runtime entries are preserved. Image configuration is adapted to the parent charts' registry contract, including when applying an older published bundle. Repeated application of the same bundle is idempotent. Unmarked existing `agentio` values are rejected so they can be reconciled before synchronization.

Applied images use `registry`, `repository`, `tag`, and `digest` fields. Docker Hub defaults inherit the parent chart's `image.registry`; a per-image `registry` takes precedence. The manager also supports `agentio.global.registry` between those two levels. A repository that already includes a registry hostname keeps that host. Each image defaults to the bundle's fixed release version, such as `0.2.0`, with an empty `digest`. `apply` rejects bundles with a missing or moving global tag such as `latest`. Mirrors must contain these version tags. A user-supplied `digest` still takes precedence over `tag`.

## Configure the installation

Enable Agentio in the sandbox-manager release values:

```yaml
agentio:
  enabled: true
  agentiod:
    env:
      AGENTIO_SANDBOX_MODE: "true"
      AGENTIO_SANDBOX_RUNTIMES: kruise
  global:
    namespace: sandbox-system
    createNamespace: true
  egressGateway:
    mode: static
  epe:
    mode: managed
    credentialProvider:
      url: https://credentials.example.com
```

When Agentio is enabled, the gateway defaults to `static` and EPE to `managed`. A catch-all egress policy routes outbound traffic to the integrated gateway. Explicit `agentio.agentiod.config.values.egressPolicies` replace that default (including an empty list); custom gateway names, namespaces, and cluster domains are reflected in the generated Service address. Setting the gateway mode to `disabled` suppresses the generated gateway route. Existing `agentio-config-primary` routing overrides still take precedence. The Agentio namespace defaults to `sandbox-system`, independently of the manager's Helm release namespace. The chart creates and retains that namespace unless `agentio.global.createNamespace` is false or it is already the release namespace. The four policy CRDs always render, even when `agentio.enabled` is false, and carry `helm.sh/resource-policy: keep` to preserve policies on uninstall.

The manager bundle omits the standalone `profile`, CNI, node ztunnel, admission webhook, and application client-trust injection settings. Sandbox injection is owned by sandbox-controller. The manager does not provide an injector ConfigMap, injector values, or gateway injection template files. Admission injection, application client-trust injection, and the gateway deployer are disabled by default. The Kruise integration does not include agentgateway templates or settings.

Static gateway mode works without injector configuration. Explicitly selecting `gatewayAPI` enables Agentiod's gateway deployer and requires an externally managed gateway template ConfigMap; this bundle does not install one. Its default name is `agentio-sidecar-injector`; an existing ConfigMap with another name can be selected through `agentio.agentiod.env.AGENTIO_INJECTOR_CONFIGMAP_NAME`.

Configure the sandbox-controller release separately when changing bootstrap settings in the manager:

| sandbox-manager value | sandbox-controller value |
| --- | --- |
| `agentio.global.namespace` | `agentio.trafficProxy.controlPlaneNamespace` |
| `agentio.agentiod.fullnameOverride` | `agentio.trafficProxy.controlPlaneService` |
| `agentio.global.clusterDomain` | `agentio.trafficProxy.clusterDomain` |
| `agentio.global.clusterId` | `agentio.trafficProxy.clusterId` |
| `agentio.agentiod.tokenAudience` | `agentio.trafficProxy.tokenAudience` |
| `agentio.agentiod.ca.trustBundleConfigMapName` | `agentio.trafficProxy.caCertConfigMap` |

The defaults use `agentiod.sandbox-system.svc.cluster.local:15012`, token audience `agentio-ca`, and the namespace-local `agentio-ca-root-cert` trust bundle. `xdsAddress` and `caAddress` can override the derived addresses. The runtime adds an `agentio-init` container and a native `traffic-proxy` sidecar. Its `agentio.kruise.io/dataplane-mode: none` label prevents a second injection by the standalone Agentio webhook or CNI.

See [Integrate OpenKruise Agents](../../docs/integrations/openkruise-agents.md) for the Sandbox runtime declaration and workload verification.

## Migrate release-0.1 values

The generated manager configuration follows master's values API. Update existing release-0.1 overrides before upgrading:

| release-0.1 | master |
| --- | --- |
| `agentio.agentiod.replicas` | `agentio.agentiod.replicaCount` |
| `agentio.epe.enabled: true` | `agentio.epe.mode: managed` |
| `agentio.epe.replicas` | `agentio.epe.replicaCount` |
| `agentio.egressGateway.gateways: [{name: my-egress}]` | `agentio.egressGateway.mode: static` and `fullnameOverride: my-egress` |
| `agentio.egressGateway.replicas` | `agentio.egressGateway.replicaCount` |
| Component `image.hub` and `image.name` | `image.repository`, with `image.tag` or `image.digest` |
| `agentio.global.meshInternalTrafficPolicy` | `agentio.agentiod.meshInternalTrafficPolicy` |
| `agentio.agentioConfig` | `agentio.agentiod.config.values` |
| `agentio.sniTrafficPolicy.enabled` | `agentio.agentiod.enableSNITrafficPolicy` |

Master renders one static gateway per release. For multiple controller-managed gateways, select `gatewayAPI` and manage the Gateway resources separately. The mesh-internal traffic policy now defaults to `PEER_AWARE`; set `agentio.agentiod.meshInternalTrafficPolicy: PASSTHROUGH` explicitly if the installation still needs the release-0.1 default.

The control-plane image is `agentiod` and its configuration uses `AGENTIO_*` environment variables. Legacy pilot environment overrides and `meshConfig` settings require migration to master's supported Agentio configuration; they are not translated automatically. Use the generated values and [chart guide](README.md) for the complete available configuration.

The workload trust bundle is now `agentio-ca-root-cert`, separate from the control-plane CA ConfigMap `agentio-ca-certs`. Update controller overrides for the CA ConfigMap and token audience together with the manager upgrade. Kubernetes Pods need recreation to receive an updated runtime injection template.

## Release and downstream synchronization

`tools/prepare-release-chart.sh` pins the standalone chart's images first, then rebuilds and verifies the embedded integrations. Both controller images retain the exact ztunnel and proxy-init digests used by the standalone sidecar injector. The release workflow packages this prepared chart without rebuilding it and publishes matching version tags for all six images, including external dependencies. The standalone chart remains digest-pinned; downstream `apply` converts its image defaults to the fixed release tag. For older releases, run `agentio-dependency-tags` first if dependency version tags are missing.

The `sync-sandbox-manager-agentio-chart` workflow can be dispatched with a published chart version. It pulls the OCI chart, checks that all version tags match the published BOM digests, verifies and applies its bundled integration, lints and renders the downstream charts, and opens a pull request in `openkruise/charts`. It requires the existing release environment's `AGENTIO_SYNC_APP_CLIENT_ID` variable and `AGENTIO_SYNC_APP_PRIVATE_KEY` secret. The corresponding GitHub App must be installed for `openkruise/charts` with Contents and Pull requests write access. A 404 while looking up the repository installation means this access is missing or the configured App is incorrect; rerunning the workflow alone cannot resolve it.
