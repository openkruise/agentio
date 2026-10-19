# Getting started

Agentio supports two data-plane profiles. The ambient profile captures traffic with a node-level CNI and ztunnel, while the sidecar profile injects a per-Pod ztunnel. Both profiles use the same `agentiod` control plane and Agentio policy APIs.

## Before you begin

You need a Kubernetes cluster, `kubectl`, Helm 3.10 or later, and access to the images configured in [`manifests/charts/agentio/values.yaml`](../manifests/charts/agentio/values.yaml). Run the commands in these guides from the repository root.

Install the [Kruise Agents API](https://github.com/openkruise/agents-api) before using `Sandbox` resources. Install the [Kubernetes Gateway API CRDs](https://gateway-api.sigs.k8s.io/guides/#installing-gateway-api) before enabling `egressGateway.mode=gatewayAPI`.

## Choose a profile

**Use sidecar mode as the preferred deployment mode. Ambient mode is in Alpha and does not yet have full feature parity with sidecar mode.**

| Profile | Traffic capture | Start here |
| --- | --- | --- |
| Sidecar (recommended) | One injected ztunnel per workload Pod | [Get started with sidecar mode](getting-started/sidecar-mode.md) |
| Ambient (Alpha) | Agentio CNI and one ztunnel per node | [Get started with ambient mode](getting-started/ambient-mode.md) |

The chart installs one profile at a time and defaults to `sidecar`. To use the Alpha ambient mode, set `profile: ambient` in your values file or pass `--set profile=ambient`. Keep the selected profile in a values file so later upgrades use the same mode explicitly.

If OpenKruise Agents creates the workload, also read [Integrate OpenKruise Agents](integrations/openkruise-agents.md) after installing Agentio. That integration changes the workload source, not the Agentio data-plane profile.

## Continue with policy and egress

Each onboarding guide creates a test workload and exports the variables used by the task pages. Continue with:

1. [Route traffic through an egress gateway](tasks/route-traffic-through-egress-gateway.md).
2. [Configure a TrafficPolicy](tasks/configure-traffic-policy.md).
3. [Get started with EPE](getting-started/epe.md) when Layer 7 request policy is required.

For production settings, upgrades, and profile changes, see the [Agentio Helm chart guide](../manifests/charts/README.md).

## Continue by task

Keep the enrolled workload, gateway and route while moving between tutorials. Remove each tutorial's demo policies when finished; defer infrastructure cleanup until the end.

- [Traffic processing and capability boundaries](concepts/traffic-processing.md): choose the right configuration and understand Porter, gateway and EPE responsibilities.
- [Inspect HTTPS traffic](tasks/inspect-https-traffic.md): TLS termination and client trust.
- [Configure a SecurityProfile](tasks/configure-security-profile.md): HTTP blocking and credentials.
- [Modify request headers](tasks/modify-request-headers.md): ordinary header set/remove actions.
- [EPE destination authorization](tasks/configure-epe-destination-authorization.md): opt-in deployment prerequisites and verification.
- [Troubleshoot policy enforcement](tasks/troubleshoot-policy-enforcement.md): trace an unexpected result through the actual request path.
