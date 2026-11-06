# Getting started

Agentio supports two data-plane profiles. The ambient profile captures traffic with a node-level CNI and ztunnel, while the sidecar profile injects a per-Pod ztunnel. Both profiles use the same `agentiod` control plane and Agentio policy APIs.

## Before you begin

You need a Kubernetes cluster, `kubectl`, Helm 3, and access to the images configured in [`manifests/charts/agentio/values.yaml`](../manifests/charts/agentio/values.yaml). Run the commands in these guides from the repository root.

Install the [Kruise Agents API](https://github.com/openkruise/agents-api) before using `Sandbox` resources. A `Sandbox` is an OpenKruise Sandbox workload — the unit of identity and policy subject in Agentio. Install the [Kubernetes Gateway API CRDs](https://gateway-api.sigs.k8s.io/guides/#installing-gateway-api) before enabling `agentiod.gatewayDeployer.enabled=true`.

## Choose a profile

**Sidecar mode is the recommended deployment mode; ambient mode is Alpha.**

| Profile | Traffic capture | Start here |
| --- | --- | --- |
| Sidecar (recommended) | One injected ztunnel per workload Pod | [Get started with sidecar mode](getting-started/sidecar-mode.md) |
| Ambient (Alpha) | Agentio CNI and one ztunnel per node | [Get started with ambient mode](getting-started/ambient-mode.md) |

The standalone chart defaults to `profile: sidecar`; set `profile: ambient` for ambient mode.

If OpenKruise Agents creates the workload, start with [Integrate OpenKruise Agents](integrations/openkruise-agents.md) instead. Its embedded installation runs Agentio in the sandbox-manager release and uses sandbox-controller's traffic-proxy injection.

## Continue with policy and egress

Each onboarding guide creates a test workload and exports the variables used by the task pages. Continue with:

1. [Route traffic through an egress gateway](tasks/route-traffic-through-egress-gateway.md).
2. [Configure a TrafficPolicy](tasks/configure-traffic-policy.md).
3. [Get started with the Egress Policy Enforcer (EPE)](getting-started/epe.md) when Layer 7 request policy is required.

For production settings, upgrades, and profile changes, see the [Agentio Helm chart guide](../manifests/charts/README.md).
