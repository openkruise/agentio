# Integrate OpenKruise Agents

Use this integration when OpenKruise Agents creates a workload as a `Sandbox`. A Sandbox is an OpenKruise Sandbox workload, the unit of identity and policy in Agentio. Agentio watches the Sandbox and its controller-owned Pod, derives a stable Sandbox identity, and attaches Agentio policy to that identity.

This guide uses Agentio embedded in sandbox-manager, with traffic-proxy injection owned by sandbox-controller. It is an alternative to the standalone sidecar/ambient installation.

## Before you begin

You need:

- OpenKruise Agents and the `sandboxes.agents.kruise.io` CRD installed;
- Helm and `kubectl` configured for the cluster;
- the sandbox-manager and sandbox-controller charts with the Agentio integration bundle.

Verify the API:

```console
$ kubectl get crd sandboxes.agents.kruise.io
```

## Install the chart integration

The Agentio chart includes generated integrations for the OpenKruise
sandbox-manager and sandbox-controller charts. Follow
[OpenKruise chart integration](../../manifests/charts/OPENKRUISE.md) to generate or
synchronize these bundles and configure their releases. The manager runs `agentiod`;
the controller supplies the `traffic-proxy` runtime injection configuration.

For this installation, configure bootstrap addresses, the token audience, and the
workload CA bundle consistently in both releases. The default workload bundle is
`agentio-ca-root-cert`, and the token audience is `agentio-ca`.

Enable `agentio.sandbox.enabled: true` in both releases. In the manager's existing values file, enable Agentio, a static gateway and managed EPE:

```yaml
agentio:
  enabled: true
  sandbox:
    enabled: true
  global:
    namespace: sandbox-system
  egressGateway:
    enabled: true
  epe:
    mode: managed
```

Keep the rest of the manager settings in that file. Upgrade the existing sandbox-manager release with it; do not install a standalone Agentio release for this path. Verify the default control-plane namespace:

```console
$ kubectl rollout status deployment/agentiod --namespace sandbox-system --timeout=5m
$ kubectl rollout status deployment/agentio-egress --namespace sandbox-system --timeout=5m
$ kubectl rollout status deployment/agentio-epe --namespace sandbox-system --timeout=5m
```

## Understand the identity boundary

Agentio treats the `Sandbox` as the policy subject and its backing Pod as the network endpoint and authenticated attester. The delivery identity is the stable identifier Agentio binds policy to: it is derived from the Sandbox's namespace and name, or taken from the `agents.kruise.io/sandbox-id` label when that label is present.

Do not copy a Sandbox identity label onto an unrelated Pod. Labels are selection metadata, not proof that a Pod owns a Sandbox identity. See [Sandbox identity derivation](../design/openkruise-agents-identity.md) for the exact rules.

## Create a Sandbox

The exact runtime list is owned by the installed OpenKruise Agents distribution. The following example uses its `traffic-proxy` runtime contract; confirm that your distribution provides that runtime before applying it:

```console
$ kubectl create namespace agentio-agents-demo

$ kubectl apply --namespace agentio-agents-demo -f - <<'EOF'
apiVersion: agents.kruise.io/v1alpha1
kind: Sandbox
metadata:
  name: agentio-sample
spec:
  runtimes:
  - name: traffic-proxy
  template:
    metadata:
      labels:
        app: agentio-agents-sample
    spec:
      containers:
      - name: sandbox
        image: docker.io/curlimages/curl:8.16.0
        command: ["/bin/sleep", "infinity"]
EOF
```

Wait for the resource and its Pod:

```console
$ kubectl wait sandbox/agentio-sample --namespace agentio-agents-demo --for=condition=Ready --timeout=2m
$ kubectl wait pod --namespace agentio-agents-demo --selector app=agentio-agents-sample --for=condition=Ready --timeout=2m
$ kubectl get sandbox agentio-sample --namespace agentio-agents-demo --output yaml
```

If the Sandbox never becomes ready, inspect the OpenKruise Agents controller and runtime-distribution logs first. Agentio consumes the resulting Sandbox and Pod; it does not create or repair the external runtime integration.

## Continue with Agentio policy

Save the generated Pod name and export the interface used by the shared tasks:

```console
$ export AGENTIO_DEMO_NAMESPACE=agentio-agents-demo
$ export AGENTIO_WORKLOAD_LABEL=agentio-agents-sample
$ export AGENTIO_WORKLOAD_CONTAINER=sandbox

$ AGENTIO_WORKLOAD_POD=$(kubectl get pod --namespace "$AGENTIO_DEMO_NAMESPACE" --selector "app=$AGENTIO_WORKLOAD_LABEL" --output jsonpath='{.items[0].metadata.name}')
$ test -n "$AGENTIO_WORKLOAD_POD"
```

The integrated manager generates a catch-all route through its static gateway. Verify a real request from the Sandbox:

```console
$ kubectl exec "$AGENTIO_WORKLOAD_POD" \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --container "$AGENTIO_WORKLOAD_CONTAINER" -- \
    curl --fail --silent --show-error --head http://www.example.com
```

To route only the demo destination, set this in the manager's existing values file. It replaces the generated catch-all route:

```yaml
agentio:
  agentiod:
    config:
      values:
        egressPolicies:
        - namespaces: [agentio-agents-demo]
          matchHosts: [www.example.com]
          policy: GATEWAY
          gateway:
            service: agentio-egress.sandbox-system.svc.cluster.local
        - namespaces: [agentio-agents-demo]
          policy: PASSTHROUGH
```

Use your actual manager release, release namespace and integrated chart path. For example, for a release named `sandbox-manager` installed in `sandbox-system`:

```bash
helm upgrade sandbox-manager \
  "$CHARTS_REPO/versions/kruise-agents-sandbox-manager/next" \
  --namespace sandbox-system --values values-manager.yaml --wait
kubectl get configmap agentio-config agentio-config-primary \
  --namespace sandbox-system --ignore-not-found --output yaml
```

Adjust the gateway address if you customized its name, Agentio namespace or cluster domain. An existing primary ConfigMap still takes precedence over the Helm-managed base.

Continue with [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md). For request policy, managed EPE is already enabled above; use [Apply a minimal profile](../getting-started/epe.md#apply-a-minimal-profile) and its request verification. Skip the standalone Helm enable/disable commands on that page. Policy selectors use the Sandbox's effective labels; protected internal labels from an unrelated Pod cannot replace Sandbox-owned identity.

## Clean up

Delete sample TrafficPolicy/SecurityProfile resources using their task cleanup commands, then delete the Sandbox and namespace:

```console
$ kubectl delete sandbox agentio-sample --namespace agentio-agents-demo
$ kubectl delete namespace agentio-agents-demo
```

Restore any demo route changes in the manager's values file and upgrade that same release. Keep the shared gateway and EPE enabled if other Sandboxes use them. Do not run the standalone Agentio Helm cleanup commands for this installation.

## See also

- [Getting started](../getting-started.md)
- [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md)
