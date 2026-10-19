# Integrate OpenKruise Agents

Use this integration when OpenKruise Agents creates a workload as a `Sandbox`. The Agentio watches the `Sandbox` and its controller-owned Pod, derives a stable sandbox identity, and attaches Agentio policy to that identity.

This integration changes the workload source. Choose which release owns the control plane before configuring routes or EPE.

## Choose an installation path

| Installation | Control plane | Values and subsequent commands |
| --- | --- | --- |
| Standalone Agentio plus an externally configured Sandbox runtime | The `agentio` release, normally in `agentio-system` | Follow [Getting started](../getting-started.md). Configure the runtime to use this control plane. Use `agentiod.*` and `epe.*` values and the standalone task commands. |
| Manager-integrated Agentio plus sandbox-controller injection | The sandbox-manager release; Agentio resources default to `sandbox-system` | Follow [OpenKruise chart integration](../../manifests/charts/OPENKRUISE.md). Use `agentio.*` values in the manager release. Do not install or upgrade a second standalone release for these Sandboxes. |

For both paths, install OpenKruise Agents and the `sandboxes.agents.kruise.io` CRD, and ensure the runtime distribution provides `traffic-proxy`.

Enable Sandbox discovery in the control plane. For a manager-integrated installation, include these values in the **sandbox-manager** release:

```yaml
agentio:
  enabled: true
  agentiod:
    env:
      AGENTIO_SANDBOX_MODE: "true"
      AGENTIO_SANDBOX_RUNTIMES: kruise
```

For standalone Agentio, omit the outer `agentio` wrapper and put the same environment entries under `agentiod.env`. Enabling Sandbox mode only on the runtime proxy does not enable discovery in Agentiod.

The manager integration defaults to a static gateway, managed EPE, and a catch-all gateway route. Customize routing under `agentio.agentiod.config.values.egressPolicies` and EPE under `agentio.epe` in the manager's values file. Upgrade the existing manager release using its chart and Helm release namespace; the Agentio resource namespace (`agentio.global.namespace`) can differ from that Helm namespace. The standalone task's `helm upgrade agentio ... --namespace agentio-system` command does not update this control plane.

Configure bootstrap addresses, token audience, and workload trust consistently in the manager and controller releases using the [installation mapping](../../manifests/charts/OPENKRUISE.md#configure-the-installation). The default workload bundle is `agentio-ca-root-cert`, and the token audience is `agentio-ca`.

Verify the selected installation (use `agentio-system` for the standalone defaults):

```console
$ export AGENTIO_CONTROL_PLANE_NAMESPACE=sandbox-system
$ kubectl get crd sandboxes.agents.kruise.io
$ kubectl rollout status deployment/agentiod \
    --namespace "$AGENTIO_CONTROL_PLANE_NAMESPACE" --timeout=5m
$ kubectl get deployment agentiod --namespace "$AGENTIO_CONTROL_PLANE_NAMESPACE" \
    --output jsonpath='{.spec.template.spec.containers[?(@.name=="discovery")].env}'
```

Confirm both discovery variables appear in the Deployment. Adjust its name if you configured `fullnameOverride`.

## Understand the identity boundary

Agentio treats `Sandbox` as the policy subject and its backing Pod as the network endpoint and authenticated attester. The controller binds an unambiguous Sandbox to its owned backing Pod when the Pod is not being deleted and is eligible for networking. A pooled Sandbox must be claimed. Binding is not gated on the Sandbox phase being `Running` or a runtime-initialized condition; the data plane must authenticate the bound Workload identity.

For a non-pooled Sandbox, the fallback identity is `<namespace>--<name>`. When `agents.kruise.io/sandbox-id` is present, that label is the delivery identity. A pooled Sandbox is published as a policy subject only while it is claimed; ambiguous or stale bindings fail closed.

Do not copy a sandbox identity label onto an unrelated Pod. Labels are selection metadata, not proof that a Pod owns a Sandbox identity.

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

For standalone Agentio, follow [Route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md). For the manager integration, use the gateway route from the manager release and inspect its `agentio-config` and `agentio-config-primary` in `$AGENTIO_CONTROL_PLANE_NAMESPACE`; customize it through that release's `agentio.agentiod.config.values`, not the standalone Helm commands.

Then follow [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md) using the workload variables above. Shared TrafficPolicy and SecurityProfile selectors match the backing Pod/Workload labels. Put business labels under `spec.template.metadata.labels`, as in this example; labeling only the Sandbox's top-level metadata does not select its Pod. Sandbox inline rules are a separate policy source.

The managed EPE defaults are already enabled in the manager integration. When following EPE tasks, use its actual EPE namespace and ServiceAccount for logs and Secret RoleBindings, and apply Helm settings under `agentio.epe` in the manager release.

## Clean up

Complete the cleanup sections in the shared tasks, then delete the Sandbox and namespace:

```console
$ kubectl delete sandbox agentio-sample --namespace agentio-agents-demo
$ kubectl delete namespace agentio-agents-demo
```

Do not remove the shared OpenKruise Agents installation or runtime configuration as part of this sample cleanup.

## See also

- [Getting started](../getting-started.md)
- [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md)
