# Get started with sidecar mode

**Sidecar mode is the recommended deployment mode.** Ambient mode is in Alpha and does not yet have full feature parity with sidecar mode.

This guide installs the Agentio with sidecar injection, enrolls a namespace, and creates a test workload for the shared egress and policy tasks.

## Before you begin

Complete the prerequisites in [Getting started](../getting-started.md). If the cluster already runs Istio or another sidecar injector, inspect the existing namespace labels and mutating webhooks before continuing.

```console
$ kubectl get namespace -L agentio.kruise.io/dataplane-mode
$ kubectl get mutatingwebhookconfigurations
```

## Install Agentio

Install the chart with the sidecar profile:

```console
$ helm upgrade --install agentio manifests/charts/agentio \
    --namespace agentio-system \
    --create-namespace \
    --set profile=sidecar \
    --atomic \
    --wait
```

Verify the control plane and injection webhook:

```console
$ kubectl rollout status deployment/agentiod --namespace agentio-system --timeout=5m
$ kubectl get mutatingwebhookconfiguration agentiod-sidecar-injector-agentio-system
```

## Enroll a workload

Create a namespace and enable injection before creating its Pods:

```console
$ kubectl create namespace agentio-demo-sidecar
$ kubectl label namespace agentio-demo-sidecar agentio.kruise.io/dataplane-mode=sidecar --overwrite
```

Create a curl workload:

```console
$ kubectl apply --namespace agentio-demo-sidecar -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: curl
spec:
  replicas: 1
  selector:
    matchLabels:
      app: curl
  template:
    metadata:
      labels:
        app: curl
    spec:
      containers:
      - name: curl
        image: docker.io/curlimages/curl:8.16.0
        command: ["/bin/sleep", "infinity"]
EOF

$ kubectl rollout status deployment/curl --namespace agentio-demo-sidecar --timeout=2m
```

The injected ztunnel appears as the `agentio-proxy` container — either a regular container or a restartable init container, depending on native-sidecar support. Inspect both lists:

```console
$ kubectl get pod --namespace agentio-demo-sidecar --selector app=curl --output jsonpath='{range .items[0].spec.containers[*]}container={.name}{"\n"}{end}{range .items[0].spec.initContainers[*]}initContainer={.name} restartPolicy={.restartPolicy}{"\n"}{end}'
```

Send a baseline request from the application container:

```console
$ kubectl exec deployment/curl --namespace agentio-demo-sidecar --container curl -- curl --fail --silent --show-error --head http://www.example.com
```

Export the workload variables used by the shared tasks:

```console
$ export AGENTIO_DEMO_NAMESPACE=agentio-demo-sidecar
$ export AGENTIO_WORKLOAD_LABEL=curl
$ export AGENTIO_WORKLOAD_CONTAINER=curl
```

## Injection metadata

The injector uses the following Agentio metadata. These fields replace the corresponding Istio names for new Pods; recreate workloads from their original Pod templates after upgrading rather than reusing previously injected Pod YAML.

| Field | Purpose |
| --- | --- |
| Annotation `sidecar.agentio.kruise.io/status` | Records injected containers and volumes for reinjection. |
| Annotation `sidecar.agentio.kruise.io/overrides` | Records user-provided proxy container overrides for reinjection. |
| Label `agentio.kruise.io/network` | Overrides the injected proxy's network, taking precedence over injector URL and Helm values. |
| Annotation `prometheus.agentio.kruise.io/merge-metrics` | Enables or disables application metrics merging for this Pod. |
| Label `cni.agentio.kruise.io/uninitialized` | Default failure label when CNI repair is configured to label broken Pods. |

The chart's pinned CNI image still reads `sidecar.istio.io/status`. Injection through a CNI-enabled template therefore also writes that key; default init-container injection writes only the Agentio status. The CNI repair controller is configured to read the Agentio status. Traffic capture settings (`traffic.sidecar.istio.io/*`, `sidecar.istio.io/interceptionMode`, `status.sidecar.istio.io/port`, and `istio.io/reroute-virtual-interfaces`) retain their existing names because the CNI plugin consumes them. Ambient enrollment also retains the CNI-written `ambient.istio.io/redirection` annotation.

The injector no longer validates the unused `readiness.status.sidecar.istio.io/*` tuning annotations; they do not configure the ztunnel readiness probe. New injection does not add Istio revision, TLS mode, tunnel, or canonical-service labels. User-supplied metadata is preserved.

## Continue

Follow [Route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md), then [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md).

## Clean up

Complete the cleanup sections in the shared tasks before deleting the workload namespace:

```console
$ kubectl delete namespace agentio-demo-sidecar
```

Removing the namespace label does not remove an already injected container. Recreate workloads when changing enrollment or switching profiles.

## See also

- [Getting started](../getting-started.md)
- [Ambient mode](ambient-mode.md)
- [Integrate OpenKruise Agents](../integrations/openkruise-agents.md)
- [Agentio Helm chart guide](../../manifests/charts/README.md)
