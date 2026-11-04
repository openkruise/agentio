# Get started with sidecar mode

**Sidecar mode is the recommended deployment mode; ambient mode is Alpha.**

This guide installs Agentio with sidecar injection, enrolls a namespace, and creates a test workload for the shared egress and policy tasks.

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

The injected ztunnel appears as the `agentio-proxy` container. Depending on native-sidecar support, it is injected as either a regular container or a restartable init container, so check both lists:

```console
$ kubectl get pod --namespace agentio-demo-sidecar --selector app=curl --output jsonpath='{range .items[0].spec.containers[*]}container={.name}{"\n"}{end}{range .items[0].spec.initContainers[*]}initContainer={.name} restartPolicy={.restartPolicy}{"\n"}{end}'
```

The command prints each regular container as `container=<name>` and each init container as `initContainer=<name> restartPolicy=<policy>`. Expect `agentio-proxy` in one of the two lists.

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

See [Sidecar injection metadata](../design/sidecar-injection-metadata.md) for the annotations and labels the injector adds to Pods.

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
