# Get started with ambient mode

> **Alpha:** Sidecar mode is the recommended deployment mode; ambient mode is Alpha.

This guide installs Agentio in ambient mode, enrolls a namespace, and creates a test workload for the shared egress and policy tasks.

## Before you begin

Complete the prerequisites in [Getting started](../getting-started.md). Ambient mode requires Linux nodes.

If the cluster already runs Istio or another service-mesh CNI, confirm the existing CNI configuration before installing. Check the CNI DaemonSets in `kube-system` and any existing namespace enrollment labels:

```console
$ kubectl get daemonset --namespace kube-system
$ kubectl get namespace -L agentio.kruise.io/dataplane-mode
```

## Install Agentio

Install the chart with the ambient profile:

```console
$ helm upgrade --install agentio manifests/charts/agentio \
    --namespace agentio-system \
    --create-namespace \
    --set profile=ambient \
    --atomic \
    --wait
```

Verify the control plane and both node components:

```console
$ kubectl rollout status deployment/agentiod --namespace agentio-system --timeout=5m
$ kubectl rollout status daemonset/agentio-cni --namespace agentio-system --timeout=5m
$ kubectl rollout status daemonset/ztunnel --namespace agentio-system --timeout=5m
```

## Enroll a workload

Create and label a namespace before creating its Pods:

```console
$ kubectl create namespace agentio-demo-ambient
$ kubectl label namespace agentio-demo-ambient agentio.kruise.io/dataplane-mode=ambient --overwrite
```

Create a curl workload. The Pod does not receive a proxy container in ambient mode:

```console
$ kubectl apply --namespace agentio-demo-ambient -f - <<'EOF'
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

$ kubectl rollout status deployment/curl --namespace agentio-demo-ambient --timeout=2m
$ kubectl get pods --namespace agentio-demo-ambient --selector app=curl
```

Confirm that the Pod has only the application container, then send a baseline request:

```console
$ kubectl get pod --namespace agentio-demo-ambient --selector app=curl --output jsonpath='{.items[0].spec.containers[*].name}{"\n"}'
curl

$ kubectl exec deployment/curl --namespace agentio-demo-ambient --container curl -- curl --fail --silent --show-error --head http://www.example.com
```

Export the workload variables used by the shared tasks:

```console
$ export AGENTIO_DEMO_NAMESPACE=agentio-demo-ambient
$ export AGENTIO_WORKLOAD_LABEL=curl
$ export AGENTIO_WORKLOAD_CONTAINER=curl
```

## Continue

Follow [Route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md), then [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md).

## Clean up

Complete the cleanup sections in the shared tasks before deleting the workload namespace:

```console
$ kubectl delete namespace agentio-demo-ambient
```

- Removing the namespace label from existing Pods does not undo their network setup. Delete or restart workloads when changing enrollment.
- Follow your Kubernetes distribution's node cleanup procedure before removing a CNI installation.

## See also

- [Getting started](../getting-started.md)
- [Sidecar mode](sidecar-mode.md)
- [Agentio Helm chart guide](../../manifests/charts/README.md)
