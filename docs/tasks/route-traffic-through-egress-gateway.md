# Route traffic through an egress gateway

This task routes outbound traffic for `www.example.com` from an enrolled workload through an Agentio egress gateway. Other outbound traffic continues directly to its destination.

You can create the gateway as a static chart workload or with the Kubernetes Gateway API. These commands target the standalone Agentio release used by the sidecar and ambient guides. The [OpenKruise manager integration](../integrations/openkruise-agents.md#choose-an-installation-path) uses a different release, namespace, and values prefix; do not run these Helm commands against that installation. Choose one method, then configure the common routing policy.

## Protocol detection and server-first connections

The gateway waits up to one second for protocol detection, both inside the
CONNECT tunnel and after TLS termination. If inspection times out, the gateway
continues with the protocol information available. Connections with no detected
protocol use TCP forwarding, allowing server-first protocols such as SMTP and
MySQL to receive the server greeting without sending application data first.
This adds about one second before the upstream connection is opened at each
inspection stage that times out.

A client that delays its first HTTP request or TLS ClientHello beyond this
window can also enter TCP forwarding. The connection stays on that chain;
HTTP inspection and policies that depend on detecting TLS/SNI do not apply to
traffic classified as opaque TCP. Policies for successfully detected protocols
retain their normal behavior.

## Before you begin

Complete one onboarding path from [Getting started](../getting-started.md). The selected guide exports these variables:

| Variable                     | Purpose                                      |
| ---------------------------- | -------------------------------------------- |
| `AGENTIO_DEMO_NAMESPACE`     | Namespace containing the workload            |
| `AGENTIO_WORKLOAD_LABEL`     | Value of the workload Pod's `app` label      |
| `AGENTIO_WORKLOAD_CONTAINER` | Application container used for test requests |

Confirm that they are set, wait for a selected Pod, and save its name:

```console
$ : "${AGENTIO_DEMO_NAMESPACE:?Set AGENTIO_DEMO_NAMESPACE from the onboarding guide}"
$ : "${AGENTIO_WORKLOAD_LABEL:?Set AGENTIO_WORKLOAD_LABEL from the onboarding guide}"
$ : "${AGENTIO_WORKLOAD_CONTAINER:?Set AGENTIO_WORKLOAD_CONTAINER from the onboarding guide}"

$ kubectl wait pod \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --selector "app=$AGENTIO_WORKLOAD_LABEL" \
    --for=condition=Ready \
    --timeout=2m

$ AGENTIO_WORKLOAD_POD=$(kubectl get pod \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --selector "app=$AGENTIO_WORKLOAD_LABEL" \
    --output jsonpath='{.items[0].metadata.name}')
$ test -n "$AGENTIO_WORKLOAD_POD"
```

Verify that the application can reach the destination before you change the egress path:

```console
$ kubectl exec "$AGENTIO_WORKLOAD_POD" \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --container "$AGENTIO_WORKLOAD_CONTAINER" -- \
    curl --fail --silent --show-error --head http://www.example.com
```

## Create a static gateway

Use this method when the Agentio Helm release should own the gateway Deployment and Service directly.

Create an evaluation values file:

```console
$ cat >/tmp/agentio-static-gateway-values.yaml <<'EOF'
egressGateway:
  mode: static
  replicaCount: 1
  autoscaling:
    enabled: false
EOF
```

Update the existing Agentio release:

```console
$ helm upgrade agentio manifests/charts/agentio \
    --namespace agentio-system \
    --reuse-values \
    --values /tmp/agentio-static-gateway-values.yaml \
    --wait \
    --timeout 5m
```

Verify the gateway:

```console
$ kubectl rollout status deployment/agentio-egress \
    --namespace agentio-system \
    --timeout=2m

$ kubectl get service/agentio-egress \
    --namespace agentio-system
```

The chart also registers the static gateway identity in the generated Agentio configuration. Continue with [Configure egress routing](#configure-egress-routing).

## Create the gateway with the Gateway API

Use this method when the cluster has the Gateway API CRDs and `agentiod` should reconcile an Agentio-owned Gateway.

Verify the API, then enable Gateway API mode and ask the chart to create one Gateway:

```console
$ kubectl get crd gateways.gateway.networking.k8s.io

$ cat >/tmp/agentio-gateway-api-values.yaml <<'EOF'
egressGateway:
  mode: gatewayAPI
  gatewayAPI:
    create: true
    name: agentio-egress
    gatewayClassName: agentio-egress
    listeners:
    - name: mesh
      port: 15008
      protocol: HBONE
EOF

$ helm upgrade agentio manifests/charts/agentio \
    --namespace agentio-system \
    --reuse-values \
    --values /tmp/agentio-gateway-api-values.yaml \
    --wait \
    --timeout 5m
```

Verify the Agentio GatewayClass, Gateway status, and managed workload:

```console
$ kubectl get gatewayclass agentio-egress \
    --output=jsonpath='{.spec.controllerName}{"\n"}' \
  | grep --line-regexp 'agentio.kruise.io/egress-gateway-controller'

$ kubectl wait gateway/agentio-egress --namespace agentio-system --for=condition=Programmed --timeout=2m
$ kubectl rollout status deployment/agentio-egress \
    --namespace agentio-system \
    --timeout=2m

$ kubectl get service/agentio-egress \
    --namespace agentio-system
```

If the GatewayClass check fails because `agentio-egress` already belongs to another controller, resolve that ownership conflict before continuing. Delete the existing GatewayClass only when you have confirmed that no other workloads depend on it; `agentiod` then recreates the class with the expected controller name.

To customize the generated Deployment, Service, ServiceAccount, HPA, or PDB, see [Customize Gateway resources](customize-gateway-resources.md).

## Configure egress routing

Create a values file that routes only `www.example.com` from the selected workload namespace to the gateway. Agentio evaluates egress policies in order, so keep the `PASSTHROUGH` fallback last:

```console
$ cat >/tmp/agentio-egress-routing-values.yaml <<EOF
agentiod:
  config:
    values:
      egressPolicies:
      - namespaces:
        - "${AGENTIO_DEMO_NAMESPACE}"
        matchHosts:
        - www.example.com
        gateway:
          service: agentio-egress.agentio-system.svc.cluster.local
        policy: GATEWAY
      - namespaces:
        - "${AGENTIO_DEMO_NAMESPACE}"
        policy: PASSTHROUGH
EOF
```

Update the release without replacing its other values:

```console
$ helm upgrade agentio ./manifests/charts/agentio \
    --namespace agentio-system \
    --reuse-values \
    --values /tmp/agentio-egress-routing-values.yaml \
    --wait \
    --timeout 5m
```

Confirm that the generated Agentio configuration contains the ordered policies:

```console
$ kubectl get configmap agentio-config \
    --namespace agentio-system \
    --output jsonpath='{.data.config}'
```

`agentio-config` is the Helm-managed base. If `agentio-config-primary` exists, Agentio applies it afterward and its fields take precedence. Inspect both sources before troubleshooting the effective route:

```console
$ kubectl get configmap \
    agentio-config agentio-config-primary \
    --namespace agentio-system \
    --ignore-not-found \
    --output yaml
```

See [Agentio configuration](../reference/agentio-configuration.md) for the complete precedence and merge rules.

## Verify the traffic path

Send a real request through the configured path:

```console
$ kubectl exec "$AGENTIO_WORKLOAD_POD" \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --container "$AGENTIO_WORKLOAD_CONTAINER" -- \
    curl --fail --silent --show-error --head http://www.example.com
```

For HTTP traffic, confirm that the response includes a header added by the Envoy-based gateway:

```console
$ kubectl exec "$AGENTIO_WORKLOAD_POD" \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --container "$AGENTIO_WORKLOAD_CONTAINER" -- \
    curl --fail --silent --show-error --head http://www.example.com \
  | tr -d '\r' \
  | grep --ignore-case '^x-envoy-'
```

Policy and DNS changes can take a few seconds to reach the data plane. Retry the request if the first response does not contain the header.

## Clean up

Skip this section while continuing to [Configure a TrafficPolicy](configure-traffic-policy.md) or [Get started with EPE](../getting-started/epe.md). Both tasks need this gateway and route. Return here after removing the sample policies.

Remove the demo routing policy before you remove its gateway:

```console
$ helm upgrade agentio ./manifests/charts/agentio \
    --namespace agentio-system \
    --reuse-values \
    --set-json 'agentiod.config.values.egressPolicies=[]' \
    --wait \
    --timeout 5m
```

Disable the selected gateway mode. This removes the static workload or the chart-created Gateway:

```console
$ helm upgrade agentio manifests/charts/agentio \
    --namespace agentio-system \
    --reuse-values \
    --set egressGateway.mode=disabled \
    --wait \
    --timeout 5m
```

Do not remove the gateway while workloads still use its route. Existing connections and new requests can fail while the gateway or route is missing.

## See also

- [Getting started](../getting-started.md)
- [Configure a TrafficPolicy](configure-traffic-policy.md)
- [Agentio configuration reference](../reference/agentio-configuration.md)
- [Agentio Helm values](../../manifests/charts/agentio/values.yaml)
- [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/)
