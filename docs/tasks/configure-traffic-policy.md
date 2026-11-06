# Configure a TrafficPolicy

This task applies a namespaced `TrafficPolicy` to an enrolled workload. The policy allows DNS and `www.example.com` and rejects unmatched outbound destinations.

## Before you begin

Complete one onboarding path from [Getting started](../getting-started.md), then complete [Route traffic through an egress gateway](route-traffic-through-egress-gateway.md).

The selected onboarding guide exports these variables:

| Variable | Purpose |
| --- | --- |
| `AGENTIO_DEMO_NAMESPACE` | Namespace containing the workload and policy |
| `AGENTIO_WORKLOAD_LABEL` | Value of the workload Pod's `app` label and the policy selector |
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

Confirm that the selected Pod has the label used by the policy:

```console
$ kubectl get pod "$AGENTIO_WORKLOAD_POD" \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --show-labels
```

## Verify baseline traffic

Before you apply the policy, verify that the workload can reach the gateway-routed destination and an unmatched control destination:

```console
$ kubectl exec "$AGENTIO_WORKLOAD_POD" \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --container "$AGENTIO_WORKLOAD_CONTAINER" -- \
    curl --fail --silent --show-error --head http://www.example.com

$ kubectl exec "$AGENTIO_WORKLOAD_POD" \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --container "$AGENTIO_WORKLOAD_CONTAINER" -- \
    curl --fail --silent --show-error --head http://www.iana.org
```

## Apply the policy

Every egress rule must declare `to`, and every ingress rule must declare `from`, including rules that only restrict ports or protocols. For an IPv4 rule covering all peers, use `cidr: 0.0.0.0/0`; use `::/0` for IPv6. Routing uses `GATEWAY` or `PASSTHROUGH`; express rejection with `action: reject`.

Egress FQDN peers are published with both their names and resolved IPs. Compatible
ztunnel and native Envoy gateways can also match names learned through the local
DNS proxy; see [DNS candidates and FQDN traffic rules](../reference/dns-candidates.md)
for opt-in configuration and deployment ordering.

Create a `TrafficPolicy` in the workload namespace. The unquoted heredoc substitutes the selected app label into the manifest:

```console
$ kubectl apply --namespace "$AGENTIO_DEMO_NAMESPACE" -f - <<EOF
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: agentio-sample-egress
spec:
  selector:
    matchLabels:
      app: "${AGENTIO_WORKLOAD_LABEL}"
  egress:
    rules:
    - action: allow
      to:
      - service:
          name: kube-dns
          namespace: kube-system
    - action: allow
      to:
      - fqdn: www.example.com
EOF
```

The selector limits this policy to Pods with the selected `app` label. The DNS rule lets the workload resolve hostnames, and the FQDN rule lets it reach the gateway-routed destination. Unmatched outbound traffic is rejected.

Verify that Kubernetes accepted the resource:

```console
$ kubectl get trafficpolicy agentio-sample-egress \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --output yaml
```

The resource status is not a reliable indication that the data plane has applied the policy. Verify the policy with real traffic instead.

FQDN rules resolve hostnames at the control plane. If an address family has no valid cached answer, it is not used by `allow` or `reject` rules; use explicit CIDR rules when that gap is unacceptable. See [FQDN resolution and DNS cache behavior](../design/fqdn-resolution-and-cache.md).

## Verify the policy

The routed destination remains available:

```console
$ kubectl exec "$AGENTIO_WORKLOAD_POD" \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --container "$AGENTIO_WORKLOAD_CONTAINER" -- \
    curl --fail --silent --show-error --head http://www.example.com
```

The unmatched control destination is rejected. The following command must return a non-zero exit code:

```console
$ kubectl exec "$AGENTIO_WORKLOAD_POD" \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --container "$AGENTIO_WORKLOAD_CONTAINER" -- \
    curl --fail --silent --show-error --head http://www.iana.org
```

Policy changes can take a few seconds to reach the data plane. Retry both requests before you diagnose an unexpected result.

## Clean up

Delete the policy:

```console
$ kubectl delete trafficpolicy agentio-sample-egress \
    --namespace "$AGENTIO_DEMO_NAMESPACE"
```

After the deletion reaches the data plane, the control destination becomes available again:

```console
$ kubectl exec "$AGENTIO_WORKLOAD_POD" \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --container "$AGENTIO_WORKLOAD_CONTAINER" -- \
    curl --fail --silent --show-error --head http://www.iana.org
```

## See also

- [Getting started](../getting-started.md)
- [Route traffic through an egress gateway](route-traffic-through-egress-gateway.md)
- [`TrafficPolicy` API reference](../reference/traffic-policy-api.md)
