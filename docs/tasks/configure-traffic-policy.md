# Configure a TrafficPolicy

This task applies a namespaced `TrafficPolicy` to an enrolled workload. The policy allows DNS and `www.example.com`, while rejecting unmatched outbound destinations.

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

Scope exception: an empty selector on a `TrafficPolicy` in the mesh root namespace (normally `agentio-system`) creates a mesh-wide baseline. Outside that namespace it selects only local Pods. Use the workload namespace and an explicit label selector for this example; use `GlobalTrafficPolicy` when you want an explicitly cluster-scoped API.

Every egress rule must declare `to`, and every ingress rule must declare `from`, including rules that only restrict ports or protocols. For an IPv4 rule covering all peers, use `cidr: 0.0.0.0/0`; use `::/0` for IPv6. Rules without the direction's peer field are skipped by the compiler and do not establish a default deny. Routing uses `GATEWAY` or `PASSTHROUGH`; express rejection with TrafficPolicy `action: reject`.

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

## FQDN resolution failures

Agentiod resolves A and AAAA independently. A successful answer is available even while the other query is pending or failing. Each address family's cached answer expires according to its own TTL; a failed refresh does not extend that lifetime. A successful empty answer (NODATA) clears that family's old addresses. NXDOMAIN is recorded separately from NODATA. Neither is treated as a temporary DNS failure.

Temporary failures are retried and logged with the hostname and query type. The `dns-results` diagnostic collection also records per-family errors. Until its TTL expires, the last successful answer for a failing family remains usable. Expired addresses are withdrawn even if a refresh is still queued or in progress; they are not retained indefinitely.

Both `allow` and `reject` FQDN rules use only the remaining valid addresses. A failure does not broaden a `reject` rule to an entire address family. Consequently, if other rules allow the traffic, unknown or expired destination addresses may no longer be blocked by that FQDN reject rule. Use explicit CIDR rules when that DNS-dependent protection gap is unacceptable.

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
