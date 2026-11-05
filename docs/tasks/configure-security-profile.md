# Configure a SecurityProfile

This task configures a namespaced `SecurityProfile` for HTTP traffic that already routes through an Agentio egress gateway and the Egress Policy Enforcer (EPE). Use a `SecurityProfile` for policy owned by one namespace; use a `GlobalSecurityProfile` only when a platform team must apply the same L7 control across namespaces.

## Before you begin

Complete [Get started with EPE](../getting-started/epe.md), including the egress-gateway route. EPE does not run for the direct passthrough path.

Set the namespace and calling workload label for the examples:

```console
$ export AGENTIO_EPE_NAMESPACE=agentio-system
$ export AGENTIO_PROFILE_NAMESPACE=agentio-demo
$ export AGENTIO_PROFILE_WORKLOAD_LABEL=curl
```

Confirm the selected workload exists:

```console
$ kubectl get pods \
    --namespace "$AGENTIO_PROFILE_NAMESPACE" \
    --selector "app=$AGENTIO_PROFILE_WORKLOAD_LABEL"
```

## Select traffic and choose match conditions

`spec.selector` selects calling Pods, not the external service. A namespaced profile can select only Pods in its own namespace; an empty selector selects every Pod in that namespace. Use narrow labels where possible.

Each rule requires `domains`; add `paths`, `methods`, `ports`, `schemes`, `headers`, or `queryParams` to further restrict it. Match semantics are documented in the [SecurityProfile reference](../reference/security-profile.md#rule-structure-and-matching).

A terminal action stops all later EPE processing and returns a response. A non-terminal action applies its mutation and lets the request continue.

## Apply a non-terminal transformation

The following manifest stores a demonstration API key and applies a non-terminal token transformation. The transformation replaces the outbound `Authorization` header for matching requests, then lets later rules and the upstream request continue. The Secret must be in the EPE system namespace (`AGENTIO_EPE_NAMESPACE`) and use the `apiKey` data key.

```console
$ kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: epe-demo-api-key
  namespace: ${AGENTIO_EPE_NAMESPACE}
type: Opaque
stringData:
  apiKey: demo-api-key
---
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: inject-epe-demo-api-key
  namespace: ${AGENTIO_PROFILE_NAMESPACE}
spec:
  selector:
    matchLabels:
      app: ${AGENTIO_PROFILE_WORKLOAD_LABEL}
  rules:
  - name: inject-api-key-for-example
    match:
    - domains:
      - www.example.com
      paths:
      - type: Prefix
        value: /api/
    actions:
      tokenTransformation:
        credentialRef:
          secret:
            name: epe-demo-api-key
            namespace: ${AGENTIO_EPE_NAMESPACE}
        apiKey:
          targetHeaders:
            names:
            - Authorization
          value:
            template: 'Bearer {{ .Token }}'
EOF
```

This example uses a non-production credential. In production, restrict the selector and match conditions and choose `failStrategy` deliberately: `Allow` and `Ignore` forward the request without the transformation, which can disclose the workload's original credentials to the upstream.

## Add a terminal rule

Apply a separate terminal rule to block a path. A block returns the configured response without forwarding upstream:

```console
$ kubectl apply -f - <<EOF
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: block-epe-demo-path
  namespace: ${AGENTIO_PROFILE_NAMESPACE}
spec:
  selector:
    matchLabels:
      app: ${AGENTIO_PROFILE_WORKLOAD_LABEL}
  rules:
  - name: block-sensitive-path
    match:
    - domains:
      - www.example.com
      paths:
      - type: Exact
        value: /epe-denied
    actions:
      block:
        statusCode: 403
        body: request blocked by SecurityProfile
EOF
```

Use `bypass: true` instead of `block` only when the request must skip all remaining EPE actions and rules. Bypass preserves mutations from actions that have already run, so it is not a general-purpose allow rule.

## Order profiles and rules deliberately

EPE evaluates lower profile priorities first, then creation time, name, and namespace. It evaluates matching rules in their manifest order, and does not stop at the first broad match. A terminal action stops all later EPE work. Set an explicit `priority` when multiple profiles can select the same workload, especially when a `GlobalSecurityProfile` and a namespaced profile overlap.

Keep terminal actions in separate rules when you need a transformation to run before a later policy decision.

## Verify the profile

Check that Kubernetes accepted both profiles:

```console
$ kubectl get securityprofiles \
    --namespace "$AGENTIO_PROFILE_NAMESPACE"
```

Then verify the terminal decision with a gateway-routed request from the selected workload. The command must return a `403` and the configured response body:

```console
$ AGENTIO_PROFILE_POD=$(kubectl get pod \
    --namespace "$AGENTIO_PROFILE_NAMESPACE" \
    --selector "app=$AGENTIO_PROFILE_WORKLOAD_LABEL" \
    --output jsonpath='{.items[0].metadata.name}')

$ kubectl exec "$AGENTIO_PROFILE_POD" \
    --namespace "$AGENTIO_PROFILE_NAMESPACE" \
    --container curl -- \
    curl --silent --show-error --include http://www.example.com/epe-denied
```

If the request reaches the upstream service, first verify that the host uses the egress gateway rather than direct passthrough, then check the EPE Deployment logs and the workload's labels. A profile resource appearing in `kubectl get` does not by itself prove that its compiled version is enforcing.

## Clean up

Remove the demonstration resources:

```console
$ kubectl delete securityprofile inject-epe-demo-api-key block-epe-demo-path \
    --namespace "$AGENTIO_PROFILE_NAMESPACE"

$ kubectl delete secret epe-demo-api-key \
    --namespace "$AGENTIO_EPE_NAMESPACE"
```

## See also

- [Egress Policy Enforcer overview](../concepts/epe-overview.md)
- [EPE policy evaluation](../concepts/epe-policy-evaluation.md)
- [SecurityProfile API reference](../reference/security-profile-api.md)
