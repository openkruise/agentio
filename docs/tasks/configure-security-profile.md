# Configure a SecurityProfile

This task configures a namespaced `SecurityProfile` for HTTP traffic that already routes through an Agentio egress gateway and the Egress Policy Enforcer (EPE). Use a `SecurityProfile` for policy owned by one namespace. Use a `GlobalSecurityProfile` only when a platform team must apply the same L7 control to selected Pods across namespaces; it is cluster-scoped, shares priority ordering with namespaced profiles, and therefore needs tighter change control.

## Before you begin

Complete [Get started with EPE](../getting-started/epe.md), including the egress-gateway route. EPE does not run for the direct passthrough path.

Set the namespace and calling workload label for the examples:

```console
$ export AGENTIO_PROFILE_NAMESPACE="${AGENTIO_DEMO_NAMESPACE:?Complete an onboarding guide first}"
$ export AGENTIO_PROFILE_WORKLOAD_LABEL="${AGENTIO_WORKLOAD_LABEL:?Set the calling workload label}"
```

Confirm the selected workload exists:

```console
$ kubectl get pods \
    --namespace "$AGENTIO_PROFILE_NAMESPACE" \
    --selector "app=$AGENTIO_PROFILE_WORKLOAD_LABEL"
```

## Select traffic and choose match conditions

`spec.selector` selects calling Pods, not the external service. A namespaced profile can select only Pods in its own namespace; an empty selector selects every Pod in that namespace. Use narrow labels where possible.

Each rule requires `domains`. Add `paths`, `methods`, `ports`, `schemes`, `headers`, or `queryParams` to further restrict it. Fields within one match entry are ANDed. Multiple entries in a rule are ORed. Keep broad rules last when a later terminal rule must take precedence.

## Apply a non-terminal transformation

The following complete manifest stores a demonstration API key and applies a non-terminal token transformation. The transformation replaces the outbound `Authorization` header for matching requests, then lets later rules and the upstream request continue. The Secret must use the `apiKey` data key for the `ApiKey` transformation.

```console
$ kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: epe-demo-api-key
  namespace: ${AGENTIO_PROFILE_NAMESPACE}
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
        apiKey:
          targetHeaders:
            names:
            - Authorization
          value:
            template: 'Bearer {{ .Token }}'
EOF
```

This example intentionally uses a non-production credential. In production, restrict the selector and match conditions, store the Secret in an appropriate namespace, and decide whether the default `failStrategy: Block` is correct for credential lookup and signing failures. `Allow` and `Ignore` permit the request to continue without the transformation, which can disclose the workload's original credentials to the upstream service.

## Grant access to the demonstration Secret

The managed chart grants EPE Secret access only in its installation namespace. For this business-namespace Secret, grant the EPE ServiceAccount `get` on this one name. These commands discover the account used by the standard EPE Deployment; adjust the namespace and Deployment for a customized or manager-integrated installation.

```console
$ export AGENTIO_EPE_NAMESPACE=agentio-system
$ AGENTIO_EPE_SERVICE_ACCOUNT=$(kubectl get deployment agentio-epe \
    --namespace "$AGENTIO_EPE_NAMESPACE" \
    --output jsonpath='{.spec.template.spec.serviceAccountName}')
$ test -n "$AGENTIO_EPE_SERVICE_ACCOUNT"
$ kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: epe-demo-credential-reader
  namespace: ${AGENTIO_PROFILE_NAMESPACE}
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["epe-demo-api-key"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: epe-demo-credential-reader
  namespace: ${AGENTIO_PROFILE_NAMESPACE}
subjects:
- kind: ServiceAccount
  name: ${AGENTIO_EPE_SERVICE_ACCOUNT}
  namespace: ${AGENTIO_EPE_NAMESPACE}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: epe-demo-credential-reader
EOF
```

A forbidden Secret read follows `failStrategy`, which defaults to `Block`. A successful block-rule test below does not exercise this permission or prove the credential transformation works.

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
        value: /security-profile-denied
    actions:
      block:
        statusCode: 403
        body: request blocked by SecurityProfile
EOF
```

Use `bypass: true` instead of `block` only when the request must skip all remaining EPE actions and rules. Bypass preserves mutations from actions that have already run, so it is not a general-purpose allow rule.

## Order profiles and rules deliberately

EPE evaluates lower profile priorities first, then creation time, name, and namespace. It evaluates matching rules in their manifest order, and does not stop at the first broad match. A terminal action stops all later EPE work. Set an explicit `priority` when multiple profiles can select the same workload, especially when a `GlobalSecurityProfile` and a namespaced profile overlap.

Within a rule, current EPE action registration order is `bypass`, `block`, `mcpToolPolicy`, `headerManipulation`, then `tokenTransformation`; YAML key order does not change it. Keep terminal actions in separate rules when you need a transformation to run before a later policy decision.

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
    --container "$AGENTIO_WORKLOAD_CONTAINER" -- \
    curl --silent --show-error --include http://www.example.com/security-profile-denied
```

If the request reaches the upstream service, first verify that the host uses the egress gateway rather than direct passthrough, then check the EPE Deployment logs and the workload's labels. A profile resource appearing in `kubectl get` does not by itself prove that its compiled version is enforcing.

### Verify the credential transformation separately

`www.example.com` is suitable for the local block response above, but it does not echo request headers. To verify the non-terminal transformation, use a test HTTP endpoint you control that reports the received `Authorization` header:

1. Route that endpoint's hostname through the same gateway, preserving your existing egress rules, and allow its destination in any applicable TrafficPolicy.
2. In `inject-epe-demo-api-key`, replace `www.example.com` with that hostname and `/api/` with the endpoint's path prefix. Reapply the manifest.
3. From the selected workload, send a request with `Authorization: Bearer original-demo-value`. Inspect the endpoint's received headers: it must see `Bearer demo-api-key` instead.
4. Temporarily remove only `inject-epe-demo-api-key` and repeat: the endpoint must now see `Bearer original-demo-value`. This control confirms that EPE caused the change. Reapply the profile if continuing.

For an HTTPS endpoint, first complete [Inspect HTTPS traffic](inspect-https-traffic.md). Use only these dummy values in echo output. A 403, an upstream success status, or a profile appearing in `kubectl get` alone is not proof of successful transformation. If the value is unchanged, check routing, TLS termination, selector and path matching; if it is blocked, inspect EPE's profile state and Secret-read errors using [Troubleshoot policy enforcement](troubleshoot-policy-enforcement.md).

## Clean up

If continuing with another policy task, remove these demonstration policies and Secret, but keep EPE, the gateway, and the enrolled workload running.

Remove the demonstration resources:

```console
$ kubectl delete securityprofile inject-epe-demo-api-key block-epe-demo-path \
    --namespace "$AGENTIO_PROFILE_NAMESPACE"

$ kubectl delete secret epe-demo-api-key \
    --namespace "$AGENTIO_PROFILE_NAMESPACE"

$ kubectl delete role,rolebinding epe-demo-credential-reader \
    --namespace "$AGENTIO_PROFILE_NAMESPACE"
```

## See also

- [Egress Policy Enforcer overview](../concepts/epe-overview.md)
- [EPE policy evaluation](../concepts/epe-policy-evaluation.md)
- [SecurityProfile API reference](../reference/security-profile-api.md)
