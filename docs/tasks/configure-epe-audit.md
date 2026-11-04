# Configure EPE audit events

The Egress Policy Enforcer (EPE) can emit an asynchronous audit webhook after a matched `SecurityProfile` rule reaches its final outcome. Audit delivery never changes the request result.

## Before you begin

This task assumes that EPE is enabled, the selected workload reaches an EPE-enabled egress gateway, and an audit receiver is reachable from the `agentio-epe` Pod. Complete [Get started with EPE](../getting-started/epe.md) and keep the workload namespace and Pod available:

```console
$ : "${AGENTIO_DEMO_NAMESPACE:?Set the namespace containing the selected workload}"
$ : "${AGENTIO_WORKLOAD_POD:?Set the selected workload Pod name}"
$ : "${AGENTIO_WORKLOAD_CONTAINER:?Set the workload container name}"
```

The example below matches `https://api.example.com`. Configure the selected gateway to terminate TLS for `api.example.com`, configure the MITM signing CA, and make the workload trust that CA before testing. Otherwise HTTPS stays on the gateway's TCP path and bypasses EPE's HTTP filter chain. See [TLS termination for HTTPS inspection](../reference/agentio-configuration.md#tls-termination-for-https-inspection).

Audit is part of `SecurityProfile` and `GlobalSecurityProfile`, not `TrafficPolicy`.

## Add an audit action

An audit list at `spec.audit` is inherited by matched rules. A non-empty `rules[].actions.audit` list replaces that inherited list for that rule. Each entry has a name, a webhook, and an optional CEL `when` condition; an omitted `when` always fires.

Apply the following complete namespaced profile. Replace the receiver URL and the selector before using it in a shared cluster. Its rule blocks `GET https://api.example.com/admin`, and its audit action sends an event only when the final result is `blocked`.

```console
$ kubectl apply --namespace "$AGENTIO_DEMO_NAMESPACE" -f - <<'EOF'
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: audit-blocked-admin
spec:
  selector:
    matchLabels:
      app: agent-demo
  audit:
  - name: blocked-request
    when: result == "blocked"
    webhook:
      url: "https://audit-receiver.example.com/v1/events"
      timeout: 2s
      request:
        method: POST
        headers:
        - name: X-Agentio-Audit-Type
          value: "blocked-request"
        body:
          json:
            result: "{{ .Result }}"
            profile: "{{ .Profile.Name }}"
            namespace: "{{ .Profile.Namespace }}"
            rule: "{{ .Rule.Name }}"
            host: "{{ .Request.Host }}"
            path: "{{ .Request.Path }}"
            method: "{{ .Request.Method }}"
            status: "{{ .Response.Status }}"
  rules:
  - name: deny-admin
    match:
    - domains:
      - api.example.com
      methods:
      - GET
      paths:
      - type: Exact
        value: /admin
    actions:
      block:
        statusCode: 403
        body: request blocked by policy
EOF
```

The webhook URL must render to an absolute `http` or `https` URL. Timeout defaults to `2s` (bounded to `500ms`–`30s`); the request method defaults to `POST` (`POST`, `PUT`, or `PATCH`).

`when` is a CEL expression over the request, Pod, profile, rule, and result. It must compile to a boolean; a compile error prevents that profile version from loading, and a runtime error drops only that event. See [EPE audit delivery and evaluation](../design/epe-audit-delivery.md) for the full variable reference.

## Verify audit output

Confirm that the profile was accepted and that EPE has loaded it. The admin endpoint is loopback-only in the Pod, so port-forward it:

```console
$ EPE_POD=$(kubectl get pod --namespace agentio-system \
    --selector app.kubernetes.io/name=agentio-epe \
    --output jsonpath='{.items[0].metadata.name}')
$ test -n "$EPE_POD"
$ kubectl port-forward --namespace agentio-system "$EPE_POD" 15000:15000
```

In another terminal, inspect the compiled profile identity:

```console
$ curl --fail --silent http://127.0.0.1:15000/debug/profiles?namespace="$AGENTIO_DEMO_NAMESPACE"
```

Trigger the matching request through the workload and expect a non-zero `curl` exit from the policy's 403 response:

```console
$ kubectl exec "$AGENTIO_WORKLOAD_POD" \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --container "$AGENTIO_WORKLOAD_CONTAINER" -- \
    curl --fail --silent --show-error https://api.example.com/admin
```

Port-forward the metrics endpoint, then check the receiver result counter and the access log stream:

```console
$ kubectl port-forward --namespace agentio-system "$EPE_POD" 9090:9090
```

```console
$ curl --fail --silent http://127.0.0.1:9090/metrics \
  | grep '^epe_audit_webhook_dispatched_total'

$ kubectl logs --namespace agentio-system "$EPE_POD" \
  | grep 'egress request handled'
```

## Clean up

```console
$ kubectl delete securityprofile audit-blocked-admin \
    --namespace "$AGENTIO_DEMO_NAMESPACE"
```

## See also

- [EPE audit delivery and evaluation](../design/epe-audit-delivery.md)
- [EPE observability](../reference/epe-observability.md)
- [EPE configuration](../reference/epe-configuration.md)
- [EPE admin API](../reference/epe-admin-api.md)
