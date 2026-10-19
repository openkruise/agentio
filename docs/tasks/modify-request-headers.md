# Modify request headers

Use `headerManipulation` to set or remove ordinary outbound request headers. Use [tokenTransformation](transform-outbound-credentials.md) for credentials so their values come from a Secret or credential provider.

## Before you begin

Complete [Get started with EPE](../getting-started/epe.md), retaining the workload, route and EPE. Use a controlled HTTP endpoint that reports received request headers, and route its hostname through the gateway. If it uses HTTPS, first configure [TLS termination and client trust](inspect-https-traffic.md).

Replace `echo.example.com` below with that endpoint's hostname before applying. The onboarding workload variables must remain set.

## Apply the profile

```console
$ kubectl apply --namespace "$AGENTIO_DEMO_NAMESPACE" -f - <<EOF_PROFILE
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: request-header-demo
spec:
  selector:
    matchLabels:
      app: "${AGENTIO_WORKLOAD_LABEL}"
  rules:
  - name: tag-outbound-request
    match:
    - domains: [echo.example.com]
    actions:
      headerManipulation:
        set:
        - name: x-agentio-demo
          value: inspected
        remove:
        - x-agentio-remove-me
EOF_PROFILE
```

The action is non-terminal. EPE runs it after MCP checks and before token transformation within the same rule; a later mutation of the same header wins. Header names are compared case-insensitively. An earlier `block` or `bypass` prevents this action from running.

## Values and templates

Current EPE evaluates `SecurityProfile` and `GlobalSecurityProfile` header values as Go templates. For example, `value: '{{ .Pod.Namespace }}'` uses the caller namespace from the [request context](../reference/epe-request-context.md). Templates see the original request context, not the output of earlier mutations. Invalid templates reject the profile version; request-time render errors fail closed. This action has no configurable fail-open strategy.

The upstream CRD schema currently describes these values as verbatim; that description differs from the EPE implementation. The literal example above works without depending on that distinction. Sandbox inline annotation values are explicitly escaped and remain literal, so do not assume the same template works through that entry point.

## Verify and clean up

Send a request from the selected workload with `X-Agentio-Demo: original` and `X-Agentio-Remove-Me: present`. At the controlled upstream, verify that `x-agentio-demo` is `inspected` and `x-agentio-remove-me` is absent. Check the received request, not just the response status.

Delete the demo profile and repeat the same request: both original headers should arrive unchanged, unless another matching policy modifies them. This control distinguishes the demo from other profiles or upstream behavior.

```console
$ kubectl delete securityprofile request-header-demo --namespace "$AGENTIO_DEMO_NAMESPACE"
```

If the first request is unchanged, use [Troubleshoot policy enforcement](troubleshoot-policy-enforcement.md) to check routing, TLS, selector matching and earlier terminal actions.
