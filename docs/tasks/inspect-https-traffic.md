# Inspect HTTPS traffic

Use this task when a SecurityProfile must inspect an HTTPS path, header, credential, or MCP request. Routing a connection through the gateway is only the first step: TLS passthrough does not invoke EPE's HTTP filters.

## Before you begin

Complete [Get started with EPE](../getting-started/epe.md) and retain its gateway, route, and enrolled workload. This task uses `www.example.com` and the workload variables from onboarding. If a TrafficPolicy limits destinations, allow this host on TCP port 443 as well as any DNS access your workload needs.

These instructions describe the Agentio Envoy egress gateway. The separate [agentgateway deployment](deploy-agentgateway.md) uses its own native configuration.

## Choose the TLS decision mode

| Gateway mode | What selects termination | What bypasses termination |
| --- | --- | --- |
| `agentiod.enableSNITrafficPolicy: false` (default) | Gateway `tlsTermination.includeHosts` | Unmatched hosts and `excludeHosts` |
| `agentiod.enableSNITrafficPolicy: true` | The policy-derived TLS action | A passthrough action and gateway `excludeHosts` |

Gateway exclusions take precedence in both modes. An excluded host cannot be inspected by adding another HTTP rule. In policy mode, `includeHosts` is not the termination selector.

For a first inspection test, use the default static mode. Merge this fragment into the values file for your existing standalone release:

```yaml
agentiod:
  enableSNITrafficPolicy: false
  injector:
    clientTrust:
      enabled: true
  config:
    values:
      egressGateways:
      - name: agentio-egress
        namespace: agentio-system
        tlsTermination:
          includeHosts:
          - www.example.com
```

`egressGateways` is a replacement list: retain every existing gateway entry and its other settings. The gateway name must match its ServiceAccount. A primary ConfigMap can override this entire list; inspect it as described in [Agentio configuration](../reference/agentio-configuration.md#configuration-sources-and-precedence).

Apply the merged values with `helm upgrade` to the same release used for onboarding, preserving its other settings. The manager integration instead uses the `agentio.*` wrapper in its manager release and does not provide standalone application client-trust injection.

## Configure signing and client trust

The gateway presents a certificate signed by Agentio's MITM CA. The default `SELF_SIGN` mode maintains this CA in a Secret. For an operator-managed CA, configure `agentiod.mitm.signMode: SECRET` with its Secret namespace and name; the Secret must contain `ca.crt` and `ca.key`.

The caller must trust that CA. The sidecar client-trust setting above enables bundle distribution and injection into newly created supported workloads. Recreate the sample Pod after enabling it, refresh the Pod name, and verify the injected bundle and client environment using [Configure client CA trust](configure-client-ca-trust.md). Existing Pods do not acquire the injected mounts and environment through a gateway update. Ambient workloads and the manager's Sandbox runtime need their own application trust configuration.

Do not use `curl -k` for this verification: the test should prove both inspection and trusted certificate validation.

## Verify request-level enforcement

Apply a profile with a response that cannot come from the upstream service:

```console
$ kubectl apply --namespace "$AGENTIO_DEMO_NAMESPACE" -f - <<EOF_PROFILE
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: https-inspection-demo
spec:
  selector:
    matchLabels:
      app: "${AGENTIO_WORKLOAD_LABEL}"
  rules:
  - name: block-test-path
    match:
    - domains: [www.example.com]
      schemes: [https]
      paths:
      - type: Exact
        value: /agentio-https-denied
    actions:
      block:
        statusCode: 403
        body: blocked by HTTPS inspection demo
EOF_PROFILE

$ AGENTIO_HTTPS_POD=$(kubectl get pod --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --selector "app=$AGENTIO_WORKLOAD_LABEL" --output jsonpath='{.items[0].metadata.name}')
$ test -n "$AGENTIO_HTTPS_POD"
$ kubectl exec "$AGENTIO_HTTPS_POD" --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --container "$AGENTIO_WORKLOAD_CONTAINER" -- \
    curl --silent --show-error --include https://www.example.com/agentio-https-denied
```

Expect HTTP 403 and `blocked by HTTPS inspection demo`, with no certificate-validation error. Delete only this profile and repeat: the custom body must disappear. A 403 alone is insufficient evidence because another policy or the upstream could return it.

If TLS validation fails, inspect client trust and the signing CA. If the request reaches the upstream, inspect the effective gateway mode, route, exclusions, and profile selection using [Troubleshoot policy enforcement](troubleshoot-policy-enforcement.md).

## Using policy-derived termination

In SNI policy mode, Agentiod projects HTTPS-capable SecurityProfile matches into SNI rules. A match with omitted `schemes` or with `https` contributes its domains; an HTTP-only match does not. Paths and headers cannot be evaluated before TLS termination, so a path-specific rule can still cause all HTTPS connections to its domain to be terminated before EPE evaluates the complete request.

On the native Envoy gateway, Porter resolves the source identity and policies, and the listener module evaluates the actual ClientHello SNI. A valid empty policy selects passthrough; missing or malformed policy denies detected TLS. The legacy gateway also supports TLS action headers and its policy fallback. See [Traffic processing and capability boundaries](../concepts/traffic-processing.md) before changing modes on an existing deployment. Preserve gateway exclusions and validate a real request after the change.

## Clean up

```console
$ kubectl delete securityprofile https-inspection-demo --namespace "$AGENTIO_DEMO_NAMESPACE"
```

If you already deleted the profile for the control request, skip this command. Keep TLS termination and trust while other HTTPS policy tasks depend on them; otherwise restore the gateway and client-trust settings you recorded before the task.
