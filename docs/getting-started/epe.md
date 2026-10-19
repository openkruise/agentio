# Get started with EPE

This guide enables the Egress Policy Enforcer (EPE), applies a minimal `SecurityProfile`, and verifies that EPE blocks a gateway-routed request. The commands use the standalone chart release from the sidecar or ambient onboarding guide. For the manager-integrated release, use the [OpenKruise installation path](../integrations/openkruise-agents.md#choose-an-installation-path) and its release namespace and `agentio.*` values.

## Before you begin

You need:

- A Kubernetes cluster that you can administer.
- `kubectl` configured for that cluster.
- Helm 3 and a local clone of this repository.
- An enrolled workload and an Agentio egress route that sends `www.example.com` through an egress gateway.

Complete one onboarding guide, then [route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md). The onboarding guide exports `AGENTIO_DEMO_NAMESPACE`, `AGENTIO_WORKLOAD_LABEL`, and `AGENTIO_WORKLOAD_CONTAINER`, which the egress-route task consumes. Do not use the direct passthrough path for this verification: EPE is invoked only on the gateway-routed path.

This example tests plaintext HTTP. HTTPS additionally needs gateway TLS termination and client CA trust; see [Inspect HTTPS traffic](../tasks/inspect-https-traffic.md). Keep the gateway and route from the preceding task.

Confirm the sample workload is ready and record its Pod name:

```console
$ kubectl wait pod \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --selector "app=$AGENTIO_WORKLOAD_LABEL" \
    --for=condition=Ready \
    --timeout=2m

$ AGENTIO_EPE_DEMO_POD=$(kubectl get pod \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --selector "app=$AGENTIO_WORKLOAD_LABEL" \
    --output jsonpath='{.items[0].metadata.name}')
$ test -n "$AGENTIO_EPE_DEMO_POD"
```

## Enable EPE

`epe.mode: managed` renders EPE and wires its Service into the Agentio configuration. Update the existing Agentio release while preserving the egress-gateway and route values you configured earlier:

```console
$ helm upgrade --install agentio ./manifests/charts/agentio \
    --namespace agentio-system \
    --create-namespace \
    --reuse-values \
    --set epe.mode=managed \
    --wait \
    --timeout 5m
```

By default, this renders the `agentio-epe` Deployment and headless Service in `agentio-system`. The Service exposes the `extproc` port `9002`, health port `9003`, and metrics port `9090`; Agentio configures gateway Envoy to call `agentio-epe.agentio-system.svc.cluster.local:9002`.

## Verify the EPE workload and Service

Wait for the Deployment and inspect the Service ports:

```console
$ kubectl rollout status deployment/agentio-epe \
    --namespace agentio-system \
    --timeout=5m

$ kubectl get service/agentio-epe \
    --namespace agentio-system \
    --output wide
```

Confirm that the Helm-managed configuration contains the ext_proc service endpoint:

```console
$ kubectl get configmap agentio-config \
    --namespace agentio-system \
    --output jsonpath='{.data.config}'
```

The output includes `sandboxExtProc` with the EPE Service address and port. It is control-plane configuration; the traffic test below is the enforcement check.

## Apply a minimal profile

Apply this complete namespaced `SecurityProfile`. It selects the curl sample and blocks only the `/epe-denied` path at the already gateway-routed host:

```console
$ kubectl apply --namespace "$AGENTIO_DEMO_NAMESPACE" -f - <<EOF
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: block-epe-demo
spec:
  selector:
    matchLabels:
      app: "${AGENTIO_WORKLOAD_LABEL}"
  rules:
  - name: block-epe-denied-path
    match:
    - domains:
      - www.example.com
      paths:
      - type: Exact
        value: /epe-denied
    actions:
      block:
        statusCode: 403
        body: blocked by the EPE demo profile
EOF
```

## Send a request and verify the decision

The request should receive EPE's configured `403` response before it reaches the external service:

```console
$ kubectl exec "$AGENTIO_EPE_DEMO_POD" \
    --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --container "$AGENTIO_WORKLOAD_CONTAINER" -- \
    curl --silent --show-error --include http://www.example.com/epe-denied
HTTP/1.1 403 Forbidden

blocked by the EPE demo profile
```

Policy propagation can take a few seconds. Retry the request before investigating an unexpected response. A `404` or a successful upstream response instead of the configured `403` usually means that the host is not using the egress-gateway route, EPE is not ready, or the profile selector does not match the calling Pod.

## Clean up

If continuing to [Configure a SecurityProfile](../tasks/configure-security-profile.md), delete only the demo profile below. Keep EPE, the gateway route, and the workload running; skip the EPE-disable command until all policy tasks are finished.

Delete the profile:

```console
$ kubectl delete securityprofile block-epe-demo \
    --namespace "$AGENTIO_DEMO_NAMESPACE"
```

To disable EPE after removing profiles that require it, update the release:

```console
$ helm upgrade agentio ./manifests/charts/agentio \
    --namespace agentio-system \
    --reuse-values \
    --set epe.mode=disabled \
    --wait \
    --timeout 5m
```

Do not disable EPE while egress routes still depend on its policy decisions; gateway requests that need EPE can fail or lose enforcement during the change.

## See also

- [Egress Policy Enforcer overview](../concepts/epe-overview.md)
- [EPE policy evaluation](../concepts/epe-policy-evaluation.md)
- [Configure a SecurityProfile](../tasks/configure-security-profile.md)
- [Agentio Helm values](../../manifests/charts/agentio/values.yaml)
