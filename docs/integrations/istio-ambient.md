# Integrate with Istio ambient

Use an Agentio waypoint to apply TrafficPolicy and SecurityProfile to traffic from an existing Istio ambient workload. Istio provides traffic capture, ztunnel, and workload certificates. Agentiod configures the gateway, Porter evaluates connection policy, and EPE evaluates HTTP request policy. Agentio can also inject client CA trust without injecting its own sidecar, allowing HTTPS inspection through the same waypoint.

```text
curl -> Istio ztunnel -> HBONE/mTLS -> Agentio waypoint -> HTTP origin
                                      Porter + EPE
```

The [example manifests](../../manifests/examples/istio-ambient/README.md) deploy a curl client and a small HTTP origin, bind the origin Service to an Agentio waypoint, and block one HTTP path. An optional HTTPS example routes `httpbin.org` through the waypoint and demonstrates MITM with CA-only injection. Run the commands from the repository root.

## Prerequisites

- A working Istio ambient installation, including Istio CNI, ztunnel, and Gateway API CRDs.
- A Kubernetes version supported by your Istio release, with native sidecars enabled (stable in Kubernetes 1.33 and later), Helm 3.10 or later, and `kubectl`.
- Matching Agentio charts and images with independent CA token support, Gateway address publication, the physical-peer workload identity fallback, and ambient CA-only admission support. Use a release or CI commit tag containing all those features; older images do not serve the CA-only admission endpoint.
- Direct connectivity from ztunnel to the gateway that preserves the source Pod IP.

This uses Agentiod's `agentio-egress` GatewayClass. It is separate from Istio's `istio-waypoint` and `istio-agentgateway-waypoint` implementations.

## Install Agentiod and EPE

Set the cluster ID, trust domain, and DNS domain to the values used by your Istio installation:

```sh
export ISTIO_CLUSTER_ID=Kubernetes
export ISTIO_TRUST_DOMAIN=cluster.local
export CLUSTER_DOMAIN=cluster.local
export AGENTIO_IMAGE_TAG=latest
export AGENTIO_ISTIO_OUTPUT=$(mktemp -d)

kubectl apply -f manifests/examples/istio-ambient/namespaces.yaml
kubectl apply --server-side -f manifests/charts/agentio/crds/
```

Reuse existing Agentio policy CRDs if they are already installed. If an Agentio control plane already manages this cluster, configure it for this integration instead of installing another GatewayClass controller.

Install with the predefined [Istio integration values](../../manifests/examples/istio-ambient/agentio-values.yaml). They keep `profile: ambient`, disable Agentio CNI and node ztunnel, enable the Gateway controller and managed EPE, and enable CA-only admission. Istio continues to capture traffic.

```sh
helm upgrade --install agentio manifests/charts/agentio \
  --namespace agentio-istio-system \
  --values manifests/examples/istio-ambient/agentio-values.yaml \
  --set-string global.clusterId="$ISTIO_CLUSTER_ID" \
  --set-string global.trustDomain="$ISTIO_TRUST_DOMAIN" \
  --set-string global.clusterDomain="$CLUSTER_DOMAIN" \
  --set-string global.tag="$AGENTIO_IMAGE_TAG" \
  --atomic --wait --timeout 5m
```

Keep the same values file for upgrades. Helm owns the control-plane resources, including policy validation and CA admission webhooks. The application namespace retains Istio's `istio.io/dataplane-mode: ambient` label and sets `agentio.kruise.io/dataplane-mode: none`; CA injection does not change either label. Use a pinned image tag instead of `latest` for repeatable deployments.

## Connect the waypoint to Istiod

Before applying `manifests/examples/istio-ambient/waypoint.yaml`, check its parameters ConfigMap:

- The CA endpoint defaults to `istiod.istio-system.svc:15012`. For a revisioned installation, update `CA_ADDR` and `AGENTIO_CA_SERVER_NAME`. The TLS server name must match the Istiod serving certificate.
- The projected CA token audience defaults to `istio-ca`. Adjust it if your Istio installation accepts another audience.

Copy the public Istio CA bundle into the Agentio namespace. Adjust the source ConfigMap name if your distribution publishes the mesh trust bundle elsewhere:

```sh
export ISTIO_ROOT_NAMESPACE=istio-system
export ISTIO_ROOT_CONFIGMAP=istio-ca-root-cert

kubectl get configmap "$ISTIO_ROOT_CONFIGMAP" -n "$ISTIO_ROOT_NAMESPACE" \
  -o jsonpath='{.data.root-cert\.pem}' \
  > "$AGENTIO_ISTIO_OUTPUT/root-cert.pem"
test -s "$AGENTIO_ISTIO_OUTPUT/root-cert.pem"

kubectl create configmap agentio-istio-root -n agentio-istio-system \
  --from-file=root-cert.pem="$AGENTIO_ISTIO_OUTPUT/root-cert.pem" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f manifests/examples/istio-ambient/waypoint.yaml
kubectl wait gateways.gateway.networking.k8s.io/agentio-egress \
  -n agentio-istio-system --for=condition=Programmed --timeout=5m
kubectl rollout status deployment/agentio-egress -n agentio-istio-system --timeout=5m
```

Keep the copied CA bundle synchronized with Istio's trust bundle when roots rotate.

The gateway uses separate CA and configuration credentials:

| Setting | Purpose |
| --- | --- |
| `CA_ADDR`, `AGENTIO_CA_SERVER_NAME` | Istiod CA endpoint and TLS server name |
| `AGENTIO_CA_ROOT_CA` | Trust bundle for the connection to Istiod |
| `AGENTIO_CA_TOKEN_FILE` | Projected gateway ServiceAccount token with audience `istio-ca` |
| `AGENTIO_ROOT_CA` | Istio mesh roots for verifying incoming HBONE peers |
| `AGENTIO_XDS_ROOT_CA` | Agentiod roots for gateway ADS; the existing `agentio-ca` audience token remains unchanged |

With the default trust domain, Istiod issues the gateway identity `spiffe://cluster.local/ns/agentio-istio-system/sa/agentio-egress`.

The Gateway publishes a Service hostname using `networking.istio.io/address-type: Hostname` and permits waypoint attachment from `agentio-istio-demo` through `allowedRoutes`.

## Deploy the application and bind its Service

The client namespace has `istio.io/dataplane-mode: ambient`. If your Istio revision requires an `istio.io/rev` namespace label, set it on `agentio-istio-demo` before creating the application Pods below. The origin Pod opts out of capture, so it acts as an ordinary HTTP server behind the gateway. All example Pods disable Istio sidecar injection. The curl Pod opts into Agentio CA-only injection with `client-trust.agentio.kruise.io/inject: "true"`.

```sh
kubectl apply -f manifests/examples/istio-ambient/workloads.yaml
kubectl rollout status deployment/curl -n agentio-istio-demo --timeout=3m
kubectl rollout status deployment/origin -n agentio-istio-demo --timeout=3m
kubectl apply -f manifests/examples/istio-ambient/service.yaml
```

The origin Service selects the Agentio gateway through these labels:

```yaml
istio.io/use-waypoint: agentio-egress
istio.io/use-waypoint-namespace: agentio-istio-system
```

These labels select a waypoint for traffic **to the Service**. They do not configure a source-wide outbound route. See [Istio waypoint configuration](https://istio.io/latest/docs/ambient/usage/waypoint/) for namespace inheritance and cross-namespace attachment.

## Apply policy and send requests

The [policy manifest](../../manifests/examples/istio-ambient/policies.yaml) selects only the curl workload:

- `TrafficPolicy` allows TCP port `18082` to the origin Service and port `443` to `httpbin.org` for the optional HTTPS example. Porter enforces it when a new connection reaches the gateway; the waypoint manifest enables this with `ENABLE_TRAFFIC_POLICY=true`.
- `SecurityProfile` blocks HTTP path `/deny` with status `403`. EPE applies this request-level rule after the connection is allowed.

```sh
kubectl apply -f manifests/examples/istio-ambient/policies.yaml
export ORIGIN_URL="http://origin.agentio-istio-demo.svc.$CLUSTER_DOMAIN:18082"

kubectl exec deployment/curl -n agentio-istio-demo -c curl -- \
  curl --fail --silent --show-error "$ORIGIN_URL/"
```

The allowed request returns `200` with `hello from origin`. Then request the blocked path:

```sh
kubectl exec deployment/curl -n agentio-istio-demo -c curl -- \
  curl --silent --show-error --include "$ORIGIN_URL/deny"
```

Expected response:

```http
HTTP/1.1 403 Forbidden

blocked by Agentio EPE
```

Policy discovery is asynchronous. If an initial request arrives before policy convergence, retry after checking component readiness. Verify gateway traversal and source selection in its access log:

```sh
kubectl logs deployment/agentio-egress -n agentio-istio-system \
  -c agentio-proxy --tail=20
```

The log should identify a `curl-...` workload in `agentio-istio-demo` and show the `200` and `403` responses. Ordinary Istio workload certificates are supported through the TLS-verified peer principal and source Pod IP lookup; this setup requires no special Porter command-line mode.

## Inspect HTTPS with CA-only injection

CA trust and traffic capture are independent. The preset enables `agentiod.injector.clientTrust.enabled`, and the curl Deployment selects CA injection with this Pod label:

```yaml
spec:
  template:
    metadata:
      labels:
        client-trust.agentio.kruise.io/inject: "true"
```

For your own workloads, set the same label on a Namespace to enable CA injection by default, or on a Pod template to override the Namespace. `"false"` opts out. Recreate existing Pods after changing labels. The preset excludes `istio-proxy` from CA changes; applications keep their existing Istio sidecar or ambient enrollment.

Agentio mounts the public + MITM CA bundle from `agentio-client-ca` and sets `AGENTIO_TRUST_BUNDLE`, `CURL_CA_BUNDLE`, and the other configured client trust variables. In this ambient preset, admission does not add Agentio proxy/init containers or rewrite probes, even if a Pod also carries an Agentio sidecar label. Inspect the curl workload before enabling HTTPS interception:

```sh
kubectl get configmap agentio-client-ca -n agentio-istio-demo
kubectl exec deployment/curl -n agentio-istio-demo -c curl -- \
  printenv AGENTIO_TRUST_BUNDLE CURL_CA_BUNDLE
kubectl get pods -n agentio-istio-demo -l app=istio-demo-client \
  -o jsonpath='{range .items[*]}{.metadata.name}{": "}{.spec.containers[*].name}{"\n"}{end}'
```

Both variables point to `/etc/agentio/client-ca/ca-bundle.pem`, and the only application Pod container is `curl`. Libraries that ignore these variables need their own trust configuration; see [client CA trust](../tasks/configure-client-ca-trust.md).

The waypoint parameters already select `httpbin.org` for TLS termination:

```yaml
data:
  config: |
    tlsTermination:
      includeHosts: [httpbin.org]
```

This setting belongs in the Gateway's parameters ConfigMap alongside its existing access-log settings. For another destination, update the hostname, routing resource, and TrafficPolicy together. Client trust alone does not route HTTPS through the waypoint or enable termination.

For the optional public HTTPS example, ensure your Istio ambient installation supports ServiceEntry DNS capture and address allocation, as described in [Istio DNS proxying](https://istio.io/latest/docs/ops/configuration/traffic-management/dns-proxy/). The [HTTPS ServiceEntry](../../manifests/examples/istio-ambient/https-service.yaml) binds `httpbin.org:443` to this cross-namespace waypoint. It requires external HTTPS connectivity.

```sh
kubectl apply -f manifests/examples/istio-ambient/https-service.yaml
kubectl exec deployment/curl -n agentio-istio-demo -c curl -- \
  curl --fail --silent --show-error https://httpbin.org/get
kubectl exec deployment/curl -n agentio-istio-demo -c curl -- \
  curl --silent --show-error --include https://httpbin.org/deny
```

The first request returns the HTTPS origin's JSON. The second returns `403` with `blocked by Agentio EPE`, proving that EPE sees the decrypted HTTP path. Keep certificate verification enabled; do not add `-k`. Check the gateway access log if requests do not match those results.

Istio's CA continues to authenticate HBONE peers. The Agentio MITM CA signs certificates presented to application HTTPS clients, and the gateway verifies upstream HTTPS with its public CA package. These are separate trust relationships. For private upstream roots or an operator-managed MITM signer, see [TLS termination and upstream CA trust](../reference/agentio-configuration.md#tls-termination-for-https-inspection).

## Deployment considerations

This example governs connections routed through the bound HTTP Service and optional HTTPS ServiceEntry. Istio ztunnel does not execute Agentio policy CRDs, and these bindings do not force every outbound destination through Agentio. Additional external destinations and a mandatory egress path require their own routing and enforcement configuration.

The example uses plaintext gateway-to-EPE gRPC. Configure [EPE transport security](../reference/epe-configuration.md) when that connection requires authentication and encryption. The CA-injection labels can also be used on Istio sidecar workloads, but this guide's waypoint-routing example is for ambient sources; retain the routing appropriate to your Istio data-plane mode.

## Clean up

Remove the example's Service binding and policies before deleting its workloads:

```sh
kubectl delete -f manifests/examples/istio-ambient/service.yaml
kubectl delete -f manifests/examples/istio-ambient/https-service.yaml --ignore-not-found
kubectl delete -f manifests/examples/istio-ambient/policies.yaml
kubectl delete -f manifests/examples/istio-ambient/waypoint.yaml
kubectl delete namespace agentio-istio-demo
```

If the Helm release was created only for this example, remove it as well:

```sh
helm uninstall agentio -n agentio-istio-system
kubectl delete namespace agentio-istio-system
```

Leave shared Agentio and Gateway API CRDs installed.

## See also

- [Customize Gateway resources](../tasks/customize-gateway-resources.md)
- [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md)
- [Get started with EPE](../getting-started/epe.md)
