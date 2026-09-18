# Get started with sidecar mode

This guide installs Agentio with per-Pod sidecar injection, enrolls a sample workload, and prepares the workload for the shared egress gateway and `TrafficPolicy` tasks.

## Before you begin

You need:

- A Kubernetes cluster that you can administer.
- `kubectl` configured for that cluster.
- Helm 3.
- A local clone of this repository.
- Access to the container images configured in [`manifests/charts/agentio/values.yaml`](../../manifests/charts/agentio/values.yaml).

Run the commands in this guide from the repository root.

Agentio uses the standard `istio-injection` and `sidecar.istio.io/inject` selectors. If the cluster already runs Istio or another injector that watches these selectors, review the existing namespace labels and mutating webhooks before you continue:

```console
$ kubectl get namespace -L istio-injection,istio.io/rev,istio.io/dataplane-mode
$ kubectl get mutatingwebhookconfigurations
```

## Install Agentio in sidecar mode

Create an explicit sidecar-mode values file:

```console
$ cat >/tmp/agentio-sidecar-values.yaml <<'EOF'
sidecarInjector:
  enabled: true
ambient:
  enabled: false
EOF
```

Install Agentio from this repository:

```console
$ helm upgrade --install agentio ./manifests/charts/agentio \
    --namespace agentio-system \
    --create-namespace \
    --values /tmp/agentio-sidecar-values.yaml \
    --wait \
    --timeout 5m
```

Some default Agentio images use `docker.io/openkruise` and mutable `latest` tags. Review every image value and override it when your environment uses a private registry or pinned release images.

Verify the control plane and Agentio APIs:

```console
$ kubectl rollout status deployment/agentiod \
    --namespace agentio-system \
    --timeout=5m

$ kubectl wait --for=condition=Established \
    crd/securityprofiles.agents.kruise.io \
    crd/trafficpolicies.agents.kruise.io \
    crd/globaltrafficpolicies.agents.kruise.io \
    --timeout=60s

$ kubectl api-resources --api-group=agents.kruise.io
```

## Add a workload

Create an isolated namespace and enable sidecar injection:

```console
$ kubectl create namespace agentio-demo
$ kubectl label namespace agentio-demo istio-injection=enabled
```

Deploy the repository's curl sample:

```console
$ kubectl apply --namespace agentio-demo -f samples/curl/curl.yaml
$ kubectl rollout status deployment/curl \
    --namespace agentio-demo \
    --timeout=2m
```

## Verify sidecar injection

Wait for the sample Pod to become ready:

```console
$ kubectl wait pod \
    --namespace agentio-demo \
    --selector app=curl \
    --for=condition=Ready \
    --timeout=2m
```

Depending on the Kubernetes version and native-sidecar support, the injected proxy can appear as a regular container or as a restartable init container. Inspect both lists:

```console
$ kubectl get pod \
    --namespace agentio-demo \
    --selector app=curl \
    --output jsonpath='{range .items[0].spec.containers[*]}container={.name}{"\n"}{end}{range .items[0].spec.initContainers[*]}initContainer={.name} restartPolicy={.restartPolicy}{"\n"}{end}'
```

Confirm that the output contains the `curl` application and an injected `istio-proxy`. Agentio also labels the injected Pod with its proxy type:

```console
$ kubectl get pod \
    --namespace agentio-demo \
    --selector app=curl \
    --output jsonpath='{.items[0].metadata.labels.networking\.agents\.kruise\.io/proxy-type}{"\n"}'
ztunnel
```

Send a baseline request from the application container:

```console
$ kubectl exec deployment/curl \
    --namespace agentio-demo \
    --container curl -- \
    curl --fail --silent --show-error --head http://www.example.com
```

Export the workload interface used by the shared task pages:

```console
$ export AGENTIO_DEMO_NAMESPACE=agentio-demo
$ export AGENTIO_WORKLOAD_LABEL=curl
$ export AGENTIO_WORKLOAD_CONTAINER=curl
```

## Route traffic through an egress gateway

Follow [Route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md). You can create the gateway with either the Gateway API or the Agentio Helm chart.

## Apply a TrafficPolicy

After the egress route works, follow [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md).

## Clean up

First follow the cleanup sections in the shared `TrafficPolicy` and egress gateway tasks. Then delete the sample namespace created by this guide:

```console
$ kubectl delete namespace agentio-demo
```

Uninstalling Agentio is a separate operation because the chart owns the Agentio CRDs and uninstalling it removes custom resources stored under them.

## See also

- [Getting started](../getting-started.md)
- [Ambient mode](ambient-mode.md)
- [OpenKruise Agents integration](../integrations/openkruise-agents.md)
- [Agentio Helm values](../../manifests/charts/agentio/values.yaml)

## Opt in to outbound UDP capture

For a deployment with a CONNECT-UDP-capable ztunnel and egress gateway, enable
UDP on injected sidecars:

```yaml
sidecarInjector:
  ztunnel:
    udpProxy:
      enabled: true
      captureMark: 1339
      routeTable: 134
```

Apply these values with `helm upgrade`, then recreate the application Pods.
Existing Pods are not reinjected. Use a `proxy-init` image built from this change;
the official image already includes `pilot-agent istio-iptables`, so no custom
entrypoint is needed. The ztunnel image must support `ENABLE_UDP_PROXY=true` and
listen for transparent UDP on port 15002. Configure a CONNECT-UDP-capable egress
gateway and its egress policy separately; this switch only enables source Pod
capture, not gateway UDP support.

The injector enables ztunnel UDP and grants it `NET_ADMIN` even when
`global.enableFirewallRules=false`. The init container marks outbound UDP with
`captureMark` and installs a policy rule and local route in `routeTable`, all
inside the source Pod's network namespace. The rerouted packets reach port
15002 through TPROXY with their original destination intact. TCP continues to
use REDIRECT, including inbound TCP capture.

Reserve a distinct capture mark and routing table. The default capture mark
1339 differs from ztunnel's socket `PACKET_MARK=1337` and the TCP interception
marks 1337/1338. These marks are local to the source Pod and are independent of
any tenant socket marks configured on the gateway. Conflicting proxy metadata
for `ENABLE_UDP_PROXY` or `PACKET_MARK` is rejected during injection.

UDP capture honors the existing outbound IP range, port, owner-group and
interface exclusions. Included outbound ports and IP ranges form a union, as
for TCP. UDP DNS on destination port 53 follows the same capture rules. Local,
broadcast, multicast, proxy-generated traffic, and replies to inbound UDP
requests are excluded. Inbound UDP is not intercepted. Every outbound datagram
is captured, including subsequent datagrams in an established session.

This option supports the init-container iptables path, including the
iptables-nft frontend. The native nftables init backend, CNI-managed capture and interception
mode `NONE` are not supported by this option. It does not enable UDP on ambient
ztunnel DaemonSets, even when sidecar and ambient modes coexist.
