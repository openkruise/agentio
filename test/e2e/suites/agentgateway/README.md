# Agentgateway e2e

This suite installs the production Agentio chart, its real gatewaydeployer, ztunnel, the pinned echo workload, and the shared ext-proc fixture. It provisions `agentio-agentgateway` Gateways backed by native static ConfigMaps and translated Agentio egress settings.

The suite reuses `harness.RunGatewayTraffic`, `RunGatewayExtProc`, and `RunGatewayMatchPorts` with the Envoy gateway suite. HTTP and gRPC traversal proofs use a native gateway header mutation instead of Envoy-specific response headers and access-log fields. Traffic crosses the injected ztunnel and a native `hboneGateway` mTLS CONNECT tunnel. The chart enables `egressGateway.agentgateway.ca.enabled`: gateway Pods request and renew their workload certificates directly from Agentiod using projected ServiceAccount tokens. The raw configuration fixture passes HTTPS through without interception.

`TestAgentgatewayDeploymentLifecycle` covers class acceptance, missing config, initial provisioning, config rollout, invalid YAML, rejection by the native binary while the old replica continues serving, recovery, Service/HPA/PDB recreation, Gateway deletion/child garbage collection, and Gateway recreation. Rollout checks require the expected config hash and fully updated Deployment replicas; a stale `Programmed=True` does not count as completion.

Certificate renewal and failure recovery are covered separately by `TestAgentgatewayNativeCACertificateRotation`. See the [certificate bootstrap design](../../../../docs/design/agentgateway-certificate-bootstrap.md#end-to-end-coverage) for how to run it.

`TestAgentgatewayGeneratedEgress` supplies `data.config` egress settings to the production deployer and waits for its generated ConfigMap and ready Deployment. Generated mode mounts the directory for native file watching and uses a stable mode marker rather than a per-configuration rollout hash. It sends traffic to an unreachable intercepted IP with a synthetic Host; success requires static endpoint selection and request/response processing by the configured Service/EndpointSlice ext-proc fixture through real ztunnel/HBONE traffic.

`TestAgentgatewayPorterEPEIdentity` checks Porter identity resolution and workload-selected EPE policy with forged application identity headers. `TestAgentgatewayPorterTLSIdentity` checks Porter-triggered MITM, identity after decryption, EPE-selected static endpoints, private upstream CA trust, and rejection of mismatched SNI and Host. It uses a cluster-local HTTPS origin and a temporary test CA.

## Run

Use an isolated Kubernetes cluster with Gateway API v1.4.1 standard CRDs already installed. As with the other suites, provide immutable images for Agentiod, EPE, Porter, ext-proc, ztunnel, proxy-init, and CNI using the component flags or an `-agentio.config` file. Set `gateway-image` to the [Agentio agentgateway v1.7.0 adapter image](../../../../extensions/agentgateway/README.md) digest. From `test/e2e`:

```bash
AGENTIO_E2E=1 go test ./suites/agentgateway -v -timeout=25m \
  -e2e.cluster.mode=existing \
  -e2e.cluster.kubeconfig="$KUBECONFIG" \
  -e2e.artifacts.dir="$ARTIFACTS" \
  -e2e.lifecycle.retain=on-failure \
  -agentio.config="$AGENTIO_CONFIG" \
  -agentio.gateway-dataplane=agentgateway \
  -agentio.profile=sidecar
```

A cross-compiled `go test -c` binary accepts the same flags, with `-test.v` and `-test.timeout` instead of `-v` and `-timeout`. To run remotely, copy the binary and production chart to the test host and supply its kubeconfig and chart path.
