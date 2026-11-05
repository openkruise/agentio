# Deploy agentgateway with the Gateway API

Agentio's gateway deployer supports the `agentio-agentgateway` GatewayClass. It provisions a ServiceAccount, Deployment, and Service, and runs agentgateway with either operator-supplied native YAML or native configuration generated from Agentio egress settings. HorizontalPodAutoscaler (HPA) and PodDisruptionBudget (PDB) are opt-in resources.

The generated configuration uses the official agentgateway v1.7.0 image. It supports HTTP Host routing, static service entries, HTTP route timeouts and retries, static TLS interception and standard HTTP external processing. Workload certificate bootstrap uses Agentiod CA. Workload identity attributes enable Porter enrichment before HTTP processing. Sandbox identity, workload/Sandbox-driven SNI decisions, and the full EPE destination-authorization contract are not integrated. Existing `agentio-egress` Gateways continue to use Envoy.

## Enable the deployer

Install Gateway API CRDs, then enable `egressGateway.mode: gatewayAPI` in the Agentio Helm release:

```yaml
egressGateway:
  mode: gatewayAPI
  agentgateway:
    image: cr.agentgateway.dev/agentgateway:v1.7.0
    resources:
      requests: {cpu: 100m, memory: 128Mi}
      limits: {cpu: "2", memory: 1Gi}
```

The image is an operator-controlled value; a Gateway annotation cannot override it. Scheduling can be configured with `egressGateway.agentgateway.nodeSelector`, `tolerations`, `affinity`, and `topologySpreadConstraints`.

The Deployment template leaves `spec.replicas` unset. To create an HPA or PDB, add a `horizontalPodAutoscaler` or `podDisruptionBudget` resource patch; an empty `{}` patch enables the template defaults. See [Customize Gateway resources](customize-gateway-resources.md).

## Supply file configuration

Create the configuration and Gateway in the same namespace. `parametersRef` must reference a core ConfigMap, and the configuration must be stored in `data["config.yaml"]`.

This example serves a fixed response to confirm deployment and configuration loading:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: agentgateway-config
  namespace: agentio-system
data:
  config.yaml: |
    config:
      adminAddr: 127.0.0.1:15000
    binds:
    - port: 8080
      listeners:
      - protocol: HTTP
        routes:
        - policies:
            directResponse:
              status: 200
              body: agentgateway is ready
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: agentgateway
  namespace: agentio-system
spec:
  gatewayClassName: agentio-agentgateway
  infrastructure:
    parametersRef:
      group: ""
      kind: ConfigMap
      name: agentgateway-config
  listeners:
  - name: http
    port: 8080
    protocol: HTTP
```

The Gateway listeners determine the Service ports; the ConfigMap determines what the proxy actually listens on and how it routes. Keep them consistent. Keep readiness on port 15021 at `/healthz/ready` and metrics on port 15020 at `/metrics`.

To configure an egress gateway, replace the example body with the HBONE/internal-listener configuration below and corresponding Gateway ports. The deployment controller does not automatically connect application or ztunnel traffic to this gateway.

If Helm should also create the Gateway, set `egressGateway.gatewayAPI.create: true`, `gatewayClassName: agentio-agentgateway`, and `infrastructure.parametersRef` under `egressGateway.gatewayAPI`. The referenced ConfigMap remains operator-owned.

## Generate configuration from Agentio egress settings

Use `data.config` instead of `data["config.yaml"]` in the referenced ConfigMap to generate a native egress configuration. Enable `egressGateway.agentgateway.ca.enabled: true` and expose one HBONE listener. Both configuration formats use `egressGateway.agentgateway.image`; no custom proxy image or source patch is required. Do not supply both formats.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: agentgateway-settings
  namespace: agentio-system
data:
  config: |
    extProc: {}
    serviceEntries:
    - hosts: [api.example.com]
      endpoints: [{address: 203.0.113.10}]
    http:
      routing:
        fallback:
          timeout: 30s
          retries: {attempts: 2, retryOn: '502,503,504'}
        hostOverrides:
        - hosts: ['*.stream.example.com']
          settings: {timeout: 0s}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: agentgateway
  namespace: agentio-system
spec:
  gatewayClassName: agentio-agentgateway
  infrastructure:
    parametersRef:
      group: ''
      kind: ConfigMap
      name: agentgateway-settings
  listeners:
  - name: mesh
    port: 15008
    protocol: HBONE
```

The controller creates a separate Gateway-owned `<deployment-name>-native` ConfigMap. It does not modify or adopt the input ConfigMap. The generated directory is mounted without `subPath`: agentgateway watches and reloads routes, listeners, processor endpoints, certificates and trust files. Configuration changes keep the Pod template's `generated-v1.7.0` mode marker stable and do not trigger a rollout. Workload identity mode uses `generated-v1.7.0-identity` and adds a Porter sidecar; changing identity mode or switching between native and generated modes triggers a rollout. Deleting the Gateway garbage-collects its generated ConfigMap.

Generated internal binds accept destination ports 80 and 443. Add non-HBONE listener ports to declare additional internal destination ports. These binds do not open public sockets; application traffic still enters through HBONE. Gateway listeners also determine Service ports, so additional internal-only ports advertised by the Service do not accept direct connections.

For ordinary HTTP requests, the gateway resolves the HTTP Host instead of connecting to the intercepted IP. A matching `serviceEntries` entry selects one of its static IPv4 endpoints with equal weights. Both paths preserve the intercepted destination port and original Host. TLS passthrough resolves SNI when available; opaque TCP uses the original IP and port. Configure application/ztunnel routing separately with `egressPolicies`, as in the Envoy egress task.

Supported settings are deliberately limited to fields with a native implementation:

| Agentio setting | Native behavior |
| --- | --- |
| `serviceEntries` | Exact host matching and equally weighted static IPv4 endpoints for HTTP, including decrypted HTTPS. TLS verification uses the service hostname when dialing a static IP. |
| `tlsTermination` | Native `dynamicCa` certificates selected by static exact, `*.suffix` and `*` SNI patterns. An exclusion wins over an identical inclusion. Requires the signing Secret described below. Workload/Sandbox policy does not select termination. |
| `upstreamTrustBundle` | ConfigMap/Secret sources in the Agentio system namespace are validated, merged and deduplicated with Agentiod's public CA package, then mounted as the HTTPS origination root file. Invalid sources retain the existing generated configuration. |
| `http.acceptHttp10` | Defaults to accepting HTTP/1.0. Explicit `false` rejects HTTP/1.0 through native authorization with HTTP 403. |
| `http.routing.fallback` | Default timeout/retry settings. An override for `*` replaces them. |
| `http.routing.hostOverrides` | Exact names, `*.suffix`, and `*`; the most specific host wins. Overrides replace the complete timeout/retry settings. |
| Route `timeout` | Native `requestTimeout`; zero or omission disables it. The native timeout ends when response headers arrive and does not bound the response body. |
| Route `retries` | In v1.7.0, both Agentio and native `attempts` count retries after the original request, so the value is passed through. Maximum 255 retries. `perTryTimeout` maps to `backendRequestTimeout`. `backoff` uses the native delay. Supported `retryOn` values are HTTP status numbers, `5xx`, `gateway-error`, `connect-failure`, `refused-stream`, `unavailable`, and `cancelled`. Connection failures follow agentgateway's native retry classification; previous-host/locality selection is not translated. |
| `extProc` | Per-gateway override or inherited global `sandboxExtProc`, plaintext endpoint, failure mode, header modes and body mode override. `serviceRef` uses the shared Service/EndpointSlice cache and authoritative endpoint ports; only ready, serving, non-terminating TCP endpoints participate. Missing Services/endpoints produce an empty native Service and never fall back to DNS. |
| `additionalExtProcs` | One additional processor is supported through native gateway and route phases: requests run primary then additional, responses run in reverse order. Workload identity consumes the first phase for Porter, so it cannot be combined with `additionalExtProcs`. Explicit per-gateway `extProc: {}` disables processing. Longer chains are rejected. |
| ext-proc attributes | Source address and destination address/port are supplied automatically. Request attributes can also select `source.port`, `request.method`, `request.host`, `request.path`, `request.scheme`, `request.protocol`, `request.headers`. Requesting Workload UID, name or namespace enables trusted Workload enrichment through Porter and supplies all three fields. Sandbox and other unsupported filter-state attributes are rejected. Response attributes can select `response.code` and `response.headers`. Attribute values follow native proxy semantics. |
| Explicit transport defaults | TLS 1.2–1.3 without a cipher override, `http.streamIdleTimeout: 0s`, and `tcp.idleTimeout: 0s` are accepted. Native defaults do not reproduce Envoy's nonzero idle timeout defaults. |

Unsupported populated fields are rejected with `Accepted=False` and `Programmed=False` before changing generated configuration or the Deployment. Remaining gaps require native capabilities with matching semantics: CONNECT rate/concurrency/bandwidth limits and identity buckets; nonzero bidirectional HTTP/TCP idle timeouts and TCP maximum lifetime; TLS origination version/cipher restrictions; Envoy log-format operators; ext-proc per-message timeouts, legacy label attributes, HTTP/2 connection limits, and longer processor chains. The native CA's legacy mTLS transport can fall back to plaintext when identity acquisition fails, so it cannot safely implement Agentio's fail-closed `extProc.tls: MUTUAL` contract. SPIFFE Workload API configurations can be supplied in native mode, but are a different identity source.

Configure a standard HTTP processor explicitly in `data.config`, for example `extProc: {serviceRef: {name: processor, namespace: agentio-system}}`. The chart's inherited Envoy EPE provider includes per-message timeouts and Sandbox attributes that cannot be translated.

To select EPE SecurityProfiles by Workload, request a Workload identity attribute:

```yaml
extProc:
  serviceRef: {name: agentio-epe, namespace: agentio-system}
  request:
    attributes: ["filter_state['agentio.workload.uid']"]
```

The generated gateway deploys the configured `egressGateway.porter` image as a local sidecar. Use a Porter version supporting the `agentio.identity.mode: http` ext-proc attribute. Register the Gateway in global `egressGateways` before waiting for readiness so Porter can authenticate to Agentiod. On each HTTP request, including decrypted HTTPS, agentgateway sends its authenticated connection certificate, peer principal and physical source IP to Porter. Porter reuses its certified-instance lookup or validated IP/principal fallback, then returns canonical Workload UID, name and namespace. Native ext-proc metadata carries that result to EPE; application identity headers do not participate. Identity failures deny the request even if the downstream processor permits transport failures.

This mode does not run Porter's CONNECT destination authorization or select TLS handling dynamically. The HBONE path does not expose outer Sandbox CONNECT headers, so Sandbox identity/token attributes remain unsupported. The integration also does not interpret EPE's `agentio.route` metadata to bind the actual dial target. Workload-selected HTTP policies are supported; full EPE destination-authorization parity is not claimed.

Application-level HTTP CONNECT is explicitly denied with HTTP 405 before HTTP processing. Native `connect.mode: route` terminates CONNECT and establishes a byte tunnel; it does not forward the original CONNECT request to the intercepted upstream HTTP proxy as `agentio-egress` does. This restriction does not affect the outer HBONE CONNECT transport.

With two processors, the primary runs before native route selection. A primary processor that rewrites Host can therefore affect host overrides and static endpoint selection. In identity mode this phase is occupied by Porter, which does not mutate Host.

To enable MITM, provision a CA Secret in the Gateway's namespace with `ca.crt` and `ca.key`, add the existing Gateway annotation `gateway.agentio.kruise.io/agentgateway-certs: <secret-name>`, and set static `tlsTermination.includeHosts`. Clients must trust that CA. Native interception does not reproduce Agentio's Porter-driven decisions or the Envoy SNI/Host equality guard. Agentgateway holds this signing key and issues SNI leaf certificates locally; the controller does not copy Agentiod's MITM signing Secret or private keys. Projected Secret changes are watched by the native resource manager. Use a dedicated CA appropriate for the gateway's trust boundary.

Agentgateway v1.7.0 filters loopback, unspecified and link-local addresses after resolution for dynamic backends. Generated configuration retains that default, including static service entries represented by dynamic targets. Private service networks remain reachable. EPE and TrafficPolicy authorization remain separate from this native address restriction. Use native `config.yaml` for other native features; retain `agentio-egress` for the unsupported enforcement settings listed above.

## Upgrade to v1.7.0

The default image is `cr.agentgateway.dev/agentgateway:v1.7.0`. Review the [official release notes](https://github.com/agentgateway/agentgateway/releases/tag/v1.7.0) when supplying an existing native configuration. Dynamic backends now deny loopback, link-local and unspecified destinations by default. Native configurations that intentionally reach a gateway-local service can set `config.backend.allowDynamicLoopback: true`; generated egress configuration does not disable the restriction.

The release also changes repeated-header CEL lookups to return lists and enables automatic MCP session encryption. Native MCP deployments using read-only configuration should supply their session key explicitly if stable sessions across restarts are required.

## Enable workload certificates from agentiod

Enable native certificate bootstrap from `agentiod` for agentgateway deployments:

```yaml
egressGateway:
  mode: gatewayAPI
  agentgateway:
    ca:
      enabled: true
```

This option defaults to `false` to preserve existing file/Secret deployments. It applies to all `agentio-agentgateway` Gateways managed by this installation. It enables certificate bootstrap; routes come from native or generated configuration and no agentgateway xDS connection is configured.

Agentio supplies the CA address, the Pod's namespace and ServiceAccount identity, the trust domain and cluster ID, a projected short-lived ServiceAccount token, and the public trust bundle. Configure the HBONE bind in the native ConfigMap as follows, and expose port 15008 with `protocol: HBONE` in the Gateway listeners:

```yaml
binds:
- port: 15008
  tunnelProtocol: hboneGateway
  listeners:
  - protocol: HBONE
- port: 80
  mode: internal
  protocol: AUTO
  listeners: &egress-listeners
  - protocol: HTTP
    routes:
    - backends:
      - dynamic:
          target: 'string(destination.address) + ":" + string(destination.port)'
  - protocol: TLS
    hostname: "*"
    tcpRoutes:
    - backends:
      - dynamic:
          target: 'string(destination.address) + ":" + string(destination.port)'
  - protocol: TCP
    tcpRoutes:
    - backends:
      - dynamic:
          target: 'string(destination.address) + ":" + string(destination.port)'
- port: 443
  mode: internal
  protocol: AUTO
  listeners: *egress-listeners
```

The `hboneGateway` tunnel requires an IP:port CONNECT authority and an explicit internal bind for each destination port; the example permits ports 80 and 443. Add internal binds for other required ports. This example forwards to the original destination IP and passes inner HTTPS through unchanged; scope permitted destinations with your egress configuration.

Use `hboneGateway` rather than a `connect` + `tls.cert/key` bind: enabling the CA client alone does not replace certificates on static TLS listeners.

Certificate lifetime, renewal, and failure behavior are documented in [agentgateway certificate bootstrap (design)](../design/agentgateway-certificate-bootstrap.md).

## Mount additional or externally managed certificates

For configurations requiring TLS certificates or a MITM CA, reference a Secret in the Gateway namespace:

```yaml
metadata:
  annotations:
    gateway.agentio.kruise.io/agentgateway-certs: agentgateway-certs
```

The Secret's keys are mounted as files beneath `/etc/agentgateway/certs`. Use those paths in `config.yaml`. The deployer does not issue certificates, read this Secret's contents, or manage its rotation. The native resource manager watches referenced certificate/key files and reloads them after projected Secret updates; verify the result with a fresh authenticated connection. Clients must trust the appropriate server/MITM CA; upstream TLS verification is configured in the native file.

External Secret mounts can coexist with native CA mode, for example for a separate HTTPS listener or MITM CA. When `ca.enabled` is false, the generated bootstrap has no CA connection or projected ServiceAccount token.

## Updates and status

Updating the referenced `config.yaml` triggers a rollout. The Deployment uses `maxUnavailable: 0` and `maxSurge: 1`.

- Missing references, empty configuration, or invalid YAML report `Accepted=False` and `Programmed=False`, without replacing the Deployment configuration.
- YAML syntax is checked by Agentio; agentgateway validates its configuration schema during startup. A schema-invalid configuration can create a failing new Pod while the old replica continues serving. Correct the ConfigMap to recover.
- `Programmed=True` means the desired configuration's Deployment rollout is available. It does not assert HTTPRoute attachment, policy enforcement, or end-to-end application connectivity.
- Generated mode uses native file watching rather than a configuration-specific Pod hash. `Programmed=True` verifies Pod availability, not acknowledgement of the latest file reload. Check native reload errors and exercise the changed route to verify application behavior; a rejected reload retains the last valid native configuration.
- Deleted HPA/PDB resources are recreated while their corresponding patch keys are configured. Removing a patch key does not delete an existing HPA/PDB. Removing the Gateway allows Kubernetes to garbage-collect its owned Deployment, Service, ServiceAccount, HPA, PDB and generated ConfigMap. Input ConfigMaps and certificate Secrets remain operator-owned.

```bash
kubectl -n agentio-system get gateway agentgateway -o yaml
kubectl -n agentio-system rollout status deployment/agentgateway
kubectl -n agentio-system logs deployment/agentgateway
```

## See also

- [Customize Gateway resources](customize-gateway-resources.md)
- [agentgateway certificate bootstrap (design)](../design/agentgateway-certificate-bootstrap.md)
