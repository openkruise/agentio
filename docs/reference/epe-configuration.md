# EPE configuration

The Egress Policy Enforcer (EPE) is deployed by the Agentio chart as `agentio-epe` when `epe.mode` is `managed`. This reference separates the Helm surface from EPE process settings so operators can see which controls a normal chart upgrade can change.

## Watched EPEConfig

EPE always watches its base and primary configuration ConfigMaps and referenced Secrets, CA ConfigMaps, and certificate files. The chart selects `<epe-name>-config` and `<epe-name>-config-primary` in the installation namespace; standalone EPE defaults to `agentio-epe-config` and `agentio-epe-config-primary` in `agentio-system`. Set `epe.config` to have Helm create the base with named `httpCallout` and `credentialProvider` extensions. SecurityProfile HTTPCallout API integration is deferred. `epe.config: null` leaves the base externally managed; primary is always externally managed.

Environment settings supply the default EPEConfig layer, followed by base and primary. Missing ConfigMaps or blank `data.config` leave the lower layer unchanged; EPE watches for later creation. Invalid content is logged and discarded, retaining the last good configuration, or the defaults before any valid configuration has been loaded.

`extensionProviders` merges by name across layers. New names are added; a same-name entry replaces the whole provider, including its type, timeout, and TLS settings. Omitted or null lists inherit the lower layer; an explicit `extensionProviders: []` clears the inherited list. Duplicate names within one layer are invalid. Each update recomputes from defaults: removing an entry or deleting a ConfigMap restores any lower-layer definition. Unchanged providers keep their clients and caches; replaced providers are recreated when restored.

Environment defaults use the ordinary name `agentio-default-credential-provider`, which ConfigMaps may redefine. Adding only HTTPCallout providers preserves this credential provider and its default selection. No environment provider is generated when `IDENTITY_PROVIDER_URL` is empty. Omitting `defaultProviders` inherits the lower layer's selection; `defaultProviders: {credentialProvider: ""}` (or `defaultProviders: {}`) clears it. A missing or wrong-type selected default fails at call time; there is no fallback to another provider. TLS material or call failures likewise do not change the selected provider.

An `httpCallout` provider owns its URL, timeout, and TLS settings. The HTTPCallout client implements the Invocation/Decision protocol and enforces the process-wide `HTTP_CALLOUT_MAX_RESPONSE_BYTES` response limit (default 1 MiB). Audit webhooks still use their existing configuration and do not yet reference EPEConfig providers.

## Helm values

| Value | Default | Rendered effect |
| --- | --- | --- |
| `epe.mode` | `disabled` | `managed` creates the EPE ServiceAccount, cluster RBAC, headless Service, Deployment, and PodDisruptionBudget and writes `sandboxExtProc` into `agentio-config`; `external` wires the configured external address without deploying EPE. |
| `epe.nameOverride` | `agentio-epe` | Names the Kubernetes objects and the generated ext_proc Service hostname. |
| `epe.config` | `null` | When set, creates `<epe-name>-config` with EPEConfig in `data.config`. EPE watches this name even when the ConfigMap is absent. |
| `epe.tls.enabled` | `false` | Enables gateway-to-EPE mTLS. Managed mode also configures the EPE listener. |
| `epe.tls.certificateSource` | `{}` | Managed EPE certificate source: select `ca` or `file`. Omission or `{}` uses Agentiod with default token and root mounts. |
| `epe.tls.peerSpiffeIDs` | `[]` | EPE identities accepted by the gateway. Managed mode derives EPE's ServiceAccount identity; external mode requires an explicit list. |
| `epe.extraVolumes`, `.extraVolumeMounts` | `[]` | Native Kubernetes volumes and EPE container mounts. Also available with TLS disabled. |
| `epe.service.grpcPort` | `9002` | Service, container, EPE `-grpc-port`, and `sandboxExtProc.port`. |
| `epe.service.healthPort`, `.metricsPort` | `9003`, `9090` | Health-probe and Prometheus listener ports. |
| `epe.image.repository`, `.name`, `.tag` | empty, `agentio-epe`, empty | EPE container image. Empty repository and tag values inherit `global.hub` and `global.tag`. |
| `epe.credentialProvider.url` | empty | Credential provider base URL, rendered as `IDENTITY_PROVIDER_URL`. Credential lookups fail while it is empty. |
| `epe.credentialProvider.mtls.source` | `none` | The source of credential-provider mTLS material: `none` or `secret`. Always rendered as `CREDENTIAL_PROVIDER_MTLS_SOURCE`. Any other value fails rendering. |
| `epe.credentialProvider.mtls.secret.namespace`, `.name` | empty | `source=secret` only. The Secret EPE watches directly. Both are required for that source; rendering fails if either is missing. |
| `epe.credentialProvider.mtls.insecureSkipVerify` | `false` | Rendered only when `true`. Disables provider server-certificate verification — exposes the bearer token to an on-path attacker. |
| `epe.env` | `{}` | Adds arbitrary string environment variables to the container after the chart-managed variables, so a key set here overrides the same chart-managed variable. |
| `epe.replicaCount` | `1` | Deployment replica count when autoscaling is disabled. |
| `epe.autoscaling.enabled` | `false` | Creates an HPA instead of setting Deployment replicas. |
| `epe.autoscaling.minReplicas`, `.maxReplicas` | `2`, `20` | HPA bounds when enabled. |
| `epe.autoscaling.targetCPUUtilizationPercentage` | `80` | Adds the CPU utilization metric when non-zero. |
| `epe.autoscaling.targetMemoryUtilizationPercentage` | unset | Adds the memory utilization metric only when set and non-zero. |
| `epe.autoscaling.behavior` | unset | Copies HPA scale behavior when set. |
| `epe.resources` | CPU `500m`, memory `512Mi` requests | Container resources. Limits are unset by default. |
| `epe.podDisruptionBudget.enabled`, `.minAvailable` | `true`, `1` | Controls the PodDisruptionBudget and its minimum available Pods. |
| `epe.nodeSelector`, `.tolerations`, `.affinity` | empty | Pod placement settings. |
| `epe.messageTimeout` | `5s` | Value used for generated `sandboxExtProc.messageTimeout`. |
| `epe.auditWebhook.insecureSkipVerify` | `false` | Sets the EPE audit-webhook TLS verification flag. Keep `false` in production. |

The chart supplies the EPEConfig name and namespace, the three listener ports and `epe.auditWebhook.insecureSkipVerify` as container arguments. Use `epe.env` only for EPE environment variables. Serving TLS arguments are rendered from `epe.tls`; other Go flags such as `--enable-pprof` require deployment customization.

## Rendered Kubernetes behavior

The Service is headless (`clusterIP: None`) and exposes TCP ports named `extproc` (`epe.service.grpcPort`), `health` (`epe.service.healthPort`), and `metrics` (`epe.service.metricsPort`). Its selector matches `app.kubernetes.io/name: <epe.nameOverride>`. The Deployment opts out of sidecar injection, adds Prometheus scrape annotations for port 9090, and configures gRPC liveness and readiness probes against the health port. Liveness starts after five seconds and runs every ten seconds; readiness starts after three seconds and runs every five seconds.

The chart grants the ServiceAccount `get/list/watch` on `SecurityProfile` and `GlobalSecurityProfile`, but only `get` on their status subresources. It also grants `get/list/watch` on CRDs, ConfigMaps, and Secrets. EPE needs the CRD watch before its delayed profile informers can synchronize; without it the process cannot complete startup.

With the default `epe.credentialProvider.mtls.source=none`, EPE presents no client certificate and verifies HTTPS credential providers against the system trust store. Set `source=secret` with `secret.namespace` and `secret.name` to watch TLS material directly through the Kubernetes API; the chart does not create or mount that Secret. EPEConfig also supports `caConfigMapRef` for a watched CA trust bundle, and `caCertificateFile` / `clientCertificateFiles` for provider TLS files; the deployment must supply these files inside the EPE container. See the [file configuration example](credential-provider.md#transport-security). Provider TLS settings do not enable TLS on the ext_proc listener.

## Agentio ext_proc wiring

When EPE is enabled, `agentio-config` contains:

```yaml
sandboxExtProc:
  service: agentio-epe.agentio-system.svc.cluster.local
  port: 9002
  messageTimeout: 5s
  request:
    headerMode: SEND
    attributes:
      - filter_state['sandbox.id']
      - filter_state['sandbox.token']
      - filter_state['sandbox.labels']
      - filter_state['agentio.workload.name']
      - filter_state['agentio.workload.namespace']
      - filter_state['downstream_peer'].name
      - filter_state['downstream_peer'].namespace
      - destination.port
      - source.address
  response:
    headerMode: SKIP
```

The service name uses the chart namespace, so `agentio-system` above is only the standard installation namespace. `agentiod.config.values` deep-merges over this chart-generated ConfigMap, and `agentio-config-primary`, if present, has runtime precedence. A per-gateway `egressGateways[].extProc` replaces the global `sandboxExtProc`; an explicitly empty gateway provider disables external processing for that gateway. See [Agentio configuration](agentio-configuration.md) for ConfigMap precedence and provider fields.

When upgrading a custom provider or overriding `request.attributes`, include `filter_state['agentio.workload.name']` and `filter_state['agentio.workload.namespace']` to forward the source Pod headers captured by the gateway. Keep the two `downstream_peer` attributes for fallback when the headers are missing or empty.

The generated provider leaves `failureModeAllow` unset, so its effective default is `false`. An unavailable EPE service, gRPC processing error, or ext_proc message timeout therefore fails the gateway request closed. Setting `agentiod.config.values.sandboxExtProc.failureModeAllow: true` keeps traffic moving but bypasses all EPE enforcement during those failures. A per-gateway override can choose differently through `egressGateways[].extProc.failureModeAllow`, but it must also repeat the complete provider service, port, modes, attributes, and timeout because the gateway provider replaces the global one. This provider outage setting is separate from a matched token transformation's `failStrategy`, which handles request-time transformation failures after EPE has received and projected the policy.

The generated `5s` message timeout must remain above EPE's default `--plugin-budget=4.5s`. An EPE action that exceeds its plugin budget follows that action's failure policy. If Envoy itself reaches the ext_proc message timeout, the provider-level `failureModeAllow` behavior above applies. A response header mode of `SKIP` means EPE does not receive upstream response headers by default.

## Process flags and listeners

| Flag | Default | Purpose |
| --- | --- | --- |
| `--epe-config` | `agentio-epe-config` | Base ConfigMap for extension providers and default selection. An absent ConfigMap leaves defaults unchanged. |
| `--epe-config-primary` | `agentio-epe-config-primary` | ConfigMap applied after base; empty disables the overlay. Missing or empty content leaves base unchanged. |
| `--epe-config-namespace` | `agentio-system` | Namespace of EPEConfig; the default namespace for its Secret references. The chart sets this to the installation namespace. |
| `--grpc-port` | `9002` | ext_proc gRPC listener. The chart sets it from `epe.service.grpcPort`. |
| `--grpc-health-port` | `9003` | gRPC health listener used by Kubernetes probes. |
| `--metrics-port` | `9090` | HTTP listener serving only `/metrics`. |
| `--admin-addr` | `127.0.0.1:15000` | Admin HTTP bind address. |
| `--enable-debug` | `true` | Registers the `/debug/profiles` and `/debug/logging` admin endpoints. |
| `--enable-pprof` | `false` | Starts Go pprof on `--pprof-addr`. |
| `--pprof-addr` | `:6060` | pprof listener address when enabled. |
| `--observe-responses` | `false` | Requests response headers through ext_proc so audit can record upstream status. |
| `--plugin-budget` | `4.5s` | Per-evaluation-phase limit; `0` disables it. Keep it below Envoy's ext_proc message timeout. |
| `--kubeconfig` | empty | Kubeconfig path; empty selects in-cluster configuration. |
| `--v` | `2` | Log verbosity unless `--zap-log-level` is supplied. |
| `--audit-log-buffer-size` | `4096` | Access-log queue capacity; full queues drop entries. |
| `--audit-webhook-buffer-size` | `8192` | Audit-webhook queue capacity; full queues drop events. |
| `--audit-webhook-workers` | `96` | Audit-webhook worker count. |
| `--audit-webhook-insecure-skip-verify` | `false` | Skips TLS certificate verification for every HTTPS audit webhook when explicitly enabled. |

The binary also accepts controller-runtime Zap flags, including `--zap-log-level` and `--zap-stacktrace-level`. The metrics and health listeners bind all interfaces because they are constructed from their port numbers. The chart exposes both through its headless Service. The admin listener is loopback-only by default and is not in that Service. pprof binds all interfaces by default when enabled; only enable it with an intentionally restricted bind address and network exposure.

Use the [runtime logging admin endpoint](epe-admin-api.md#runtime-log-level) to inspect or change verbosity without restarting EPE. For example, PUT `{"output_level":"debug"}` to `/debug/logging/default` to enable EPE debug logs, then PUT `{"output_level":"info"}` to restore the default. The request format matches agentiod; EPE exposes only the process-wide `default` scope. Changes apply to one process and are lost on restart.

## TLS for ext_proc

With `--tls-source=none`, EPE serves plaintext ext_proc gRPC. To enable workload mTLS, configure both the gateway client and EPE server. The gateway uses its existing local SDS `default` certificate and `ROOTCA` trust bundle, with exact URI SAN matching for the EPE identity.

For the managed Helm deployment:

```yaml
epe:
  mode: managed
  tls:
    enabled: true
    certificateSource: {}
```

With an omitted or empty `certificateSource`, EPE generates a private key in memory and requests its ServiceAccount's SPIFFE certificate from Agentiod. The chart mounts a projected ServiceAccount token with Agentiod's configured audience and the existing `agentio-ca-root-cert` trust bundle (or its configured name). Each request reads the current token and opens a CA connection using the current roots and DNS verification. The private key is never uploaded or written to a Secret. Neither sandbox tokens nor SecurityProfile changes are required.

Set `certificateSource.ca` to override the CA connection. It uses the Istio `CreateCertificate` API, not xDS/SDS. All three fields are optional; omit a field to retain its default. For example:

```yaml
epe:
  mode: managed
  tls:
    enabled: true
    certificateSource:
      ca:
        address: agentiod.security.svc:15012
        tokenFile: /custom/token
        caCertificateFile: /custom/root.pem
```

An explicit `tokenFile` or `caCertificateFile` disables the corresponding automatic mount, even when the path equals its default. Provide the file using `epe.extraVolumes` and `epe.extraVolumeMounts`. An address-only override retains both default mounts. In CA mode the root bundle is shared by CA-server verification and incoming client-certificate verification. The expected EPE SPIFFE ID still comes from the chart's trust domain, namespace and EPE ServiceAccount.

EPE requires and verifies client certificates against its configured trust bundle, including certificate validity and client-authentication usage. It currently accepts every verified client, without a gateway SPIFFE ID allow-list. Adding a gateway requires no EPEConfig change, and mTLS works even when the EPEConfig ConfigMap is absent.

**Current limitation:** CA verification does not distinguish gateways from other workloads issued by the same CA. EPE trusts the calling proxy's workload attributes when selecting SecurityProfiles and returning credential mutations. Deployments must trust all clients that can present an accepted certificate and reach EPE, or restrict EPE access to gateways through network isolation. Gateway-specific authorization is deferred.

EPE renews before expiry, with roughly one third of the returned certificate's remaining lifetime left and randomized scheduling. Each renewal generates a new key. CA failures retain an unexpired certificate and trigger bounded backoff retries. Before initial issuance or after expiry, readiness is `NOT_SERVING` and new connections/streams fail closed; liveness remains `SERVING` so recovery does not require a restart. Kubernetes probes use the named `readiness` and `liveness` gRPC services. Existing streams may finish.

Trust files reload independently of certificate renewal, with a 10-second polling backstop for reissuance when roots change. Missing or malformed trust material rejects new authentication; there is no system-CA fallback. Root-key replacement requires distributing overlapping old/new roots before switching issuance and removing the old root after old leaves expire.

For externally managed certificates, select `certificateSource.file` and supply all three paths. File mode does not create automatic mounts or request certificates; the operator manages renewal. The serving certificate must carry EPE's SPIFFE identity and chain to the gateway's workload trust bundle. `caCertificateFile` supplies the trust bundle for verifying incoming clients and may be mounted separately:

```yaml
epe:
  mode: managed
  tls:
    enabled: true
    certificateSource:
      file:
        certificateFile: /etc/epe/tls/tls.crt
        privateKeyFile: /etc/epe/tls/tls.key
        caCertificateFile: /etc/epe/trust/ca.crt
  extraVolumes:
    - name: serving-certificate
      secret:
        secretName: epe-server-tls
    - name: client-ca
      configMap:
        name: gateway-client-ca
  extraVolumeMounts:
    - name: serving-certificate
      mountPath: /etc/epe/tls
      readOnly: true
    - name: client-ca
      mountPath: /etc/epe/trust
      readOnly: true
```

`ca` and `file` are mutually exclusive. Mounts use native Kubernetes volume syntax, so Secrets, ConfigMaps, projected volumes and CSI sources are supported. Mount directories without `subPath` for projected certificate updates. These are deployment settings; changing sources, paths or mounts rolls the Deployment rather than updating EPEConfig. External EPE mode only configures the gateway connection; certificate sources and mounts apply to managed EPE.

The chart configures `AgentioConfig.sandboxExtProc.tls` as follows (also supported in an individual gateway's `extProc` override):

```yaml
sandboxExtProc:
  service: agentio-epe.agentio-system.svc.cluster.local
  port: 9002
  tls:
    mode: MUTUAL
    peerSpiffeIDs:
    - spiffe://cluster.local/ns/agentio-system/sa/agentio-epe
```

Managed mode derives the expected EPE identity from the configured trust domain, namespace and EPE ServiceAccount. Override it with `epe.tls.peerSpiffeIDs`; external mode requires this list explicitly. `MUTUAL` requires a nonempty list and uses TLS 1.3 with HTTP/2. An omitted TLS block or `DISABLE` keeps plaintext; an invalid TLS update retains the last valid AgentioConfig.

| Flag | Requirement and behavior |
| --- | --- |
| `--tls-source` | `none` (default), `ca`, or `file`. CA and file settings cannot be mixed. |
| `--ca-address` | CA `host:port`; defaults to `agentiod.agentio-system.svc:15012`. Helm uses `certificateSource.ca.address`, defaulting to the chart's Agentiod address. |
| `--tls-spiffe-id` | Required expected ServiceAccount SPIFFE identity in CA mode. Agentiod derives the actual identity from the authenticated token. |
| `--ca-token-path`, `--ca-root-path` | Projected token and trust bundle paths. Defaults: `/var/run/secrets/tokens/agentio-token` and `/var/run/secrets/agentio/root-cert.pem`. |
| `--tls-cert-lifetime` | Requested lifetime, default `24h`, capped by Agentiod. Renewal follows the returned certificate's actual expiry. |
| `--tls-cert-path`, `--tls-key-path` | Require `--tls-source=file` and must be set together. They load the serving certificate and key from PEM files and enable server TLS. Material reloads after file events and a 10-second polling backstop. |
| `--tls-ca-path` | Requires the serving certificate and key. It enables required, CA-verified client certificates. Missing trust anchors reject new handshakes. |

Client certificates are verified at TLS handshakes. Before each new mTLS ext_proc stream, including streams on existing HTTP/2 connections, EPE also checks that its serving certificate and trust material remain available. In-flight streams may finish. Certificate/trust updates affect new connections; established connections are not forcibly terminated. mTLS session resumption is disabled so new connections revalidate the current trust bundle. Enabling/disabling TLS or changing certificate paths requires restarting EPE; EPEConfig does not configure inbound TLS.

Invalid TLS flag combinations, unreadable initial certificate/key files, or an invalid initial CA bundle fail EPE startup. A malformed later certificate update retains the last good certificate; deleting certificate material makes new handshakes unavailable. The serving Secret is independent of the credential-provider client Secret. Neither provider TLS settings nor `epe.env` configures these flags directly.

## Credential-provider and webhook environment variables

`IDENTITY_PROVIDER_URL`, `TOKEN_CACHE_TTL=15m`, and `TOKEN_CACHE_MAX_SIZE=10000` are set by the chart. `TOKEN_CACHE_TTL` applies only to `apiKey` responses that omit `cacheExpiresInSeconds`; see [caching semantics](credential-provider.md#caching-semantics). The `CREDENTIAL_PROVIDER_*` mTLS variables come from the typed `epe.credentialProvider.mtls` values described below. Everything else uses `epe.env` (or a non-chart deployment):

The cache environment variables configure every credential provider, whether registered by the environment defaults or EPEConfig. Providers retain independent caches with the same limits. Cache settings are read at startup and require a restart to change; they are not part of EPEConfig.

`HTTP_CALLOUT_MAX_RESPONSE_BYTES` bounds the Decision response read by each HTTPCallout client. It defaults to `1048576` bytes (1 MiB); non-positive or invalid values use that default. The client reads the setting once at initialization, so changing it in a deployment requires restarting EPE. It does not affect credential lookups or the rule's `maxBodyBytes` disclosure limit. The HTTPCallout client supports this setting; production SecurityProfile integration remains deferred.

The following table is generated from EPE's credential-provider, token-cache, STS-cache, HTTPCallout, and audit-webhook registrations. It shows binary defaults; in particular, the chart sets `TOKEN_CACHE_MAX_SIZE=10000` while the binary defaults to `100000`.

```console
$ epe -print-env -print-env-format=markdown
```

Use `epe -print-env` to inspect all visible registrations, including shared and dependency packages. Shared packages can register settings that EPE does not consume; registration alone does not imply that a setting affects EPE.

<!-- BEGIN GENERATED ENVIRONMENT VARIABLES -->
<!-- Generated by make gen.envdocs from env.Register metadata; do not edit this table. -->

| Variable | Type | Binary default | Description |
| --- | --- | --- | --- |
| <code>AUDIT_WEBHOOK_DIAL_KEEPALIVE</code> | Duration | <code>30s</code> | Interval between TCP keep-alive probes for active connections in the audit webhook client |
| <code>AUDIT_WEBHOOK_DIAL_TIMEOUT</code> | Duration | <code>5s</code> | Maximum duration for establishing a TCP connection in the audit webhook client |
| <code>AUDIT_WEBHOOK_EXPECT_CONTINUE_TIMEOUT</code> | Duration | <code>1s</code> | Maximum time to wait for 100-continue response in the audit webhook client |
| <code>AUDIT_WEBHOOK_IDLE_CONN_TIMEOUT</code> | Duration | <code>1m30s</code> | Maximum idle time for a keep-alive HTTP connection in the audit webhook client |
| <code>AUDIT_WEBHOOK_MAX_CONNS_PER_HOST</code> | Integer | <code>128</code> | Maximum number of HTTP connections per host for the audit webhook client |
| <code>AUDIT_WEBHOOK_MAX_IDLE_CONNS</code> | Integer | <code>256</code> | Maximum number of idle HTTP connections across all hosts for the audit webhook client |
| <code>AUDIT_WEBHOOK_MAX_IDLE_CONNS_PER_HOST</code> | Integer | <code>64</code> | Maximum number of idle HTTP connections per host for the audit webhook client |
| <code>AUDIT_WEBHOOK_RESPONSE_HEADER_TIMEOUT</code> | Duration | <code>10s</code> | Maximum time to wait for server response headers in the audit webhook client |
| <code>AUDIT_WEBHOOK_TLS_HANDSHAKE_TIMEOUT</code> | Duration | <code>5s</code> | Maximum duration for a TLS handshake in the audit webhook client |
| <code>CREDENTIAL_PROVIDER_INSECURE_SKIP_VERIFY</code> | Boolean | <code>false</code> | Skip verification of the credential provider&#39;s server certificate. The client certificate, when one is configured, is still presented. Intended for self-signed providers on trusted networks; any on-path attacker can then read the bearer token and forge the credential response |
| <code>CREDENTIAL_PROVIDER_MTLS_SOURCE</code> | String | <code>none</code> | Where the credential provider&#39;s mTLS material comes from: &#34;secret&#34; (the Secret named by CREDENTIAL&#95;PROVIDER&#95;SECRET&#95;NAMESPACE and &#95;NAME), or &#34;none&#34;. Exactly one source is used; there is no fallback between them. Material that is absent or unusable means no client certificate is presented and the provider&#39;s certificate is verified against the system trust store |
| <code>CREDENTIAL_PROVIDER_SECRET_NAME</code> | String | empty | Name of the Secret holding the credential provider mTLS certificate, key, and CA |
| <code>CREDENTIAL_PROVIDER_SECRET_NAMESPACE</code> | String | empty | Namespace of the Secret holding the credential provider mTLS certificate, key, and CA |
| <code>HTTP_CALLOUT_MAX_RESPONSE_BYTES</code> | Integer | <code>1048576</code> | Maximum response body bytes read by HTTP callouts; a non-positive value falls back to 1048576 bytes (1 MiB) |
| <code>IDENTITY_PROVIDER_URL</code> | String | empty | Base URL of the credential provider API. The client fails every credential lookup while it is unset |
| <code>STS_CACHE_MAX_SIZE</code> | Integer | <code>100000</code> | Maximum number of cached credential provider STS credentials; a non-positive value falls back to the default |
| <code>TOKEN_CACHE_MAX_SIZE</code> | Integer | <code>100000</code> | Maximum number of cached credential provider API keys; a non-positive value falls back to the default |
| <code>TOKEN_CACHE_TTL</code> | Duration | <code>15m0s</code> | Fallback time-to-live for cached credential provider API keys, used when the provider&#39;s response omits cacheExpiresInSeconds; a non-positive value disables caching |

<!-- END GENERATED ENVIRONMENT VARIABLES -->

Set `CREDENTIAL_PROVIDER_MTLS_SOURCE` through `epe.credentialProvider.mtls.source`, which the chart always renders explicitly. An unrecognized source fails startup and is rejected by the chart. When the source is `secret`, both `epe.credentialProvider.mtls.secret.namespace` and `.name` are required by the chart and binary. They are ignored for other sources.

The credential client draws its mTLS material from the one source named by `CREDENTIAL_PROVIDER_MTLS_SOURCE`, never from a chain of them; whenever that source has no usable material the client presents no certificate and verifies the provider against the system trust store. See the [credential provider contract](credential-provider.md) for its request and caching behavior.

## Scaling and availability

The default single replica and `minAvailable: 1` PDB provide no disruption headroom. Raise replicas and set a compatible PDB before planned maintenance. When HPA is enabled, its CPU utilization metric is based on requests. EPE keeps compiled profiles in memory per Pod; each replica independently watches the Kubernetes API and serves the same policy objects.

Audit queues, credential calls, and plugin execution are local to each Pod. Scaling can reduce queue pressure and request latency, but it does not provide audit delivery persistence or retries. For operational signals, see [EPE observability](epe-observability.md).

## See also

- [Agentio configuration](agentio-configuration.md)
- [EPE observability](epe-observability.md)
- [EPE admin API](epe-admin-api.md)
- [Configure EPE audit events](../tasks/configure-epe-audit.md)
