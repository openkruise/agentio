# EPE configuration

The Egress Policy Enforcer (EPE) is deployed by the Agentio chart as `agentio-epe` when `epe.mode` is `managed`. This reference separates the Helm surface from EPE process settings so operators can see which controls a normal chart upgrade can change.

## Helm values

| Value | Default | Rendered effect |
| --- | --- | --- |
| `epe.mode` | `disabled` | `managed` creates the EPE ServiceAccount, cluster RBAC, headless Service, Deployment, and PodDisruptionBudget and writes `sandboxExtProc` into `agentio-config`; `external` wires the configured external address without deploying EPE. |
| `epe.nameOverride` | `agentio-epe` | Names the Kubernetes objects and the generated ext_proc Service hostname. |
| `epe.service.grpcPort` | `9002` | Service, container, EPE `-grpc-port`, and `sandboxExtProc.port`. |
| `epe.service.healthPort`, `.metricsPort` | `9003`, `9090` | Health-probe and Prometheus listener ports. |
| `epe.image.repository`, `.name`, `.tag` | empty, `agentio-epe`, empty | EPE container image. Empty repository and tag values inherit `global.hub` and `global.tag`. |
| `epe.credentialProvider.url` | empty | Credential provider base URL, rendered as `IDENTITY_PROVIDER_URL`. Credential lookups fail while it is empty. |
| `epe.credentialProvider.mtls.source` | `files` | The one source of credential-provider mTLS material: `files`, `secret`, or `none`. Always rendered as `CREDENTIAL_PROVIDER_MTLS_SOURCE`. Any other value fails rendering. |
| `epe.credentialProvider.mtls.secretName` | empty | `source=files` only. Secret mounted at `/etc/epe/credential-provider`; empty means `<epe.nameOverride>-mtls-client-cert`. The chart never creates it. |
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
| `epe.sandboxPolicyWait` | `200ms` | Rendered as EPE `-sandbox-policy-wait`: how long a request from a known Sandbox is held while its first policy version converges. Keep it below `epe.messageTimeout` and the plugin budget (EPE validates the latter at startup). |
| `epe.auditWebhook.insecureSkipVerify` | `false` | Sets the EPE audit-webhook TLS verification flag. Keep `false` in production. |

The chart supplies the three listener ports, `epe.sandboxPolicyWait`, and `epe.auditWebhook.insecureSkipVerify` as container arguments. Use `epe.env` only for EPE environment variables. Other Go flags such as `--enable-pprof` or `--tls-cert-path` remain binary-only unless you add container arguments through an authorized deployment customization.

## Rendered Kubernetes behavior

The Service is headless (`clusterIP: None`) and exposes TCP ports named `extproc` (`epe.service.grpcPort`), `health` (`epe.service.healthPort`), and `metrics` (`epe.service.metricsPort`). Its selector matches `app.kubernetes.io/name: <epe.nameOverride>`. The Deployment opts out of sidecar injection, adds Prometheus scrape annotations for port 9090, and configures gRPC liveness and readiness probes against the health port. Liveness starts after five seconds and runs every ten seconds; readiness starts after three seconds and runs every five seconds.

The chart grants the ServiceAccount `get/list/watch` on `SecurityProfile` and `GlobalSecurityProfile`, but only `get` on their status subresources. It also grants `get/list/watch` on CRDs, ConfigMaps, and Secrets. EPE needs the CRD watch before its delayed profile informers can synchronize; without it the process cannot complete startup.

With the default `epe.credentialProvider.mtls.source=files`, the Pod mounts an optional Secret at `/etc/epe/credential-provider` — `epe.credentialProvider.mtls.secretName`, defaulting to `<epe.nameOverride>-mtls-client-cert`. The chart does not create that Secret. That mount is for the credential-provider client; it does not enable TLS on the ext_proc listener. An empty mount leaves the credential client with no client certificate, verifying the provider against the system trust store; because the mount is watched, the Secret appearing later takes effect without a restart. Setting the source to `secret` or `none` omits the volume and its mount entirely.

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
| `--grpc-port` | `9002` | ext_proc gRPC listener. The chart sets it from `epe.service.grpcPort`. |
| `--grpc-health-port` | `9003` | gRPC health listener used by Kubernetes probes. |
| `--metrics-port` | `9090` | HTTP listener serving only `/metrics`. |
| `--admin-addr` | `127.0.0.1:15000` | Admin HTTP bind address. |
| `--enable-debug` | `true` | Registers the `/debug/profiles` admin endpoint. |
| `--enable-pprof` | `false` | Starts Go pprof on `--pprof-addr`. |
| `--pprof-addr` | `:6060` | pprof listener address when enabled. |
| `--observe-responses` | `false` | Requests response headers through ext_proc so audit can record upstream status. |
| `--plugin-budget` | `4.5s` | Per-evaluation-phase limit; `0` disables it. Keep it below Envoy's ext_proc message timeout. |
| `--sandbox-policy-wait` | `200ms` | Bounded hold for a request from a Sandbox whose first policy version is still converging; `0` fails closed immediately. Must stay below `--plugin-budget` (checked at startup). |
| `--kubeconfig` | empty | Kubeconfig path; empty selects in-cluster configuration. |
| `--v` | `2` | Log verbosity unless `--zap-log-level` is supplied. |
| `--audit-log-buffer-size` | `4096` | Access-log queue capacity; full queues drop entries. |
| `--audit-webhook-buffer-size` | `8192` | Audit-webhook queue capacity; full queues drop events. |
| `--audit-webhook-workers` | `96` | Audit-webhook worker count. |
| `--audit-webhook-insecure-skip-verify` | `false` | Skips TLS certificate verification for every HTTPS audit webhook when explicitly enabled. |

The binary also accepts controller-runtime Zap flags, including `--zap-log-level` and `--zap-stacktrace-level`. The metrics and health listeners bind all interfaces because they are constructed from their port numbers. The chart exposes both through its headless Service. The admin listener is loopback-only by default and is not in that Service. pprof binds all interfaces by default when enabled; only enable it with an intentionally restricted bind address and network exposure.

`--sandbox-policy-wait` is the one flag that takes a position on data-plane convergence. EPE holds a request from a Sandbox the store knows while that Sandbox's policy is still `Unknown`, and releases it the moment the store publishes a usable state; a request that outlasts the window is refused with `503 epe_policy_not_ready`. The window is a courtesy, not a convergence bound: convergence is watch latency plus the collection debounce plus compilation, and watch latency has no upper bound. Size the window for availability and never derive it from `AGENTIO_KRT_DEBOUNCE`, which only coalesces events the informer already holds — no arithmetic over the debounce bounds convergence. Keep it below `--plugin-budget`: EPE validates that at startup because the budget would otherwise cancel the request context first and turn the intended 503 into a gRPC error. A Sandbox the store has not observed is an ordinary caller and is never held.

## TLS for ext_proc

Without TLS flags, EPE serves plaintext ext_proc gRPC. This is the chart's default. Agentio's `ExtProcProvider` has no client-TLS fields, and the generated gateway ext_proc cluster is plaintext HTTP/2 with no TLS transport socket. Consequently, the Agentio-generated gateway cannot connect to an EPE listener after server TLS is enabled. Enabling only the EPE listener flags breaks the ext_proc connection and, with the default `failureModeAllow: false`, fails gateway requests closed. End-to-end ext_proc TLS currently requires a custom data-plane/xDS integration or a trusted intermediary that accepts the gateway's plaintext HTTP/2 connection and establishes TLS to EPE; neither is part of the chart or `AgentioConfig` surface.

| Flag | Requirement and behavior |
| --- | --- |
| `--tls-cert-path`, `--tls-key-path` | Must be set together. They load the serving certificate and key from PEM files and enable server TLS. The certificate/key pair hot-reloads after file events and a 10-second polling backstop. |
| `--tls-ca-path` | Requires the serving certificate and key. It enables required, CA-verified client certificates; the CA bundle is re-read on every handshake. |
| `--peer-spiffe-ids` | Comma-separated exact SPIFFE IDs. Requires `--tls-ca-path` and restricts verified client certificate URI SANs to the supplied IDs. |

Invalid combinations, unreadable initial certificate/key files, or an invalid initial CA bundle fail EPE startup. A failed later certificate reload keeps the last good certificate. Neither the chart's optional credential-client Secret nor `epe.env` configures these flags directly.

## Credential-provider and webhook environment variables

`IDENTITY_PROVIDER_URL`, `TOKEN_CACHE_TTL=15m`, and `TOKEN_CACHE_MAX_SIZE=10000` are set by the chart. `TOKEN_CACHE_TTL` applies only to `apiKey` responses that omit `cacheExpiresInSeconds`; see [caching semantics](credential-provider.md#caching-semantics). The `CREDENTIAL_PROVIDER_*` mTLS variables come from the typed `epe.credentialProvider.mtls` values described below. Everything else uses `epe.env` (or a non-chart deployment):

The following table is generated from EPE's credential-provider, token-cache, STS-cache, and audit-webhook registrations. It shows binary defaults; in particular, the chart sets `TOKEN_CACHE_MAX_SIZE=10000` while the binary defaults to `100000`.

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
| <code>CREDENTIAL_PROVIDER_CA_CERT_PATH</code> | String | <code>/etc/epe/credential-provider/ca.crt</code> | Path to the CA certificate used to verify the credential provider&#39;s server certificate |
| <code>CREDENTIAL_PROVIDER_CLIENT_CERT_PATH</code> | String | <code>/etc/epe/credential-provider/client.crt</code> | Path to the client certificate presented to the credential provider |
| <code>CREDENTIAL_PROVIDER_CLIENT_KEY_PATH</code> | String | <code>/etc/epe/credential-provider/client.key</code> | Path to the private key for CREDENTIAL&#95;PROVIDER&#95;CLIENT&#95;CERT&#95;PATH |
| <code>CREDENTIAL_PROVIDER_INSECURE_SKIP_VERIFY</code> | Boolean | <code>false</code> | Skip verification of the credential provider&#39;s server certificate. The client certificate, when one is configured, is still presented. Intended for self-signed providers on trusted networks; any on-path attacker can then read the bearer token and forge the credential response |
| <code>CREDENTIAL_PROVIDER_MTLS_SOURCE</code> | String | <code>files</code> | Where the credential provider&#39;s mTLS material comes from: &#34;files&#34; (the CREDENTIAL&#95;PROVIDER&#95;&#42;&#95;PATH paths), &#34;secret&#34; (the Secret named by CREDENTIAL&#95;PROVIDER&#95;SECRET&#95;NAMESPACE and &#95;NAME), or &#34;none&#34;. Exactly one source is used; there is no fallback between them. Material that is absent or unusable means no client certificate is presented and the provider&#39;s certificate is verified against the system trust store |
| <code>CREDENTIAL_PROVIDER_SECRET_NAME</code> | String | empty | Name of the Secret holding the credential provider mTLS certificate, key, and CA |
| <code>CREDENTIAL_PROVIDER_SECRET_NAMESPACE</code> | String | empty | Namespace of the Secret holding the credential provider mTLS certificate, key, and CA |
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
