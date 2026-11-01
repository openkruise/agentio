# Credential Provider Contract

EPE's `tokenTransformation` action injects or re-signs credentials on egress requests so that long-lived secrets never enter the sandbox. The credentials themselves come from a **credential provider**: an HTTP service that EPE calls at request time to exchange a sandbox's identity for a short-lived API key or STS triplet.

The credential provider is an **extension point, not a fixed backend**. Any service that implements the contract below works; integrations that target a specific cloud vendor (for example an Alibaba Cloud-backed provider) are implementations of this same contract. EPE ships the client side only (`extensions/epe/pkg/credential`).

Configure a policy consumer with [Transform outbound credentials](../tasks/transform-outbound-credentials.md). For the `SecurityProfile` action fields, credential-reference forms, and provider parameter expressions, see the [SecurityProfile reference](security-profile.md).

For OAuth2, [Configure OAuth credential isolation](../tasks/broker-oauth-credentials.md) describes the separate device-session integration. It reuses the default credential connection and trusted Sandbox identity, but calls the service's device-session APIs rather than `GetResourceCredential`.

## Request flow

```text
sandbox ──> egress gateway ──ext_proc──> EPE ──HTTPS/mTLS──> credential provider
                                          │
                                          └─ injects apiKey / signs with STS
```

1. ztunnel sends the caller's identity in the HBONE CONNECT header `x-agentio-sandbox-metadata`. The gateway captures it as `filter_state['agentio.sandbox.metadata']`:

   ```text
   agent-identity.access-token=...,agent-identity.sandbox-client-id=...
   ```

   Values are percent-encoded; `+` remains literal. Set Helm `sandbox.enabled=true` to enable the sidecar Sandbox Manager. Enable `SANDBOX_TOKEN_ENABLED=true` on the ztunnel container and mount the token producer's directory at `/var/opt/sandbox/agent-token` (or set `SANDBOX_TOKEN_PATH`). Token files still contain JSON with `accessToken` and `sandboxClientId`. The Sandbox switch does not enable token reading or supply credentials automatically. Ambient Sandbox Manager integration is not supported.

   For older gateways and ztunnels, EPE accepts the existing base64/raw JSON `filter_state['sandbox.token']` only when the metadata attribute is absent. Present but malformed metadata does not fall back to a legacy identity.

2. When a matched rule carries `tokenTransformation` with a `credentialRef.credentialProvider`, EPE calls the provider using `accessToken` as the bearer credential and `sandboxClientId` as the resource being acted for.

3. The provider authenticates the caller (mTLS client certificate and the bearer token), authorizes the `(resource, provider name)` pair, and returns the credential.

## Wire contract

EPEConfig supports multiple named credential services and selects the default through `defaultProviders.credentialProvider`. SecurityProfile's existing `name` field continues to select the remote credential configuration. Per-rule extension provider references are deferred to future SecurityProfile API work.

EPE converts `IDENTITY_PROVIDER_URL` (chart value `epe.credentialProvider.url`) and its related environment settings into a default EPEConfig containing a credential provider named `agentio-default-credential-provider` and the corresponding `defaultProviders` selection. An unset URL generates no provider. Base and primary ConfigMaps overlay this default configuration; provider lists merge by name, with same-name entries replaced in full. Adding only HTTPCallout providers preserves the environment credential provider. An explicit `extensionProviders: []` clears the inherited list, and deleting a ConfigMap restores the lower layer. The registry consumes only the resulting configuration; the environment-generated name is ordinary and can be overridden like any other. See [EPE configuration](epe-configuration.md#watched-epeconfig) for default selection and clearing semantics. The environment variable's name predates the credential-provider naming and is retained for compatibility. EPE sends:

```text
POST <IDENTITY_PROVIDER_URL>
Authorization: Bearer <accessToken>
X-Api-Action-Name: GetResourceCredential
Content-Type: application/json
```

Request body:

```json
{
  "resourceId": "<sandboxClientId>",
  "credentialProviderName": "<SecurityProfile credentialRef.credentialProvider.name>",
  "credentialType": "apiKey" | "stsToken",
  "extraMetadata": { "<parameter>": <any JSON value> }
}
```

- `credentialProviderName` selects a provider configuration on the server side; it is the `name` from the SecurityProfile's `credentialRef.credentialProvider`.
- `extraMetadata` carries the rule's `credentialProvider.parameters` after CEL evaluation (values may be strings, lists, or any JSON-compatible value). Omitted when empty.

Success response — `200 OK` with a JSON body. Exactly one of the credential fields is expected, matching the requested `credentialType`:

```json
{ "requestId": "...", "apiKey": "sk-...", "cacheExpiresInSeconds": 600 }
```

`cacheExpiresInSeconds` is optional; see [caching semantics](#caching-semantics).

```json
{
  "requestId": "...",
  "stsToken": {
    "accessKeyId": "...",
    "accessKeySecret": "...",
    "securityToken": "...",
    "expiration": "2026-01-01T00:00:00Z"
  }
}
```

- `stsToken.expiration` is RFC 3339 and optional; when present it bounds the cache lifetime (see below).
- An empty `apiKey`, or an `stsToken` missing any of the three key fields, is treated as a failure by EPE.

Failure response — any non-200 status. The body is logged and surfaced in the error. EPE does not retry; the failure resolves through the matched rule's `failStrategy` (block the request or pass it through unmodified).

## Transport security

`CREDENTIAL_PROVIDER_MTLS_SOURCE` selects the TLS source for the environment-derived default provider. It supports `none` and `secret`; file sources are configured through EPEConfig.

| Source | Where the material comes from |
| --- | --- |
| `secret` | The Secret named by `CREDENTIAL_PROVIDER_SECRET_NAMESPACE` / `CREDENTIAL_PROVIDER_SECRET_NAME`, data keys `ca.crt` and `tls.crt`/`tls.key` (or legacy `client.crt`/`client.key` when both `tls.*` keys are absent). Both variables are required. |
| `none` (default) | No client certificate; HTTPS uses the system trust store. |

Within the chosen source the client identity and the trust anchors are independent: a source may supply anchors without an identity, or an identity without anchors. Material that is absent or unusable means EPE presents no client certificate and verifies the provider against the system trust store; it is never a startup failure. A misconfigured source fails startup: an unrecognized `CREDENTIAL_PROVIDER_MTLS_SOURCE` value, or `secret` without both a namespace and a name.

EPE watches sources referenced by the effective configuration, so material that appears or rotates after startup takes effect without a restart. A Secret that does not exist yet leaves no client identity for the optional environment-derived provider while EPE watches for its creation. Secret watches use the explicitly referenced namespace, defaulting to the EPE system namespace (`--namespace`, defaulting to `POD_NAMESPACE`) when omitted, and are filtered by `metadata.name`. The EPE ServiceAccount needs `list`/`watch` permission for those Secrets, granted through a Role and RoleBinding in each referenced namespace; the Role can be restricted with `resourceNames`. With the default `epe.secretWatchScope: system`, the chart grants Secret access only in its installation namespace, so access to other namespaces must be granted separately. With `cluster`, the EPE ClusterRole grants Secret `list/watch` across all namespaces, which also covers provider certificate watches. When no provider references a Secret, EPE makes no provider-certificate Secret requests. TLS 1.2 is the minimum in every case.

Provider TLS Secret synchronization does not block EPE startup. Missing Secrets or denied API access leave required-TLS providers unavailable; `tls.optional: true` providers retain the optional behavior described above. EPE retries Secret access in the background and reloads providers when material becomes available. Changing references stops unused watches and starts watches for the new references.

These settings become ordinary EPEConfig TLS fields: `caSecretRef` and `clientCertificateSecretRef`, each with an optional `namespace` that defaults to the EPE system namespace. CA references read `ca.crt`; client references read `tls.crt` and `tls.key`. When neither of those two keys exists, client references read the legacy `client.crt` and `client.key` pair instead, including for environment-derived default providers. If either standard key exists, EPE uses only the standard pair: an incomplete, empty, or invalid pair does not fall back to the legacy entries. Key names cannot be configured. Missing or empty entries are unavailable material, subject to `tls.optional` as described below.

For server-only TLS, omit client identity fields. An HTTPS URL without TLS settings uses system roots. To use a ConfigMap trust bundle, place the PEM CA certificates in its fixed `data["ca.crt"]` entry and configure:

```yaml
tls:
  caConfigMapRef:
    name: provider-ca
    namespace: security-system
```

The namespace defaults to the EPE system namespace. EPE watches this ConfigMap for creation, updates, and deletion. No client certificate or `optional: true` setting is required for server-only TLS.

Both `credentialProvider.tls` and `httpCallout.tls` also accept PEM file paths in EPEConfig:

```yaml
extensionProviders:
- name: corporate
  credentialProvider:
    url: https://credentials.example
    tls:
      caCertificateFile: /etc/epe/certs/ca.crt
      clientCertificateFiles:
        certificateFile: /etc/epe/certs/tls.crt
        privateKeyFile: /etc/epe/certs/tls.key
defaultProviders:
  credentialProvider: corporate
```

Paths refer to files inside the EPE container; the deployment must provide them. EPEConfig does not create volume mounts. Changing a configured path updates its watch, and file contents reload on filesystem events with a 10-second polling backstop, including when a directory appears after startup. The CA source is a oneof: `caSecretRef`, `caConfigMapRef`, or `caCertificateFile`. The client identity source is a separate oneof: `clientCertificateSecretRef` or `clientCertificateFiles`, whose `certificateFile` and `privateKeyFile` are both required. Each group permits at most one source; CA and client identity sources can be mixed independently.

Environment defaults set `tls.optional: true`: unavailable or invalid client material is dropped, and unavailable or invalid CA material falls back to system roots. Explicit EPEConfig TLS sources are strict unless marked optional; invalidating a required source makes the provider unavailable and prevents serving its cached credentials.

`CREDENTIAL_PROVIDER_INSECURE_SKIP_VERIFY=true` is an explicit exception for trusted test environments: it disables provider server-certificate verification while retaining any configured client certificate. It exposes the bearer token and returned credentials to an on-path attacker and must not be used in production.

Providers should require the client certificate and treat the bearer `accessToken` as the per-sandbox authorization, not as the only authentication factor.

## Caching semantics

Providers must tolerate credential reuse within a bounded window; EPE caches per `(providerName, resourceId, hash(extraMetadata))`:

Each registered credential provider has its own caches. `TOKEN_CACHE_TTL`, `TOKEN_CACHE_MAX_SIZE`, and `STS_CACHE_MAX_SIZE` are read at process startup and apply to all credential providers, including those added later through EPEConfig. Capacity limits are per provider, not a shared process-wide budget. Changing these environment variables requires restarting EPE; EPEConfig does not expose cache settings.

| Credential | Lifetime | Size bound |
| --- | --- | --- |
| `apiKey` | `cacheExpiresInSeconds` when the response carries it, else `TOKEN_CACHE_TTL` (chart default `15m`) | `TOKEN_CACHE_MAX_SIZE` |
| `stsToken` | until `stsToken.expiration` minus 5 minutes (uncacheable without it), additionally capped by a positive `cacheExpiresInSeconds` when supplied | `STS_CACHE_MAX_SIZE` |

`cacheExpiresInSeconds` is an optional response field naming how many seconds the credential may be cached. For `apiKey`, it takes precedence over `TOKEN_CACHE_TTL` and is applied verbatim — no safety margin is subtracted, unlike `stsToken.expiration`. Absent, `null`, zero, and negative all mean "no opinion": API keys use `TOKEN_CACHE_TTL`, while STS keeps its expiration-based lifetime.

It must be a JSON **integer** (`600`), not a string (`"600"`) and not fractional (`600.5`). EPE decodes it as part of the credential response, so a non-integer value fails that decode and the credential becomes unreachable — the request then follows `failStrategy` instead of merely losing the caching hint. Providers must not quote this field.

Practical consequences:

- Without an external invalidation trigger, key rotation on the provider side becomes visible to EPE only after the cache entry expires. Returning `cacheExpiresInSeconds` is the direct way to control this per credential; `TOKEN_CACHE_TTL` is the deployment-wide fallback for providers that do not.
- A non-positive `TOKEN_CACHE_TTL` is honoured rather than corrected: it disables the fallback lifetime, so responses without `cacheExpiresInSeconds` are not cached at all.
- Returning `expiration` on STS responses is strongly recommended — STS responses without it are never cached. A positive `cacheExpiresInSeconds` can shorten STS reuse further, including while a provider replica catches up to its Secret cache.

## External cache invalidation

EPE exposes `credential.Client.InvalidateCredentials` and [`POST /cache/credentials/invalidate`](epe-admin-api.md#credential-cache-invalidation) for provider-wide invalidation. API-key, STS, and OAuth2 Resource entries are removed, across all resources, metadata, caller, and scope variants. The next request fetches credentials using that request's bearer token. An invalidation never performs background prefetch and does not require a Kubernetes CRD or a particular credential-provider implementation.

### Optional short-TTL window

Invalidation always clears the affected caches. By default, new cache entries are capped at 5 seconds for 30 seconds after invalidation. Both durations are configurable using Go duration syntax:

```console
CREDENTIAL_CACHE_INVALIDATION_WINDOW=30s
CREDENTIAL_CACHE_INVALIDATION_MAX_TTL=5s
```

For Helm deployments, set the same variables through the existing `epe.env` map:

```yaml
epe:
  env:
    CREDENTIAL_CACHE_INVALIDATION_WINDOW: "30s"
    CREDENTIAL_CACHE_INVALIDATION_MAX_TTL: "5s"
```

The window defaults to `30s` and the maximum TTL to `5s`. The policy is enabled only when **both are positive**; a non-positive value for either disables TTL adjustment, not invalidation. Each invalidation for that provider restarts the window. When a response is cached during the window, its lifetime is the smaller of the normal lifetime and the configured maximum TTL. At and after the window's end, new entries use their normal lifetime. Entries already cached keep their expiry. No refresh markers or additional provider response fields are required.

This window limits how long a response from a lagging provider replica is cached while replicas converge. It does not guarantee freshness: a replica still serving old credentials after the window can have those credentials cached for the normal lifetime. Size the window for the deployment's propagation delay.

These are upper bounds: shorter provider lifetimes and disabled caching remain unchanged. STS entries still require a usable expiration and retain the 5-minute safety margin. Responses from fetches started before an invalidation cannot refill the affected cache, even if they finish after a newer fetch. Already in-flight requests can still use their fetched credentials; this mechanism does not revoke credentials or retry requests. Fetch failures retain the rule's existing `failStrategy` behavior.

### Integrating a trigger

In-process integrations call the same `extensionprovider.Registry` used by the filters. `providerName` is the remote `credentialProviderName`, not an `EPEConfig.extensionProviders[].name`. The registry invalidates that remote name across all current credential-provider connections and aggregates removed counts; replaced configuration versions remain isolated from current caches.

```go
result, err := registry.InvalidateCredentials(credential.InvalidationRequest{
    ProviderName: "my-provider",
})
```

Direct users of `credential.Client` can call its `InvalidateCredentials` method to affect only that client. `credential.NewClient` accepts `credential.WithInvalidationCachePolicy(window, maxTTL)` to override the 30s/5s defaults, including setting both to zero to disable TTL adjustment. The EPE registry passes the environment settings explicitly when constructing each client.

Adapters for watches, message queues, webhooks, or manual tools are supplied by the integrator. EPE does not register these external event sources. Adapters map source identities to the exact provider names sent to `GetResourceCredential` and deliver invalidations to every EPE replica. Replayed notifications invalidate again and restart the configured window. After a missed event or reconnect, an adapter can invalidate each affected provider.

Caches and invalidation state are process-local and empty after restart. Provider invalidation state is reclaimed lazily after its short-TTL window ends and all in-flight credential fetches finish: later invalidations sweep expired idle states, and completed fetches check their own provider state. This API does not provide cross-replica delivery, persistence, or a fixed end-to-end freshness deadline.

## Environment variable reference

| Variable | Meaning |
| --- | --- |
| `IDENTITY_PROVIDER_URL` | Provider endpoint; unset means provider-backed rules fail through `failStrategy` |
| `CREDENTIAL_PROVIDER_MTLS_SOURCE` | The single source of mTLS material: `none` (default) or `secret` |
| `CREDENTIAL_PROVIDER_SECRET_NAMESPACE` / `_NAME` | Secret holding mTLS material; both required by the `secret` source |
| `TOKEN_CACHE_TTL`, `TOKEN_CACHE_MAX_SIZE` | API-key cache tuning; `TOKEN_CACHE_TTL` is the fallback lifetime for responses without `cacheExpiresInSeconds` |
| `STS_CACHE_MAX_SIZE` | STS cache tuning |
| `CREDENTIAL_CACHE_INVALIDATION_WINDOW` | Duration of the optional short-TTL window after invalidation; default `30s`; non-positive disables the policy |
| `CREDENTIAL_CACHE_INVALIDATION_MAX_TTL` | Maximum credential cache lifetime within that window; default `5s`; both durations must be positive to enable the policy |

## Implementing a provider

A conforming provider must:

1. Serve `POST` on a single HTTPS endpoint and read `X-Api-Action-Name: GetResourceCredential`.
2. Authenticate the mTLS client certificate and the `Authorization: Bearer` token; authorize the `(resourceId, credentialProviderName)` pair.
3. Return `200` with `apiKey` or a complete `stsToken` per the requested `credentialType`; return a non-200 status with a diagnostic body otherwise.
4. Issue short-lived credentials and set `stsToken.expiration`.
5. Treat `extraMetadata` as provider-defined routing/scoping input — EPE passes it through verbatim and never interprets it.
