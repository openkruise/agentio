# Transform outbound credentials

Use `SecurityProfile.spec.rules[].actions.tokenTransformation` to replace a sandbox-supplied credential with an API key or sign an outbound request with Aliyun STS credentials. Egress Policy Enforcer (EPE) obtains the credential after a rule matches, so a long-lived provider credential does not need to enter the sandbox.

This task configures the built-in `ApiKey` signer with a credential provider. The provider HTTP contract is [Credential provider](../reference/credential-provider.md); policy fields are defined by the [SecurityProfile reference](../reference/security-profile.md).

## Before you begin

Enable EPE and configure `epe.credentialProvider.url` with the provider's single HTTPS endpoint. This task assumes Agentio is already installed for the selected workload, so update that release with `--reuse-values`; without it, Helm can replace the release's routing, gateway, data-plane, and image settings with chart defaults. From the repository root:

```console
$ tee epe-provider-values.yaml >/dev/null <<'EOF'
epe:
  mode: managed
  credentialProvider:
    url: https://credentials.example.net/v1/resource-credential
  env:
    STS_CACHE_MAX_SIZE: "100000"
EOF

$ helm upgrade agentio ./manifests/charts/agentio \
    --namespace agentio-system \
    --reuse-values \
    --values epe-provider-values.yaml
```

For a new installation, provide the complete installation values instead of this EPE-only fragment; [Get started with EPE](../getting-started/epe.md#enable-epe) shows the update path after an Agentio release exists.

Replace the example URL with a provider endpoint reachable from the EPE Pods. The chart maps it to `IDENTITY_PROVIDER_URL`, sets the API-key cache to `TOKEN_CACHE_TTL=15m` and `TOKEN_CACHE_MAX_SIZE=10000`, and the example makes the default STS cache capacity explicit. See [EPE configuration](../reference/epe-configuration.md#credential-provider-and-webhook-environment-variables) for the complete Helm and environment surface.

The provider must authenticate the EPE client and authorize the sandbox identity carried in Envoy `filter_state['agentio.sandbox.metadata']` (or legacy `filter_state['sandbox.token']`). A missing or malformed identity cannot serve a provider-backed rule. See the [credential provider contract](../reference/credential-provider.md#request-flow) for token file and ztunnel settings.

This example matches `https://api.example.com`, so the selected egress gateway must terminate TLS for `api.example.com`; otherwise the connection stays on the gateway's TCP path and never reaches EPE's HTTP filter chain. Configure `egressGateways[].tlsTermination.includeHosts`, configure the MITM signing CA, and make the calling workload trust that CA as described in [TLS termination for HTTPS inspection](../reference/agentio-configuration.md#tls-termination-for-https-inspection).

## Apply a provider-backed API-key transformation

The complete policy below matches calls from selected Pods to `api.example.com`, obtains a short-lived API key from provider configuration `example-api`, and replaces the `Authorization` header with `Bearer <key>`. Its provider metadata is rendered per request; it is not a Kubernetes Secret reference.

```yaml
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: example-api-credentials
  namespace: agent-demo
spec:
  selector:
    matchLabels:
      app: agent
  inputs:
    - name: routing
      inline:
        tenant: production
  rules:
    - name: transform-example-api
      match:
        - domains:
            - api.example.com
          schemes:
            - https
          paths:
            - type: Prefix
              value: /v1/
      actions:
        tokenTransformation:
          type: ApiKey
          failStrategy: Block
          credentialRef:
            credentialProvider:
              name: example-api
              parameters:
                audience:
                  value: example-api
                namespace:
                  template: "{{ .Pod.Namespace }}"
                tenant:
                  cel: inputs.routing.tenant
          apiKey:
            targetHeaders:
              names:
                - Authorization
            value:
              template: "Bearer {{ .Token }}"
```

Apply it with `kubectl apply -f example-api-credentials.yaml`. The source identity's bearer token and sandbox client ID travel only from EPE to the configured provider; neither is available to CEL nor to policy templates.

## Verify the transformation

First confirm that Kubernetes accepted the exact typed provider reference:

```console
$ kubectl get securityprofile example-api-credentials \
    --namespace agent-demo --output yaml
```

Then send a request from a selected sandbox through the egress gateway. Verify on the trusted upstream or a controlled test endpoint that it receives the generated `Authorization` value, not the sandbox's original value. Do not echo credentials in shared logs.

Repeat the request with the same provider name, sandbox client ID, and rendered metadata. An API-key cache hit avoids another provider request until the entry's lifetime expires or the bounded LRU evicts it. That lifetime is the response's `cacheExpiresInSeconds` when present, otherwise `TOKEN_CACHE_TTL`. Changing a metadata value changes the cache key.

## Credential sources, signers, and failure behavior

### Unwrap a JSON credential and replace placeholders

If the provider returns an API-key string containing `{"apiKey":"real-key"}`, use `json.decode` to extract the named field while preserving each selected header's prefix and suffix:

```yaml
apiKey:
  targetHeaders:
    cel: |-
      request.headers.filter(
        name,
        request.headers[name].contains("aaa_placeHolder")
      )
  value:
    cel: |-
      cel.bind(
        decoded,
        json.decode(token),
        header.value.replace("aaa_placeHolder", decoded["apiKey"])
      )
```

For example, `Authorization: Bearer aaa_placeHolder` becomes `Authorization: Bearer real-key`, while `X-API-Key: aaa_placeHolder` becomes `X-API-Key: real-key`. Headers without the placeholder are not selected. The JSON field must exist and contain a string; invalid JSON or a missing or non-string field follows `failStrategy`.

The same selector can use a Go template instead of `value.cel`:

```yaml
value:
  template: |-
    {{- $decoded := mustFromJson .Token -}}
    {{- .Header.Value | replace "aaa_placeHolder" $decoded.apiKey -}}
```

Choose exactly one value source. `mustFromJson` rejects invalid JSON; the existing `fromJson` helper retains its permissive behavior for templates that explicitly handle plain-text tokens.

### Credential and signer behavior

`credentialRef` is a union: set exactly one of `secret` or `credentialProvider`.

- `secret` reads a shared KRT cache, scoped by default to the EPE system namespace (`--namespace`, defaulting to `POD_NAMESPACE`). Requests do not call the Kubernetes API; watch events apply Secret updates and deletions. `ApiKey` expects data key `apiKey`; `AliyunSTS` expects `accessKeyId`, `accessKeySecret`, and `securityToken`. A missing Secret, missing data key, invalid header value, provider failure, or signer failure follows `failStrategy`.
- For `secret.namespace`, EPE uses the reference namespace, then the `SecurityProfile` namespace, then the selected Pod namespace. A `GlobalSecurityProfile` therefore falls back to the selected Pod namespace. With the default scope, the resolved namespace must equal the EPE system namespace. References outside it fail without an API lookup or fallback to a same-named Secret. Business-namespace profiles using centrally managed credentials must explicitly set `secret.namespace` to the EPE system namespace. The chart already grants `get/list/watch` Secret access through a Role in the EPE installation namespace, where it places EPEConfig. Custom deployments need `list/watch` for Secrets in their configured EPE system namespace; `get` alone or a Role restricted to individual `resourceNames` cannot support this namespace-wide cache. EPE waits for initial cache synchronization before starting ext_proc and becoming ready. Missing permissions keep it unready while the informer retries; health and admin endpoints remain available, and liveness stays healthy.
- To read token credentials in other namespaces, explicitly set `--secret-watch-scope=cluster` (Helm: `epe.secretWatchScope: cluster`) and Helm adds global Secret `list/watch` to the existing EPE ClusterRole. Custom deployments must grant these permissions through a ClusterRoleBinding. It preserves reference namespace resolution and does not silently fall back to the scoped cache on permission errors. The flag affects token credential Secrets; provider TLS Secrets retain their existing per-reference watches.
- Secret watch updates are eventually consistent. After initial synchronization, a watch interruption retains the last cached contents while the informer reconnects; this is not an immediate credential or RBAC revocation mechanism. Only trusted administrators should be able to author policies that reference the centrally managed credentials.
- `credentialProvider` requires a valid sandbox token and passes its evaluated `parameters` as `extraMetadata`. Every parameter must set exactly one of `value`, `template`, or `cel`; CEL values must be JSON-compatible and may not be null. The provider-reference `namespace` field is currently ignored.
- `ApiKey` is the default signer. Prefer `targetHeaders` plus one shared `value`: `names` selects known headers and `cel` may select names from the original request. A selector that returns no names is a successful no-op and skips the credential provider. `value.template` can read `.Token`, `.Header`, `.Request`, `.Pod`, `.Profile`, `.Rule`, and `.Inputs`; `value.cel` additionally exposes `token`, `header.name`, and `header.value`. The legacy `targetHeader`, `valueTemplate`, and optional `when` form remains supported when `targetHeaders` is omitted.
- `AliyunSTS` uses the STS triplet to re-sign four detected formats. It recognizes ACS3/V3 when the trimmed `Authorization` header starts with `ACS3-HMAC-SHA256` followed by a space, V1-ROA when that header starts with `acs` followed by a space and contains `:`, and OSS V4 when it starts with `OSS4-HMAC-SHA256` followed by a space. If no header scheme matches, it recognizes V1-RPC through query parameters only when the raw query parses and contains non-empty `Signature` and `AccessKeyId` values plus exactly `SignatureMethod=HMAC-SHA1`. `apiKey` is ignored for this signer; use the provider contract's `stsToken` response or the STS Secret fields. Any other Aliyun request format is undetectable and resolves through `failStrategy` before a credential is fetched.
- `failStrategy: Block` is the default and returns a generic HTTP 403. `Allow` and `Ignore` forward the request unmodified when the transformation cannot be applied. Provider calls use a 10-second HTTP timeout and are not retried by EPE.

EPE trims surrounding whitespace from credential fields and rejects embedded control bytes before creating header mutations. This prevents response errors and header injection, but it also means malformed credential material blocks or passes through according to `failStrategy`.

## Provider transport, caching, and secret boundaries

The credential provider client uses TLS 1.2 or later and normally verifies the provider certificate. `CREDENTIAL_PROVIDER_MTLS_SOURCE` selects exactly one source of mTLS material — `none` (the default, using system trust roots without a client certificate) or `secret` — with no fallback between them. When `secret` is selected, the Secret is watched, so material that appears or rotates later takes effect without a restart; while it is absent or unusable EPE presents no client certificate and verifies the provider against the system trust store. `CREDENTIAL_PROVIDER_INSECURE_SKIP_VERIFY=true` disables server-certificate verification; it is unsafe because an on-path attacker can read the sandbox bearer token and forge credentials. Do not use it outside tightly controlled test environments.

API keys are cached by provider name plus a hash of evaluated metadata and sandbox resource ID. A response that carries `cacheExpiresInSeconds` sets that entry's lifetime directly, overriding the configured TTL. Otherwise EPE's Helm deployment sets `TOKEN_CACHE_TTL=15m` and `TOKEN_CACHE_MAX_SIZE=10000`; unset values use the process defaults of fifteen minutes and 100000. A non-positive `TOKEN_CACHE_TTL` is honoured and disables the fallback lifetime, so every response without `cacheExpiresInSeconds` reaches the provider again; a non-positive `TOKEN_CACHE_MAX_SIZE` falls back to 100000, because a zero-capacity cache cannot be constructed. Provider-side rotation is visible after expiry or eviction.

STS credentials are cached only when the provider supplies an RFC 3339 `expiration`; EPE expires an entry five minutes before that timestamp. `STS_CACHE_MAX_SIZE` bounds this cache. Returned API keys and STS credentials live in EPE process memory for their cache lifetime, so keep credentials short-lived and do not place them in profile inputs, ConfigMaps, logs, policy manifests, or audit templates.

## Clean up

```console
$ kubectl delete securityprofile example-api-credentials --namespace agent-demo
```

Deleting the profile stops future transformations after the change reaches EPE. It does not revoke credentials already issued by the provider or clear credentials cached by a running EPE process; use short provider lifetimes and provider-side revocation for emergency response.

## See also

- [Credential provider contract](../reference/credential-provider.md)
- [SecurityProfile reference](../reference/security-profile.md)
- [EPE request context](../reference/epe-request-context.md)
