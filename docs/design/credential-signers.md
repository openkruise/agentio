# Credential signers and Secret references — internals

> Design note. This page records signer behavior and Secret reference internals behind [Replace outbound credentials](../tasks/transform-outbound-credentials.md). The provider HTTP contract and cache lifetime rules are in [Credential provider](../reference/credential-provider.md).

## ApiKey signer

`ApiKey` is the default signer. Prefer `targetHeaders` plus one shared `value`: `targetHeaders.names` selects known headers and `targetHeaders.cel` may select names from the original request. A selector that returns no names is a successful no-op and skips the credential provider.

`value.template` can read `.Token`, `.Header`, `.Request`, `.Pod`, `.Profile`, `.Rule`, and `.Inputs`; `value.cel` additionally exposes `token`, `header.name`, and `header.value`.

The legacy `targetHeader`, `valueTemplate`, and optional `when` form remains supported when `targetHeaders` is omitted.

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

## AliyunSTS signer

`AliyunSTS` uses the STS triplet to re-sign four detected formats:

- ACS3/V3: the trimmed `Authorization` header starts with `ACS3-HMAC-SHA256` followed by a space.
- V1-ROA: that header starts with `acs` followed by a space and contains `:`.
- OSS V4: that header starts with `OSS4-HMAC-SHA256` followed by a space.
- V1-RPC: recognized through query parameters only when the raw query parses and contains non-empty `Signature` and `AccessKeyId` values plus exactly `SignatureMethod=HMAC-SHA1`.

`apiKey` is ignored for this signer; use the provider contract's `stsToken` response or the STS Secret fields. Any other Aliyun request format is undetectable and resolves through `failStrategy` before a credential is fetched.

## Secret references

`credentialRef` is a union: set exactly one of `secret` or `credentialProvider`.

`secret` reads a shared cache, scoped by default to the EPE system namespace (`--namespace`, defaulting to `POD_NAMESPACE`). Requests do not call the Kubernetes API; watch events apply Secret updates and deletions. `ApiKey` expects data key `apiKey`; `AliyunSTS` expects `accessKeyId`, `accessKeySecret`, and `securityToken`. A missing Secret, missing data key, invalid header value, provider failure, or signer failure follows `failStrategy`.

For `secret.namespace`, EPE uses the reference namespace, then the `SecurityProfile` namespace, then the selected Pod namespace. A `GlobalSecurityProfile` therefore falls back to the selected Pod namespace. With the default scope, the resolved namespace must equal the EPE system namespace; references outside it fail without an API lookup or fallback to a same-named Secret. Business-namespace profiles using centrally managed credentials must explicitly set `secret.namespace` to the EPE system namespace.

The chart grants Secret `get/list/watch` access through a Role in the EPE installation namespace. Custom deployments need `list/watch` for Secrets in their configured EPE system namespace; `get` alone or a Role restricted to individual `resourceNames` cannot support this namespace-wide cache. EPE waits for initial cache synchronization before starting and becoming ready; missing permissions keep it unready while the informer retries.

To read token credentials in other namespaces, explicitly set `--secret-watch-scope=cluster` (Helm: `epe.secretWatchScope: cluster`); Helm adds global Secret `list/watch` to the existing EPE ClusterRole. It preserves reference namespace resolution and does not silently fall back to the scoped cache on permission errors.

Secret watch updates are eventually consistent. After initial synchronization, a watch interruption retains the last cached contents while the informer reconnects; this is not an immediate credential or RBAC revocation mechanism.

`credentialProvider` requires a valid sandbox token and passes its evaluated `parameters` as `extraMetadata`. Every parameter must set exactly one of `value`, `template`, or `cel`; CEL values must be JSON-compatible and may not be null. The provider-reference `namespace` field is currently ignored.

## Failure behavior

`failStrategy: Block` is the default and returns a generic HTTP 403. `Allow` and `Ignore` forward the request unmodified when the transformation cannot be applied. Provider calls use a 10-second HTTP timeout and are not retried by EPE.

EPE trims surrounding whitespace from credential fields and rejects embedded control bytes before creating header mutations. This prevents response errors and header injection, but it also means malformed credential material blocks or passes through according to `failStrategy`.

## Cache boundaries

API keys are cached by provider name plus a hash of evaluated metadata and the sandbox resource ID; changing a metadata value changes the cache key. A response that carries `cacheExpiresInSeconds` sets that entry's lifetime directly. Otherwise the deployment's `TOKEN_CACHE_TTL` (chart default `15m`) applies; unset values use the process defaults of fifteen minutes and `TOKEN_CACHE_MAX_SIZE=10000`. A non-positive `TOKEN_CACHE_TTL` is honoured and disables the fallback lifetime, so every response without `cacheExpiresInSeconds` reaches the provider again; a non-positive `TOKEN_CACHE_MAX_SIZE` falls back to the process default, because a zero-capacity cache cannot be constructed.

STS credentials are cached only when the provider supplies an RFC 3339 `expiration`; EPE expires an entry five minutes before that timestamp. `STS_CACHE_MAX_SIZE` bounds this cache.

The canonical lifetime, capacity, and invalidation semantics are in [Credential provider caching](../reference/credential-provider.md#caching-semantics). Returned API keys and STS credentials live in EPE process memory for their cache lifetime, so keep credentials short-lived and do not place them in profile inputs, ConfigMaps, logs, policy manifests, or audit templates.
