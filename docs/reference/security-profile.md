# SecurityProfile reference

`SecurityProfile` is a namespaced TLS connection and HTTP egress policy for selected Pods. `GlobalSecurityProfile` has the same `spec` but is cluster-scoped and can select Pods in every namespace. Agentio projects TLS connection selection into SNI policy; Egress Policy Enforcer (EPE) processes HTTP rules. `TrafficPolicy` and `GlobalTrafficPolicy` control destination routing.

The complete field schemas for both kinds are in the [SecurityProfile API reference](security-profile-api.md). This page explains the implemented evaluation behavior instead of duplicating the field reference.

## Scope, selection, and precedence

A `SecurityProfile` selects Pods only in its metadata namespace. A `GlobalSecurityProfile` has no namespace and its selector is considered for every Pod. An empty selector matches every Pod in that scope.

All matching profiles are ordered by lower `spec.priority` first (default `1000`), then earlier creation time, name, and namespace. Global and namespaced profiles are merged into that one order; an exact ordering tie places the global profile first because its namespace is empty.

For each selected request, EPE evaluates every matching rule from the first profile through the last, preserving rule order inside each profile. A terminal action stops the remaining chain. A later rule may still match after a broad earlier rule: matching is not first-rule-wins.

## Failure behavior

EPE fails closed at every boundary:

- **Authoring.** A profile whose selector, regular expression, CEL expression, template, or action payload fails to compile keeps its last successfully compiled version. Without one, its selected Pods have no protection from that profile. The `epe_profile_stale` and `epe_profile_unenforced` metrics report these states.
- **Request time.** A runtime error — credential lookup, parameter or template evaluation, signing, or an unavailable provider — follows the failing action's `failStrategy`, whose default is `Block` (fail closed).
- **Provider availability.** If EPE itself is unavailable or returns an error, the gateway's `failureModeAllow` setting decides. The default `false` fails closed; `true` lets traffic continue.

The one exception is inputs availability, which is not an authoring failure: a profile with a missing ConfigMap input still installs and enforces, while expressions that depend on `inputs` fail per the consuming action's failure policy.

Per-Sandbox rules obey the same authoring rule. A Sandbox is an OpenKruise Sandbox workload, the unit of identity and policy subject in Agentio. A Sandbox whose `agents.kruise.io/security-rules` annotation fails to compile keeps its previous rules when it has any, and enforces none otherwise.

## Rule structure and matching

Every rule has a unique `name`, at least one `match` clause, and `actions`. The clauses in `match` are ORed. Within a clause, every populated field is ANDed:

| Field | Behavior |
| --- | --- |
| `domains` | Required. `*` matches any host. `*.example.com` matches subdomains but not `example.com`; exact host matching is case-insensitive. |
| `paths` | ORed. `Prefix` is the default; `Exact` and RE2 `Regex` are supported. The query string is excluded. |
| `methods` | ORed and case-insensitive. The schema restricts the vocabulary to common HTTP methods. |
| `ports` | ORed. EPE uses authority port, HTTP/HTTPS inferred port, then an Envoy destination-port override. Port `0` never matches a non-empty list. |
| `schemes` | ORed and case-insensitive. |
| `headers` | ANDed. Header names are case-insensitive/lowercased; `Exact` is the default, with `Prefix` and RE2 `Regex` available. |
| `queryParams` | ANDed. `Exact` is the default, with `Prefix` and RE2 `Regex`. Only the first percent-decoded value for a repeated key is considered. |

Invalid regexes reject the whole profile version rather than silently making a rule non-matching. The request values and absence rules are detailed in [Request context](#request-context).

## Action order and actions

### TLS connection actions

`rules[].actions.tls.action` accepts `Deny` or `Passthrough`, with no default. `Deny` rejects the connection without decrypting TLS; it does not guarantee an HTTP response or a particular TLS alert. `Passthrough` forwards encrypted traffic without HTTP rule processing. TLS actions cannot be combined with HTTP actions or rule-level audit; `bypass: false` is equivalent to omission. Profile-level audit applies only to HTTP rules.

```yaml
rules:
  - name: allow-pinned-client
    match:
      - domains: [pinned.example.com]
        ports: [443]
    actions:
      tls:
        action: Passthrough
  - name: deny-other-tls
    match:
      - domains: ["*"]
    actions:
      tls:
        action: Deny
```

Explicit TLS rules allow only `domains` and `ports` in each match clause. Domains match the TLS inspector's visible SNI, never the CONNECT authority. Missing SNI does not match, including `*`. Ports match the original destination port restored from CONNECT: values are ORed, an empty list allows any port, and a missing destination port never matches a restricted list. Each clause keeps its own domain/port pair.

The first matching connection rule decides, in profile order and then source rule order. HTTP rules also participate in connection selection: each clause with no `schemes` or with `https` selects TLS termination using its domains and ports. Paths, methods, headers, and query parameters are deferred to HTTP processing. Put passthrough exceptions before broader HTTP rules; an earlier HTTP rule may already select TLS termination. TLS rules themselves are excluded from EPE's HTTP processing and audit.

No matching connection rule preserves the existing passthrough default. Gateway exclusions still take precedence, and cleartext follows the existing HTTP path. The same projection applies to per-Sandbox security rules. Install the updated SecurityProfile CRDs and use matching Agentio control-plane, Porter, and gateway builds before using port-restricted rules.

### HTTP actions

EPE registers actions in this fixed order within each matched rule:

1. `bypass`
2. `block`
3. `mcpToolPolicy`
4. `headerManipulation`
5. `httpCallout`
6. `tokenTransformation`

`bypass` skips all remaining actions and rules across every matching profile while preserving mutations already made by earlier rules. `block` stops immediately, discards pending mutations, and returns `statusCode` (default 403) with optional `body`.

`mcpToolPolicy` is a non-terminal allow/deny filter for MCP JSON-RPC `tools/call`. `defaultAction` defaults to `deny`; its ordered `rules` match method and optionally tool names. `unsupportedVersionAction` defaults to `deny`, and `denyResponse` defaults to HTTP 403. It buffers complete request bodies and only understands MCP versions currently documented in [Configure MCP access control](../tasks/configure-mcp-access-control.md).

`tokenTransformation` injects credentials into resource requests. In OAuth2 mode, DeviceAuthorization and Token operations return a terminal local response; Resource remains non-terminal. It has these fields:

| Field | Behavior |
| --- | --- |
| `type` | `ApiKey` (default) injects a rendered credential into a target header; `AliyunSTS` re-signs Alibaba Cloud requests with a Security Token Service (STS) triplet; `OAuth2` brokers OAuth flows and injects Bearer credentials. |
| `credentialRef` | Required typed union: exactly one `secret` or `credentialProvider`. Deprecated flat `kind`/`name`/`namespace` values are normalized for compatibility but must not be mixed with the typed form. |
| `credentialRef.secret` | `name` is required; namespace falls back from reference to profile to source Pod. `ApiKey` reads `apiKey`; `AliyunSTS` reads `accessKeyId`, `accessKeySecret`, `securityToken`. |
| `credentialRef.credentialProvider` | `name` is required. `parameters` supplies metadata values from exactly one of `value`, `template`, or `cel`. Its namespace field is currently ignored. |
| `apiKey` | Required for `ApiKey`, ignored for `AliyunSTS`. Prefer `targetHeaders` plus `value`; all selected headers use the same value source. `targetHeaders.names` selects fixed names, while `targetHeaders.cel` returns dynamic names from the original request. When `targetHeaders` is present, EPE ignores legacy `when`, `targetHeader`, and `valueTemplate`. Without it, the legacy fields retain their existing single-header behavior. |
| `oauth2` | Required only for `OAuth2`. Select exactly one `operation` branch: `deviceAuthorization`, `token`, or `resource`. Shared `customResponse` belongs beside `operation`; `success` is Token-only. OAuth2 requires a parameter-free CredentialProvider reference and cannot be combined with `apiKey`. |
| `disabled` | Defaults to `false`; when true, leaves the configuration stored but does not mount the action. |
| `failStrategy` | `Block` is the default. ApiKey/STS failures return generic 403 for Block; Allow and Ignore pass the failed transformation through unmodified. OAuth2 requires Block and returns operation-specific OAuth errors. |

An unavailable signer type or malformed credential reference — including an uncompilable provider parameter CEL expression or template — rejects the profile version at the collection boundary, retaining any last-known-good version, as described under [Failure behavior](#failure-behavior). At request time, an unavailable credential, unresolved profile inputs, bad provider response, invalid header value, or signing error uses the token transformation's `failStrategy`. Provider details, TLS, and cache semantics are in [Credential provider](credential-provider.md).

`AliyunSTS` detects ACS3/V3, V1-ROA, and OSS V4 from the trimmed `Authorization` header. Their required prefixes are `ACS3-HMAC-SHA256`, `acs` (also requiring a `:`), and `OSS4-HMAC-SHA256`, respectively, each followed by a space. When none matches, V1-RPC is detected from a parseable raw query containing non-empty `Signature` and `AccessKeyId` parameters and exactly `SignatureMethod=HMAC-SHA1`. A request that meets none of these requirements is unsupported; detection fails and the action follows its configured `failStrategy` (`Block` by default, or unmodified forwarding for `Allow`/`Ignore`).

OAuth2 branch selection, credential-source restrictions, and response-field constraints are validated when the profile is compiled. The CRDs provide basic types and grant-set constraints without OAuth2 cross-field CEL. An invalid OAuth2 action rejects the profile version under the same collection rules described above. See [Configure OAuth credential isolation](../tasks/broker-oauth-credentials.md) for Content-Type decoding, scope and session boundaries, and a complete example.

## HTTP callouts

`rules[].actions.httpCallout` delegates request processing, response processing, or both to the named `httpCallout` extension provider in [EPE configuration](epe-configuration.md). The provider supplies the URL, timeout, and TLS settings.

```yaml
httpCallout:
  provider:
    name: content-scanner
  request:
    headers:
      enabled: true
      filter:
        allowList: [content-type, x-request-id]
    body:
      enabled: true
      maxBytes: 1048576
  response: {}
  failStrategy: Block
```

Omitting a phase disables it; `{}` enables a metadata-only callout. Headers and bodies are hidden by default. With headers enabled, omitting `filter` sends all headers, including credentials and cookies. A filter must contain exactly one non-empty `allowList` or `denyList`; matching is case-insensitive. Disabled headers ignore their filter.

Enabling a body buffers and sends the complete UTF-8 body. Each phase has its own `maxBytes` (default 1 MiB, maximum 8 MiB); oversized content fails without truncation. Disabled bodies ignore the limit. These limits do not configure Envoy buffering or the provider's decision-response size limit. Response invocations include request correlation metadata, but no request headers or body.

`failStrategy` defaults to `Block`. Provider lookup, transport, timeout, disclosure, and protocol errors follow this strategy; `Allow` and `Ignore` skip the failed callout's mutations and continue. A valid immediate response is always honored. Missing or wrong-type providers fail at execution time without fallback. Invalid phase, header-filter, or action configuration rejects the profile version during compilation and retains its last valid version.

For a runnable server, wire examples and EPE integration, see [Develop an HTTPCallout server](../development/httpcallout-server.md).

## Audit configuration

`spec.audit` defines profile defaults. A non-empty `rules[].actions.audit` list replaces those defaults for that rule; an empty rule list inherits the profile list. Every audit action has a unique `name`, a required webhook `url`, optional boolean CEL `when`, and a webhook request:

- Request method is `POST` by default and may be `POST`, `PUT`, or `PATCH`.
- Timeout defaults to `2s` and must be 500 ms through 30 s.
- Headers and text/JSON body leaves are Go templates. JSON bodies preserve non-string values and render string leaves.
- Audit is asynchronous and fires after stream resolution. Template/evaluation failures drop that event; audit never changes the request verdict or upstream response.

Audit CEL sees `result` and `response.status` in addition to the request context. It may send selected request, input, and match information to the webhook, so treat its endpoint as a data-disclosure boundary.

## Inputs and credential references

`spec.inputs` provides named configuration values to CEL and Go templates. Each entry contains exactly one `inline` string map or `configMap` source. A namespaced profile defaults a ConfigMap namespace to its own namespace; a global profile requires it. Inputs are resolved profile-wide, not per-rule and not per-request credentials.

A missing ConfigMap is an availability problem, not an authoring error: the profile still installs and enforces, while expressions that depend on `inputs` fail per the consuming action's failure policy. A statically invalid input — zero or two sources, or a global profile's ConfigMap reference without a namespace — rejects the profile version like any other compile error.

Use `credentialRef` for credentials and `inputs` for non-secret configuration such as tenant or routing labels. EPE does not redact input values in templates, provider metadata, or audit requests.

## Request context

Policy expressions see the same request tuple, caller identity, and profile inputs. The request tuple is built during request headers; `:authority` takes precedence over `host`.

| Attribute | Type | Source and absence behavior |
| --- | --- | --- |
| `host` | string | Authority/Host name without brackets or port. Empty if neither is sent. |
| `port` | int | Explicit authority port, inferred HTTP/HTTPS port, or Envoy `destination.port`. `0` if unavailable or invalid. |
| `path` | string | Portion of `:path` before `?`; empty when absent. |
| `method` | string | `:method`; empty when absent. |
| `scheme` | string | `:scheme`; empty when absent. |
| `headers` | map<string, string> | Request headers keyed in lowercase. In CEL, indexing an absent key raises a `no such key` evaluation error; duplicate values are collapsed to the last value supplied by Envoy. |
| `queryParams` | map<string, string> | First parsed value of each query parameter. Empty when there is no query. |

Path matching excludes the query string. Query matching uses the first percent-decoded value for a key.

### CEL variables

Audit conditions and provider parameter values compile in separate CEL environments that share these request-time variables:

| Variable | CEL type | Values |
| --- | --- | --- |
| `request` | `map<string, dyn>` | `host`, `port` (int), `path`, `method`, `scheme`, `headers`, `queryParams`. |
| `pod` | `map<string, dyn>` | `name`, `namespace`, `ip`, `labels`. |
| `profile` | `map<string, string>` | `name`, `namespace` (empty for a global profile). |
| `rule` | `map<string, string>` | `name`. |
| `inputs` | `map<string, dyn>` | Named inline/ConfigMap inputs; nil when none are configured. Any read fails when the profile's inputs are unavailable. |
| `result` | string | Audit only: final disposition. A provider parameter that references it is rejected during compilation. |
| `response` | `map<string, dyn>` | Audit only: `status` (int; `0` if no response observed). |

Audit `when` expressions must return `bool`; an empty `when` is true. Provider `parameters[].cel` may return any JSON-compatible value other than null.

CEL receives ordinary maps, so indexing a missing header, label, query parameter, or input key raises a `no such key` error rather than returning an empty string. Guard membership before indexing, for example, `"content-type" in request.headers && request.headers["content-type"].startsWith("application/json")`. An audit CEL runtime error drops that audit event; a provider-parameter CEL runtime error follows the matched token transformation's `failStrategy`.

`json.decode(string)` parses one JSON value: objects become string-keyed maps, arrays become lists, numbers become doubles, and strings, booleans, and null retain their types. Invalid or empty JSON, including trailing data, raises an evaluation error rather than falling back to the original string.

### Go templates

Go templates use `missingkey=zero`. In addition to Go's built-in functions (`index`, `len`, `printf`), EPE exposes this helper allowlist:

| Helpers | Behavior |
| --- | --- |
| `default fallback value` | Uses the fallback for an empty string; both arguments must be strings. |
| `json value` | Serializes a value as JSON. |
| `fromJson value`, `mustFromJson value` | Parses JSON. `fromJson` yields nothing on invalid input; `mustFromJson` aborts rendering. |
| `kindIs kind value` | Tests the Go kind, such as `"map"` or `"string"`. |
| `trim value`, `lower value`, `upper value` | Trims surrounding whitespace or changes case. |
| `contains substring value`, `hasPrefix prefix value`, `hasSuffix suffix value` | Tests string contents or boundaries. |
| `trimPrefix prefix value`, `trimSuffix suffix value` | Removes one matching prefix or suffix. |
| `replace old new value` | Replaces every literal occurrence of `old` with `new`. |
| `splitList separator value`, `join separator list` | Splits a string or joins list elements. |
| `fail message`, `values map`, `first list` | Aborts rendering, extracts map values, or selects the first list element. |

String helpers take the input last for pipelines, for example `{{ .Token | trimPrefix "Bearer " | trim }}`. Unlike CEL map indexing, the `.Request.Header` and `.Request.QueryParam` accessors return `""` when the requested key is absent. `fromJson` yields nothing on invalid input, so guard the result with `kindIs` before treating it as a map or list. The sandbox bearer token is intentionally unavailable.

| Template root | Values |
| --- | --- |
| Token transformation `apiKey.value.template` | `.Token`, `.Header.Name`, `.Header.Value`, `.Request`, `.Pod`, `.Profile`, `.Rule`, and lazy `.Inputs`. `.Pod` has `Name`, `Namespace`, `IP`, `Labels`, and `Label key`. |
| Legacy token transformation `apiKey.valueTemplate` | The same context as `apiKey.value.template`; EPE normalizes the legacy single-header form to the same internal rule. |
| Credential-provider parameter `template` | `.Request`, `.Pod`, `.Profile`, `.Rule`, `.Inputs`. `.Request` has `Host`, `Port`, `Path`, `Scheme`, `Method`, `Query`, `Header name`, and `QueryParam name`. |
| Audit webhook URL, headers, and body | The shared roots above plus `.Result`, `.Response.Status`, and `.MatchedCriteria`/`.Matched`. Matched fields are populated only when the corresponding rule match constrained them. |

Use lower-risk data in audit and provider templates. Rendered values can be transmitted to external providers/webhooks, and the `json` helper serializes its argument rather than redacting it.

## Defaults and validation

The CRD validates required fields, enum values, header-name syntax, lengths, ports, and audit timeout bounds. At collection time, EPE additionally validates selector parsing, rule-match regex compilation, one source per input, audit CEL/template compilation and types, and every rule's action payloads — token transformations included. All of these participate in the last-known-good decision described under [Failure behavior](#failure-behavior).

Notable defaults are priority `1000`, `block.statusCode` `403`, MCP `defaultAction`/`unsupportedVersionAction` `deny`, token type `ApiKey`, token failure strategy `Block`, and token `disabled` `false`. The legacy API-key mode has no CRD default for `targetHeader`; EPE preserves compatibility by falling back to `Authorization` when it is omitted.

## GlobalSecurityProfile differences

`GlobalSecurityProfile` is cluster-scoped, participates in selection for every source namespace, and has an empty profile namespace in templates/CEL/audit. Because it has no own namespace, any ConfigMap input must specify one, and a Secret credential reference without a namespace falls back to each selected Pod's namespace. The actions, matching, priority, audit, and validation rules are otherwise the same as `SecurityProfile`.

## See also

- [Request context](epe-request-context.md)
- [Credential provider contract](credential-provider.md)
- [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md)
- [SecurityProfile API reference](security-profile-api.md)

## Validation status

agentiod reports `Accepted` and `ResolvedRefs` using the existing status fields.
See [Policy validation status](../components/securityprofile-status.md) for
condition meanings, reference scope and the distinction from data-plane loading.
