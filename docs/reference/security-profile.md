# SecurityProfile reference

`SecurityProfile` is a namespaced L7 egress policy for selected Pods. `GlobalSecurityProfile` has the same `spec` but is cluster-scoped and can select Pods in every namespace. Both are consumed by Egress Policy Enforcer (EPE); they are distinct from `TrafficPolicy` and `GlobalTrafficPolicy`, which control destination routing rather than request-level actions.

The complete field schemas for both kinds are in the [SecurityProfile API reference](security-profile-api.md). This page explains the implemented evaluation behavior instead of duplicating the field reference.

## Scope, selection, and precedence

A `SecurityProfile` selects Pods only in its metadata namespace. A `GlobalSecurityProfile` has no namespace and its selector is considered for every Pod. An empty selector matches every Pod in that scope.

All matching profiles are ordered by lower `spec.priority` first (default `1000`), then earlier creation time, name, and namespace. Global and namespaced profiles are merged into that one order; an exact ordering tie places the global profile first because its namespace is empty.

For each selected request, EPE evaluates every matching rule from the first profile through the last, preserving rule order inside each profile. A terminal action stops the remaining chain. A later rule may still match after a broad earlier rule: matching is not first-rule-wins.

EPE compiles collection-level data when it observes a profile: the label selector, rule matchers and RE2 expressions, audit CEL/templates, and every rule's action payloads. For token transformations that includes the signer type, credential-reference normalization, provider parameter CEL/templates, API-key header selectors and values, value-template probes, and the legacy `when` regex. If any of that work fails, EPE retains the previous valid version for the resource when one exists. Without a prior valid version, its selected Pods have no protection from that profile. The stale/unenforced metrics and admin state describe these collection-time failures.

ConfigMap-backed inputs are resolved at the same boundary but fail differently: a ConfigMap that does not exist (or no longer exists) is availability, not authoring. The profile version still installs and all of its rules enforce — a Block rule keeps blocking — while the inputs are marked unavailable. Every CEL expression or template whose result depends on `inputs` then fails with that reason and resolves through the consuming action's failure policy: a token transformation follows its `failStrategy`, and a header mutation — which has no fail-open option — fails closed. The `epe_profile_inputs_unavailable` metric counts affected profiles, and a deleted ConfigMap makes the inputs unavailable rather than silently serving stale values. Static input authoring errors — an entry with zero or two sources, a global profile's ConfigMap reference without a namespace — reject the version like any other compile error.

Because action payloads are projected at the collection boundary, a malformed action never reaches the request path: the projection error rejects that profile version instead of surfacing as an ext_proc processing error decided by the gateway provider's `failureModeAllow`. Request-time credential lookup, parameter/template evaluation, and signing errors follow the token transformation's `failStrategy`.

This is one rule with no exceptions: every compile-time error — a bad selector, an uncompilable regex or CEL expression, a malformed action — rejects the version and keeps the last known good one, and every runtime error resolves through the failing action's own failure policy. Per-Sandbox rules obey it too: a Sandbox whose `agents.kruise.io/security-rules` annotation fails to compile or project keeps its previous rules when it has any and enforces none otherwise, reported by `epe_profile_stale` and `epe_profile_unenforced` under `scope="pod"`. Because those rules are authored when the Sandbox is created, a rejected first version simply not taking effect is the intended authoring feedback.

Header-mutation values and API-key `value.template` values are additionally probe-rendered when the profile is compiled, including the legacy `apiKey.valueTemplate` after it is normalized to a header rule. That probe catches a reference to a field the render scope does not have. Credential-provider parameter templates and audit templates are compiled but not probe-rendered, so a bad field reference in those surfaces per request instead. The probe has no request data to work with, so it does not exercise helper behavior guarded on real request values: a guarded `fail` call and JSON extraction from a request value are accepted at compile time and evaluated for real per request.

With Sandbox mode enabled, inline HTTPS matches are published on the native Sandbox resource. For legacy data planes, Agentio also appends these matches after shared SNI rules in the bound Workload's `sni-traffic-policy` extension, using `Sandbox.attester.workload_uid`. Projection starts when the binding is available and follows binding changes or removal. If multiple Sandboxes share a Workload, their inline SNI is not projected onto that host; their native Sandbox output remains available. Invalid annotation or SNI updates retain the last valid policy; removing the annotation or Sandbox, or changing to valid HTTP-only rules, removes the inline SNI policy. Legacy EPE still selects inline rules by Pod namespace/name, so end-to-end legacy compatibility assumes a Sandbox and Pod with the same namespace/name; binding-based SNI projection alone does not add EPE support for differently named Pods.

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

Invalid regexes reject the whole profile version rather than silently making a rule non-matching. The request values and absence rules are detailed in [EPE request context](epe-request-context.md).

## Action order and actions

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
| `type` | `ApiKey` (default) injects a rendered credential into the legacy `targetHeader` (EPE falls back to `Authorization` when it is omitted); `AliyunSTS` re-signs a detected ACS3/V3, V1-ROA, OSS V4, or V1-RPC request using an STS triplet; `OAuth2` brokers OAuth replies and injects real Bearer credentials into resource requests. |
| `credentialRef` | Required typed union: exactly one `secret` or `credentialProvider`. Deprecated flat `kind`/`name`/`namespace` values are normalized for compatibility but must not be mixed with the typed form. |
| `credentialRef.secret` | `name` is required; namespace falls back from reference to profile to source Pod. `ApiKey` reads `apiKey`; `AliyunSTS` reads `accessKeyId`, `accessKeySecret`, `securityToken`. |
| `credentialRef.credentialProvider` | `name` is required. `parameters` supplies metadata values from exactly one of `value`, `template`, or `cel`. Its namespace field is currently ignored. |
| `apiKey` | Required for `ApiKey`, ignored for `AliyunSTS`. Prefer `targetHeaders` plus `value`; all selected headers use the same value source. `targetHeaders.names` selects fixed names, while `targetHeaders.cel` returns dynamic names from the original request. When `targetHeaders` is present, EPE ignores legacy `when`, `targetHeader`, and `valueTemplate`. Without it, the legacy fields retain their existing single-header behavior. |
| `oauth2` | Required only for `OAuth2`. Select exactly one `operation` branch: `deviceAuthorization`, `token`, or `resource`. Shared `customResponse` belongs beside `operation`; `success` is Token-only. OAuth2 requires a parameter-free CredentialProvider reference and cannot be combined with `apiKey`. |
| `disabled` | Defaults to `false`; when true, leaves the configuration stored but does not mount the action. |
| `failStrategy` | `Block` is the default. ApiKey/STS failures return generic 403 for Block; Allow and Ignore pass the failed transformation through unmodified. OAuth2 requires Block and returns operation-specific OAuth errors. |

An unavailable signer type or malformed credential reference — including an uncompilable provider parameter CEL expression or template — rejects the profile version at the collection boundary, retaining any last-known-good version, as described above. At request time, an unavailable credential, unresolved profile inputs, bad provider response, invalid header value, or signing error uses the token transformation's `failStrategy`. Provider details, TLS, and cache semantics are in [Credential provider](credential-provider.md).

`AliyunSTS` detects ACS3/V3, V1-ROA, and OSS V4 from the trimmed `Authorization` header. Their required prefixes are `ACS3-HMAC-SHA256`, `acs` (also requiring a `:`), and `OSS4-HMAC-SHA256`, respectively, each followed by a space. When none matches, V1-RPC is detected from a parseable raw query containing non-empty `Signature` and `AccessKeyId` parameters and exactly `SignatureMethod=HMAC-SHA1`. A request that meets none of these requirements is unsupported; detection fails and the action follows its configured `failStrategy` (`Block` by default, or unmodified forwarding for `Allow`/`Ignore`).

OAuth2 branch selection, credential-source restrictions, and response-field constraints are validated during EPE policy projection. The CRDs provide basic types and grant-set constraints without OAuth2 cross-field CEL. An invalid OAuth2 action rejects the profile version under the same collection rules described above. See [Configure OAuth credential isolation](../tasks/broker-oauth-credentials.md) for Content-Type decoding, scope and session boundaries, and a complete example.

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

Use `credentialRef` for credentials and `inputs` for non-secret configuration such as tenant or routing labels. EPE does not redact input values in templates, provider metadata, or audit requests.

## Defaults and validation

The CRD validates required fields, enum values, header-name syntax, lengths, ports, and audit timeout bounds. At collection time, EPE additionally validates selector parsing, rule-match regex compilation, one source per input, audit CEL/template compilation and types, and every rule's action payloads — token transformations included. All of these participate in the last-known-good decision described under [Scope, selection, and precedence](#scope-selection-and-precedence). Input _availability_ is deliberately not one of them: a referenced ConfigMap that does not exist leaves the version installed and marks its inputs unavailable.

Notable defaults are priority `1000`, `block.statusCode` `403`, MCP `defaultAction`/`unsupportedVersionAction` `deny`, token type `ApiKey`, token failure strategy `Block`, and token `disabled` `false`. The legacy API-key mode has no CRD default for `targetHeader`; EPE preserves compatibility by falling back to `Authorization` when it is omitted.

## GlobalSecurityProfile differences

`GlobalSecurityProfile` is cluster-scoped, participates in selection for every source namespace, and has an empty profile namespace in templates/CEL/audit. Because it has no own namespace, any ConfigMap input must specify one, and a Secret credential reference without a namespace falls back to each selected Pod's namespace. The actions, matching, priority, audit, and validation rules are otherwise the same as `SecurityProfile`.

## See also

- [EPE request context](epe-request-context.md)
- [Credential provider contract](credential-provider.md)
- [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md)
- [SecurityProfile API reference](security-profile-api.md)

## Validation status

agentiod reports `Accepted` and `ResolvedRefs` using the existing status fields.
See [Policy validation status](../components/securityprofile-status.md) for
condition meanings, reference scope and the distinction from data-plane loading.
