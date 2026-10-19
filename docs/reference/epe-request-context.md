# EPE request context

This reference defines the context that Egress Policy Enforcer (EPE) exposes while evaluating a `SecurityProfile` or `GlobalSecurityProfile`. It lists only the values implemented by `extensions/epe/`; fields not listed here are not policy APIs.

EPE receives request data through Envoy external processing. Header names are normalized to lowercase. EPE buffers a request body only when a matched action requires it; body bytes and the sandbox bearer token are deliberately not exposed to CEL, Go templates, profile inputs, or audit payloads.

The chart ships the public `SecurityProfile` fields `apiKey.targetHeaders` and `apiKey.value`. Prefer these fields for new policies; the legacy single-header form remains supported. See [Transform outbound credentials](../tasks/transform-outbound-credentials.md).

## Request attributes

EPE builds the request tuple during request headers. `:authority` takes precedence over `host`; its explicit port is used, otherwise `http` defaults to 80 and `https` to 443. For ordinary requests, Envoy's restored `destination.address` and `destination.port` override that inferred port when valid. CONNECT retains its authority port because the downstream local address identifies the proxy listener, not the tunnel target.

| Attribute | Type | Source and absence behavior |
| --- | --- | --- |
| `host` | string | Authority/Host name without brackets or port. Empty if neither is sent. |
| `port` | int | Explicit authority port, inferred HTTP/HTTPS port, or Envoy `destination.port`. `0` if unavailable or invalid. |
| `path` | string | Portion of `:path` before `?`; empty when absent. |
| `method` | string | `:method`; empty when absent. |
| `scheme` | string | `:scheme`; empty when absent. |
| `headers` | map<string, string> | Request headers keyed in lowercase. In CEL, indexing an absent key raises a `no such key` evaluation error; duplicate values are collapsed to the last value supplied by Envoy. |
| `queryParams` | map<string, string> | First parsed value of each query parameter. It is empty when there is no query. Invalid query syntax can be partially parsed; semicolon-separated pairs and invalid escapes are not a byte-for-byte policy surface. |

Policy matching sees the same host, port, path, method, scheme, headers, and parsed query fields. Path matching excludes the query string. Query matching uses the first percent-decoded value for a key.

The internal routing filters use additional fields that are not exposed to CEL or templates. Request callbacks receive an owned `Stream.Upstream` snapshot of the target selected by preceding filters, including after a buffered body continuation. Place `route` before `egressauthz`: authorization checks the selected IP and port, retains an allowed target without DNS, and rejects a denied explicit target without switching destinations. Without an explicit target, authorization prefers an allowed `HTTPRequest.OriginalDestination` from Envoy's restored downstream destination attributes; an absent or denied original target falls back to resolving the request Host and selecting an allowed candidate. An allowed original target need not occur in the Host's DNS answer. Host/authority stays unchanged. `Config.Family` constrains host resolution, not an already selected or restored address.

The `route` filter is an internal building block, not public SecurityProfile routing configuration. The EPE binary can independently enable mandatory destination authorization with `--enable-egressauthz`; the Agentio Envoy gateway consumes its emitted `agentio.route` IP/port metadata to pin the upstream connection. See [deployment prerequisites and verification](../tasks/configure-epe-destination-authorization.md).

## Source peer and stream information

Envoy filter-state attributes identify the caller. On the native Envoy gateway, Porter resolves the verified Workload from discovery and writes its name, namespace and labels into this context. The CONNECT-header and `downstream_peer` sources below describe the legacy gateway compatibility path; native gateways do not trust caller-supplied workload name/label headers. See [Traffic processing](../concepts/traffic-processing.md#porter-and-epe-handle-different-requests).

| EPE stream field | Envoy attribute | Type | Absence behavior |
| --- | --- | --- | --- |
| Pod namespace | `filter_state['agentio.workload.namespace']` | string | Captured from `x-agentio-workload-namespace` on HBONE CONNECT. Missing or empty falls back to `filter_state['downstream_peer'].namespace`; empty after fallback makes the peer invalid. |
| Pod name | `filter_state['agentio.workload.name']` | string | Captured from `x-agentio-workload-name` on HBONE CONNECT. Missing or empty falls back to `filter_state['downstream_peer'].name`; empty after fallback makes the peer invalid. |
| Pod IP | `source.address` | string | EPE removes a valid port and surrounding IPv6 brackets. It is empty when absent; otherwise malformed input may be preserved after this syntactic stripping. |
| Workload labels | `filter_state['agentio.workload.labels']` | map<string, string> | Parsed from base64 `k=v,k2=v2`; falls back to legacy `filter_state['sandbox.labels']` only when the new attribute is absent. A present empty or invalid new value does not fall back. |
| Sandbox token | `filter_state['sandbox.token']` | internal object | Base64 JSON or raw JSON with `requestId`, `accessToken`, and `sandboxClientId`; nil when absent or malformed. Not expression-visible. |
| Request ID | `x-request-id` | string | Empty when absent. Used for log correlation, not expression evaluation. |

On the legacy path, ztunnel sets these headers from the source Pod's name and namespace, not its owning Deployment. The gateway preserves them in filter state across internal HTTP/TLS hops and exports them in EPE request attributes. EPE reads this captured context, not same-named headers on the inner application request. Default gateway access logs use the same per-field precedence for `workload_name` and `workload_namespace`, replacing `sandbox_name` and `sandbox_namespace`.

Both Pod namespace and name are required. Without them EPE cannot select a profile. It passes the request through by default, or returns HTTP 403 when `--fail-closed-on-missing-identity` or `--enable-egressauthz` is enabled. The token is consumed only by provider-backed credential transformations; its bearer `accessToken` is never exposed in `request`, `pod`, `inputs`, templates, CEL, or audit context.

The filter stream also records matched profile/rule actions, filter outcomes, final disposition (`passthrough`, `mutated`, `blocked`, `bypassed`, or `error`), any resolved error text, and bytes forwarded before a verdict. These are internal/audit observations, not general CEL variables.

## Phase availability

| Phase | Available data | Mutability and limits |
| --- | --- | --- |
| Request headers | Request tuple, peer identity, profile/rule, and resolved inputs. | Matching and header transformations occur here. `block` and `bypass` are header-only. |
| Request body | The same request context plus a complete buffered body only for actions that request it. | Current body consumers are MCP ACL and body-dependent signing. The body is not exposed to CEL/templates. Buffered mode prevents bytes from reaching upstream before the verdict. |
| Response headers | Upstream response status and lowercased response headers are recorded on the stream. | The current response phase is observation-only: filters cannot mutate response headers. Only status reaches audit CEL/templates. |
| Stream end | Final disposition and response status, if response headers arrived. | Audit actions are evaluated asynchronously; they cannot modify the already-resolved request or upstream response. |

Request and response bodies are not expression-visible. EPE's response-body and trailer handlers currently pass through. A blocked request may have no upstream response, in which case audit `response.status` is `0`.

## Shared inputs

`SecurityProfile.spec.inputs` creates profile-scoped values under `inputs`. An input sets exactly one source:

- `inline` is a `map<string, string>` stored in the profile.
- `configMap` reads ConfigMap `data` into a `map<string, string>`. A namespaced `SecurityProfile` defaults the ConfigMap namespace to its own namespace. A `GlobalSecurityProfile` must name a ConfigMap namespace explicitly.

Inputs are configuration, not credentials. EPE resolves them when the profile is compiled. A statically invalid input (zero or two sources, or a global profile's ConfigMap reference without a namespace) rejects the candidate profile, and the store retains the last known good version when one exists. A ConfigMap that does not exist (or no longer exists) does not reject the profile: the version installs and its rules enforce, but the inputs are unavailable — every CEL expression or template whose result depends on `inputs` fails with that reason and resolves through the consuming action's failure policy. Do not put secrets, sandbox identities, or generated credential material in inputs.

## CEL variables and functions

EPE compiles audit conditions and provider parameter values in separate CEL environments that share the request-time variables and extensions below. Audit `when` expressions must return `bool`; an empty `when` is true. Provider `parameters[].cel` may return any JSON-compatible value other than null.

| Variable | CEL type | Values |
| --- | --- | --- |
| `request` | `map<string, dyn>` | `host`, `port` (int), `path`, `method`, `scheme`, `headers`, `queryParams`. |
| `pod` | `map<string, dyn>` | `name`, `namespace`, `ip`, `labels`. |
| `profile` | `map<string, string>` | `name`, `namespace` (empty for a global profile). |
| `rule` | `map<string, string>` | `name`. |
| `inputs` | `map<string, dyn>` | Named inline/ConfigMap input maps; it may be nil when no inputs are configured. When the profile's inputs are unavailable, any read of `inputs` (including `has(inputs.x)`) evaluates to an error. |
| `result` | string | Audit only: final disposition. A provider parameter that references it is rejected during CEL compilation. |
| `response` | `map<string, dyn>` | Audit only: `status` (int; `0` if no response observed). |

The CEL environment includes the standard CEL binding, string, set, and list extensions. CEL receives ordinary maps, so direct indexing of a missing header, label, query parameter, or input key raises a `no such key` evaluation error; it does not produce an empty string. Guard membership before indexing, for example, `"content-type" in request.headers && request.headers["content-type"].startsWith("application/json")`. An audit CEL runtime error drops that audit event, while a provider-parameter CEL runtime error follows the matched token transformation's `failStrategy`.

`json.decode(string)` is available in every CEL environment, including audit conditions, provider parameters, and token-header selectors and values. It parses one JSON value: objects become string-keyed maps, arrays become lists, numbers become doubles, and strings, booleans, and null retain their corresponding types. Invalid or empty JSON, including trailing data, raises an evaluation error; it does not fall back to the original string. Use strings for identifiers that must retain exact digits. A decoded null is valid CEL, but cannot be the final value of a provider parameter or a token-header value.

### Token-header evaluation

`apiKey.targetHeaders` and `apiKey.value` use separate selector and value evaluations. A selector CEL expression sees the standard `request`, `pod`, `profile`, `rule`, and `inputs` variables described above; it never sees `token`. It must return a list of header names. All selectors observe the original request snapshot, before any selected header is mutated. Header names returned by a selector, like statically configured names, are canonicalized to lowercase before they are used. Token-header CEL does not expose the unbounded `lists.range` constructor, and each selector or value evaluation has a runtime cost limit of 10,000 CEL cost units; a size or cost violation follows the transformation's `failStrategy` like any other evaluation error.

A value CEL expression sees that same standard context plus `token` and `header.name`/`header.value`. Here `token` is the resolved transformation credential, not the sandbox bearer token. It must return a string. `header.name` is the canonicalized target name, while `header.value` is the target's original request value. A selector that returns no names is a successful no-op and skips credential access entirely.

Token-header value templates expose `.Token` (the resolved transformation credential), `.Header.Name`, `.Header.Value`, `.Request`, `.Pod`, `.Profile`, `.Rule`, and lazy `.Inputs`. `.Header.Value` remains the original request value even when another selected header has already been staged for replacement. EPE renders and validates every selected value before returning any header mutations, so a failure cannot leave a partial set of selected headers applied; the transformation's `failStrategy` handles the failure as a whole.

## Template values and functions

Go templates use `missingkey=zero`. In addition to Go's built-in template functions such as `index`, `len`, and `printf`, EPE exposes this helper allowlist:

| Helpers | Behavior |
| --- | --- |
| `default fallback value` | Uses the fallback for an empty string; both arguments must be strings. |
| `json value` | Serializes a value as JSON. |
| `fromJson value`, `mustFromJson value` | Parses JSON. `fromJson` yields nothing on invalid input; `mustFromJson` aborts rendering with an error. |
| `kindIs kind value` | Tests the Go kind, such as `"map"` or `"string"`. |
| `trim value`, `lower value`, `upper value` | Trims surrounding whitespace or changes case. |
| `contains substring value`, `hasPrefix prefix value`, `hasSuffix suffix value` | Tests string contents or boundaries. |
| `trimPrefix prefix value`, `trimSuffix suffix value` | Removes one matching prefix or suffix, leaving unmatched strings unchanged. |
| `replace old new value` | Replaces every literal occurrence of `old` with `new`. |
| `splitList separator value`, `join separator list` | Splits a string or joins list elements. |
| `fail message`, `values map`, `first list` | Aborts rendering, extracts map values, or selects the first list element. |

String helpers take the input last for pipelines, for example `{{ .Token | trimPrefix "Bearer " | trim }}`. Unlike CEL map indexing, the `.Request.Header` and `.Request.QueryParam` accessors return `""` when the requested key is absent. The sandbox bearer token is intentionally unavailable.

`values` follows Go map iteration order. Using `values | first` is deterministic for a single-key object, but templates that need deterministic selection from a multi-key map must address a named key directly.

`fromJson` yields nothing when its input is not valid JSON, so guard with `kindIs` before treating the result as a map or list; `first` aborts the render when given something that is not a list. Indexing a key the JSON object does not carry yields an untyped nothing that `default`, `trim`, and `hasPrefix` all reject, so guard the key rather than relying on `default` as a fallback for it.

Use `fail` to abort a render deliberately. What that costs depends on the action: a token transformation follows its `failStrategy`, so `Allow` and `Ignore` forward the request without the mutation, while a header mutation has no fail-open option and returns `500`, discarding any header changes earlier filters had staged for that request. `values` needs a `map<string, dyn>`; `.Pod.Labels` and a single named input are string maps, so `values` accepts `.Inputs` itself and `fromJson` output but not those.

`mustFromJson` follows the same action-specific failure handling. Its JSON parsing and the string helpers run on real values at request time; compile-time template probes do not reject a valid template merely because request data is unavailable.

| Template root | Values |
| --- | --- |
| Token transformation `apiKey.value.template` | `.Token`, `.Header.Name`, `.Header.Value`, `.Request`, `.Pod`, `.Profile`, `.Rule`, and lazy `.Inputs`. `.Pod` has `Name`, `Namespace`, `IP`, `Labels`, and `Label key`; `.Inputs` is the profile input map. |
| Legacy token transformation `apiKey.valueTemplate` | The same context as `apiKey.value.template`; EPE normalizes the legacy single-header form to the same internal rule. |
| Credential-provider parameter `template` | `.Request`, `.Pod`, `.Profile`, `.Rule`, `.Inputs`. `.Request` has `Host`, `Port`, `Path`, `Scheme`, `Method`, `Query`, `Header name`, and `QueryParam name`. |
| Audit webhook URL, headers, and body | The shared roots above plus `.Result`, `.Response.Status`, and `.MatchedCriteria`/`.Matched`. Matched fields are populated only when the corresponding rule match constrained them. |

Use lower-risk data in audit and provider templates. Rendered values can be transmitted to external providers/webhooks, and the `json` helper serializes its argument rather than redacting it.

## See also

- [SecurityProfile reference](security-profile.md)
- [Credential provider contract](credential-provider.md)
- [Configure MCP access control](../tasks/configure-mcp-access-control.md)
- [Transform outbound credentials](../tasks/transform-outbound-credentials.md)
