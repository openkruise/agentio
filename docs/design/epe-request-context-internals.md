# EPE request context internals

> Design note. The internal EPE filter payload: how caller identity, stream state, and target forwarding flow through the Envoy `filter_state` and EPE's `Stream`/`Caller`/`RouteMutation` types. Policy authors should use the public [CEL and template context](../reference/security-profile.md#request-context) instead.

## How request data reaches EPE

EPE receives request data through Envoy external processing. Header names are normalized to lowercase. EPE buffers a request body only when a matched action requires it; body bytes and the sandbox bearer token are deliberately not exposed to CEL, Go templates, profile inputs, or audit payloads.

The token-header evaluation contract below describes the internal EPE filter payload. It is not a currently published `SecurityProfile` CRD field: until the corresponding agents-api prerequisite is released, public policy examples continue to use the legacy `apiKey` form.

EPE builds the request tuple during request headers. `:authority` takes precedence over `host`; its explicit port is used, otherwise `http` defaults to 80 and `https` to 443. For ordinary requests, Envoy's restored `destination.address` and `destination.port` override that inferred port when valid. CONNECT retains its authority port because the downstream local address identifies the proxy listener, not the tunnel target.

The internal routing filters use additional fields that are not exposed to CEL or templates. When a ServiceEntry matches, request-local `filter_state['agentio.route.upstream']` supplies its selected numeric `IP:port` as the initial `Stream.Upstream`.

## Target forwarding

- Target selection is independent of authorization. Native gateways always consume this filter state, even without EPE or ServiceEntries. It uses the `envoy.string` factory and contains a numeric `IP:port` (bracketed for IPv6). Only trusted gateway configuration or filters may populate it; never copy an unchecked client header into this key. EPE rejects malformed supplied targets.
- An internal `RouteMutation.Upstream` overrides the connection target without changing HTTP Host. Multiple rules specifying different upstream targets produce a conflict error. `ClearCache` only invalidates Envoy's route cache; it does not discard the selected target or rerun EPE. Request callbacks retain the initial target, including across body buffering, unless an explicit upstream mutation replaces it.
- EPE checks the final explicit target without DNS and rejects a denied target without choosing another endpoint. Its authorized target is returned in `agentio.route.upstream` **dynamic metadata**, distinct from the input filter state, and takes precedence when DFP connects. This uses the existing single EPE processing stream.

Without an explicit target, EPE resolves the request Host first. It prefers the original IP only when that IP occurs in the resolved candidates and TrafficPolicy allows it at the request routing port; if the original candidate is denied, the request is rejected without fallback. When the original IP is not a candidate, it selects an allowed candidate from the same result. DNS errors fail the request, and no allowed candidate produces HTTP 403. Literal IP hosts supply a single candidate without a DNS lookup. Ordinary requests retain the original destination port when available. Hostname resolution uses IPv4-only (`A`) queries, matching the gateway DNS cache's `V4_ONLY` setting; IPv6 answers in custom DNS records are also excluded. IPv4 and IPv6 literal hosts, explicit ServiceEntry targets, and upstream targets are checked directly without DNS. An IPv6 original destination is retained only for a matching IPv6 literal host, not for a hostname resolved as IPv4-only.

The `route` filter is an EPE building block, not public SecurityProfile routing configuration. Public HeaderMutation configuration and HTTP callout responses continue to reject Host and pseudo-header mutations. No target-reselection operation is provided.

## Caller context and stream information

`Stream.Caller` contains a `CallerContext`: its `Subject` holds Workload/Sandbox identity, and its `Token` holds the credential. HTTP request/response data and execution observations remain on `Stream`. Envoy filter-state attributes identify the caller:

| EPE stream field | Envoy attribute | Type | Absence behavior |
| --- | --- | --- | --- |
| Workload UID | `filter_state['agentio.workload.uid']` | string | Canonical discovery resource name supplied by native Porter after Workload identity verification. Legacy gateways may omit it; EPE then derives the Kubernetes Workload resource from namespace/name. Not expression-visible. |
| Sandbox UID | `filter_state['agentio.sandbox.uid']` | string | Optional canonical discovery resource name captured from `x-agentio-sandbox-uid` on CONNECT. When present, selects Sandbox metadata by discovery UID, independently of the Workload name. An absent value leaves the same-name Kubernetes lookup in effect. Not expression-visible. |
| Workload namespace | `filter_state['agentio.workload.namespace']` | string | Resolved by Porter from WDS; legacy gateways capture `x-agentio-workload-namespace` on HBONE CONNECT. Missing or empty falls back to `filter_state['downstream_peer'].namespace`; without a Workload UID, both namespace and name are required to identify the Workload. |
| Workload name | `filter_state['agentio.workload.name']` | string | Resolved by Porter from WDS; legacy gateways capture `x-agentio-workload-name` on HBONE CONNECT. Missing or empty falls back to `filter_state['downstream_peer'].name`; without a Workload UID, both namespace and name are required to identify the Workload. |
| Workload IP | `source.address` | string | EPE removes a valid port and surrounding IPv6 brackets. It is empty when absent; otherwise malformed input may be preserved after this syntactic stripping. |
| Workload labels | WDS `workload-metadata` | map<string, string> | Loaded by EPE from the current Workload, alongside ordered SecurityProfile references. Native gateways do not pass labels. The legacy `sandbox.labels` Base64 parser remains available to internal/legacy callers, but production WDS resolution replaces its result. |
| Sandbox identity | `filter_state['agentio.sandbox.metadata']` | internal object | Comma-separated `key=value` entries with percent-encoded values. EPE reads `agent-identity.access-token` and `agent-identity.sandbox-client-id`, preserving literal `+`. Both must be nonempty; malformed encoding or duplicate identity keys makes the credential unavailable. Decoded once, only when token transformation or OAuth2 needs it. Not expression-visible. |
| Legacy Sandbox token | `filter_state['sandbox.token']` | internal object | Base64 JSON or raw JSON with `requestId`, `accessToken`, and `sandboxClientId`. Used only when `agentio.sandbox.metadata` is absent; a present empty or malformed metadata value does not fall back. Parsing does not validate the access token. |
| Request ID | `x-request-id` | string | Empty when absent. Used for log correlation, not expression evaluation. |

ztunnel sets these headers from the source Pod's name and namespace, not its owning Deployment. The gateway preserves them in filter state across internal HTTP/TLS hops and exports them in EPE request attributes. EPE reads this captured context, not same-named headers on the inner application request. Default gateway access logs use the same per-field precedence for `workload_name` and `workload_namespace`, replacing `sandbox_name` and `sandbox_namespace`.

The request boundary recognizes a Workload UID, complete Workload namespace/name, or a Sandbox UID as supplied identity and passes it to policy resolution. With none of these, EPE skips profiles but still checks global destination restrictions and pins an allowed target. WDS fills the canonical Workload namespace/name and supplies SecurityProfile references, including for UID-only requests; unavailable Workloads or referenced profiles fail closed. TrafficPolicy accepts a Workload UID without namespace/name, but a Sandbox UID alone does not identify its Workload. The token is consumed only by provider-backed credential transformations; its bearer `accessToken` is never exposed in `request`, `pod`, `inputs`, templates, CEL, or audit context.

The filter stream also records matched profile/rule actions, filter outcomes, final disposition (`passthrough`, `mutated`, `blocked`, `bypassed`, or `error`), any resolved error text, and bytes forwarded before a verdict. These are internal/audit observations, not general CEL variables.

## Phase availability

| Phase | Available data | Mutability and limits |
| --- | --- | --- |
| Request headers | Request tuple, Workload/Sandbox identity, profile/rule, and resolved inputs. | Matching and header transformations occur here. `block` and `bypass` are header-only. |
| Request body | The same request context plus a complete buffered body only for actions that request it. | Current body consumers are MCP ACL and body-dependent signing. The body is not exposed to CEL/templates. Buffered mode prevents bytes from reaching upstream before the verdict. |
| Response headers | Upstream response status and lowercased response headers are recorded on the stream. | The current response phase is observation-only: filters cannot mutate response headers. Only status reaches audit CEL/templates. |
| Stream end | Final disposition and response status, if response headers arrived. | Audit actions are evaluated asynchronously; they cannot modify the already-resolved request or upstream response. |

Request and response bodies are not expression-visible. EPE's response-body and trailer handlers currently pass through. A blocked request may have no upstream response, in which case audit `response.status` is `0`.

## Token-header evaluation

`apiKey.targetHeaders` and `apiKey.value` use separate selector and value evaluations. A selector CEL expression sees the standard `request`, `pod`, `profile`, `rule`, and `inputs` variables; it never sees `token`. It must return a list of header names. All selectors observe the original request snapshot, before any selected header is mutated. Header names returned by a selector, like statically configured names, are canonicalized to lowercase before they are used. Token-header CEL does not expose the unbounded `lists.range` constructor, and each selector or value evaluation has a runtime cost limit of 10,000 CEL cost units; a size or cost violation follows the transformation's `failStrategy` like any other evaluation error.

A value CEL expression sees that same standard context plus `token` and `header.name`/`header.value`. Here `token` is the resolved transformation credential, not the sandbox bearer token. It must return a string. `header.name` is the canonicalized target name, while `header.value` is the target's original request value. A selector that returns no names is a successful no-op and skips credential access entirely.

Token-header value templates expose `.Token` (the resolved transformation credential), `.Header.Name`, `.Header.Value`, `.Request`, `.Pod`, `.Profile`, `.Rule`, and lazy `.Inputs`. `.Header.Value` remains the original request value even when another selected header has already been staged for replacement. EPE renders and validates every selected value before returning any header mutations, so a failure cannot leave a partial set of selected headers applied; the transformation's `failStrategy` handles the failure as a whole.
