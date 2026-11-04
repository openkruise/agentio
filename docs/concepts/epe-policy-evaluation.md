# EPE policy evaluation

The Egress Policy Enforcer (EPE) evaluates a request only after Agentio has routed it through an egress gateway. `agentiod` selects and orders the matching `SecurityProfile` and `GlobalSecurityProfile` resources and publishes their references on the Workload. Policy binding and priority determine which rules apply.

## Profile and rule selection

A `SecurityProfile` can match only Workloads in its own namespace. A `GlobalSecurityProfile` is cluster-scoped and is considered for Workloads in every namespace. Both kinds use the same Workload label selector and share one ordering: lower `spec.priority` runs first; ties resolve by earlier creation timestamp, then name, then namespace. The default priority is `1000`.

For each selected profile, EPE visits rules in the order they appear in `spec.rules`. A rule is added to the chain when any entry in `match` matches the request. Within one match entry, `domains` and every supplied restriction are ANDed; separate match entries are ORed. A broad matching rule does not prevent later, more-specific rules from running.

## Action and continuation order

EPE executes the matched rule chain in profile and rule order. Within every rule, actions run in a fixed order:

1. `bypass`
2. `block`
3. `mcpToolPolicy`
4. `headerManipulation`
5. `tokenTransformation`

An action that returns a normal continuation lets evaluation proceed and can contribute a mutation. A request-body action pauses the header walk, asks Envoy for the complete buffered body, completes that action, and resumes at the exact next action and rule. This means an earlier body-dependent rule completes before a later `bypass` or `block` decision is considered.

`block` is terminal: EPE returns the configured response and discards every pending mutation. `bypass` is also terminal for EPE evaluation, but it forwards the request and preserves mutations already made by earlier actions; all later actions and rules across all matching profiles are skipped. A successful non-terminal transformation produces a mutated request.

EPE folds mutations in execution order before returning them to Envoy. Later header operations take precedence, with HTTP header names compared case-insensitively; the last body replacement wins. A route-affecting header mutation causes Envoy to clear its route cache before forwarding.

## Inputs, expressions, and audit

Each matched rule receives the same immutable request context: host, authoritative destination port, path, method, scheme, headers, and first values of query parameters; the calling Workload name, namespace, IP, and labels; the profile and rule names; and the profile's named `inputs`. CEL expressions and Go templates that operate on this scope can use `request`, `pod`, `profile`, `rule`, and `inputs`. The scope intentionally excludes the request body, Sandbox token, Secret values, and other credential material. See the [SecurityProfile reference](../reference/security-profile.md) for the public attribute tables.

`tokenTransformation` can use templates for the injected credential value and CEL or templates for credential-provider parameters. Audit `when` expressions and audit webhook templates additionally receive the final `result`. Audit is evaluated at stream end, after the final decision is known; it is queued asynchronously and cannot alter the response. Rule-level audit actions replace profile-level audit actions for that rule. Queue pressure, template rendering errors, webhook failures, and timeouts drop the audit event rather than delaying or changing workload traffic.

## Failures you can observe

EPE fails a policy error closed unless that policy explicitly permits fail-open behavior. For example, `tokenTransformation.failStrategy` defaults to `Block`; `Allow` and `Ignore` let a transformation failure continue without that mutation. A blocked transformation returns a generic `403` response so implementation details such as Secret names and RBAC errors are not disclosed to the workload.

Profile compilation is separate from API acceptance. If a newly submitted profile cannot compile, EPE keeps the last known-good version when one exists; otherwise none of that profile's rules take effect. A missing ConfigMap input does not reject the profile: its rules stay enforced while inputs-dependent actions fail per their failure strategy. With no caller identity, EPE skips profile selection but still applies destination authorization.

Monitor `epe_profile_compile_failures_total`, `epe_profile_stale`, `epe_profile_unenforced`, and `epe_profile_inputs_unavailable`, and confirm policy changes with a real request.

## See also

- [Egress Policy Enforcer overview](epe-overview.md)
- [EPE policy evaluation internals](../design/epe-policy-evaluation-internals.md)
- [Configure a SecurityProfile](../tasks/configure-security-profile.md)
- [`SecurityProfile` API reference](../reference/security-profile-api.md)
