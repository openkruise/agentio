# EPE policy evaluation

The Egress Policy Enforcer (EPE) evaluates a request only after Agentio has routed it through an egress gateway. It resolves matching `SecurityProfile` and `GlobalSecurityProfile` resources from the calling Pod's namespace and labels, binds the matching rules, then evaluates the resulting rule chain.

## Profile and rule selection

A `SecurityProfile` can match only Pods in its own namespace. A `GlobalSecurityProfile` is cluster-scoped and is considered for Pods in every namespace. Both kinds use the same Pod label selector and share one ordering: lower `spec.priority` runs first; ties resolve by earlier creation timestamp, name, then namespace. The default priority is `1000`.

For each selected profile, EPE visits rules in the order they appear in `spec.rules`. A rule is added to the chain when any entry in `match` matches the request. Within one match entry, `domains` and every supplied restriction are ANDed; separate match entries are ORed. A broad matching rule does not prevent later, more-specific rules from running.

## Action and continuation order

EPE executes the matched rule chain in profile and rule order. Within every rule, the current registration order is fixed by the EPE binary, not by YAML field order:

1. `bypass`
2. `block`
3. `mcpToolPolicy`
4. `headerManipulation`
5. `tokenTransformation`

An action that returns a normal continuation lets evaluation proceed and can contribute a mutation. A request-body action pauses the header walk, asks Envoy for the complete buffered body, completes that action, and resumes at the exact next action and rule. This means an earlier body-dependent rule completes before a later bypass or block decision is considered. The current response-header phase is observation-only: no registered policy action produces response-header mutations.

`block` is terminal: EPE returns the configured response and discards every pending mutation. `bypass` is also terminal for EPE evaluation, but it forwards the request and preserves mutations already made by earlier actions; all later actions and rules across all matching profiles are skipped. A successful non-terminal transformation produces a mutated request; no matching action produces a passthrough request.

EPE folds mutations in execution order before returning them to Envoy. Later header operations take precedence with HTTP header names compared case-insensitively, and the last body replacement wins. A route-affecting header mutation causes Envoy to clear its route cache before forwarding.

## Inputs, expressions, and audit

Each matched rule receives the same immutable request context: host, authoritative destination port, path, method, scheme, headers, and first values of query parameters; the calling Pod name, namespace, IP, and labels; the profile and rule names; and the profile's named `inputs`. CEL expressions and Go templates that operate on this scope can use `request`, `pod`, `profile`, `rule`, and `inputs`. The scope intentionally excludes the request body, sandbox token, Secret values, and other credential material.

`tokenTransformation` can use templates for the injected credential value and CEL or templates for credential-provider parameters. Audit `when` expressions and audit webhook templates additionally receive the final `result`. Audit is evaluated at stream end, after the final decision is known; it is queued asynchronously and cannot alter the response. Rule-level audit actions replace profile-level audit actions for that rule. Queue pressure, template rendering errors, CEL runtime errors, webhook failures, and timeouts drop the audit event rather than delaying or changing workload traffic.

## Failures you can observe

EPE fails a rule projection or a filter error closed unless that filter's policy explicitly permits fail-open behavior. For example, `tokenTransformation.failStrategy` defaults to `Block`; `Allow` and `Ignore` let a transformation failure continue without that mutation. A blocked transformation returns a generic `403` response so implementation details such as Secret names and RBAC errors are not disclosed to the workload.

Profile compilation is separate from API acceptance. If a newly submitted profile cannot compile, EPE keeps the last known-good version when one exists; otherwise none of that profile's rules take effect. A missing ConfigMap input does not reject the profile: its rules stay enforced while inputs-dependent actions fail per their failure strategy. Monitor `epe_profile_compile_failures_total`, `epe_profile_stale`, `epe_profile_unenforced`, and `epe_profile_inputs_unavailable`, and confirm policy changes with a real request. Missing caller identity in ext_proc attributes passes through by default. `--fail-closed-on-missing-identity=true` rejects it with HTTP 403, and `--enable-egressauthz` forces that behavior. Optional [destination authorization](../tasks/configure-epe-destination-authorization.md) runs independently of profile matching and is not skipped by `bypass`.

## See also

- [Egress Policy Enforcer overview](epe-overview.md)
- [Configure a SecurityProfile](../tasks/configure-security-profile.md)
- [`SecurityProfile` API reference](../reference/security-profile-api.md)
