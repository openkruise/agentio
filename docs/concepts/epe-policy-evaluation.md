# EPE policy evaluation

The Egress Policy Enforcer (EPE) evaluates a request only after Agentio has routed it through an egress gateway. Agentiod selects and orders matching `SecurityProfile` and `GlobalSecurityProfile` resources and publishes their references on the Workload. EPE demands that Workload through WDS, looks up the referenced bodies in its local Kubernetes watch cache, then evaluates the resulting rule chain.

## Profile and rule selection

A `SecurityProfile` can match only Workloads in its own namespace. A `GlobalSecurityProfile` is cluster-scoped and is considered for Workloads in every namespace. Both kinds use the same Workload label selector and share one ordering: lower `spec.priority` runs first; ties resolve by earlier creation timestamp, name, then namespace. The default priority is `1000`.

For each selected profile, EPE visits rules in the order they appear in `spec.rules`. A rule is added to the chain when any entry in `match` matches the request. Within one match entry, `domains` and every supplied restriction are ANDed; separate match entries are ORed. A broad matching rule does not prevent later, more-specific rules from running.

### Policy identity and bindings

Policy resolvers receive a `subject.Subject` shared by SecurityProfile and TrafficPolicy. Its `Workload subject.Workload` value contains the host Workload's discovery UID, namespace, name, IP, and labels; an optional `Sandbox *subject.Sandbox` contains the execution unit's discovery UID. Workload fields may be empty or partial, while a nil Sandbox means no execution identity was supplied. Each backend determines the fields it needs: TrafficPolicy requires a Workload identity, and admin selector queries may use namespace/labels without a Workload name. Completely empty Workload metadata does not select global profiles. Identities are read-only, and discovery UIDs are not Kubernetes object UIDs. `inputs.Workload` projects only Workload metadata, preserving existing CEL `pod` and template `.Pod` fields without making them the policy lookup contract. The transport constructs `CallerContext.Subject` directly and does not infer Sandbox identity from Workload metadata. `CallerContext.Token` stays separate from identity. Production profile matching uses Workload SecurityProfile references and Sandbox identities; existing expression names, callout JSON `source.pod`, access-log `pod`, and metric labels remain unchanged. Admin matching uses `workload_name` and `workload_labels`. Internal Sandbox profile keys use `sandbox/<namespace>/<name>`, including source tracking and diagnostic logs.

Production requests resolve administrator profiles by the ordered WDS references. Local selector indexes remain for admin queries and internal tests. Missing referenced bodies fail closed; an explicit empty binding does not fall back to selector matching. An explicit Sandbox UID selects its source through the metadata UID index, independently of the host Workload name. Lookup and initial-policy waiting use that Sandbox source's own namespace/name. Without a Sandbox UID, the backend retains the same-name lookup. Workload namespace/name remain required; the trusted gateway owns Sandbox-to-Workload binding validation. TrafficPolicy consumes the ordered references already attached to the xDS Workload. An explicit Workload UID selects that resource exactly; an unavailable resource is fetched by that UID without falling back to namespace/name.

On-demand requests pin their Workload and referenced TrafficPolicies, then capture those resources together from the discovery client. A cold lookup does not synchronously rebuild the global resource index. The index continues to publish batched updates in the background; requests reuse its compiled entry only when the Workload and policy values still match the selected resources. This keeps policy updates and synchronization loss visible even before the next background publication.

The resolver backend owns binding lookup, policy ordering, and initial Sandbox readiness. SecurityProfile bindings are distributed through WDS; SecurityProfile bodies still use Kubernetes watches. On-demand discovery of those bodies is not implemented yet.

### Sandbox initial policy readiness

Rules from a Sandbox's `agents.kruise.io/security-rules` annotation run after the administrator profiles. Before evaluating a request, EPE waits until a usable profile for the observed Sandbox UID is installed. A pending informer event, compilation, or debounced publication cannot turn a new Sandbox's first request into an empty policy chain. Raw source tracking and deletion notifications use the same `registry.Source` / `SourceRegistry` mechanism as agentiod. Deleting a Sandbox or removing its annotation wakes pending requests to recheck the source, without waiting for compiled-profile removal. The wait uses the existing `--plugin-budget`; an API lookup failure or an expired wait returns a local HTTP `503` (`epe_policy_unavailable`).

Only unresolved requests register a pending interest, keyed by their Sandbox profile. A relevant publication or raw-source deletion wakes those requests; unrelated policy updates do not wake already registered waiters. Registration checks the observed snapshot under the publication lock, so a concurrent change is rechecked without missing a notification. Requests whose policies are already available return without registering. Canceling one request does not cancel other requests waiting for the same Sandbox.

EPE checks its metadata informer first. On an explicit UID cache miss, it lists Sandbox metadata in the Workload namespace and compares registry UIDs; missing or ambiguous UIDs fail closed. This cold lookup supports both delivery-label UIDs and namespace/name-derived UIDs without interpreting the UID as an object name. Without an explicit UID, a local miss uses a metadata GET to distinguish watch lag from a Pod without a Sandbox. A confirmed absence with no explicit Sandbox UID, or an empty annotation on the matching Sandbox, needs no Sandbox policy. An explicit Sandbox UID that is missing or mismatched fails closed. Absence is not cached, so ordinary Pods without Sandbox objects incur a GET per request. API failures on this path fail closed.

This is an initial-publication guarantee, not a fresh read of every policy on every request. Updates to `SecurityProfile`, `GlobalSecurityProfile`, and an already installed Sandbox identity remain eventually consistent. When the informer observes a new Kubernetes object UID under the same name, EPE waits for that object's own profile instead of reusing its predecessor's rules. Requests do not carry that Kubernetes object UID; a discovery UID can also survive recreation. Recreation before the metadata informer observes the new object remains outside this guarantee.

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

Each matched rule receives the same immutable request context: host, authoritative destination port, path, method, scheme, headers, and first values of query parameters; the calling Workload name, namespace, IP, and labels; the profile and rule names; and the profile's named `inputs`. CEL expressions and Go templates that operate on this scope can use `request`, `pod`, `profile`, `rule`, and `inputs`. The scope intentionally excludes the request body, sandbox token, Secret values, and other credential material.

`tokenTransformation` can use templates for the injected credential value and CEL or templates for credential-provider parameters. Audit `when` expressions and audit webhook templates additionally receive the final `result`. Audit is evaluated at stream end, after the final decision is known; it is queued asynchronously and cannot alter the response. Rule-level audit actions replace profile-level audit actions for that rule. Queue pressure, template rendering errors, CEL runtime errors, webhook failures, and timeouts drop the audit event rather than delaying or changing workload traffic.

## Failures you can observe

EPE fails a rule projection or a filter error closed unless that filter's policy explicitly permits fail-open behavior. For example, `tokenTransformation.failStrategy` defaults to `Block`; `Allow` and `Ignore` let a transformation failure continue without that mutation. A blocked transformation returns a generic `403` response so implementation details such as Secret names and RBAC errors are not disclosed to the workload.

Profile compilation is separate from API acceptance. If a newly submitted profile cannot compile, EPE keeps the last known-good version when one exists; otherwise none of that profile's rules take effect. For a Sandbox with rules but no usable version for its UID, requests wait and fail closed as described above. A missing ConfigMap input does not reject the profile: its rules stay enforced while inputs-dependent actions fail per their failure strategy. Monitor `epe_profile_compile_failures_total`, `epe_profile_stale`, `epe_profile_unenforced`, and `epe_profile_inputs_unavailable`, and confirm policy changes with a real request. With no caller identity in ext_proc attributes, EPE skips profile selection but still applies destination authorization. `--fail-closed-on-missing-identity` rejects such requests at the request boundary.

## See also

- [Egress Policy Enforcer overview](epe-overview.md)
- [Configure a SecurityProfile](../tasks/configure-security-profile.md)
- [`SecurityProfile` API reference](../reference/security-profile-api.md)
