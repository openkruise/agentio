# Policy validation status

agentiod validates SecurityProfile, GlobalSecurityProfile, TrafficPolicy and GlobalTrafficPolicy and reports the result in their existing `status.conditions`. No CRD changes or new status fields are required. This is advisory validation: EPE still watches and compiles SecurityProfiles independently, and this controller neither distributes L7 configuration nor gates the existing data-plane loaders.

| Condition | True | False | Unknown |
| --- | --- | --- | --- |
| `Accepted` | The production compilers accepted the configuration. | Compilation failed; `reason: InvalidConfiguration` and `message` identify the error. | No completed validation is available yet. |
| `ResolvedRefs` | All inspectable references resolved. | A referenced object is absent from a synchronized, in-scope cache. | A cache is not synchronized, a reference is outside the watch scope, runtime resolution is required, DNS has no addresses yet, or validation failed before reference checks. |
| `Programmed` (SecurityProfiles only) | The configuration compiled successfully and is eligible for data-plane distribution. | Compilation failed; `reason: InvalidConfiguration` and `message` identify the error. | No completed compilation is available yet. |

A new object may have no conditions until it is first reconciled. Conditions carry `observedGeneration`, `reason`, `message` and `lastTransitionTime`. SecurityProfiles also retain their existing `status.observedGeneration`; TrafficPolicies use the generation in each condition. A condition describes the current spec only when its `observedGeneration` equals `metadata.generation`. `lastTransitionTime` changes only when the condition's True/False/Unknown value changes.

For SecurityProfile and GlobalSecurityProfile, `Programmed` follows the compilation result reported by `Accepted`. It does not wait for data-plane acknowledgements or confirm that EPE has loaded the configuration. Reference checks remain separate: missing or runtime-resolved references affect `ResolvedRefs`, not `Programmed`.

The controller owns `Accepted`, `ResolvedRefs` and `Programmed` on SecurityProfiles, and only `Accepted` and `ResolvedRefs` on TrafficPolicies. Other controllers may own separate condition types, but must not compete for these types.

## Enable or disable

`ENABLE_POLICY_STATUS` defaults to `true`. Set it to `false` to disable the status controller, including its advisory validation, leader election and status writes. Existing status is retained; normal configuration compilation, distribution and EPE loading continue independently.

The environment variable is read at process startup, so restart agentiod after changing it. With Helm, set:

```yaml
agentiod:
  env:
    ENABLE_POLICY_STATUS: "false"
```

## Validation and reference scope

- SecurityProfiles reuse EPE's match, audit, CEL, template and action parsers, plus agentiod's SNI and binding compiler. No network calls or filter execution are performed during validation.
- TrafficPolicies reuse the native traffic and authorization projection compilers. Named Services must exist; a selector matching no objects is valid. An FQDN with no current addresses reports `DNSResolutionPending`, because the resolver does not expose enough detail to distinguish pending and failed DNS.
- ConfigMap inputs use their explicit namespace or the namespaced profile's namespace. Global profiles must specify the ConfigMap namespace.
- Secret references support both the typed union and the legacy spelling. Explicit namespaces take precedence. A namespaced profile otherwise uses its own namespace; a global profile without an explicit Secret namespace reports `RuntimeResolutionRequired`, because EPE selects the requesting Pod's namespace.
- With `agentiod.restrictedSecretsScope=true`, Secrets outside the control-plane namespace report `OutsideWatchScope`, not `SecretNotFound`. Status checks existence only; Secret contents and required credential keys remain runtime checks. Status never contains Secret values.
- Credential providers and HTTP callout providers depend on EPE's effective configuration and report `RuntimeResolutionRequired`. Provider availability, upstream calls and request-dependent expressions remain runtime checks.

ConfigMap, Secret, Service and DNS changes update reference status without a spec change. Status-only updates do not recompile SecurityProfile expressions.

## Writing status

One agentiod replica holds the `agentiod-policy-status` Lease in the control-plane namespace. A new leader replays current results. Writes use server-side apply to the status subresource with resource version and UID preconditions, preserve other condition owners, skip stale generations and suppress unchanged writes. Failed writes retry with backoff until the writer stops or a newer result replaces them. The chart grants patch permission only for these four status subresources; it does not expand Secret access.

Inspect a policy with:

```sh
kubectl get securityprofile -n demo example -o yaml
kubectl get securityprofile -n demo
kubectl get securityprofile -n demo -o wide
kubectl get trafficpolicy -n demo example -o jsonpath='{.status.conditions}'
```

SecurityProfile and GlobalSecurityProfile list output shows `Programmed` and `Age`. Use `-o wide` to also show `Accepted` and `ResolvedRefs`.
