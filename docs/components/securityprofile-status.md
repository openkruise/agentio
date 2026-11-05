# Policy validation status

`agentiod` validates SecurityProfile, GlobalSecurityProfile, TrafficPolicy and GlobalTrafficPolicy and reports the result in their existing `status.conditions`. No CRD changes or new status fields are required. This is advisory validation: the Egress Policy Enforcer (EPE) still watches and compiles SecurityProfiles independently, and this controller neither distributes L7 configuration nor gates the existing data-plane loaders.

| Condition | True | False | Unknown |
| --- | --- | --- | --- |
| `Accepted` | The production compilers accepted the configuration. | Compilation failed; `reason: InvalidConfiguration` and `message` identify the error. | No completed validation is available yet. |
| `ResolvedRefs` | All references checked by agentiod are resolved. | A referenced object is absent from a synchronized, in-scope cache. | A cache is not synchronized, a reference is outside the watch scope, DNS has no addresses yet, or validation failed before reference checks. |
| `Programmed` | The configuration compiled successfully and is eligible for data-plane distribution. | Compilation failed; `reason: InvalidConfiguration` and `message` identify the error. | No completed compilation is available yet. |

A new object may have no conditions until it is first reconciled. Conditions carry `observedGeneration`, `reason`, `message` and `lastTransitionTime`. SecurityProfiles also retain their existing `status.observedGeneration`; TrafficPolicies use the generation in each condition. A condition describes the current spec only when its `observedGeneration` equals `metadata.generation`. `lastTransitionTime` changes only when the condition's True/False/Unknown value changes.

For all four policy kinds, `Programmed` follows the compilation result reported by `Accepted`. It does not wait for data-plane acknowledgements or confirm that the data plane has loaded the configuration. Reference checks remain separate: missing references checked by agentiod affect `ResolvedRefs`, not `Programmed`.

The controller owns `Accepted`, `ResolvedRefs` and `Programmed` on all four policy kinds. Other controllers may own separate condition types, but must not compete for these types.

## Enable or disable

`ENABLE_POLICY_STATUS` defaults to `true`. Set it to `false` to disable the status controller, including its advisory validation, leader election and status writes. Existing status is retained; normal configuration compilation, distribution and EPE loading continue independently.

The environment variable is read at process startup, so restart `agentiod` after changing it. With Helm, set:

```yaml
agentiod:
  env:
    ENABLE_POLICY_STATUS: "false"
```

## Validation and reference scope

- SecurityProfiles reuse EPE's match, audit, CEL, template and action parsers, plus `agentiod`'s SNI and binding compiler. No network calls or filter execution are performed during validation.
- TrafficPolicies reuse the native traffic and authorization projection compilers. Named Services must exist; a selector matching no objects is valid. An FQDN with no current addresses reports `DNSResolutionPending`, because the resolver does not expose enough detail to distinguish pending and failed DNS.
- ConfigMap inputs use their explicit namespace or the namespaced profile's namespace. Global profiles must specify the ConfigMap namespace.
- Secret references support both the typed union and the legacy spelling. Explicit namespaces take precedence. A namespaced profile otherwise uses its own namespace; a global profile without an explicit Secret namespace is excluded from reference checks, because EPE selects the requesting Pod's namespace.
- With `agentiod.restrictedSecretsScope=true`, Secrets outside the control-plane namespace report `OutsideWatchScope`, not `SecretNotFound`. Status checks existence only; Secret contents and required credential keys remain runtime checks. Status never contains Secret values.
- Credential providers and HTTP callout providers depend on EPE's effective configuration and are excluded from reference checks. `ResolvedRefs=True` only covers references checked by agentiod; it does not confirm provider availability. Configuration validation still checks action syntax, while provider availability, upstream calls and request-dependent expressions remain runtime checks.

ConfigMap, Secret, Service and DNS changes update reference status without a spec change. Status-only updates do not recompile SecurityProfile expressions.

## Writing status

The controller writes status in the background using a leader-election Lease and server-side apply. See [how status is written](../design/securityprofile-status-writes.md) for the implementation details.

Inspect a policy with:

```sh
kubectl get securityprofile -n demo example -o yaml
kubectl get securityprofile -n demo
kubectl get securityprofile -n demo -o wide
kubectl get trafficpolicy -n demo example -o jsonpath='{.status.conditions}'
kubectl get trafficpolicy -n demo
kubectl get trafficpolicy -n demo -o wide
```

SecurityProfile and GlobalSecurityProfile list output shows `Programmed` and `Age`. TrafficPolicy and GlobalTrafficPolicy also retain their `Priority` column. Use `-o wide` to also show `Accepted` and `ResolvedRefs` for all four policy kinds.
