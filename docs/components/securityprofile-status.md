# Policy validation status

`agentiod` validates SecurityProfile, GlobalSecurityProfile, TrafficPolicy and GlobalTrafficPolicy and reports the result in their existing `status.conditions`. SecurityProfile is a standard API; agentiod performs static API validation independently of any data-plane implementation. Consumers such as EPE watch and compile profiles independently. This controller neither distributes L7 configuration nor verifies that a consumer can load it.

| Condition | True | False | Unknown |
| --- | --- | --- | --- |
| `Accepted` | SecurityProfile passed API static validation, or TrafficPolicy passed the native traffic compiler. | Validation failed; `reason: InvalidConfiguration` and `message` identify the error. | No completed validation is available yet. |
| `ResolvedRefs` | All references checked by agentiod are resolved. | A referenced object is absent from a synchronized, in-scope cache. | A cache is not synchronized, a reference is outside the watch scope, DNS has no addresses yet, or validation failed before reference checks. |
| `Programmed` | TrafficPolicy compiled successfully and is eligible for distribution. | API validation or native traffic compilation failed. | For a valid SecurityProfile, agentiod does not check implementation loading; `reason: NotChecked`. |

A new object may have no conditions until it is first reconciled. Conditions carry `observedGeneration`, `reason`, `message` and `lastTransitionTime`. SecurityProfiles also retain their existing `status.observedGeneration`; TrafficPolicies use the generation in each condition. A condition describes the current spec only when its `observedGeneration` equals `metadata.generation`. `lastTransitionTime` changes only when the condition's True/False/Unknown value changes.

For SecurityProfile and GlobalSecurityProfile, `Accepted=True` means API static validation passed, while `Programmed=Unknown` makes no claim about a consumer's compilation or loading result. Invalid API configuration produces `Accepted=False` and `Programmed=False`. For TrafficPolicy and GlobalTrafficPolicy, `Programmed` follows native compilation and does not wait for data-plane acknowledgements. Reference checks remain separate: missing references checked by agentiod affect `ResolvedRefs`, not `Programmed`.

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

- SecurityProfiles share API static validation with the validating webhook: selector and priority constraints, TLS rules, reference and field unions, match regular expressions, and CEL and Go template syntax. Parsing does not type-check consumer-specific CEL variables or functions, check a template helper allowlist, probe-render templates, or project actions to filters. No EPE code or network calls are involved.
- TrafficPolicies reuse the native traffic and authorization projection compilers. Named Services must exist; a selector matching no objects is valid. An FQDN with no current addresses reports `DNSResolutionPending`, because the resolver does not expose enough detail to distinguish pending and failed DNS.
- ConfigMap inputs use their explicit namespace or the namespaced profile's namespace. Global profiles must specify the ConfigMap namespace.
- Secret references support both the typed union and the legacy spelling. Explicit namespaces take precedence. A namespaced profile otherwise uses its own namespace; a global profile without an explicit Secret namespace is excluded from reference checks, because the API specifies the selected Pod's namespace.
- With `agentiod.restrictedSecretsScope=true`, Secrets outside the control-plane namespace report `OutsideWatchScope`, not `SecretNotFound`. Status checks existence only; Secret contents and required credential keys remain runtime checks. Status never contains Secret values.
- Credential providers and HTTP callout providers are resolved by the API consumer and are excluded from reference checks. `ResolvedRefs=True` only covers references checked by agentiod; it does not confirm provider availability. Consumer-specific compilation, provider availability, upstream calls and expression evaluation remain consumer responsibilities.

ConfigMap, Secret, Service and DNS changes update reference status without a spec change. Status-only updates do not reparse SecurityProfile expressions.

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
