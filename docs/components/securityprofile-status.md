# Policy validation status

`agentiod` validates SecurityProfile, GlobalSecurityProfile, TrafficPolicy and GlobalTrafficPolicy and reports the result in their existing `status.conditions`. SecurityProfile is a standard API; agentiod performs static API validation independently of any data-plane implementation. Consumers such as EPE watch and compile profiles independently. This controller neither distributes L7 configuration nor verifies that a consumer can load it.

| Condition | True | False |
| --- | --- | --- |
| `Accepted` | SecurityProfile passed API static validation, or TrafficPolicy passed API validation and native compilation. | `InvalidConfiguration` identifies a validation or compilation error. |
| `ResolvedRefs` | Agentiod has no confirmed reference errors. The reason is `ResolvedRefs`. | A resource is missing, a provider has the wrong type, the required default credential provider is disabled, or a Secret is outside the permitted namespace. |
| `Programmed` | The validated configuration is eligible for distribution. | API validation or native traffic compilation failed. |

A new object may have no conditions until it is first reconciled. Conditions carry `observedGeneration`, `reason`, `message` and `lastTransitionTime`. SecurityProfiles also record `status.observedGeneration`. A condition describes the current spec only when its `observedGeneration` equals `metadata.generation`. `lastTransitionTime` records the last change to the condition's status.

For all four policy kinds, `Programmed` follows `Accepted`. `ResolvedRefs` reports reference problems independently. Agentiod checks references after successful validation and defers cache lookups until the relevant cache has synchronized.

The condition's `reason` identifies the error category. Error messages include the affected resource, rule, input or field where available.

The controller owns `Accepted`, `ResolvedRefs` and `Programmed` on all four policy kinds. Other controllers may own separate condition types, but must not compete for these types.

## Enable or disable

`AGENTIO_ENABLE_POLICY_STATUS` defaults to `true`. Set it to `false` to disable the status controller, including its advisory validation, leader election and status writes. Existing status is retained; normal configuration compilation, distribution and EPE loading continue independently.

The environment variable is read at process startup, so restart `agentiod` after changing it. With Helm, set:

```yaml
agentiod:
  env:
    AGENTIO_ENABLE_POLICY_STATUS: "false"
```

## Validation and reference scope

- SecurityProfiles share API static validation with the validating webhook. Checks cover selectors, priorities, TLS rules, field unions, match regular expressions, and CEL and Go template syntax. EPE validates consumer-specific expression and filter semantics when compiling the profile.
- TrafficPolicies reuse the native traffic and authorization projection compilers. Named Services must exist. Selectors and FQDNs can resolve to an empty set of addresses.
- ConfigMap inputs use their explicit namespace or the namespaced profile's namespace. Global profiles must specify the ConfigMap namespace.
- Secret references support both the typed union and the legacy spelling. Explicit namespaces take precedence. A namespaced profile otherwise uses its own namespace; a global profile without an explicit Secret namespace is excluded from reference checks, because the API specifies the selected Pod's namespace.
- Agentiod assumes EPE uses the same token Secret scope. With `AGENTIO_SCOPED_SECRETS=true`, Secrets outside the control-plane namespace report `RefNotPermitted`. Agentiod checks for the presence of permitted Secrets. EPE checks credential keys at runtime.
- HTTP callouts require `actions.httpCallout.provider.name` to name an `httpCallout` extension provider in the effective AgentioConfig.
- Credential transformations and OAuth2 use the local connection selected by `defaultProviders.credentialProvider`. The rule's `credentialRef.credentialProvider.name` identifies a credential configuration on that remote service. Agentiod leaves an omitted default or a selected environment provider with no AgentioConfig entry to EPE. An explicitly empty default selection reports `DefaultProviderDisabled`.
- Provider reference checks verify local names and types. EPE still validates provider configuration, loads TLS material, and handles upstream calls and remote credential lookup.

AgentioConfig, ConfigMap, Secret and Service changes update reference status without a spec change.

The validating webhook uses the same reference checks on its current cache. It returns warnings for confirmed problems and permits the write. A server-side dry run shows the admission response.

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
