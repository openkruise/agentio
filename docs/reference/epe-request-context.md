# EPE request context

The request context Egress Policy Enforcer (EPE) exposes while evaluating a `SecurityProfile` or `GlobalSecurityProfile` now lives in two places:

- **Public context** — the request attributes, CEL variables, and Go template roots you can use in policy expressions — is documented in the [SecurityProfile reference](security-profile.md#request-context).
- **Internal payload** — how caller identity, stream state, target forwarding, and phase availability flow through EPE — is documented in [EPE request context internals](../design/epe-request-context-internals.md).

## See also

- [SecurityProfile reference](security-profile.md)
- [Credential provider contract](credential-provider.md)
