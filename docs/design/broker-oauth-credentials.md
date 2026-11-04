# OAuth credential brokering — implementation notes

> Design note. This page records implementation details behind [Configure OAuth credential isolation](../tasks/broker-oauth-credentials.md). It is not required reading for operators.

## Public API

The OAuth broker's public API contract comes from `openkruise/agents-api`. `SecurityProfile` and `GlobalSecurityProfile` use the same configuration.

## Identity and authorization boundaries

Authorization is per Sandbox, remote provider, and trusted platform identity. Clients that share that binding share the same current authorization.

`unused` in Token responses is a compatibility placeholder, not a CLI session identifier. Clearing a CLI cache does not revoke authorization; replacing the binding can change the credential used by other clients that share it. Independent CLI sessions, reliable CLI logout, and concurrent accounts require coordinated client/service contracts.

The current Identity contract returns zero for the positive cache TTL, so each matched business request still asks Identity for a credential; that lookup does not necessarily refresh the upstream token. Token and DeviceAuthorization operations always call the service and invalidate the binding's Resource entries. No cache TTL is configured in the `SecurityProfile`.

Resource caching stays in trusted EPE memory. Only a positive service `cacheExpiresInSeconds`, capped by the known access-token lifetime, permits reuse. A zero, missing, or negative cache TTL disables caching.

## Test coverage

The test suite exercises published CRD admission, production policy projection, the provider registry, and the external-processing gRPC chain against an HTTP credential service fixture. A live gateway/CLI deployment is a separate verification of the destination, TLS, and platform identity configuration.
