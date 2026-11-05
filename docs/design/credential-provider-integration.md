# Credential provider integration

> Design note. Implementation and contributor notes for the EPE credential-provider extension point. The operator-facing contract is in [Credential provider](../reference/credential-provider.md).

## Scope

The credential provider is an extension point, not a fixed backend. Any service that implements the request/response contract works; integrations that target a specific cloud vendor (for example an Alibaba Cloud-backed provider) are implementations of this same contract. EPE ships the client side only (`extensions/epe/pkg/credential`).

## Per-rule extension provider references

EPEConfig supports multiple named credential services and selects the default through `defaultProviders.credentialProvider`. SecurityProfile's `name` field selects the remote credential configuration. Per-rule extension provider references are deferred to future SecurityProfile API work.

## In-process invalidation trigger

In-process integrations call the same `extensionprovider.Registry` used by the filters. `providerName` is the remote `credentialProviderName`, not an `EPEConfig.extensionProviders[].name`. The registry invalidates that remote name across all current credential-provider connections and aggregates removed counts; replaced configuration versions remain isolated from current caches.

```go
result, err := registry.InvalidateCredentials(credential.InvalidationRequest{
    ProviderName: "my-provider",
})
```

Direct users of `credential.Client` can call its `InvalidateCredentials` method to affect only that client. `credential.NewClient` accepts `credential.WithInvalidationCachePolicy(window, maxTTL)` to override the 30s/5s defaults, including setting both to zero to disable TTL adjustment. The EPE registry passes the environment settings explicitly when constructing each client.

## External triggers

Adapters for watches, message queues, webhooks, or manual tools are supplied by the integrator. EPE does not register these external event sources. Adapters map source identities to the exact provider names sent to `GetResourceCredential` and deliver invalidations to every EPE replica. Replayed notifications invalidate again and restart the configured window. After a missed event or reconnect, an adapter can invalidate each affected provider.

Caches and invalidation state are process-local and empty after restart. Provider invalidation state is reclaimed lazily after its short-TTL window ends and all in-flight credential fetches finish: later invalidations sweep expired idle states, and completed fetches check their own provider state. This API does not provide cross-replica delivery, persistence, or a fixed end-to-end freshness deadline.
