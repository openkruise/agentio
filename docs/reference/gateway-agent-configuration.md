# Gateway agent configuration

Use `egressGateway.agentConfig` as shared defaults for Helm-managed and Gateway API Envoy gateways. The `gateway.agentio.kruise.io/agent-config` annotation overrides these defaults per gateway. Use [Gateway resource patches](../tasks/customize-gateway-resources.md) for Kubernetes resources. Native agentgateway uses its own [file configuration](../tasks/deploy-agentgateway.md).

`AGENTIO_GATEWAY_CONFIG` accepts YAML or JSON using the same runtime configuration schema as `agent-config`. Envoy log defaults are `warning` and `misc:error`; configure `envoyLogLevel` and `envoyComponentLogLevel` through the corresponding agent settings or the annotation. An explicit empty `envoyComponentLogLevel` removes the component override. Gateway API deployments retain explicit `sidecar.agentio.kruise.io/log-level`, `component-log-level`, and `agent-log-level` annotations as CLI overrides. The gateway no longer reads the injector’s `global.proxy.logLevel` or `global.proxy.componentLogLevel`; use the corresponding agent settings for gateway logging.

Gateway-agent configuration can be overridden per Gateway using the `gateway.agentio.kruise.io/agent-config` annotation (YAML or JSON):

```yaml
metadata:
  annotations:
    gateway.agentio.kruise.io/agent-config: |
      statsFlushInterval: 10s
```

Gateway API deployments inherit Gateway metadata annotations unless `spec.infrastructure.annotations` is explicitly set; in that case, put the annotation there. Static deployments can set the same annotation through `egressGateway.podAnnotations`. The agent reads `/etc/agentio/pod/annotations` at startup. Supplied fields override the corresponding static or Gateway API agent defaults (`AGENTIO_GATEWAY_CONFIG`); omitted fields retain their values, and explicit command-line flags take precedence. Metadata environment variables still override configured metadata. Unknown fields and invalid configuration fail startup. Updating the Gateway annotation changes the generated Pod template and takes effect on rollout; editing a running Pod annotation does not hot-reload the agent.

Individual statistics annotations follow pilot-agent's statistics override behavior, using the Agentio gateway prefix:

```yaml
metadata:
  annotations:
    gateway.agentio.kruise.io/stats-flush-interval: "10s"
    gateway.agentio.kruise.io/stats-eviction-interval: "1m"
```

| Annotation suffix under `gateway.agentio.kruise.io/` | Value and behavior |
| --- | --- |
| `stats-flush-interval` | Positive Go duration; overrides `agent-config`. |
| `stats-eviction-interval` | Positive duration that is a multiple of the effective flush interval. |
| `stats-inclusion-prefixes`, `stats-inclusion-suffixes`, `stats-inclusion-regexps` | Comma-separated values replace the corresponding configured list; empty values preserve it. Required gateway metrics remain included. |
| `stats-histogram-buckets` | JSON object mapping metric prefixes to bucket arrays; replaces configured buckets. |
| `extra-stat-tags` | Comma-separated tags append to configured tags without duplicates. |

The effective order is defaults, environment configuration, `agent-config`, individual statistics annotations, then explicit CLI flags. Lists in `agent-config` replace previous lists; metadata keys merge. These annotations use gateway-agent's configuration schema, not Istio's `ProxyConfig` schema or `sidecar.istio.io/*` keys. Unlike pilot-agent's warning-and-ignore handling for some statistics annotations, invalid supplied configuration fails startup. MeshConfig files and sidecar interception annotations are not part of this gateway configuration interface.

Both Envoy deployment paths use `egressGateway.terminationGracePeriodSeconds` as the Pod shutdown budget (30 seconds by default). A per-Gateway `parametersRef` Deployment patch can override `spec.template.spec.terminationGracePeriodSeconds`; the deployer passes the final value to gateway-agent, which caps `terminationDrainDuration` at that value minus five seconds for cleanup. Set `logAsJSON` through the corresponding agent settings or `agent-config`; the gateway does not use the injector's `global.logAsJson` CLI override.
