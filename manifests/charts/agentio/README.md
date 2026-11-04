# Agentio

This chart installs Agentio.

**Sidecar mode is the default and recommended deployment mode. Ambient mode is in Alpha and does not yet have full feature parity with sidecar mode.** Install with the sidecar profile:

```bash
helm upgrade --install agentio . \
  -n agentio-system --create-namespace \
  --set profile=sidecar --atomic --wait
```

The default `profile: sidecar` enables per-Pod ztunnel injection. Select the Alpha ambient profile with `--set profile=ambient` to install CNI and node ztunnel. Optional components use `egressGateway.mode` and `epe.mode` rather than overlapping boolean switches.

Agentiod logging is configured with `agentiod.logging.level` (`debug`, `info`, `warn`, or `error`) and `agentiod.logging.format` (`text` or `json`).

Agentiod closes long-lived gRPC connections after `agentiod.keepalive.maxServerConnectionAge` (default `30m`) so clients periodically reconnect and re-authenticate. Set it to `0s` to disable periodic connection expiry.

Managed EPE waits `epe.preStopDelaySeconds` (default `10`) before SIGTERM so endpoint withdrawal can reach gateways. Its Pod termination budget is `epe.terminationGracePeriodSeconds` (default `45`), including that delay and EPE's 30-second gRPC drain window. The native sleep hook requires `PodLifecycleSleepAction`, enabled by default in Kubernetes 1.30+; set the delay to `0` to omit it on clusters without that feature. Use at least two EPE replicas for production availability. See [EPE configuration](../../../docs/reference/epe-configuration.md#rendered-kubernetes-behavior).

See [the repository installation guide](../README.md) for complete mode, namespace enrollment, EPE, Gateway API, and upgrade examples.

With `egressGateway.mode: gatewayAPI`, the deployer also supports `agentio-agentgateway` Gateways backed by native file configuration. Set the image and resources under `egressGateway.agentgateway`, and reference a same-namespace ConfigMap through the Gateway's `spec.infrastructure.parametersRef`. See [Deploy agentgateway](../../../docs/tasks/deploy-agentgateway.md) for the configuration contract and current scope.

`AGENTIO_GATEWAY_CONFIG` accepts YAML or JSON using the same runtime configuration schema as `agent-config`. Envoy log defaults are `warning` and `misc:error`; configure `envoyLogLevel` and `envoyComponentLogLevel` through `egressGateway.agentConfig` or the annotation. An explicit empty `envoyComponentLogLevel` removes the component override. Gateway API deployments retain explicit `sidecar.agentio.kruise.io/log-level`, `component-log-level`, and `agent-log-level` annotations as CLI overrides. The gateway no longer reads the injector’s `global.proxy.logLevel` or `global.proxy.componentLogLevel`; use `egressGateway.agentConfig` for gateway logging.

Gateway-agent configuration can be overridden per Gateway using the `gateway.agentio.kruise.io/agent-config` annotation (YAML or JSON):

```yaml
metadata:
  annotations:
    gateway.agentio.kruise.io/agent-config: |
      statsFlushInterval: 10s
```

Gateway API deployments inherit Gateway metadata annotations unless `spec.infrastructure.annotations` is explicitly set; in that case, put the annotation there. Static deployments can set the same annotation through `egressGateway.podAnnotations`. The agent reads `/etc/agentio/pod/annotations` at startup. Supplied fields override `egressGateway.agentConfig` (`AGENTIO_GATEWAY_CONFIG`); omitted fields retain their values, and explicit command-line flags take precedence. Metadata environment variables still override configured metadata. Unknown fields and invalid configuration fail startup. Updating the Gateway annotation changes the generated Pod template and takes effect on rollout; editing a running Pod annotation does not hot-reload the agent.

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

Gateway API deployments use `egressGateway.terminationGracePeriodSeconds` as the Pod default. A per-Gateway `parametersRef` Deployment patch can override `spec.template.spec.terminationGracePeriodSeconds`; the deployer passes the final value to gateway-agent, which caps `terminationDrainDuration` at that value minus five seconds for cleanup. Set `logAsJSON` through `egressGateway.agentConfig` or `agent-config`; the gateway does not use the injector's `global.logAsJson` CLI override.
