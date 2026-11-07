# Agentio

This chart installs Agentio.

**Sidecar mode is the default and recommended deployment mode. Ambient mode is in Alpha and does not yet have full feature parity with sidecar mode.** Install with the sidecar profile:

```bash
helm upgrade --install agentio . \
  -n agentio-system --create-namespace \
  --set profile=sidecar --atomic --wait
```

The default `profile: sidecar` enables per-Pod ztunnel injection. Select the Alpha ambient profile with `--set profile=ambient` to install CNI and node ztunnel. Static gateways use `egressGateway.enabled`; the Gateway API controller uses independent `agentiod.gatewayDeployer.enabled`. EPE keeps `epe.mode`.

Agentiod logging is configured with `agentiod.logging.level` (`debug`, `info`, `warn`, or `error`) and `agentiod.logging.format` (`text` or `json`).

Agentiod closes long-lived gRPC connections after `agentiod.keepalive.maxServerConnectionAge` (default `30m`) so clients periodically reconnect and re-authenticate. Set it to `0s` to disable periodic connection expiry.

Managed EPE waits `epe.preStopDelaySeconds` (default `10`) before SIGTERM so endpoint withdrawal can reach gateways. Its Pod termination budget is `epe.terminationGracePeriodSeconds` (default `45`), including that delay and EPE's 30-second gRPC drain window. The native sleep hook requires `PodLifecycleSleepAction`, enabled by default in Kubernetes 1.30+; set the delay to `0` to omit it on clusters without that feature. Use at least two EPE replicas for production availability. See [EPE configuration](../../../docs/reference/epe-configuration.md#rendered-kubernetes-behavior).

See [the repository installation guide](../README.md) for complete mode, namespace enrollment, EPE, Gateway API, and upgrade examples.

With `agentiod.gatewayDeployer.enabled: true`, the deployer also supports `agentio-agentgateway` Gateways backed by native file configuration. Set the image and CA bootstrap under `egressGateway.agentgateway`. Create the Gateway and its same-namespace parametersRef ConfigMap separately; use resource patches to customize its workloads. See [Deploy agentgateway](../../../docs/tasks/deploy-agentgateway.md) for the configuration contract and current scope.

Gateway-agent settings belong in `egressGateway.agentConfig`. For annotation overrides, statistics and precedence, see [Gateway agent configuration](../../../docs/reference/gateway-agent-configuration.md).
