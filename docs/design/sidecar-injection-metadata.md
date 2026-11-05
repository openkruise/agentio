# Sidecar injection metadata

The injector uses the following Agentio metadata. These fields replace the corresponding Istio names for new Pods; recreate workloads from their original Pod templates after upgrading rather than reusing previously injected Pod YAML.

| Field | Purpose |
| --- | --- |
| Annotation `sidecar.agentio.kruise.io/status` | Records injected containers and volumes for reinjection. |
| Annotation `sidecar.agentio.kruise.io/overrides` | Records user-provided proxy container overrides for reinjection. |
| Label `agentio.kruise.io/network` | Overrides the injected proxy's network, taking precedence over injector URL and Helm values. |
| Annotation `prometheus.agentio.kruise.io/merge-metrics` | Enables or disables application metrics merging for this Pod. |
| Label `cni.agentio.kruise.io/uninitialized` | Default failure label when CNI repair is configured to label broken Pods. |

The chart's pinned CNI image still reads `sidecar.istio.io/status`. Injection through a CNI-enabled template therefore also writes that key; default init-container injection writes only the Agentio status. The CNI repair controller is configured to read the Agentio status. Traffic capture settings (`traffic.sidecar.istio.io/*`, `sidecar.istio.io/interceptionMode`, `status.sidecar.istio.io/port`, and `istio.io/reroute-virtual-interfaces`) retain their existing names because the CNI plugin consumes them. Ambient enrollment also retains the CNI-written `ambient.istio.io/redirection` annotation.

The injector no longer validates the unused `readiness.status.sidecar.istio.io/*` tuning annotations; they do not configure the ztunnel readiness probe. New injection does not add Istio revision, TLS mode, tunnel, or canonical-service labels. User-supplied metadata is preserved.
