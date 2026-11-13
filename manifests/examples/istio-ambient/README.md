# Agentio waypoint with Istio ambient

Follow [Integrate with Istio ambient](../../../docs/integrations/istio-ambient.md) from the repository root. The example reuses Istio traffic capture and workload certificates, demonstrates policy with HTTP curl requests, and optionally inspects HTTPS using CA-only injection.

| File | Purpose |
| --- | --- |
| `agentio-values.yaml` | Helm preset for Agentiod, EPE and CA-only admission; Agentio CNI/node ztunnel disabled |
| `namespaces.yaml` | Agentio control plane and ambient application namespaces |
| `waypoint.yaml` | Gateway, certificate configuration, and access logs |
| `workloads.yaml` | Curl client and HTTP origin |
| `service.yaml` | Service binding to the Agentio waypoint |
| `https-service.yaml` | Optional Istio ServiceEntry binding for `httpbin.org:443` |
| `policies.yaml` | SecurityProfile HTTP/HTTPS deny rule |

Use the preset with `helm upgrade --install`; no template filtering is required. Istio owns traffic capture. The curl Pod receives a client CA mount and environment variables, with no Agentio sidecar.
