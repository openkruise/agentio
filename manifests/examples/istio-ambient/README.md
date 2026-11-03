# Agentio waypoint with Istio ambient

Follow [Integrate with Istio ambient](../../../docs/integrations/istio-ambient.md) from the repository root. The example reuses Istio traffic capture and workload certificates, then demonstrates Agentio policy with ordinary HTTP curl requests.

| File | Purpose |
| --- | --- |
| `agentio-values.yaml` | Render values for Agentiod and EPE |
| `namespaces.yaml` | Agentio control plane and ambient application namespaces |
| `waypoint.yaml` | Gateway and its certificate, Porter, and logging configuration |
| `workloads.yaml` | Curl client and HTTP origin |
| `service.yaml` | Service binding to the Agentio waypoint |
| `policies.yaml` | TrafficPolicy service allow rule and SecurityProfile HTTP deny rule |

Use the guide's template selection when rendering the Agentio chart. A full chart installation would also deploy Agentio traffic capture or injection.
