# Customize Gateway resources

Use `Gateway.spec.infrastructure.parametersRef` to patch the Kubernetes resources that Agentio's gateway deployer generates. Enable `agentiod.gatewayDeployer.enabled: true` and install the Gateway API CRDs first; see [Route traffic through an egress gateway](route-traffic-through-egress-gateway.md).

## Patch resource keys

Reference a core ConfigMap in the same namespace as the Gateway:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: egress
  namespace: demo
spec:
  gatewayClassName: agentio-egress
  infrastructure:
    parametersRef:
      group: ""
      kind: ConfigMap
      name: egress-parameters
  listeners:
  - name: hbone
    port: 15008
    protocol: HBONE
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: egress-parameters
  namespace: demo
data:
  deployment: |
    spec:
      template:
        spec:
          containers:
          - name: agentio-proxy
            resources:
              requests:
                cpu: 250m
                memory: 256Mi
            env:
            - name: EXAMPLE_SETTING
              value: enabled
  service: |
    spec:
      type: ClusterIP
```

Each key contains a Strategic Merge Patch applied after template rendering:

| ConfigMap data key | Resource |
| --- | --- |
| `deployment` | Deployment |
| `service` | Service |
| `serviceAccount` | ServiceAccount |
| `horizontalPodAutoscaler` | HorizontalPodAutoscaler |
| `podDisruptionBudget` | PodDisruptionBudget |

Containers and environment variables merge by `name`; a container entry with a new name adds a sidecar. Use `agentio-proxy` for the Envoy gateway and `agentgateway` for the native agentgateway. Strategic Merge Patch directives such as `$patch: delete` are supported. Patches may modify labels and annotations, but not resource identity or ownership metadata such as name, namespace, owner references, or finalizers.

The same ConfigMap may also contain `data.config` for Agentio egress settings or `data["config.yaml"]` for native agentgateway configuration. These keys are excluded from resource patching. Envoy resource-only ConfigMaps may omit `config` to use default proxy settings; an explicitly empty or invalid `config` retains the last valid proxy configuration. Agentgateway requires either `config.yaml` or translated `config`; see [Deploy agentgateway](deploy-agentgateway.md).

## Set GatewayClass defaults

Create a ConfigMap in the control-plane namespace (`agentio-system` by default) with the `gateway.agentio.kruise.io/defaults-for-class` label:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: egress-defaults
  namespace: agentio-system
  labels:
    gateway.agentio.kruise.io/defaults-for-class: agentio-egress
data:
  horizontalPodAutoscaler: |
    spec:
      minReplicas: 2
      maxReplicas: 5
  podDisruptionBudget: |
    spec:
      maxUnavailable: 1
```

Class defaults apply first; the Gateway's `parametersRef` patches apply afterward. HPA and PDB are generated only when their patch key is present; an empty `{}` patch enables the template defaults.

Controller behavior, address publication, and rendering-error handling are documented in [Gateway resource patching (design)](../design/gateway-resource-patching.md).

## See also

- [Gateway resource patching (design)](../design/gateway-resource-patching.md)
- [Deploy agentgateway](deploy-agentgateway.md)
- [Route traffic through an egress gateway](route-traffic-through-egress-gateway.md)
