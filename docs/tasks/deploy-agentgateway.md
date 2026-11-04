# Deploy agentgateway with the Gateway API

The `agentio-agentgateway` GatewayClass provisions a ServiceAccount, Deployment, and Service that run agentgateway with a native YAML configuration file supplied through a ConfigMap. HorizontalPodAutoscaler (HPA) and PodDisruptionBudget (PDB) are opt-in resources.

This class provides deployment management and opt-in workload certificate bootstrap through the `agentiod` CA. It does not translate Agentio policy or egress configuration into agentgateway configuration; existing `agentio-egress` Gateways continue to use Envoy.

## Enable the deployer

Install Gateway API CRDs, then enable `egressGateway.mode: gatewayAPI` in the Agentio Helm release:

```yaml
egressGateway:
  mode: gatewayAPI
  agentgateway:
    image: cr.agentgateway.dev/agentgateway:v1.5.0
    resources:
      requests: {cpu: 100m, memory: 128Mi}
      limits: {cpu: "2", memory: 1Gi}
```

The image is an operator-controlled value; a Gateway annotation cannot override it. Scheduling can be configured with `egressGateway.agentgateway.nodeSelector`, `tolerations`, `affinity`, and `topologySpreadConstraints`.

The Deployment template leaves `spec.replicas` unset. To create an HPA or PDB, add a `horizontalPodAutoscaler` or `podDisruptionBudget` resource patch; an empty `{}` patch enables the template defaults. See [Customize Gateway resources](customize-gateway-resources.md).

## Supply file configuration

Create the configuration and Gateway in the same namespace. `parametersRef` must reference a core ConfigMap, and the configuration must be stored in `data["config.yaml"]`.

This example serves a fixed response to confirm deployment and configuration loading:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: agentgateway-config
  namespace: agentio-system
data:
  config.yaml: |
    config:
      adminAddr: 127.0.0.1:15000
    binds:
    - port: 8080
      listeners:
      - protocol: HTTP
        routes:
        - policies:
            directResponse:
              status: 200
              body: agentgateway is ready
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: agentgateway
  namespace: agentio-system
spec:
  gatewayClassName: agentio-agentgateway
  infrastructure:
    parametersRef:
      group: ""
      kind: ConfigMap
      name: agentgateway-config
  listeners:
  - name: http
    port: 8080
    protocol: HTTP
```

The Gateway listeners determine the Service ports; the ConfigMap determines what the proxy actually listens on and how it routes. Keep them consistent. Keep readiness on port 15021 at `/healthz/ready` and metrics on port 15020 at `/metrics`.

To configure an egress gateway, replace the example body with the HBONE/internal-listener configuration below and corresponding Gateway ports. The deployment controller does not automatically connect application or ztunnel traffic to this gateway.

If Helm should also create the Gateway, set `egressGateway.gatewayAPI.create: true`, `gatewayClassName: agentio-agentgateway`, and `infrastructure.parametersRef` under `egressGateway.gatewayAPI`. The referenced ConfigMap remains operator-owned.

## Enable workload certificates from agentiod

Enable native certificate bootstrap from `agentiod` for agentgateway deployments:

```yaml
egressGateway:
  mode: gatewayAPI
  agentgateway:
    ca:
      enabled: true
```

This option defaults to `false` to preserve existing file/Secret deployments. It applies to all `agentio-agentgateway` Gateways managed by this installation. It enables certificate bootstrap only; routes still come from the referenced ConfigMap.

Agentio supplies the CA address, the Pod's namespace and ServiceAccount identity, the trust domain and cluster ID, a projected short-lived ServiceAccount token, and the public trust bundle. Configure the HBONE bind in the native ConfigMap as follows, and expose port 15008 with `protocol: HBONE` in the Gateway listeners:

```yaml
binds:
- port: 15008
  tunnelProtocol: hboneGateway
  listeners:
  - protocol: HBONE
- port: 80
  mode: internal
  protocol: AUTO
  listeners: &egress-listeners
  - protocol: HTTP
    routes:
    - backends:
      - dynamic:
          target: 'string(destination.address) + ":" + string(destination.port)'
  - protocol: TLS
    hostname: "*"
    tcpRoutes:
    - backends:
      - dynamic:
          target: 'string(destination.address) + ":" + string(destination.port)'
  - protocol: TCP
    tcpRoutes:
    - backends:
      - dynamic:
          target: 'string(destination.address) + ":" + string(destination.port)'
- port: 443
  mode: internal
  protocol: AUTO
  listeners: *egress-listeners
```

The `hboneGateway` tunnel requires an IP:port CONNECT authority and an explicit internal bind for each destination port; the example permits ports 80 and 443. Add internal binds for other required ports. This example forwards to the original destination IP and passes inner HTTPS through unchanged; scope permitted destinations with your egress configuration.

Use `hboneGateway` rather than a `connect` + `tls.cert/key` bind: enabling the CA client alone does not replace certificates on static TLS listeners.

Certificate lifetime, renewal, and failure behavior are documented in [agentgateway certificate bootstrap (design)](../design/agentgateway-certificate-bootstrap.md).

## Mount additional or externally managed certificates

For configurations requiring TLS certificates or a MITM CA, reference a Secret in the Gateway namespace:

```yaml
metadata:
  annotations:
    gateway.agentio.kruise.io/agentgateway-certs: agentgateway-certs
```

The Secret's keys are mounted as files beneath `/etc/agentgateway/certs`; reference those paths in `config.yaml`. The deployer does not issue certificates, read Secret contents, or manage rotation. After rotating certificates, explicitly roll the Deployment to reload them.

External Secret mounts can coexist with native CA mode, for example for a separate HTTPS listener or MITM CA. When `ca.enabled` is false, the generated bootstrap has no CA connection or projected ServiceAccount token.

## Updates and status

Updating the referenced `config.yaml` triggers a rollout. The Deployment uses `maxUnavailable: 0` and `maxSurge: 1`.

- A missing reference, empty configuration, or invalid YAML reports `Accepted=False` and `Programmed=False`, without replacing the Deployment configuration.
- A schema-invalid configuration can create a failing new Pod while the old replica continues serving; correct the ConfigMap to recover.
- `Programmed=True` means the desired configuration's Deployment rollout is available. It does not assert end-to-end application connectivity.
- Removing the Gateway allows Kubernetes to garbage-collect its owned Deployment, Service, ServiceAccount, HPA, and PDB. ConfigMaps and Secrets are not adopted or deleted.

```bash
kubectl -n agentio-system get gateway agentgateway -o yaml
kubectl -n agentio-system rollout status deployment/agentgateway
kubectl -n agentio-system logs deployment/agentgateway
```

## See also

- [Customize Gateway resources](customize-gateway-resources.md)
- [agentgateway certificate bootstrap (design)](../design/agentgateway-certificate-bootstrap.md)
