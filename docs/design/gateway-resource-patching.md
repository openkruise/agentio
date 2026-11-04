# Gateway resource patching — controller behavior

> Design note. This page records controller behavior behind [Customize Gateway resources](../tasks/customize-gateway-resources.md).

## Separate CA and control-plane credentials

The Envoy gateway agent uses `AGENTIO_TOKEN_FILE` for control-plane authentication. Set `AGENTIO_CA_TOKEN_FILE` to a separate projected ServiceAccount token when the certificate authority requires a different audience. If unset or empty, it uses `AGENTIO_TOKEN_FILE`, preserving the existing shared-token setup. The CA token file is read again on each signing attempt, including certificate renewal.

Use a `deployment` patch to mount the additional projected token and set `AGENTIO_CA_TOKEN_FILE` in `agentio-proxy`. Choose the token audience accepted by the CA. `CA_ADDR`, `AGENTIO_CA_SERVER_NAME`, and `AGENTIO_CA_ROOT_CA` configure the CA connection independently of `AGENTIO_XDS_ADDRESS`, `AGENTIO_XDS_SERVER_NAME`, and `AGENTIO_XDS_ROOT_CA` for the control plane.

## Gateway addresses

Once the generated Deployment is available and its managed Service exists, the deployer publishes `Gateway.status.addresses` using these rules:

- Service external IPs and LoadBalancer ingress IPs or hostnames take precedence.
- Without external addresses, `agentio-egress` reports both ClusterIPs and the Service hostname; `agentio-agentgateway` reports the hostname by default.
- The `networking.istio.io/address-type` Gateway annotation selects `IPAddress` or `Hostname` for internal addresses. It does not filter external addresses.

The internal hostname has the form `<service>.<namespace>.svc.<cluster-domain>` and uses the configured cluster domain, defaulting to `cluster.local`. A headless Service contributes no ClusterIP.

While a LoadBalancer Service has no external address, its internal hostname is omitted and `Programmed` is false with reason `AddressNotAssigned`; eligible internal IPs can still be reported. If no new address can be reported, an already published address is retained. Addresses are also retained while the Deployment is pending or rolling out and when native agentgateway configuration is invalid. Read the `Programmed` condition to distinguish availability from the retained discovery address.

## Reconciliation, rendering, and error behavior

ConfigMap creation, updates, and deletion trigger reconciliation. Deployment Pod template changes trigger a rollout; Envoy `config`-only updates use xDS without changing the Pod template. Native `config.yaml` changes still trigger a rollout.

Class-default ConfigMap selection picks the oldest matching ConfigMap, breaking timestamp ties by name. Changing or removing the `gateway.agentio.kruise.io/defaults-for-class` label reconciles Gateways from both the old and new classes; the old class falls back to its next-oldest matching ConfigMap, or to the template if none remain.

An explicitly empty or invalid Envoy `config` retains the last valid proxy configuration.

Removing a Deployment, Service, or ServiceAccount patch restores the fields owned by the controller to the template plus any remaining class defaults. Gateway deletion allows Kubernetes to garbage-collect owned resources; input ConfigMaps are not adopted or deleted.

Missing parameters, unsupported resource patch keys, invalid patch syntax, or forbidden metadata changes abort rendering and leave previously applied resources in place. The controller logs rendering failures without retrying or writing an `InvalidParameters` condition for these resource patch errors. Kubernetes apply failures return an error to the retry queue. Check `agentiod` logs to diagnose resource patch failures.
