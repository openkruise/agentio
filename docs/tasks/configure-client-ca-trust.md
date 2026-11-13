# Configure client CA trust

Distribute trusted CA certificates to workload clients and inject the standard trust environment variables so applications validate the MITM signing CA that Agentio uses for HTTPS inspection. Sidecar mode is the recommended deployment mode; ambient mode is Alpha.

Enable distribution and injection with `agentiod.injector.clientTrust.enabled: true`. Injection is independent of gateway TLS termination and SNI traffic policies. The default bundle combines the pinned public CA package with the MITM signer's public certificates, and is published to namespaces using the same scope as the workload CA ConfigMap regardless of individual Pod opt-outs. Terminating namespaces, `kube-public`, `kube-node-lease`, and `local-path-storage` are skipped.

## Enable and select clients

```yaml
profile: sidecar
agentiod:
  injector:
    clientTrust:
      enabled: true
      env:
        # Python ssl / HTTPX and clients using OpenSSL default trust paths
        - SSL_CERT_FILE
        # Python Requests
        - REQUESTS_CA_BUNDLE
        # Node.js
        - NODE_EXTRA_CA_CERTS
        # curl
        - CURL_CA_BUNDLE
      containers:
        include: ["app-*", "worker"]
        exclude: ["*-metrics"]
        includeInitContainers: false
      envConflictPolicy: Preserve
```

`enabled` defaults to `false`. Enabling or disabling it through Helm rolls `agentiod`; disabling retains existing ConfigMaps but stops their updates. Recreate existing Pods to receive new mounts and environment variables. For an existing deployment, enable client trust first and roll workloads, then activate gateway TLS termination.

Empty `include` selects all business containers. Patterns match the complete container name and support only `*`; exclusion wins. Agentio proxy and init containers are always excluded; business init containers are opt-in.

With the feature enabled, set `client-trust.agentio.kruise.io/inject: "true"` on a Namespace or Pod to inject CA mounts and client environment variables independently of sidecar injection. Use `"false"` to disable CA injection. Pod labels override Namespace labels; neither can bypass the global `enabled: false` switch. Without either label, CA injection continues to follow the `ztunnel` sidecar template in the sidecar profile. In the ambient profile, the chart installs CA-only admission when this feature is enabled; workload sidecar labels do not cause proxy injection through that endpoint.

For an existing Istio installation, use the [Istio integration preset](../integrations/istio-ambient.md), which disables Agentio CNI and node ztunnel while retaining CA injection. Istio mesh workload certificates and Agentio's HTTPS MITM trust bundle remain separate.

For example, this Namespace enables CA injection without opting into a sidecar:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: clients
  labels:
    client-trust.agentio.kruise.io/inject: "true"
```

On a Deployment, put the label under `spec.template.metadata.labels`. An explicitly enabled Pod also receives CA configuration when its dataplane mode is `none` or `ambient`. CA-only injection does not add proxy or init containers, rewrite probes, or change traffic routing. Changing labels affects newly created Pods; recreate existing Pods to apply the change.

Pod annotations continue to control container selection:

```yaml
metadata:
  labels:
    client-trust.agentio.kruise.io/inject: "true"
  annotations:
    sidecar.agentio.kruise.io/client-trust-containers: "app-*,worker"
    sidecar.agentio.kruise.io/client-trust-exclude-containers: "*-metrics"
```

The two container lists replace (not append to) their global counterparts. The legacy Pod annotation `sidecar.agentio.kruise.io/client-trust: "false"` still opts out, including in a CA-enabled Namespace, unless an explicit Pod injection label overrides it. Its `"true"` value retains the default behavior and does not independently enable CA-only injection.

The webhook selectors are mutually exclusive: each selected Pod reaches the injector once, even when both CA and sidecar injection are enabled. Agentiod waits for its namespace cache to synchronize before accepting injection requests. CA bundle distribution remains independent of Namespace/Pod injection labels and opt-outs.

## Add public and private CA sources

```yaml
agentiod:
  clientTrustBundle:
    sources:
      - defaultCAs: true
      - agentioMITM: true
      - configMap:
          namespace: agentio-system
          name: company-private-ca
          key: ca.crt
    target:
      configMapName: agentio-client-ca
      key: ca-bundle.pem
```

- `defaultCAs: true` adds the pinned public CA package.
- `agentioMITM: true` adds the MITM signer's public certificates.
- `configMap` or `secret` adds a private CA. Both require explicit `namespace`, `name`, and `key`; Secret sources use `secret` instead of `configMap`.

Store CA source objects in the Agentio system namespace (the Helm release namespace, normally `agentio-system`). By default `AGENTIO_SCOPED_SECRETS=true` restricts Secret sources to that namespace; set it to `false` to watch all namespaces and supply the required global Secret `list`/`watch` RBAC. References outside the watched scope are unavailable and retain the last complete bundle.

A custom bundle does not automatically inherit private CAs from application images; include every additional enterprise trust anchor the application needs. Sources are parsed, deduplicated, and stably ordered. Private keys and non-CA certificates are rejected.

To trust private CAs on gateway upstream connections, configure `egressGateways[].upstreamTrustBundle.additionalSources` separately. See [Agentio configuration](../reference/agentio-configuration.md#upstream-ca-trust).

## Custom mounts and environment variables

```yaml
agentiod:
  injector:
    clientTrust:
      enabled: true
      mounts:
        - name: company-ca
          mountPath: /etc/company/ca
          configMap:
            name: company-client-ca
            items:
              - key: ca-bundle.pem
                path: ca-bundle.pem
      files:
        caBundle: /etc/company/ca/ca-bundle.pem
      env:
        - SSL_CERT_FILE
        - REQUESTS_CA_BUNDLE
        - NODE_EXTRA_CA_CERTS
        - CURL_CA_BUNDLE
        - CUSTOM_CA_FILE
      envConflictPolicy: Preserve
```

Omit `mounts` to use the managed bundle. Explicit mounts replace the default and require an explicit `files.caBundle`. Each mount requires explicit `items`, is read-only, and does not use `subPath`.

`env` lists only environment variable names; every listed variable receives the `files.caBundle` path. Every selected container also receives `AGENTIO_TRUST_BUNDLE`, which custom clients must read and load into their TLS trust context:

```python
import os
import ssl

context = ssl.create_default_context(cafile=os.environ["AGENTIO_TRUST_BUNDLE"])
```

Default variables:

| Default environment variable | Common clients |
| --- | --- |
| SSL_CERT_FILE | Python ssl / HTTPX and clients using OpenSSL default trust paths |
| REQUESTS_CA_BUNDLE | Python Requests |
| NODE_EXTRA_CA_CERTS | Node.js (adds to built-in public roots) |
| CURL_CA_BUNDLE | curl |

The conflict policy applies to `AGENTIO_TRUST_BUNDLE` too. `Preserve` keeps application-defined variables and warns on different values; `Overwrite` replaces the complete variable.

Explicit Namespace or Pod injection labels enable client trust regardless of the selected proxy template. Without labels, only the `ztunnel` template receives client trust by default.

## Verify

Files projected from ConfigMaps update eventually; client processes may cache CA contents. Recreate Pods to reliably load an updated bundle.

Inspect the target ConfigMap annotations for owner, package version, and SHA-256. Failures emit a `ClientTrustReconcileFailed` event in the control-plane namespace and structured logs.

## See also

- [Client CA trust package (design)](../design/client-ca-trust-package.md)
- [Agentio configuration](../reference/agentio-configuration.md)
