# Configure client CA trust

In sidecar mode, enable client CA distribution and injection with `agentiod.injector.clientTrust.enabled: true`. Injection is independent of Gateway TLS termination configuration and SNI traffic policies. The default bundle combines the pinned public CA package with the MITM signer's public certificates. It is published to namespaces using the same scope as the workload CA ConfigMap, regardless of individual Pod opt-outs. Terminating namespaces, `kube-public`, `kube-node-lease`, and `local-path-storage` are skipped.

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

`enabled` accepts boolean `true` or `false` and defaults to `false`. This is the master switch for both CA distribution and injection. The chart derives `AGENTIO_ENABLE_CLIENT_TRUST_DISTRIBUTOR` from this value. It includes the public CA package init container only when the feature is on and `clientTrustBundle.sources` contains `defaultCAs: true`. There is no separate distributor chart setting. Enabling or disabling it through Helm rolls agentiod; disabling retains existing ConfigMaps but stops their updates. Existing Pods must be recreated to receive new mounts and environment variables. For an existing deployment, first enable client trust explicitly and roll workloads, then activate gateway TLS termination.

Empty `include` selects all business containers. Patterns match the complete name and support only `*`; exclusion wins. Agentio proxy/init containers are always excluded. Business init containers are opt-in. Container indexes are not supported. An explicit include list with no matches produces an admission warning.

With the feature enabled, Pod annotations control opt-out and container selection:

```yaml
metadata:
  annotations:
    sidecar.agentio.kruise.io/client-trust: "false"
    sidecar.agentio.kruise.io/client-trust-containers: "app-*,worker"
    sidecar.agentio.kruise.io/client-trust-exclude-containers: "*-metrics"
```

Annotation values remain strings. `"false"` opts out; `"true"` cannot bypass a globally disabled feature. The two lists replace (not append to) their global counterparts. An empty annotation sets an empty list. These settings do not change traffic routing or gateway policy.

## Public and private CA sources

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

ConfigMap and Secret sources require explicit namespace/name/key. Store CA source objects in the Agentio system namespace (the Helm release namespace, normally `agentio-system`) with the default RBAC. The namespace field is retained and used as configured; there is no validation requiring it to match the system namespace. Secret sources use `secret` instead of `configMap` and reuse the registry's shared Secret informer. `AGENTIO_SCOPED_SECRETS` defaults to `true`, restricting this informer to the system namespace. Set it to `false` to watch all namespaces, and supply the required global Secret list/watch RBAC separately. The scope is configured explicitly; agentiod does not probe RBAC. The chart does not add global Secret access or source-specific Roles and RoleBindings. References outside the watched scope are unavailable and retain the last complete bundle. Only configured names and keys enter the CA bundle. The shared informer runs for the server lifetime, independently of client trust enablement or source changes. The client trust distributor waits for its Namespace, ConfigMap, and shared Secret caches to complete their initial synchronization before processing writes. Secret list/watch permissions in the configured scope are a startup prerequisite, including when the current bundle has no Secret sources. If access is denied, the informer logs the error and retries; distribution starts after permissions are granted and synchronization completes. This does not exit agentiod, and removing a Secret source does not bypass the startup requirement. Change its scope by setting the feature flag and restarting agentiod; this implementation does not automatically switch scope or invalidate cached data when RBAC changes at runtime. MITM keeps a separate informer filtered to its fixed Secret name, using its existing delayed read-permission check before starting. The default public package is trust-manager's Debian Bookworm `20250419~deb12u1.1`, pinned in `agentio.deps` and chart values. The package has its own release/update lifecycle; keep it current through reviewed dependency updates. The chart prepares this package automatically when client trust is enabled and sources include `defaultCAs: true`. Removing that source also removes the package init container, shared volume, and package-path environment variable on the next Helm upgrade. `agentiod.trustPackage.image` selects the package image and must be pinned by digest.

When adding `defaultCAs` to a deployment installed without the public CA package, update the Helm sources and upgrade the release so agentiod receives the package init container. Editing only the injector ConfigMap does not provision the package.

The package is copied once by an agentiod init container; there is no CA merge container in business Pods. Alternate package images must implement the same `/debian-package` to `/packages` copy interface and JSON package format (name, version, bundle). Non-Helm installations enable `AGENTIO_ENABLE_CLIENT_TRUST_DISTRIBUTOR=true` alongside `clientTrust.enabled: true` and set `AGENTIO_CLIENT_TRUST_PACKAGE_PATH` to the package JSON path when using `defaultCAs`. A disabled process gate cannot be enabled through a ConfigMap update alone; restart agentiod with the feature enabled.

A custom bundle does not automatically inherit private CAs from application images. Include every additional enterprise trust anchor that the application needs. Sources are parsed, deduplicated and stably ordered. Invalid or missing sources retain the last successfully assembled bundle in the running distributor. On a fresh start, a source failure leaves existing target ConfigMaps unchanged but does not provision new targets until all sources are available. Foreign ConfigMaps are not overwritten. Private keys and non-CA certificates are rejected.

Distribution is driven by KRT dependencies on namespaces, validated configuration, and certificate sources. Namespace creation provisions its ConfigMap; a changed bundle updates all eligible namespaces. Target ConfigMap deletion or modification triggers repair. A leader-owned queue retries failed writes with backoff. There is no Pod informer or periodic full reconciliation. A namespace receives its bundle even before its first Pod is created.

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

Omit `mounts` to use the managed bundle. Explicit mounts replace the default and require an explicit `files.caBundle`, even when they match the generated default mount. Custom ConfigMaps/Secrets must exist in the Pod namespace and are user-managed. Each mount requires explicit `items`, is read-only and required, and does not use `subPath`. Mount conflicts reject admission. `files.caBundle` must resolve to a file declared in mounts, including when `env` is empty.

`env` contains only environment variable names. Every listed variable receives the same `files.caBundle` path; no value, valueFrom or placeholder syntax is accepted. Omitting `env` uses the four names below; a supplied list replaces the defaults. Every selected container automatically receives `AGENTIO_TRUST_BUNDLE`, pointing to `files.caBundle`. With the default sources this is the complete public + MITM CA bundle; additional configured CA sources are included too. Custom clients must explicitly read this variable and load the file into their TLS trust context:

```python
import os
import ssl

context = ssl.create_default_context(cafile=os.environ["AGENTIO_TRUST_BUNDLE"])
```

Use `env: []` to mount the bundle and inject only `AGENTIO_TRUST_BUNDLE`, without the additional client variables. Listing `AGENTIO_TRUST_BUNDLE` explicitly does not inject it twice. Invalid or duplicate names in `env` are rejected. Disabled or excluded containers do not receive this variable.

| Default environment variable | Common clients |
| --- | --- |
| SSL_CERT_FILE | Python ssl / HTTPX and clients using OpenSSL default trust paths |
| REQUESTS_CA_BUNDLE | Python Requests |
| NODE_EXTRA_CA_CERTS | Node.js (adds to built-in public roots) |
| CURL_CA_BUNDLE | curl |

The conflict policy also applies to `AGENTIO_TRUST_BUNDLE`. `Preserve` keeps application-defined variables and warns on different values; `Overwrite` replaces the complete variable, including any old valueFrom. Configure application-specific values or valueFrom under the container's own `env`, outside `clientTrust`. Client support depends on the library and TLS backend.

Direct injector ConfigMap users configure `clientTrust` and `clientTrustBundle` at the root of `data.values`; invalid updates retain the last valid configuration. CA augmentation runs after template rendering and proxy post-processing. Supported template names are defined in Agentio code. Currently only `ztunnel` supports client trust injection; `egress-gateway`, `agentgateway` and custom template names do not.

Aliases are expanded first; if any selected concrete template is `ztunnel`, augmentation runs once using the shared `clientTrust` settings. To combine client trust with additional templates, use an alias or selection containing `ztunnel`. The `enabled` flag and Pod opt-out still apply. A Pod-level `client-trust: "true"` cannot enable injection for an unsupported template. While the feature is enabled, namespace distribution is independent of template selection and Pod opt-outs. Those settings only determine which containers mount and use the bundle.

## Updates and troubleshooting

Files projected from ConfigMaps update eventually; client processes may cache CA contents. Recreate Pods to reliably load an updated bundle. Disabling the master switch stops new injections and managed bundle updates, including updates needed by existing workloads. A runtime ConfigMap change to `clientTrust.enabled: false` also stops distribution writes; the shared Secret informer continues running. Pod annotations cannot re-enable client trust. The process gate must be enabled for a later ConfigMap update to resume the feature. Agentio does not automatically roll business Deployments or delete retained trust ConfigMaps during feature disablement.

MITM SELF_SIGN renewal reissues the certificate using the same signing key; it is not a key rotation. For operator-managed key rotation, stage the new root alongside the old root in the MITM signing certificate bundle, distribute/reload clients, then switch the active signer. Retire the old root only after the transition. Do not treat ConfigMap delivery as proof that all clients have reloaded trust.

Inspect target ConfigMap annotations for owner, package version and SHA-256. Failures emit a `ClientTrustReconcileFailed` event in the control-plane namespace and structured logs.

Python Requests/HTTPX, Node.js https and curl default trust paths are verified by the live test under `test/e2e/suites/clienttrust`. Explicit CA settings, HTTPX `trust_env=False`, custom TLS contexts and certificate pinning can bypass these environment settings. Java/browser trust stores and upstream mTLS identity are not managed.
