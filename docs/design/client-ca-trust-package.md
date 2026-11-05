# Client CA trust package — build and distribution

> Design note. This page records how the public CA package is built, published, and synchronized. See [Configure client CA trust](../tasks/configure-client-ca-trust.md) for the operator workflow.

## Package source and pinning

The default public CA package is trust-manager's Debian Bookworm bundle, pinned by tag and digest in `agentio.deps` and the root `Dockerfile`. The image build copies its `/debian-package/` directory into `/usr/local/share/agentio/trust-package/`.

`agentiod` defaults `AGENTIO_CLIENT_TRUST_PACKAGE_PATH` to `/usr/local/share/agentio/trust-package/cert-manager-package-debian.json`. The environment variable only overrides this path; the Dockerfile does not set it.

`agentiod` validates the configured package at startup and sends its complete public CA PEM inline through xDS to both `tls_connect_originate` and `tls_proxy_originate`. An empty path or an unreadable or invalid package prevents `agentiod` from starting. Package files are read at startup, not watched. Gateways use the same public roots as the client's `defaultCAs` source, without depending on the gateway image's OS CA bundle; the gateway upstream bundle does not include the MITM signing CA or additional client ConfigMap/Secret sources.

Official `agentiod` images include the package JSON in both debug and distroless variants. Installations running a standalone binary must supply the package JSON (name, version, bundle) at the default path or override `AGENTIO_CLIENT_TRUST_PACKAGE_PATH`.

## Package synchronization

The daily `Sync public CA package` workflow checks for newer Bookworm package revisions and opens or updates a PR containing both pins. It runs at 09:17 Asia/Shanghai and also supports a manual `dry_run`. It reuses `AGENTIO_SYNC_APP_CLIENT_ID` and `AGENTIO_SYNC_APP_PRIVATE_KEY` to open PRs that trigger existing CI.

Dependabot checks Dockerfile base images weekly on Mondays at 04:00 Asia/Shanghai. The CA package is excluded there because its Debian revisions and BOM synchronization are handled by the daily workflow.

Merging uses the existing image build pipeline; release and deployment remain separate operations.

## Updating public roots

To update public roots, update the pinned package, rebuild and publish `agentiod`, then roll `agentiod` to the new image. Its new xDS cluster configuration updates connected gateways without a gateway Deployment change. `agentiod` requires the package for every installation and does not fall back to a gateway-local CA file.

## Distribution internals

Distribution is driven by control-plane dependencies on namespaces, validated configuration, and certificate sources. Namespace creation provisions its ConfigMap; a changed bundle updates all eligible namespaces. Target ConfigMap deletion or modification triggers repair, and a leader-owned queue retries failed writes with backoff. There is no Pod informer or periodic full reconciliation. A namespace receives its bundle even before its first Pod is created.
