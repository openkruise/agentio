# Client trust E2E

This Go product suite tests sidecar CA injection through the real admission
webhook and distribution controller. It installs the production chart, uses the
shared scenario ledger, and preserves failure diagnostics and configuration
through the harness retention policy. Successful scenarios restore the injector
configuration and egress baseline. Run serially with other product suites.

The fixture runs Python requests/httpx/ssl, Node https, curl, and a custom client
that loads `AGENTIO_TRUST_BUNDLE` with HTTPX environment trust disabled. No probe
disables TLS verification. Python is used only for the in-container probes;
resource creation, certificate fixtures, waiting, assertions and cleanup use Go.

## Run

Use the immutable Agentio image inputs and cluster options from the
[parent framework README](../../README.md). Build the additional client image
from the repository root and publish it to a registry reachable by the cluster:

```sh
docker build -f test/fixtures/clienttrust/Dockerfile -t <registry>/clienttrust:<tag> .
docker push <registry>/clienttrust:<tag>
export AGENTIO_E2E_CLIENT_TRUST_IMAGE='<registry>/clienttrust@sha256:<digest>'
go -C test/e2e run ./cmd/product-e2e run --suites clienttrust --timeout=20m
```

When invoking `go test` directly, `-client-trust.image` overrides the environment variable. The suite accepts only
immutable digest references and requires the sidecar profile. The CI product
workflow builds the fixture and runs this suite only in `sidecar-auto`; ambient
does not use this admission path. For optional backend verification, use
`--suites clienttrust --profile sidecar --backend iptables --force`.

The fixture uses `example.com` for MITM and `example.org` for public HTTPS
passthrough, so it requires outbound DNS and Internet access. Direct Python
package versions and the Python base image digest are pinned; OS packages and
transitive Python dependencies are resolved during the fixture build.

Each scenario explicitly enables client trust and uses a SecurityProfile to select
the fixture Pods' `example.com` traffic for TLS termination through SNI traffic
policy. The Gateway has no `tlsTermination` configuration, so these tests also
verify that CA injection does not depend on its host lists.

## Coverage

| Test | Checks |
| --- | --- |
| `TestClientTrustHTTPS` | Namespace and Pod-only enrollment; native/classic sidecars; Python, Node, curl and custom-client verified HTTPS; disabled/excluded clients reject MITM while public HTTPS succeeds |
| `TestClientTrustContainerSelection` | Default/exact/glob selectors, exclusions, opt-out, no-match warnings, invalid annotations and mount overlap rejection |
| `TestClientTrustEnvironment` | Explicit variable names, builtin deduplication, literal `env: []`, Preserve/Overwrite with existing `valueFrom`, custom client loading the builtin bundle |
| `TestClientTrustGlobalOverrides` | Master disable blocks Pod opt-in; re-enable and explicit empty selector override |
| `TestClientTrustCustomMount` | Readonly custom mount, key remapping, custom environment variables and actual business init completion |
| `TestClientTrustSupportedTemplates` | Built-in ztunnel support, aliases, multiple templates, unsupported custom names, Pod opt-out and real HTTPS through a template alias |
| `TestClientTrustSourceUpdates` | Additional CA merge, update of an existing Pod's mounted file, fresh invalid-source event, last-valid retention and deterministic source removal |
| `TestClientTrustNamespaceDistribution` | CA distribution before any Pod exists and recreation after the target ConfigMap is deleted |
| `TestClientTrustSecretSourceUpdates` | Multiple Secret sources in one namespace, certificate updates and continued updates after one reference is removed |
| `TestClientTrustSecretNamespaceIsolation` | A source outside the shared Secret informer scope retains the last bundle and can be removed without blocking configuration updates |

Injector updates carry a unique annotation to confirm the webhook consumed that
exact configuration revision. HTTP results, admitted/scheduled Pods, injector
revisions and events go to the framework artifact store. Historical error events
cannot satisfy the invalid-source check.

These tests verify source updates and distribution. They do not claim zero-error
traffic during signing-key rotation or automatic CA reload by long-lived clients.
