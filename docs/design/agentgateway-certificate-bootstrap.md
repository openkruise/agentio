# agentgateway certificate bootstrap internals

> Design note. This page records certificate bootstrap, renewal, and test coverage behind [Deploy agentgateway with the Gateway API](../tasks/deploy-agentgateway.md).

## Bootstrap settings

When native certificate bootstrap is enabled, Agentio supplies these settings to the agentgateway deployment:

- `CA_ADDRESS`: the HTTPS `agentiod` endpoint from the injector's `global.caAddress`. A scheme-less address is normalized to HTTPS; plaintext endpoints are rejected.
- `NAMESPACE` and `SERVICE_ACCOUNT`: downward API values from the Gateway Pod. The certificate identity is `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>`, including any configured Gateway ServiceAccount override.
- `TRUST_DOMAIN` and `CLUSTER_ID`: the configured mesh identity values.
- `CA_AUTH_TOKEN`: a projected, 12-hour ServiceAccount token at `/var/run/secrets/tokens/agentio-token`. Its audience uses `agentiod.tokenAudience`, as distributed through the injector values. Kubernetes refreshes the token and the native client rereads it when requesting certificates.
- `CA_ROOT_CA`: the public trust bundle at `/var/run/secrets/agentio/root-cert.pem`, from `agentiod.ca.trustBundleConfigMapName` in the Gateway namespace. The trust-bundle distributor creates and updates this ConfigMap.

## Certificate issuance

The proxy generates its private key and CSR in memory and calls `agentiod`'s certificate service. `agentiod` authenticates the token with TokenReview and restricts the CSR to that ServiceAccount's identity. The proxy does not read the CA Secret, mount a CA private key, create a leaf Secret, or need node impersonation privileges. Default Kubernetes token automount stays disabled.

## Renewal and failure behavior

The native client requests a 24-hour certificate; `agentiod` caps this at its configured workload certificate lifetime. The client checks every 30 seconds and renews at the certificate's midpoint. New connections use the updated certificate without a Deployment rollout; existing connections retain their negotiated TLS session.

- A renewal failure replaces the cached certificate state with an error, even if the previous certificate has not expired. New connections fail until a retry succeeds. The native client does not provide last-valid-certificate fallback or jittered backoff.
- `/healthz/ready` and Gateway `Programmed` do not verify certificate availability. Monitor CA fetch/renewal failures and run an authenticated mesh-tunnel probe; a ready Pod alone is insufficient proof of mesh connectivity.
- The CA connection reads its root file for each certificate request, while peer trust roots come from the last successful CA response. Root replacement must keep old and new roots trusted throughout distribution and workload renewal.

## End-to-end coverage

The standard agentgateway end-to-end suite installs the full production chart and exercises this controller with real ztunnel mTLS CONNECT traffic. It shares outbound protocol, external-processing header mutation, and port-selection checks with the Envoy suite. The suite also covers 12 deployment/configuration lifecycle scenarios, including HPA/PDB recreation and garbage collection. The suite enables native CA mode: the Gateway Pod obtains its certificate from `agentiod` using its own projected token. The fixture does not read CA private keys or issue gateway leaf Secrets.

A separate local interoperability test runs a real agentgateway binary against `agentiod` CA over TLS, with only the Kubernetes TokenReview API faked. It checks SPIFFE identity, mTLS CONNECT forwarding, refusal of unauthenticated clients, token refresh, certificate renewal without restart, and renewal failure/recovery:

```bash
AGENTIO_AGENTGATEWAY_BINARY=/absolute/path/to/agentgateway-v1.5.0 \
  go test ./pkg/security/ca -run TestAgentgatewayNativeCACertificateRotation -count=1 -v -timeout=3m
```
