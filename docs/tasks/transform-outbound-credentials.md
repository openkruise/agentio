# Replace outbound credentials

Use a `SecurityProfile` `tokenTransformation` action to replace a Sandbox-supplied credential with an API key or re-sign an outbound request with Aliyun STS credentials. Egress Policy Enforcer (EPE) fetches the credential after a rule matches, so a long-lived provider credential never enters the Sandbox.

A Sandbox is an OpenKruise Sandbox workload and is the unit of identity and policy in Agentio.

The provider HTTP contract is [Credential provider](../reference/credential-provider.md); policy fields are in the [SecurityProfile reference](../reference/security-profile.md).

## Choose a credential source and signer

`credentialRef` is a union: set exactly one of `secret` or `credentialProvider`.

- `credentialRef.secret` reads a Kubernetes Secret. `ApiKey` expects data key `apiKey`; `AliyunSTS` expects `accessKeyId`, `accessKeySecret`, and `securityToken`.
- `credentialRef.credentialProvider` fetches the credential from the configured provider.

`type` selects the signer:

- `ApiKey` (default) injects a rendered credential into selected headers.
- `AliyunSTS` re-signs a detected Aliyun request.

`failStrategy: Block` (default) returns a generic 403 when the transformation cannot be applied; `Allow` and `Ignore` forward the request unmodified. Signer behavior and Secret reference details are in [Credential signers (design)](../design/credential-signers.md).

## Prerequisites

Enable EPE and set `epe.credentialProvider.url` to the provider's HTTPS endpoint. Update an existing release with `--reuse-values`; without it, Helm can replace the release's routing, gateway, data-plane, and image settings with chart defaults.

The example matches `https://api.example.com`, so the selected egress gateway must terminate TLS for `api.example.com`; otherwise the connection stays on the gateway's TCP path and never reaches EPE. Configure `egressGateways[].tlsTermination.includeHosts`, configure the MITM signing CA, and make the calling workload trust that CA. See [TLS termination for HTTPS inspection](../reference/agentio-configuration.md#tls-termination-for-https-inspection).

## Apply a provider-backed API-key transformation

The profile below matches calls from selected Pods to `api.example.com`, obtains a short-lived API key from provider configuration `example-api`, and replaces the `Authorization` header with `Bearer <key>`.

```yaml
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: example-api-credentials
  namespace: agent-demo
spec:
  selector:
    matchLabels:
      app: agent
  inputs:
    - name: routing
      inline:
        tenant: production
  rules:
    - name: transform-example-api
      match:
        - domains:
            - api.example.com
          schemes:
            - https
          paths:
            - type: Prefix
              value: /v1/
      actions:
        tokenTransformation:
          type: ApiKey
          failStrategy: Block
          credentialRef:
            credentialProvider:
              name: example-api
              parameters:
                audience:
                  value: example-api
                namespace:
                  template: "{{ .Pod.Namespace }}"
                tenant:
                  cel: inputs.routing.tenant
          apiKey:
            targetHeaders:
              names:
                - Authorization
            value:
              template: "Bearer {{ .Token }}"
```

Apply it with `kubectl apply -f example-api-credentials.yaml`. The source identity's bearer token and Sandbox client ID travel only from EPE to the configured provider; neither is available to CEL nor to policy templates.

## Verify the transformation

Confirm that Kubernetes accepted the profile:

```console
$ kubectl get securityprofile example-api-credentials \
    --namespace agent-demo --output yaml
```

Then send a request from a selected Sandbox through the egress gateway. Verify on the trusted upstream or a controlled test endpoint that it receives the generated `Authorization` value, not the Sandbox's original value. Do not echo credentials in shared logs.

Credential reuse follows the [Credential provider caching semantics](../reference/credential-provider.md#caching-semantics).

## Clean up

```console
$ kubectl delete securityprofile example-api-credentials --namespace agent-demo
```

Deleting the profile stops future transformations after the change reaches EPE. It does not revoke credentials already issued by the provider or clear credentials cached by a running EPE process; use short provider lifetimes and provider-side revocation for emergency response.

## See also

- [Credential signers (design)](../design/credential-signers.md)
- [Credential provider contract](../reference/credential-provider.md)
- [SecurityProfile reference](../reference/security-profile.md)
