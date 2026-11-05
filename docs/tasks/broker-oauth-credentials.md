# Configure OAuth credential isolation

Keep third-party OAuth application secrets, access tokens, refresh tokens, and device codes outside a Sandbox. A `tokenTransformation` action with `type: OAuth2` brokers the client's OAuth requests through a trusted credential service and injects real Bearer credentials only into selected resource requests.

A Sandbox is an OpenKruise Sandbox workload and is the unit of identity and policy in Agentio.

## Prerequisites

- Route the selected Sandbox's traffic through an Egress Policy Enforcer (EPE)-enabled gateway.
- Apply OAuth policies to decrypted inner HTTPS requests. EPE rejects plaintext HTTP, missing schemes, and CONNECT envelopes before credential lookup. The gateway must verify the destination and upstream TLS certificate.
- Configure the default credential connection in [EPEConfig](../reference/epe-configuration.md).
- Supply the trusted platform token and Sandbox client ID through the [request identity chain](../reference/epe-request-context.md).

## Operations

Each `oauth2.operation` contains exactly one branch:

| Branch | Behavior |
| --- | --- |
| `deviceAuthorization: {}` | Starts a session and returns public verification information plus a broker handle in `device_code`. |
| `token: {}` | Parses Form or JSON according to Content-Type, handles `grant_type`, and returns `unused` token placeholders with scope/expiry metadata. |
| `resource: {}` | Retrieves the current authorized credential, overwrites `Authorization`, and forwards the request. |

`allowedGrantTypes` restricts Token to an exact string set; other grants return `unsupported_grant_type`.

`customResponse` optionally adds application fields to generated OAuth errors, authorization prompts, and Token successes. Extensions must be public JSON objects; standard OAuth fields cannot be replaced.

EPE rejects invalid operation combinations, response fields, and credential configuration when compiling the profile. OAuth requires the default Block failure strategy; Allow and Ignore are not supported.

## Configure lark-cli

Configure the `lark-cli` business provider in the credential service first, then change the namespace and selector to match your Sandbox. The JSON Token rule precedes the general Token rule because a local Token response ends policy processing.

```yaml
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: lark-oauth2
  namespace: agent-demo
spec:
  selector:
    matchLabels: {app: agent}
  rules:
    - name: device-authorization
      match:
        - domains: [accounts.feishu.cn]
          paths: [{type: Exact, value: /oauth/v1/device_authorization}]
          methods: [POST]
          schemes: [https]
      actions:
        tokenTransformation:
          type: OAuth2
          credentialRef: {credentialProvider: {name: lark-cli}}
          oauth2:
            operation: {deviceAuthorization: {}}
    - name: json-refresh
      match:
        - domains: [open.feishu.cn]
          paths: [{type: Exact, value: /open-apis/authen/v2/oauth/token}]
          methods: [POST]
          schemes: [https]
          headers:
            - name: content-type
              type: Regex
              value: '(?i)^application/json(?:\s*;.*)?$'
      actions:
        tokenTransformation:
          type: OAuth2
          credentialRef: {credentialProvider: {name: lark-cli}}
          oauth2:
            operation: {token: {}}
            customResponse:
              success: {code: 0}
              error: {code: 20050}
              authorizationRequired: {code: 20026}
    - name: standard-token
      match:
        - domains: [open.feishu.cn]
          paths: [{type: Exact, value: /open-apis/authen/v2/oauth/token}]
          methods: [POST]
          schemes: [https]
      actions:
        tokenTransformation:
          type: OAuth2
          credentialRef: {credentialProvider: {name: lark-cli}}
          oauth2:
            operation: {token: {}}
    - name: reject-app-registration
      match:
        - domains: [accounts.feishu.cn]
          paths: [{type: Exact, value: /oauth/v1/app/registration}]
          methods: [POST]
      actions:
        block:
          statusCode: 403
          body: '{"error":"access_denied","error_description":"Application registration is managed by the credential service."}'
    - name: document-business
      match:
        - domains: [open.feishu.cn]
          schemes: [https]
          paths:
            - {type: Exact, value: /open-apis/authen/v1/user_info}
            - {type: Prefix, value: /open-apis/docx/}
            - {type: Prefix, value: /open-apis/docs_ai/}
            - {type: Prefix, value: /open-apis/wiki/}
      actions:
        tokenTransformation:
          type: OAuth2
          credentialRef: {credentialProvider: {name: lark-cli}}
          oauth2:
            operation: {resource: {}}
            customResponse:
              authorizationRequired:
                code: 99991663
                msg: 'User authorization is required. Run lark-cli auth login.'
```

The domains, paths, numeric codes, and registration restriction are deployment policy; adjust them to your environment. For a `GlobalSecurityProfile`, change the kind and omit `metadata.namespace`.

## Verify

Apply the profile and confirm EPE accepted its version. Then run the unmodified CLI's login from the selected Sandbox and complete the user verification step when required. Polling and refresh should return placeholder tokens; inspect the CLI's local state without printing real credentials. A selected business request should reach its upstream with a real Bearer credential while the request body and upstream response stay unchanged.

Authorization is per Sandbox, provider, and trusted platform identity. See [OAuth implementation notes](../design/broker-oauth-credentials.md) for session and cache boundaries.

## See also

- [Credential provider contract](../reference/credential-provider.md)
- [SecurityProfile reference](../reference/security-profile.md)
