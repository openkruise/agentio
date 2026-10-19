# Configure EPE destination authorization

EPE can authorize the effective HTTP destination against the calling Workload's TrafficPolicy and return a selected IP and port to the Agentio Envoy gateway. Enable this when HTTP destination selection must be checked at the gateway in addition to the data plane's connection-level policy.

This capability is opt-in with `--enable-egressauthz`; it does not replace traffic capture, gateway routing, or TLS termination. It also does not expose an arbitrary routing action in the public SecurityProfile API.

## Deployment prerequisites

The standard managed EPE chart does not expose this flag or arbitrary extra process arguments. Use an operator-managed Deployment or a maintained deployment overlay. Setting an invented `epe.enableEgressAuthz` value or an environment variable will not enable it.

Prepare these inputs before starting EPE:

- The Agentiod TLS ADS endpoint, normally `agentiod.agentio-system.svc.cluster.local:15012` for the standalone chart.
- A mounted PEM trust bundle for that endpoint, and a projected Pod-bound token with Agentiod's expected audience (normally `agentio-ca`). The default Kubernetes API token audience is not necessarily valid for Agentiod.
- An active, authorized gateway Pod identity. Giving the default EPE Pod a token file alone does not grant gateway resource access. Its namespace, ServiceAccount, Pod binding, and gateway registration must satisfy Agentiod's gateway authorization. Use the default `waypoint` xDS node class for this consumer; the native `agentio-egress` class does not grant TrafficPolicy resource access.
- Downward-API environment variables `POD_NAME`, `POD_NAMESPACE`, `POD_UID`, and `POD_IP` for that Pod. An explicit node ID does not replace token attestation.
- A source cluster ID matching Agentiod's `--cluster-id`.
- The existing EPE Kubernetes read permissions for SecurityProfiles and inputs, and any Secret permissions needed by its actions. ADS authentication does not replace these permissions.

This is an integration-level deployment; it is not enabled by the default standalone EPE installation. Keep the Pod's mounted token and identity metadata tied to the actual running Pod.

## Process configuration

Add these arguments to the EPE process in that prepared deployment, retaining its existing listener, configuration, and TLS flags. Paths below are example mount paths that your deployment must supply:

```text
--enable-egressauthz=true
--xds-address=agentiod.agentio-system.svc.cluster.local:15012
--xds-root-path=/var/run/secrets/agentio/root-cert.pem
--xds-token-path=/var/run/secrets/tokens/agentio-token
--xds-cluster-id=Kubernetes
```

The default node ID is derived from the Pod environment. See [EPE process flags](../reference/epe-configuration.md#process-flags-and-listeners) for overrides. Configure the gateway's ext_proc provider to use this EPE deployment; an EPE process receiving no requests cannot enforce the policy.

## Request behavior

Authorization uses the effective request headers after mutations and checks the selected destination before forwarding body data. It is independent of SecurityProfile selection: requests without matching profiles and requests that hit `bypass` still require authorization. A SecurityProfile block already prevents forwarding.

An explicit selected target must be allowed; a denied explicit target is not replaced with another destination. Otherwise, authorization first tries the restored original destination. If it is absent or denied, EPE resolves the request host and selects an allowed candidate. An allowed original address need not be present in the current DNS answer. The gateway consumes EPE's `agentio.route` IP/port metadata to pin the connection; HTTP Host remains separate.

Enabling this mode forces missing-identity rejection with HTTP 403 even if `--fail-closed-on-missing-identity=false`. Authorization failures are local responses: a policy denial returns its denial response, while lookup or processing errors return HTTP 500 with `epe_request_authorization_failed` as the internal detail. These are not ext_proc transport failures and cannot be turned into forwarding by `failureModeAllow`.

## Verify enforcement

Use an isolated enrolled test workload and controlled upstreams:

1. Confirm EPE can connect to ADS without token, TLS, or resource-access errors. Check EPE and Agentiod logs if startup succeeds but requests fail.
2. Apply a narrow TrafficPolicy for that workload with a known allowed destination and a rejected control destination. Preserve any required DNS access.
3. Send gateway-routed HTTP requests and check both client responses and upstream receipt. HTTPS requires [TLS termination](inspect-https-traffic.md).
4. Confirm an allowed request reaches only the selected allowed endpoint. A blocked request must not reach the control endpoint. Where the connection-level policy already blocks the request, that result alone does not prove EPE executed; use EPE request logs to distinguish the enforcement point.
5. Apply a SecurityProfile `bypass` to the test request and confirm it does not bypass destination authorization. Missing or unavailable workload/policy data must not silently become a successful upstream request.

Record the source workload, policies, effective destination and EPE outcome for each test. A healthy EPE Pod or an accepted TrafficPolicy object alone does not establish enforcement.

## Disable the additional authorization layer

Remove `--enable-egressauthz` from the same deployment and roll its Pods. If you still require missing-identity rejection, retain `--fail-closed-on-missing-identity=true` explicitly. Connection-level TrafficPolicy remains independent; verify your intended traffic behavior after the rollout.
