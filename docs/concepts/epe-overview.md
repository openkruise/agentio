# Egress Policy Enforcer overview

The Egress Policy Enforcer (EPE) applies content-aware HTTP policy to Agentio workload traffic that is routed through an Agentio egress gateway. It is the layer to use when a decision depends on the HTTP request, such as the target host and path, request headers, an MCP tool call, or a credential transformation.

EPE does not capture workload traffic and it does not select its own traffic path. Agentio's sidecar or ambient data plane captures enrolled workload traffic; the egress route decides whether that traffic reaches an egress gateway. On a gateway-routed HTTP request, the gateway's Envoy external-processing (`ext_proc`) filter calls the `agentio-epe` Service. Requests on the direct passthrough path do not call EPE. HTTPS reaches request-level filters only after gateway TLS termination; TLS passthrough bypasses them. See [Inspect HTTPS traffic](../tasks/inspect-https-traffic.md).

```text
enrolled workload
  -> Agentio traffic capture
  -> egress gateway selected by egress routing
  -> Envoy ext_proc
  -> agentio-epe
  -> external service, or an EPE response
```

## Control-plane boundaries

`TrafficPolicy` and `GlobalTrafficPolicy` govern L3/L4 egress authorization for selected workloads. `agentiod` compiles and distributes those resources to the Agentio data plane; by default EPE does not evaluate them. With `--enable-egressauthz`, EPE additionally consumes native Workload and TrafficPolicy resources over xDS, authorizes the effective HTTP destination, and returns a pinned upstream address to the gateway. This opt-in deployment requires an authorized gateway identity; see [EPE destination authorization](../tasks/configure-epe-destination-authorization.md).

The ordered `AgentioConfig.egressPolicies` list independently decides whether matching traffic uses `PASSTHROUGH` or `GATEWAY`. Native Sandbox routing does not support legacy egress `DENY`; express rejection in TrafficPolicy. A `GATEWAY` decision sends traffic to an egress gateway whose Envoy configuration invokes EPE, but EPE does not select that route.

`SecurityProfile` and `GlobalSecurityProfile` provide the L7 rules that EPE evaluates. They select workloads, match HTTP requests, and can block a request, bypass remaining EPE work, manipulate request headers, transform credentials, enforce an MCP tool policy, or emit an audit event. A SecurityProfile cannot make an otherwise direct passthrough request visit EPE. Conversely, EPE cannot override a `TrafficPolicy` denial because the data plane enforces that decision before the request reaches EPE.

## Primary resources and actions

- A namespaced `SecurityProfile` applies only to Pods in its namespace that match its selector.
- A cluster-scoped `GlobalSecurityProfile` can select Pods in every namespace. Use it for centrally owned, cluster-wide policy; set priorities deliberately because it shares one evaluation order with namespaced profiles.
- A rule contains one or more HTTP match clauses. The `domains` field is required; paths, methods, ports, schemes, headers, and query parameters further restrict a match.
- `block` returns an HTTP response without forwarding upstream. `bypass` forwards the request but skips every remaining EPE action and rule. `headerManipulation` is non-terminal and can set or remove request headers. `tokenTransformation` is non-terminal and can rewrite a request credential. `mcpToolPolicy` can inspect a buffered MCP request and deny it. `audit` sends an asynchronous event and never changes the request decision.

## Operational boundaries

EPE is a network hop on each gateway-routed request. Its work adds processing latency, and policies that need a request body require Envoy to buffer the complete body before the decision. Size EPE independently of the gateway and keep the chart's `agentio-epe` Deployment healthy; its headless Service exposes ext-proc on port `9002`, health on `9003`, and metrics on `9090` by default.

EPE needs the caller identity and labels that the gateway sends as ext_proc attributes. If that identity is absent, the default behavior passes the request through without profile selection. `--fail-closed-on-missing-identity=true` instead returns HTTP 403. Enabling `--enable-egressauthz` always enables this rejection, regardless of the independent flag. Validate enforcement with real gateway-routed traffic and monitor the EPE logs and metrics.

Profile inputs, request headers, pod labels, and audit payloads can contain sensitive information. Give EPE's cluster-wide read permissions and audit webhook destinations the same review as other security control-plane components. EPE's expression scope intentionally excludes request bodies and sandbox identity tokens, but an audit template can disclose the request and profile data that it is given; send audit events only to trusted endpoints.

## See also

- [EPE policy evaluation](epe-policy-evaluation.md)
- [Get started with EPE](../getting-started/epe.md)
- [Configure a SecurityProfile](../tasks/configure-security-profile.md)
- [Route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md)
