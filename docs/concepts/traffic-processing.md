# Traffic processing and capability boundaries

Choose configuration by the decision you need to make. Traffic capture, connection authorization, gateway routing and HTTP actions are separate steps; configuring one does not implicitly enable the others.

| Decision | Configuration or component | User-facing result |
| --- | --- | --- |
| Enroll a Pod | Sidecar injection or ambient CNI/node ztunnel | Traffic enters the Agentio data plane |
| Allow a connection | TrafficPolicy / GlobalTrafficPolicy | L3/L4 authorization for the selected workload |
| Send traffic to a gateway | AgentioConfig `egressPolicies` | Ordered `GATEWAY` or `PASSTHROUGH` route selection |
| Authenticate the caller at a native Envoy gateway | Porter and Agentiod discovery | The gateway resolves the verified Workload and optional bound Sandbox |
| Inspect or pass through TLS | Static gateway TLS configuration, or SNI policy mode | Termination, passthrough or denial before HTTP processing |
| Act on an HTTP request | EPE SecurityProfile / GlobalSecurityProfile | Block, bypass, header modification, credentials, MCP policy and audit |
| Authorize the effective HTTP destination | Optional EPE destination authorization | TrafficPolicy check and selected upstream IP/port |

## Deployment and protocol boundaries

| Path or capability | Availability and prerequisites |
| --- | --- |
| Sidecar profile | Recommended; one injected ztunnel per Pod |
| Ambient profile | Alpha; node CNI and ztunnel, without full sidecar feature parity |
| Plaintext HTTP through an Envoy gateway | EPE inspection when an ext_proc provider is configured |
| HTTPS through an Envoy gateway | Request-level inspection only after TLS termination, with caller CA trust |
| TLS passthrough or opaque TCP | No EPE HTTP path/header/body inspection |
| CONNECT-UDP | Experimental and disabled by default; IPv4 targets, additional source capture setup, no EPE inspection |
| OpenKruise manager integration | Separate release/values path; Sandbox discovery must be enabled on Agentiod; application trust is runtime-owned |
| Native Envoy gateway | Porter resolves identities/policies for outer CONNECT; EPE handles inner HTTP |
| Legacy waypoint gateway | Retains legacy identity and SNI handling; do not assume native Porter behavior applies |
| agentgateway | Separate native configuration and deployment contract; Envoy-specific configuration and patches are not portable |
| EPE destination authorization | Opt-in binary capability requiring an operator-managed deployment and authorized ADS identity; not a default chart toggle |
| HTTPCallout / OAuth2 filter packages | Internal implementation does not imply a mounted public SecurityProfile action; consult the production action list |

For configuration, see [HTTPS inspection](../tasks/inspect-https-traffic.md), [UDP prerequisites](../reference/agentiod-environment-variables.md#experimental-udp-sessions), [OpenKruise integration](../integrations/openkruise-agents.md), and [agentgateway](../tasks/deploy-agentgateway.md).

## Porter and EPE handle different requests

On the native Envoy gateway, Porter handles the **outer HBONE CONNECT** that establishes the tunnel. It resolves the Workload from the verified peer certificate and discovery data. An optional Sandbox ID must bind to that Workload; copying a name or label does not grant that identity. Porter supplies workload context and SNI policy to the gateway, whose listener evaluates the actual ClientHello SNI.

EPE handles the **inner HTTP request**, after TLS termination when necessary. This is where URL paths, headers, MCP bodies and credentials are available. An EPE profile cannot repair a CONNECT rejected before the inner request exists.

Porter's certified instance path is distinct from its compatibility fallback for certificates without that extension. The fallback uses peer IP and principal and requires preserved source IP; SNAT or an intermediate proxy can prevent resolution. Ambient deployments have additional per-instance certificate limitations. See the [Porter implementation and operational reference](../../extensions/porter/README.md) for exact identity, discovery and failure behavior.

## Combining platform and workload policies

A namespaced SecurityProfile selects local Pods; a GlobalSecurityProfile can select across namespaces. Both enter the same order: lower priority first, then creation time, name and namespace. An early platform `block` stops later business actions. An early `bypass` also skips later profile actions; it is not a general allow rule. Use separate rules when a mutation must happen before a terminal decision, and test both the intended match and an unmatched control request.

TrafficPolicy has a different authorization model; do not transfer SecurityProfile bypass or action-order assumptions to it. In particular, a TrafficPolicy with an empty selector in the mesh root namespace creates a mesh-wide baseline. See [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md) and [SecurityProfile evaluation](../reference/security-profile.md) before combining global and workload policies.

## Where to start

- [Get started](../getting-started.md) for a first enrolled workload.
- [Inspect HTTPS traffic](../tasks/inspect-https-traffic.md) before applying HTTP policy to TLS traffic.
- [Troubleshoot policy enforcement](../tasks/troubleshoot-policy-enforcement.md) to identify which step made a decision.
