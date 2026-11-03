# Why not just Istio?

Istio can control egress traffic, but Agentio organizes that control around a different subject. Istio commonly starts from services and destination workloads. Agentio starts from a potentially untrusted client and establishes what that sandbox may reach and which enforcement point its traffic must traverse.

## Egress routing starts from the client

An agent may choose destinations dynamically, load tools at runtime, execute generated code, or become compromised. Requiring every future destination to be modeled before it can enter a controlled path ties security to an incomplete service inventory.

Agentio evaluates ordered egress policies for the source workload. A broad gateway rule can send every destination from a sandbox namespace through the same enforcement point, with a later fallback for other traffic:

```yaml
egressPolicies:
  - namespaces:
      - sandbox-a
    policy: GATEWAY
    gateway:
      service: agentio-egress.agentio-system.svc.cluster.local
  - policy: PASSTHROUGH
```

The `gateway` address names the target Service; its `port` field is optional because the egress route resolves the gateway by its service name.

Routing all destinations through a gateway does not allow all destinations. It guarantees that known and previously unknown destinations reach the policy boundary, where Layer 4 and Layer 7 rules can decide whether the request may continue.

## Routing and authorization are separate layers

Agentio uses two complementary policy layers:

- `TrafficPolicy` and `GlobalTrafficPolicy` apply destination and protocol controls to sandbox traffic;
- `SecurityProfile` and `GlobalSecurityProfile` apply request-level controls through EPE at an egress gateway.

The first layer can restrict services, CIDRs, FQDNs, ports, and protocols before traffic reaches an application-aware gateway. The second layer can inspect HTTP and MCP request attributes, transform credentials, emit audits, or block a request.

This is the inverse of the common server-side authorization question. Instead of asking only “who may call this service?”, Agentio also asks “what may this untrusted client call?” That matters for external APIs and other destinations that cannot enforce an in-mesh server policy.

## A stable enforcement path reduces policy gaps

Detailed service routing is useful for canary releases, traffic splitting, retries, and service-specific load balancing. Those features require operators to model the relevant services and routes. Sandbox security usually needs a simpler invariant first: traffic from this client must pass through this control point.

Agentio separates that stable routing invariant from dynamic request decisions. Destinations remain policy inputs, but they do not decide whether an untrusted client reaches the enforcement point.

## See also

- [Integrate with Istio ambient](../integrations/istio-ambient.md) to reuse Istio traffic capture and workload certificates with an Agentio egress waypoint
- [Getting started](../getting-started.md)
- [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md)
- [Egress Policy Enforcer overview](epe-overview.md)
