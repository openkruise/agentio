# Egress gateway protocol detection and destination restrictions

> Design note. This page records protocol-detection and destination-filter behavior behind [Route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md).

## Protocol detection and server-first connections

The gateway waits up to one second for protocol detection, both inside the CONNECT tunnel and after TLS termination. If inspection times out, the gateway closes the connection instead of selecting a TCP forwarding chain. Server-first clients, such as SMTP and MySQL clients that wait for a server greeting without sending data, therefore time out and are disconnected on this path.

A client that delays its first HTTP request or TLS ClientHello beyond this window is also disconnected, preventing delayed traffic from bypassing HTTP inspection or policies that depend on detecting TLS/SNI through the timeout fallback. Traffic that completes protocol detection retains its normal routing and policy behavior. This applies to both native and legacy gateways.

After TLS termination, the gateway detects HTTP only. Non-HTTP payloads, including another TLS stream, are forwarded unchanged over a new TLS connection. Fixed ServiceEntry endpoints retain their original IP and port; other destinations resolve the outer SNI and retain the original port. Upstream SNI and certificate name validation use the outer TLS SNI; an inner ClientHello never selects a new destination. HTTP requests retain their existing routing and policy processing.

The TCP path does not run HTTP request-level EPE authorization. Configured ServiceEntry endpoint IPs require a matching TLS SNI before passthrough or termination; plain opaque TCP cannot satisfy that binding. Native TLS passthrough resolves and authorizes the SNI destination before ORIGINAL_DST forwarding, retaining the original port. A matching endpoint binding uses ORIGINAL_DST with its configured IP and port. Allowing TLS termination is not equivalent to authorizing an HTTP request. TCP forwarding after termination does not advertise HTTP ALPN upstream; protocols that require a custom ALPN are not supported by this termination path.

## Destination restrictions

The native `agentio-egress` gateway checks actual upstream destinations using `AgentioConfig.egressAuthorization.deniedCIDRs` plus the same mandatory restrictions as EPE:

| Destination | Denied ranges |
| --- | --- |
| Loopback | `127.0.0.0/8`, `::1/128` |
| Unspecified | `0.0.0.0/32`, `::/128` |
| Link-local | `169.254.0.0/16`, `fe80::/10` |

Equivalent IPv4-mapped IPv6 addresses are also filtered. Private service networks and Alibaba Cloud metadata at `100.100.100.200` remain allowed by this default.

TCP CONNECT admission leaves destination authorization to the forwarding path, after target selection. One Rust library supplies TCP and HTTP entry points sharing CIDR evaluation and a process-wide DNS resolver. The TCP entry point also evaluates the selected SecurityProfile TCP rules. The HTTP entry point runs after EPE/target selection and before router; HTTP profile evaluation and interleaved TCP rules stay in EPE. Both authorize the selected numerical endpoint before forwarding, including IP literals, DNS results, ServiceEntry endpoints and EPE overrides. An explicit denied IP fails without falling back to another address; hostname resolution can select another allowed answer.

Plaintext application-level CONNECT retains `ORIGINAL_DST`: the HTTP entry point checks and pins the original proxy IP without DNS or DFP capacity limits. HTTPS proxy connections resolve the outer SNI and use ORIGINAL_DST; fixed ServiceEntry proxy endpoints retain their original IP and port. These checks cover the actual proxy endpoint without restricting a tunnel target reached by the external proxy. An original address replaced by an allowed final target is not rejected at tunnel admission. Internal Porter, EPE and xDS connections are excluded.

DNS answers are cached independently of authorization decisions and rechecked for every new TCP connection or HTTP request. A refresh containing only forbidden addresses denies forwarding rather than reusing an older allowed address. HTTP authorization pins a full numeric IP:port in `envoy.network.transport_socket.original_dst_address` for ORIGINAL_DST without changing Host or TLS identity. HTTP denial returns 403; DNS lookup failure returns 503. The gateway no longer emits DFP `resolved_address_filter` or CIDR-derived cache names. Native forwarding no longer uses DFP. ServiceEntry, EPE and Rust share the native address object; EPE receives its `.ip` and `.port` attributes and returns its selected address as metadata. This address is request-scoped for HTTP, so concurrent HTTP/2 streams can select different upstreams.

HTTP restrictions are RDS per-filter configuration. After Envoy accepts a route update, new requests on existing HTTP/1 and HTTP/2 connections use the new policy. In-flight requests, including pending DNS, retain their snapshot. TCP restrictions are network-filter configuration and apply to new connections after listener updates; established connections are not revoked. Rejected configuration leaves the last accepted policy active. Both entry points and their replacement configurations share one lazily initialized resolver and two DNS worker threads per loaded module. CIDR updates do not discard DNS cache entries or add threads. Changing DNS servers or cache budgets requires process replacement. Native `dnsCache.maxHosts` limits shared cached DNS records, evicting entries at capacity; `maxPendingRequests` limits waiting HTTP and TCP requests together, excluding cache hits. Completion and cancellation release admission slots. The retired `hostTtl` field is rejected in YAML/JSON configuration. Native answers expire according to DNS record TTL; legacy DFP uses a fixed 120-second idle lifetime. ORIGINAL_DST host maps and connection pools have separate lifetimes and are not bounded by DNS cache capacity.

Custom native gateway images must include the matching Rust dynamic library and HTTP per-route configuration support (the bundled Envoy 1.40.2 image does). Upgrade the gateway image and EPE before publishing the new configuration, since EPE must understand the native address-object attributes. Legacy waypoint gateways retain their existing behavior when no custom list is supplied; a custom list suppresses their resource variant because they cannot enforce it.

`EPEConfig.egressAuthorization.deniedCIDRs` and `AgentioConfig.egressAuthorization.deniedCIDRs` are independent. The gateway checks EPE's selected address, but does not send its restrictions to EPE. Matching custom lists allow EPE to exclude forbidden DNS candidates before pinning an address, avoiding rejection when a different candidate would have been allowed.
