# Egress gateway protocol detection and destination restrictions

> Design note. This page records protocol-detection and destination-filter behavior behind [Route traffic through an egress gateway](../tasks/route-traffic-through-egress-gateway.md).

## Protocol detection and server-first connections

The gateway waits up to one second for protocol detection, both inside the CONNECT tunnel and after TLS termination. If inspection times out, the gateway closes the connection instead of selecting a TCP forwarding chain. Server-first clients, such as SMTP and MySQL clients that wait for a server greeting without sending data, therefore time out and are disconnected on this path.

A client that delays its first HTTP request or TLS ClientHello beyond this window is also disconnected, preventing delayed traffic from bypassing HTTP inspection or policies that depend on detecting TLS/SNI through the timeout fallback. Traffic that completes protocol detection retains its normal routing and policy behavior. This applies to both native and legacy gateways.

After TLS termination, the gateway detects HTTP only. Non-HTTP payloads, including another TLS stream, are forwarded unchanged to the original destination IP and port over a new TLS connection. Upstream SNI and certificate name validation use the outer TLS SNI; an inner ClientHello never selects a new destination. HTTP requests retain their existing routing and policy processing.

The TCP path does not run HTTP request-level EPE authorization. Configured ServiceEntry endpoint IPs require a matching TLS SNI before passthrough or termination; plain opaque TCP cannot satisfy that binding. Native TLS passthrough uses SNI DFP, retaining the original port and using the original IP when the endpoint binding matches. Allowing TLS termination is not equivalent to authorizing an HTTP request. TCP forwarding after termination does not advertise HTTP ALPN upstream; protocols that require a custom ALPN are not supported by this termination path.

## Destination restrictions (dynamic forward proxy)

The native `agentio-egress` gateway's dynamic forward proxy (DFP) filters destination IPs using the same built-in restrictions as EPE egress authorization:

| Destination | Denied ranges |
| --- | --- |
| Loopback | `127.0.0.0/8`, `::1/128` |
| Unspecified | `0.0.0.0/32`, `::/128` |
| Link-local | `169.254.0.0/16`, `fe80::/10` |

Equivalent IPv4-mapped IPv6 addresses are also filtered. Private service networks and Alibaba Cloud metadata at `100.100.100.200` remain allowed by this default.

The filter is enabled for HTTP, native TLS passthrough, and TLS origination DFP even without EPE. It applies to IP literals and DNS results, including destinations selected through DFP filter state. Envoy removes matching addresses before adding them to the DNS cache. If none remain on the first resolution, forwarding fails; if a refresh returns only denied addresses, Envoy retains the previously allowed address. Filtered addresses increment `dns_cache.agentio_dns_cache.dns_address_filter_out`.

This requires Envoy 1.39 or later; the bundled gateway image satisfies that requirement. Custom native gateway images must also support `resolved_address_filter` in the DNS cache configuration. Legacy waypoint gateways retain their existing configuration without this filter. These restrictions cover DFP only; original-destination TCP/UDP forwarding and explicit upstream proxy connections use other clusters. Operator-added `EPEConfig.egressAuthorization.deniedCIDRs` remain EPE-only and are not copied to the gateway's DNS cache.
