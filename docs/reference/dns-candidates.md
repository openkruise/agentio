# DNS candidates and FQDN traffic rules

Native TrafficPolicy resources carry both the control-plane-resolved IP list and
the exact egress peer names in `Match.destination_fqdns` (protobuf field 4).
Sandbox inline traffic rules use the same compiler. An unresolved egress FQDN
retains its rule with no IPs; it never becomes a match-all destination. Legacy
Authorization projections omit such rules and retain their configured direction.

Deploy compatible ztunnel and Porter/EPE versions before publishing FQDN-only
rules: older native data planes ignore the new protobuf field. The legacy
Authorization API continues to enforce resolved IPs only.

Set `ENABLE_DNS_NAME_TRACKING=true` on ztunnel to learn the A/AAAA addresses returned
through its DNS proxy. It defaults to false and requires DNS proxying. Dedicated
sidecars and shared/inpod proxies use independent tables per workload. For the
DaemonSet, set `ztunnel.env.ENABLE_DNS_NAME_TRACKING: "true"`; injected sidecars can
use `proxy.istio.io/config` with `proxyMetadata.ENABLE_DNS_NAME_TRACKING: "true"`.
Restart the affected proxies after changing the environment.

The existing DNS response cache still serves repeated lookups. The additional
name-to-IP observations retain every returned address until its remaining TTL
expires, with a maximum of 16,384 associations per workload. Expired entries are
removed on DNS answers and every 60 seconds while idle. At capacity, new
associations are skipped until space becomes available; existing live evidence is
retained. This table does not extend response-cache TTLs.

ztunnel snapshots names for the original destination IP on each outbound TCP
connection or CONNECT-UDP session and sends one HTTP Structured Fields List of
String Items, omitting an empty list:

```http
x-agentio-destination-dns-candidates: "api.example.com", "cdn.example.com"
```

Names are lowercase ASCII DNS presentation names without a trailing root dot.
The native Agentio Envoy gateway captures this field on the mTLS HBONE listener
into `agentio.destination.dns_candidates` filter state. It preserves that state
through internal hops and supplies it to Porter and EPE. Ordinary application
headers with this name do not provide evidence. Lists above 8 KiB, malformed
syntax, empty strings, non-string members and Inner Lists discard the entire
candidate list; unknown parameters are ignored. Authorization then uses IPs.

For TCP, each ordered rule matches an observed FQDN **or** a resolved destination
IP, together with its port conditions. First-match order and global IP denies
remain in effect. EPE only uses DNS candidates for the original destination IP;
routing to another IP does not inherit the names. UDP and firewall enforcement
continue to use IPs. The upstream agentgateway adapter currently uses IP matching
because it does not capture this HBONE field.

These names are observations, not proof of the application's requested domain.
Shared IPs can have multiple candidates. Host and TLS SNI retain their own meaning.
EPE exposes the list as `request.dnsCandidates` in CEL and
`.Request.DNSCandidates` in templates, for example:

```cel
"api.example.com" in request.dnsCandidates
```
