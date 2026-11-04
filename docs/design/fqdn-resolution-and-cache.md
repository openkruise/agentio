# FQDN resolution and DNS cache behavior

> Design note. This page records how `agentiod` resolves FQDN egress rules and expires cached answers. See [Configure a TrafficPolicy](../tasks/configure-traffic-policy.md) for the operator workflow.

`agentiod` resolves A and AAAA records independently. A successful answer is available even while the other query is pending or failing. Each address family's cached answer expires according to its own TTL; a failed refresh does not extend that lifetime. A successful empty answer (NODATA) clears that family's old addresses. NXDOMAIN is recorded separately from NODATA. Neither is treated as a temporary DNS failure.

Temporary failures are retried and logged with the hostname and query type. The `dns-results` diagnostic collection also records per-family errors. Until its TTL expires, the last successful answer for a failing family remains usable. Expired addresses are withdrawn even if a refresh is still queued or in progress; they are not retained indefinitely.

Both `allow` and `reject` FQDN rules use only the remaining valid addresses. A failure does not broaden a `reject` rule to an entire address family. Consequently, if other rules allow the traffic, unknown or expired destination addresses may no longer be blocked by that FQDN reject rule. Use explicit CIDR rules when that DNS-dependent protection gap is unacceptable.
