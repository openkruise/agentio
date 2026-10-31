# Agentio SNI listener module

This Rust dynamic module runs after Envoy's HTTP and TLS inspectors on the gateway's internal listener. It evaluates the actual TLS SNI against a canonical `SniTrafficPolicy` in `agentio.sni.policy` filter state and writes `agentio.tls.action`: `terminate`, `passthrough`, `deny` or `cleartext`.

Porter supplies the ordered policy through ext_proc dynamic metadata. The control plane copies `%DYNAMIC_METADATA(agentio:sni:policy)%` to hashable filter state on CONNECT and shares it with the internal connection. The module does not trust `x-agentio-sni` or an action from CONNECT headers. A preexisting action closes the connection.

Rules use first-match order. Wildcards match subdomains, not the apex. Valid empty policies, unmatched SNI and absent SNI pass TLS through. Missing or malformed policy denies detected TLS. Cleartext follows ordinary HTTP/TCP routing. Gateway exclusions are applied by the listener matcher before the action. Internal inspectors close connections after a 1-second timeout, so silent server-first clients and delayed client data cannot enter TCP forwarding through the timeout fallback.

The production `docker/Dockerfile.gateway` includes this module with community Envoy. The control plane emits the extension only to authenticated `agentio-egress~` clients. The legacy proxyv2 image does not support the listener dynamic-module configuration and continues to receive its existing custom matcher during rolling upgrades.

Build on Linux with Rust 1.93+, clang/libclang, curl and tar:

```sh
cd extensions/envoy/sni-policy
bash build.sh
```

The build downloads the required subtree from pinned Envoy SDK tag `v1.40.2`, checks formatting, runs unit tests and builds `target/release/libenvoy_agentio_sni_policy.so`. The SDK cache is ignored; remove `.envoy-sdk` when changing the SDK pin.

The standalone smoke fixture uses test headers, static certificates and local origins to isolate module behavior. It exercises real TLS termination and relay, ordered matching, wildcard boundaries, normalization, denial, absent/invalid policies, cleartext, alternating policies and conflicting actions. Production HBONE, Porter discovery and on-demand SDS require the integrated gateway test as well.

```sh
docker build -t agentio-envoy-sni-policy:dev .
python3 tests/smoke.py
```
