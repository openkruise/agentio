# Agentio adapter for agentgateway

This adapter pins upstream agentgateway **v1.7.0** to the commit in
`source-revision`. It reuses Porter's standard ext-proc interface, EPE's
`agentio.route` metadata, and the existing Agentio SNI evaluator.

The seam is the outer HBONE CONNECT handler. `frontendPolicies.hboneExtProc`
calls the configured processor before accepting each tunnel, with a five-second
default deadline and headers-only processing. Errors and immediate responses
reject CONNECT. Its interface takes a native backend reference, request
attributes, a timeout, and optional TLS include/exclude hosts.

The implementation keeps the TLS-authenticated source, CONNECT headers and
processor metadata on the individual tunnel. Inner HTTP policies read
`source.connectMetadata` and `source.connectHeaders`; application headers cannot
replace them. CONNECT credentials are redacted from debug formatting. Porter
continues to validate certificate claims, IP/principal fallback, Sandbox binding
and discovery freshness. New CONNECT streams read the current frontend policy,
including when they share an existing HTTP/2 connection.

Decrypted HTTP requests must retain the TLS SNI as their Host, compared without
the port and ignoring case. A mismatch is rejected with HTTP 403 before EPE.

The SNI adapter evaluates gateway exclusions, Porter's ordered rules, then
gateway includes. Termination requires an HTTPS listener and a mounted local
MITM CA; absent termination material rejects the connection. The evaluator is
copied from `extensions/envoy/sni-policy/src/policy.rs` at build time so both
adapters use the same rules.

EPE metadata pins the actual dynamic backend to the authorized numeric IP:port.
The authorizing processor can update that target during buffered body checks;
another processor cannot replace it. A target received after request dispatch
fails processing. TLS verification retains the HTTP hostname when the dial
target becomes an IP. Static endpoint candidates are selected once by EPE
before authorization, rather than being independently selected again by the
proxy.

## Build

```bash
docker build -f docker/Dockerfile.agentgateway -t registry.example/agentio-agentgateway:dev .
```

The image builds the pinned source with `hbone-ext-proc.patch` and the adapter's
Rust files. It omits the optional native web UI. Supply the resulting image or
digest as `egressGateway.agentgateway.agentioImage`; generated configuration
requires this setting. Operator-owned `config.yaml` continues to use
`egressGateway.agentgateway.image` and can use the official image.

To work on the patch locally, use a fresh checkout of the pinned commit:

```bash
bash extensions/agentgateway/prepare.sh /path/to/agentgateway
cd /path/to/agentgateway
cargo test --locked -p agentgateway --lib proxy::hbone_ext_proc
cargo build --locked -p agentgateway-app
cargo xtask schema
```

The tests exercise the ext-proc interface, per-tunnel isolation, trusted TLS
attributes, deny/timeout behavior, SNI decisions, target ownership and actual
forwarding to the authorized endpoint. Run Agentio's binary interoperability
tests with that executable:

```bash
AGENTIO_AGENTGATEWAY_BINARY=/path/to/agentgateway/target/debug/agentgateway \
  go test ./pkg/gatewaydeployer -run TestAgentgatewayNativeGenerated -count=1
```

Keep edits to the adapter Rust files here. Regenerate the patch from changes to
upstream's tracked source files, excluding the installed adapter files:

```bash
git -C /path/to/agentgateway diff --binary -- crates/agentgateway/src > extensions/agentgateway/hbone-ext-proc.patch
```
