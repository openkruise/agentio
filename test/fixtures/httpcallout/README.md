# HTTPCallout test server

The standalone server implements EPE's HTTPCallout protocol using the production `Invocation` / `Decision` types. It validates invocations, limits request JSON to 8 MiB, and never logs request bodies or credentials. It is a test application, not an authorization service. Bind to loopback by default; use `-listen :18080` only when a remote test proxy needs to reach it.

From the repository root:

```sh
go run ./test/fixtures/httpcallout/server -listen 127.0.0.1:18080
curl -sS http://127.0.0.1:18080/continue -H 'Content-Type: application/json' \
  -d '{"version":"0.1","phase":"request","request":{"method":"POST"},"policy":{"scope":"default/test","rule":"test","ordinal":0}}'
```

POST endpoints accept request- or response-phase invocations:

| Path | Behavior |
| --- | --- |
| `/continue` | Continue without mutation |
| `/mutate` | Set `x-callout-verdict: clean` and replace the phase's body with `changed by callout` |
| `/respond` | Return a local 403 with body `blocked by callout` |
| `/status` | HTTP 503 |
| `/malformed` | Truncated decision JSON |
| `/oversize` | Response larger than the default 1 MiB client limit |
| `/delay?duration=500ms` | Delay then continue; stop work on client cancellation (maximum 1 minute) |
| `/reset` | Close the HTTP/1 connection or abort the HTTP/2 stream without a response |

GET `/healthz` checks readiness. GET `/stats` returns validated call count, currently active calls, and calls canceled during delay. Counters do not retain request data. Successful decision responses have protocol version `0.1`.

## HTTP/2 tuning

Add `-h2c` to accept prior-knowledge HTTP/2 as well as HTTP/1.1. The same flags are available in the ext-proc fixture's `-http-callout-port` mode:

```sh
go run ./test/fixtures/httpcallout/server -listen 127.0.0.1:18080 -h2c \
  -http2-max-streams 32 -http2-connection-window 4194304 -http2-stream-window 1048576
```

The defaults are 32 concurrent streams, a 4 MiB connection receive window and a 1 MiB stream receive window. The windows control incoming request data, not response data. The connection window is deliberately larger than Go's 1 MiB default to reduce contention when multiple large JSON bodies share a connection. Measure memory and tail latency when increasing either limit. Without `-h2c`, this cleartext server uses HTTP/1.1.

## Tests and reuse

Run `go test -race ./test/fixtures/httpcallout/...` from the repository root. The existing ext-proc fixture image also serves this handler with `-http-callout-port=8080`; the product E2E suite deploys that mode, so it needs no additional image input.

`TestHTTPCalloutFixture` in `test/e2e/suites/epe` verifies Kubernetes deployment, Service reachability, both invocation phases, mutations, local responses, invalid input, failure responses and counters. With the product E2E image inputs configured, run `go run ./cmd/product-e2e run --suites epe --tests '^TestHTTPCalloutFixture$'` from `test/e2e`.

`TestHTTPCalloutFixture` calls the fixture directly. `TestEPEHTTPCallout` additionally exercises public SecurityProfile/GlobalSecurityProfile distribution through ztunnel, Envoy and EPE, using this same handler. The ext-proc fixture adds an origin endpoint and an observation callback for checking actual HTTP hops; the standalone server does not retain invocation content. The [Envoy integration and performance tests](../../../bench/epe/callout/README.md) cover EPE's real callout client, engine, buffering, fail-open/closed behavior and recovery with a static policy resolver.

The transport-lifecycle subtest in `TestEPEHTTPCallout` sends concurrent cold requests to an HTTP/2 server advertising only four streams, then updates the deployed AgentioConfig from HTTP/2 to HTTP/1.1 while an old request is held. It checks the protocol, exact call count, refused streams, successful old response and closure of the drained connection. It also keeps each provider URL and protocol fixed while changing only `maxConnections` (2 → 1), `maxIdleConnections` (2 → 1), or `idleTimeout` (30s → 500ms), for both HTTP1 and HTTP2, and `maxConcurrentStreams` (1 → 2 and 2 → 1) for HTTP2. Each case checks that the retired idle connection closes, the new pool admits exactly its configured capacity and queues an extra call, the updated idle limits take effect, and an active old connection completes its responses before closing. The ext-proc fixture exposes `/transport`, `/hold`, `/controlled/{case}` and POST `/release` for these assertions. Controlled requests wait until POST `/release?connection=<remote-address>` releases their connection, independently of other connections; these controls are not part of the standalone callout protocol.
