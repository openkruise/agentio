# Gateway HTTP and ext_proc fixture

This fixture separates Envoy forwarding, ext_proc transport, and EPE policy execution. It reuses `bench/load` for request scheduling and latency accounting.

The EPE mode runs the production ext_proc server, engine, SecurityProfile compiler, and header mutation filter. Its resolver returns fixed in-memory profiles; it does not measure xDS discovery, policy lookup, Porter, HBONE, MITM, TLS, or DFP. Each profile matches all domains and sets `x-policy: applied`. The load mode can check that the origin actually receives this mutation.

Run on Linux with an Envoy gateway image containing `libagentio_gateway_metrics.so`:

```sh
go build -o /tmp/gateway-fixture ./bench/gateway
/tmp/gateway-fixture -mode=origin -listen=127.0.0.1:19201
```

In separate terminals:

```sh
/tmp/gateway-fixture -mode=epe -listen=127.0.0.1:19202 -profiles=1

docker run --rm --network host --cpus 2 --memory 1g \
  --entrypoint /usr/local/bin/envoy \
  -v "$PWD/bench/gateway/envoy.json:/etc/envoy/bench.json:ro" \
  YOUR_GATEWAY_IMAGE -c /etc/envoy/bench.json --concurrency 2

/tmp/gateway-fixture -mode=load -concurrency=64 -requests=100000 -expect-policy
```

The supplied Envoy configuration injects a fixed test identity. Use it only in an isolated benchmark. It sends request headers to EPE and skips response headers and bodies unless EPE requests them.

Use `-mode=noop` instead of `epe` to measure only the RPC path; omit `-expect-policy` for that case. `-delay=500ms` in noop mode simulates a slow processor. Use `-authority=api.example.test:8443` to set the upstream Host independently of the gateway URL. Load options include `-body-bytes=16384` for a POST body and `-rate=5000` for a fixed offered rate. JSON output includes throughput, errors, request latency, and scheduling delay. Failed requests make the command exit nonzero.

Pin Envoy, processor, origin, and load generator to separate physical CPU cores for comparisons. Warm each configuration first and repeat measurements. Keep the same Envoy filters and request attributes when comparing noop and real EPE. For dynamic bandwidth/concurrency modules, use [the CONNECT benchmark](../connect/README.md).

```sh
go test -race ./bench/gateway
```

## Open-loop gateway capacity client

`load/` drives a deployed gateway using the shared Go scheduler. Build it for the Linux node architecture:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/gateway-load ./bench/gateway/load
```

The HTTP action validates status 200 and the exact origin body `ok\n`. Add `-expect-policy` to require the origin to echo `X-Policy: applied`, proving that EPE's request mutation reached the origin. HTTPS and TLS inside CONNECT verify both the supplied CA and `-tls-server-name`; there is no insecure TLS mode. `-h2` requires HTTP/2 and rejects HTTP/1 fallback.

```sh
gateway-load -mode=http -endpoint=https://GATEWAY_IP:18443/ \
  -authority=bench.test:19443 -ca-file=/fixtures/ca.pem \
  -tls-server-name=bench.test -h2 -expect-policy \
  -rate=5000 -concurrency=128 -seconds=60
```

`-endpoint` selects the gateway socket; `-authority` selects its HTTP routing target. `-targets-mode=names`, `cold`, `ttl` or `ips` rotates HTTP authorities while retaining that gateway socket. These modes take a **port only** in `-authority`, for example `-authority=19443 -targets-mode=names -targets=1024`. Names use `pool-N.test`, `ttl.pool-N.test`, or a unique `cold-PREFIX-N.test`; the test DNS must resolve them. IP mode uses `10.200.0.0/15` (up to 131,072 distinct addresses); the isolated test network must route that prefix to the origin, and the origin must accept traffic to all those addresses. It does not create addresses or routes. The TLS name remains explicitly selected by `-tls-server-name`. `-body=16384` sends a POST, and `-close` disables HTTP/1 keepalive. Keep the same connection mode in compared runs.

For CONNECT/TCP fixtures:

```sh
gateway-load -mode=tcp -endpoint=GATEWAY_IP:18000 \
  -authority=ORIGIN_IP:19444 -tls-tcp -ca-file=/fixtures/ca.pem \
  -tls-server-name=bench.test -rate=1000 -concurrency=64 -seconds=60
```

`-stream` reuses one tunnel per logical target; otherwise each operation establishes a fresh tunnel. TCP target modes are `fixed`, `names`, and `cold`; `-tcp-host`, `-slot` and `-profiles` populate the isolated fixture's test headers. They are not production authentication. A TLS echo through CONNECT exercises inner TLS but does not by itself prove production MITM, HBONE, Porter discovery or dynamic SDS.

The matching origin serves HTTP/1 and h2c on the HTTP port, HTTP/1 and HTTP/2 over TLS on the HTTPS port, and plain/TLS TCP echo ports:

```sh
gateway-load -mode=serve -cert-file=/fixtures/cert.pem -key-file=/fixtures/key.pem \
  -listen=:19201 -tls-listen=:19443 -tcp-listen=:18080 -tcp-tls-listen=:19444
```

All four listener addresses are configurable. Supply a certificate valid for the names the gateway uses upstream; trust it in the generated Envoy configuration as well as in the load client.

`-rate` is a positive offered arrival rate, and total requested operations equal `rate × seconds`. JSON retains the shared scheduler's successful and failed operation counts, throughput, end-to-end P50/P95/P99, `queue_p99_ms` and `operation_p99_ms`. `unique_attempted` counts logical scheduler targets; in `cold` mode it does not count distinct domain names. No application-level retries are added; Go's HTTP transport retains its default retry behavior for eligible requests when a reused connection fails. Errors or incomplete work make the process exit nonzero after emitting the result. `-seconds` is the arrival window; a ten-second drain allowance lets already scheduled requests finish. Persistent TCP target locks contribute to operation latency, so provide enough targets when measuring parallel capacity.

Measure the generator, origin and gateway on separate CPU resources. Run a baseline origin probe first, and report scheduling delay beside request latency rather than attributing generator saturation to the gateway. This fixture has no deployment orchestration and does not create or delete Kubernetes resources.

```sh
go test -race ./bench/gateway/load
```
