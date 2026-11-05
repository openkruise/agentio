# Develop an HTTPCallout server

An HTTPCallout server receives a JSON `Invocation` from the Egress Policy Enforcer (EPE) and returns a JSON `Decision`. The wire format is the same over HTTP1, HTTPS HTTP2 and cleartext HTTP2 (h2c); it is not gRPC. This example allows requests by default, rejects the illustrative destination `blocked.example`, and adds a verdict header to the message for the current phase. It is a minimal HTTP-only server: it sets up no TLS listener and no Kubernetes Service.

## Run the example

Use the Go version in the repository's `go.mod` (currently 1.26.8). Save the following as `/tmp/httpcallout-example.go` and run it from the Agentio repository root so imports resolve against the same checkout as EPE. The protocol types are reused from the implementation, not a separately versioned SDK; an independently built service should pin its Agentio dependency to the release it integrates with.

```go
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/filters/httpcallout"
)

func callout(w http.ResponseWriter, r *http.Request) {
	var inv httpcallout.Invocation
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	if err := decoder.Decode(&inv); err != nil {
		http.Error(w, "invalid invocation", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "one JSON document required", http.StatusBadRequest)
		return
	}
	if err := inv.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	builder := httpcallout.Continue(inv.Phase).SetHeader("x-scanner-verdict", "allowed")
	if inv.Request.Host == "blocked.example" {
		builder = httpcallout.Respond(inv.Phase, http.StatusForbidden).
			Reason("blocked_destination").
			Body("blocked by scanner\n")
	}
	decision, err := builder.Build()
	if err != nil {
		log.Printf("build callout decision: %v", err)
		http.Error(w, "invalid decision", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(decision); err != nil {
		log.Printf("write callout decision: %v", err)
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18080", "listen address")
	h2c := flag.Bool("h2c", false, "also accept cleartext HTTP2 prior knowledge")
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /callout", callout)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(*h2c)
	server := &http.Server{
		Addr: *listen, Handler: mux, Protocols: protocols,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
		IdleTimeout: 90 * time.Second,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams: 32,
			MaxReceiveBufferPerConnection: 4 << 20,
			MaxReceiveBufferPerStream: 1 << 20,
		},
	}
	log.Printf("callout server listening on %s (h2c=%t)", *listen, *h2c)
	log.Fatal(server.ListenAndServe())
}
```

```sh
go run /tmp/httpcallout-example.go -h2c
```

Without `-h2c`, the server accepts HTTP1 only. With it, the same listener accepts both HTTP1 and HTTP2 prior knowledge, matching EPE's `protocol: HTTP2` with an `http://` URL. h2c provides no TLS encryption; for HTTPS, serve TLS with HTTP2/ALPN enabled and configure the provider's TLS settings.

`Continue(inv.Phase)` targets request mutations in the request phase and response mutations in the response phase. `Respond(inv.Phase, statusCode)` always constructs a local response. Both return a builder with `SetHeader`, `AppendHeader`, `RemoveHeader`, `Body`, `StatusCode` and `Reason` methods; `Build()` supplies the protocol version and checks the existing decision contract. `Body("")` explicitly clears the body, while omitting it leaves the body unchanged. Header operations keep their call order. Invalid combinations, such as `Continue(PhaseRequest).StatusCode(403)` or removing a header from a new local response, return an error from `Build()`.

## Exercise the contract

Send a request-phase invocation directly to the server:

```sh
curl -sS http://127.0.0.1:18080/callout \
  -H 'Content-Type: application/json' \
  --data-binary '{"version":"0.1","phase":"request","source":{"namespace":"default","pod":"agent-demo"},"policy":{"scope":"example","rule":"scan","ordinal":0},"request":{"id":"demo-1","method":"GET","scheme":"https","host":"allowed.example","port":443,"path":"/","rawQuery":"","contentType":""}}'
```

The decision continues processing and sets a request header; omission of `action` means `continue`:

```json
{
  "version": "0.1",
  "request": {
    "headers": [
      {
        "operation": "set",
        "name": "x-scanner-verdict",
        "value": "allowed"
      }
    ]
  }
}
```

Change `host` to `blocked.example` to receive this decision, still with HTTP status 200 from the callout server:

```json
{
  "version": "0.1",
  "action": "respond",
  "reason": "blocked_destination",
  "response": {
    "statusCode": 403,
    "body": "blocked by scanner\n"
  }
}
```

EPE returns that 403 to the original caller. In the request phase it does not send the request upstream; in the response phase it replaces the already received upstream response. Returning HTTP 403 directly from the callout endpoint instead is a callout failure and follows the rule's `failStrategy`, so it is not an equivalent way to deny traffic. Keep `reason` a short, stable audit explanation; the protocol limits it to 256 bytes and permits it only with `respond`.

For a response-phase call, set `phase` to `response`, add `"response":{"statusCode":200,"contentType":"text/plain","body":"hello"}`, and keep the `request` object free of `headers` and `body`. The example then sets `response.headers` instead of `request.headers`. To check h2c with an HTTP2-enabled curl build, add `--http2-prior-knowledge` to the command; otherwise the command exercises HTTP1 even though the server accepts both.

## Connect EPE to the server

Configure a provider in EPEConfig, or under `epe.config` in Helm values:

```yaml
extensionProviders:
  - name: content-scanner
    httpCallout:
      url: http://scanner.agentio-system.svc:18080/callout
      protocol: HTTP2
      timeout: 1s
      http2:
        maxConcurrentStreams: 32
```

Replace the URL with an address reachable from EPE. The service name above assumes you deploy the server behind that Kubernetes Service. For a container deployment, run the server with `-listen :18080 -h2c`; a laptop's `127.0.0.1` is not reachable as localhost from an EPE Pod. If you run the server without `-h2c`, select `HTTP1` instead. The explicit 1s timeout is illustrative; an omitted timeout defaults to 500ms. See [transport configuration and capacity planning](../reference/epe-configuration.md#httpcallout-transport) for pool defaults and tuning.

Add this action to a matching SecurityProfile rule for the selected workload:

```yaml
httpCallout:
  provider:
    name: content-scanner
  request:
    headers:
      enabled: true
      filter:
        allowList: [content-type, x-request-id]
    body:
      enabled: true
      maxBytes: 1048576
  response: {}
  failStrategy: Block
```

This sends the request body and selected headers, and enables a metadata-only response-phase call. It makes two callouts for an exchange that reaches the response phase; remove `response` if only request scanning is needed. The destination must also be permitted by the applicable traffic policy. See [SecurityProfile HTTP callouts](../reference/security-profile.md#http-callouts) for rule placement, phase selection and failure behavior.

## Extend the handler

- Replace the example host comparison with your service's decision logic. For backend calls, propagate `r.Context()` so work can stop when EPE cancels or times out; keep shared state safe for concurrent handlers.
- Treat an absent body as "not collected," distinct from a present empty string. Bodies are complete UTF-8 strings, not base64 or streamed chunks. In the response phase only `response.body` can be present; the original request body is not retained. Enable the corresponding phase body in the policy before relying on it for scanning.
- Set `request` mutations only when continuing the request phase and `response` mutations when continuing the response phase. `respond` instead requires `response.statusCode` and cannot include request mutations. A body mutation replaces the whole body. The builder validates these rules in `Build()`; when constructing `Decision` structs directly, use `Decision.Validate(phase)` in your service's tests.
- The example caps the encoded invocation JSON at 8 MiB, which is separate from the policy's original-body limit. JSON escaping and forwarded headers add bytes, so do not assume an 8 MiB original body fits in an 8 MiB invocation. Size this limit for your policy. EPE separately limits the decision JSON to 1 MiB by default through `HTTP_CALLOUT_MAX_RESPONSE_BYTES`.
- Return a non-2xx status for service failures and a 2xx response with a valid decision for business outcomes. EPE does not follow redirects or retry failed callouts. Avoid logging forwarded bodies, credentials or cookies; use `request.id` and the source/policy metadata for correlation.

For reusable integration testing, the [existing test server](../../test/fixtures/httpcallout/README.md) already provides continue, mutation, denial, delay, reset and malformed-response endpoints, plus configurable HTTP2 streams and receive windows. Its [handler](../../test/fixtures/httpcallout/handler.go) is a larger example using the same production protocol types.
