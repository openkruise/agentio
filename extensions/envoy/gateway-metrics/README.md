# Native gateway HTTP metrics

This Rust HTTP filter records gateway request metrics directly in Envoy Stats. It targets the Envoy version pinned in `docker/Dockerfile.gateway` (v1.40.2), has no Rust crate dependencies, and is packaged as `/usr/local/lib/libagentio_gateway_metrics.so`.

The module emits exactly two metric families:

- `istio_requests_total`, labeled by `response_code` and `response_flags`.
- `istio_request_duration_milliseconds`, with the same labels; its Prometheus buckets also have `le`.

A completed HTTP stream contributes one request and one duration observation, including locally generated errors and interrupted requests. The module reads the final response code and Envoy response flags during `on_stream_complete`; a stream without a valid response code uses `0`, and a stream without flags uses `-`. Multiple core flags are joined by commas in Envoy core-flag enum order, for example `UF,URX`. The HTTP-filter ABI exposes a bitmask rather than the order in which flags were set, so a legacy label such as `URX,UF` becomes `UF,URX`. Exact-match queries on multi-flag strings need this canonical order; `response_flags="-"`, single-flag matches, and aggregations that omit this label retain their meaning. It does not add `request_protocol`, `grpc_response_status`, source, destination, HTTP byte, or TCP metrics. Socket and network-throughput metrics come from container monitoring independently of this module.

Duration uses Envoy `StreamInfo::requestComplete()`, converted from nanoseconds to integer milliseconds. This includes the original request start and header receipt rather than starting a separate timer when the filter is initialized. Envoy v1.40.0 supplies the required HTTP-filter timing callback; v1.39.4 only declares `RequestDuration` as an attribute without implementing it. The module uses Envoy histograms and the existing gateway histogram bucket configuration.

## Configuration and scraping

Use `envoy.filters.http.dynamic_modules` with `DynamicModuleConfig.name` and `filter_name` set to `agentio_gateway_metrics`, and `metrics_namespace` set to `agentio_gateway`. Set `dynamic_module_config.module.local.filename` to `/usr/local/lib/libagentio_gateway_metrics.so`, matching the packaged image; loading by name alone depends on Envoy's library search path. `filter_config` is a protobuf `StringValue`: empty enables both metrics, `requests` enables only the counter, and `duration` enables only the histogram. Insert the filter first in each business HTTP filter chain so it also observes local replies from subsequent filters. Do not attach it to the outer CONNECT tunnel or TCP proxy, where an event is not an HTTP business request.

Counter and histogram templates are registered once during configuration initialization. The module retains no per-stream state and updates metrics without module-owned per-request allocations or locks. Envoy owns the label series and worker-local metric storage. Metrics remain cumulative between Prometheus scrapes; no ALS events or per-request IPC are required. Envoy process restarts reset the counters, as with other Envoy metrics.

Envoy Admin exposes `envoy_agentio_gateway_istio_*` names. The gateway-agent status port (`15020`) serves `/metrics` and `/stats/prometheus`, converting these names to `istio_*` and merging agent metrics at scrape time. Port `15090` forwards raw Envoy Admin Prometheus metrics. Scrape labels such as `namespace` and `pod` are added by Prometheus rather than by this module. Ordinary access logs remain independent of the metric path.

## Upgrade and verification

Upgrade the gateway image before the controller starts producing the new HTTP-filter configuration. The shared library retains the previous native access-logger entry points in `src/legacy.rs` so older controller configurations can still load them. Those entry points retain their old metric shape (request counter by response code, aggregate duration); they do not add response flags. The old and new metric implementations must not be enabled together on one business HTTP chain.

Build with `cargo build --release --locked --offline` in this directory, or run `docker build -f docker/Dockerfile.gateway --target metrics-artifact --output type=local,dest=out/gateway-metrics .` from the repository root. The Docker build compiles for the target platform and the final gateway image includes the library.

Run `cargo test --locked --offline` here for selection, status-code/response-flag formatting and ABI layout tests. Run `bin/test_gateway_runtime.sh` to build the module and test it with the pinned community Envoy; supplying a gateway image tests its packaged module. The runtime tests check final status codes, local errors, interrupted requests, both labels, histogram observations and bucket boundaries, the legacy entry points, and the gateway scrape endpoints.

Loading this library into a different Envoy ABI is unsupported. Update the pinned version and ABI declarations together and rerun the runtime tests. The module executes within Envoy, so a module crash affects the Envoy process.
