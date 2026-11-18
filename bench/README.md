# Bench tools

- [Scenario framework](scenario/README.md): reusable Go host/Docker execution, timeouts, cleanup, replay plans, pass/fail results and retained evidence; CONNECT stability profiles are its first consumer.
- [Fake xDS client and load scenarios](xds/README.md): reusable Delta ADS client, standalone load application, and Kubernetes connection/shared-policy workloads.
- [Load scheduler](load/README.md): protocol-independent Go identity scheduling, concurrency, rate control and latency measurement.
- [CONNECT data-plane benchmarks](connect/README.md): Go HTTP/2 CONNECT byte-throughput generator, CPU-affined Envoy/origin runner, sandbox bandwidth/concurrency comparisons, and JSONL analysis.
- [Porter scale tests](porter/README.md): Go ext_proc load generator and WDS clients, with Go/client-go orchestration for cold/hot caches, reconnects, policy lifecycle and control-plane failover.
- [Kubernetes Sandbox lifecycle tests](sandbox/README.md): KWOK nodes, real Sandbox/Pod changes, node WDS clients, and authenticated traffic through production gateways.
- [EPE HTTPCallout](epe/callout/README.md): real Envoy integration and proxy-chain performance/stability tests using the shared HTTPCallout fixture.
- [EPE on-demand load](epe/demand/README.md): request SecurityProfile lookups at a fixed offered rate and measure cold and warm paths.
- [Sandbox stability tools](sandbox/stability/README.md): real HTTPS handshakes, hot and long-tail domains, streaming and file transfers, with request and resource summaries.
- [Gateway capacity tools](gateway/README.md): isolated Envoy and ext_proc fixture, plus open-loop HTTP, HTTP/2, and CONNECT/TCP traffic against a deployed gateway.
