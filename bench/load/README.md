# Shared Go load scheduler

`github.com/openkruise/agentio/bench/load` schedules requests independently of the target protocol or Kubernetes. Scenario adapters provide `func(context.Context, int) error`; the integer is a logical identity, suitable for indexing Pod/workload identities, credentials or request payloads. Connections and response validation belong to the adapter.

```go
result, err := load.Run(ctx, load.Config{
    Requests:    1000000,
    Identities:  100000,
    Concurrency: 128,
    Rate:        10000,
    Duration:    2 * time.Minute,
}, func(ctx context.Context, identity int) error {
    return client.Request(ctx, identities[identity])
})
```

- `Identities` and `Offset` define a round-robin identity range. Different workers can use disjoint ranges; identities do not create real Pods, IP addresses or one connection per Pod.
- `Rate: 0` uses closed-loop concurrency. Positive rate assigns arrivals at fixed intervals; latency includes queueing from the scheduled arrival, including when workers are saturated. `Requests` bounds the total offered work; the runner does not drop late requests automatically.
- `Start` optionally specifies a common start after adapters prepare messages/connections. A missed start fails explicitly.
- `Duration` limits the measurement phase. Callbacks must honor context cancellation. Cancellation returns partial measurements and an error; counts include only callbacks actually invoked.
- `Started` and `Finished` bracket the measurement window for adapter-specific CPU sampling. Result aggregation happens afterward.

Results contain completed operations/errors, actual identities attempted, per-second completion counts, latency percentiles and request-batch means. Percentiles describe one scheduler instance; a scenario must explicitly choose how to aggregate multiple workers. There is no Kubernetes inventory size minimum in this layer; the Porter scale scenario imposes its own 50,000 minimum.

This is a deterministic load primitive, not a claim of realistic application traffic. A reusable protocol adapter can map identities onto requests; scenarios choose inventory, hot/cold ranges and lifecycle events. The current Porter suites compose concurrent schedulers for mixed hot/cold traffic.

`NewQueue` supports continuous open-loop traffic with live rate updates. It keeps workers alive, bounds pending arrivals, reports drops separately, and drains accepted work when canceled. Callers aggregate observations incrementally using the scheduled arrival time. The finite-batch `Run` retains its original result and scheduling behavior.

Validate scheduling, queueing latency and cancellation with `go test -race ./bench/load`.

The [CONNECT benchmark](../connect/README.md) reuses this scheduler for tunnel establishment only, then measures sustained byte throughput independently after warmup. Its adapter detaches established tunnel lifetime from the setup deadline while preserving transfer cancellation.
