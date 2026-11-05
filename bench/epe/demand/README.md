# EPE Workload demand benchmark

Run only in an isolated test cluster. The fixture creates synthetic Pods on an
unschedulable inventory Node with no kubelet; they consume no running containers.
Agentiod compiles their actual Kubernetes labels into WDS SecurityProfile
references. The load generator supplies only the Workload UID, and checks the
profile's HTTP 453 response, so an empty profile chain cannot pass the benchmark.

Install the current chart and binaries with `epe.mode=managed`. Configure
`epe.xdsCache.idleTTL` and `epe.xdsCache.maxEntries` to test retention bounds.
The chart registers the managed EPE's trusted SPIFFE identity automatically.

```sh
kubectl --context YOUR_TEST_CONTEXT apply -f bench/epe/demand/fixtures.yaml
kubectl --context YOUR_TEST_CONTEXT proxy --port=18049
# In a second terminal:
python3 bench/epe/demand/seed.py --count 1024
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o epe-load ./bench/epe/demand
# Run the binary where the EPE Pod IP is routable, e.g. inside its Kind node:
epe-load -address EPE_POD_IP:9002 -requests 1024 -identities 1024 -concurrency 16
epe-load -address EPE_POD_IP:9002 -requests 30000 -identities 128 -concurrency 16
```

`-status 0 -path /allow` checks successful header processing and target
authorization. `-rate` uses scheduled arrivals, including generator queueing;
zero measures closed-loop concurrency. Each operation opens an ext_proc stream
on a shared gRPC connection (`-connections` sets the pool size) and validates the
first response. Only the isolated
benchmark endpoint uses plaintext; EPE's ADS connection still uses TLS and its
Pod-bound token.

Collect EPE and Agentiod `/metrics` before and after each run. In particular:

- `agentio_epe_demand_cache_entries` counts retained and active subscriptions.
- `agentio_xds_client_demand_wait_duration_seconds_count` counts waiting calls,
  including concurrent waiters for the same subscription.
- Agentiod's `agentio_xds_push_resources_sum` counts resources actually sent.
  A hot run should add no resources; 64 concurrent cold calls for one UID should
  cause only one resource to be sent.
- `process_cpu_seconds_total`, `process_resident_memory_bytes` and
  `go_memstats_heap_inuse_bytes` describe the EPE process.

For TTL, use `2s`, warm 64 identities, then access identity zero twice per second
for eight seconds: only that identity should remain. After three idle seconds,
the cache should be empty and its next request should rediscover one resource.
For capacity, use 128 entries and cycle through 1024 identities; entries may
temporarily exceed the target while active requests pin related resources, but
must return to 128 afterward.

This measures EPE header processing and actual Agentiod discovery, not full
Envoy/ztunnel forwarding, body processing, or production network capacity.
Delete the dedicated test cluster after collecting evidence.

For the larger matrix, `seed.py --count 100000 --labels 20` creates 100,000
actual Kubernetes Pod objects, each with 20 generated labels plus the selector
label. Their IPs span multiple /24 networks. They remain inventory objects;
there are no 100,000 business processes.
