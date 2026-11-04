# Kubernetes Sandbox lifecycle benchmark

This fixture creates real Kubernetes `Sandbox`, `Pod`, `Node`, `Service`, and policy
objects. The installed Agentio controllers watch and compile them normally. KWOK
supplies virtual node/Pod status; no container runs on a virtual node.

The data plane is real: production CA authenticates Pod-bound service-account
tokens and signs instance certificates; a few HTTP/2 clients make mTLS CONNECT
requests through Envoy + Porter + EPE to an HTTP backend. Each request checks the
CONNECT status and the exact inner HTTP status/body. One simulated ztunnel ADS
client per virtual node authenticates with a token bound to that node's proxy Pod,
subscribes to Address/Sandbox/TrafficPolicy, and ACKs updates.

This covers Kubernetes watches, resource compilation, node-scoped ADS, demand
loading, cache expiry, certificate identity, policy enforcement and actual network
forwarding. It does **not** run 100,000 containers, a real sandbox runtime/operator,
or source ztunnel processes. The fixture writes the Sandbox status/Pod ownership
that a runtime would normally maintain. CONNECT currently uses a fresh TLS/HTTP2
connection per operation, so results include handshake costs and are not a measure
of maximum throughput with persistent ztunnel connections.

## Requirements and installation

Use a disposable kind cluster with sufficient host RAM/disk and a Node CIDR large
enough for 1,000 virtual nodes (100 sandboxes/node). A default `/16` cluster CIDR
with `/24` node CIDRs only fits 256 nodes. Check etcd's backend quota before loading
100,000 Sandbox + Pod pairs; the default 2 GiB can be insufficient. Record any
cluster setting changes. Other controllers in a shared cluster may also watch
these objects and consume memory.

Build the fixture from the repository root:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o sandbox-bench ./bench/sandbox
```

`values.yaml` is the tested production-chart configuration, with three control-plane
replicas, two gateways/Porters, and two EPE replicas. Set image tags to builds being
measured, and record both repository revisions and resolved image IDs. Build
Agentio/EPE/Porter/gateway using the repository Dockerfiles. The example tags are
local test artifacts, not public releases.

Render on a machine with Helm and PyYAML, then apply to the test cluster:

```sh
python3 bench/sandbox/render.py --real-node KIND_CONTROL_PLANE_NODE --output install.yaml
kubectl create namespace sandbox-scale-system
kubectl apply -n sandbox-scale-system -f install.yaml
```

The renderer pins real Deployments to the actual node and omits the second global
injection webhook. Unique CA ConfigMap names prevent interference with other
Agentio installations. Install the Kruise Agents Sandbox CRD and this repository’s policy CRDs before
applying the chart. The Sandbox runtime controller itself must not reconcile the
fixture namespaces.

For the 100k run on the shared 60 GiB host, `values-100k.yaml` changes the control
plane to two replicas with 8 CPU / 8 GiB limits and `GOMEMLIMIT=6GiB` each. Each
replica holds the full inventory. This configuration still exhausted practical
host memory headroom during traffic/replacement in the shared-host trial; it is
not a validated 100k sizing recommendation. Budget Kubernetes, retained services,
traffic connections and replacement overlap as well as steady control-plane memory.
This is a different resource
configuration from the 10k/50k runs, not a strict fixed-resource scale comparison:

```sh
python3 bench/sandbox/render.py --real-node KIND_CONTROL_PLANE_NODE \
  --values bench/sandbox/values.yaml --values bench/sandbox/values-100k.yaml \
  --output install-100k.yaml
```

Run KWOK v0.8.0 with `kwok-stages.yaml`, restricted to the annotated virtual nodes:

```sh
kwok --kubeconfig=KUBECONFIG --config=bench/sandbox/kwok-stages.yaml \
  --manage-all-nodes=false \
  --manage-nodes-with-annotation-selector=kwok.x-k8s.io/node=fake \
  --cidr=10.224.0.0/12 --node-ip=10.223.0.1
```

The stages derive from [KWOK v0.8.0 stage-fast.yaml](https://github.com/kubernetes-sigs/kwok/releases/tag/v0.8.0).
One necessary change: `pod-delete` excludes `bench.agentio.io/run=sandbox-scale`
Pods, since the fixture explicitly deletes those with zero grace. KWOK v0.8.0
queues deletion by name without a UID precondition; an old deletion can otherwise
remove a newly recreated Pod with the same name. If changing the fixture prefix,
change this stage selector too. The original failed trial must not be counted as
an Agentio availability result.

The renderer also includes `backend.yaml`: four real backend Pods, exposed by a
Service named `backend` on port 8080. Each runs `sandbox-bench --action=backend` and returns
`sandbox-scale-ok\n`. A local image with the fixture binary can serve both backend
and test clients. The runner example uses `agentio-sandbox-bench:1018`. Load traffic distributes
identities across the four backend Pod IPs; lifecycle and policy probes use the Service.
A single upstream address is also a useful separate capacity test: large populations of
HTTP/1 upstream connections can exhaust a gateway’s ephemeral source-port range.
Do not classify those 503 responses as successful CONNECTs or hide them by retrying.

## Resource population and individual actions

All mutation commands require an explicit kubeconfig. Use a dedicated prefix; do
not reuse namespaces containing resources managed by a real sandbox runtime.
Each 1,000 sandboxes gets a namespace; each 100 gets a virtual node. Sandbox IDs
are globally unique within the fixture. Each Pod has 21 labels and an owner
reference to the actual Sandbox UID. Sandbox status references the actual Pod UID.

```sh
sandbox-bench --kubeconfig=KUBECONFIG --action=seed --count=10000 --output=10000-seed.json
sandbox-bench --kubeconfig=KUBECONFIG --action=configure --count=10000
# Grow the same scene; seed refuses to silently overwrite existing pairs.
sandbox-bench --kubeconfig=KUBECONFIG --action=seed --offset=10000 --count=40000
sandbox-bench --kubeconfig=KUBECONFIG --action=configure --count=50000
sandbox-bench --kubeconfig=KUBECONFIG --action=seed --offset=50000 --count=50000
sandbox-bench --kubeconfig=KUBECONFIG --action=configure --count=100000
```

`configure` creates ten selected Services per namespace and a shared
GlobalTrafficPolicy. `labels`, `recreate`, and `delete` operate on `offset/count`;
`--api-qps` and `--workers` bound mutation load. Failed partial population is
reported as failure; inspect affected objects before resuming.

Network actions require `--ca=HOST:15012 --gateway=HOST:15008 --target=HOST:8080`.
Run them from a network namespace that can reach cluster IPs. Gateway certificates
are checked against the configured CA and the exact gateway SPIFFE principal.

- `traffic`: signs `--active` uniformly spaced Pod identities, then sends
  `--requests` at `--rate` with `--workers`. Latency includes generator queueing.
  `--start-file` synchronizes separately prepared hot/cold clients. Preparation
  time is reported separately. Any error or incomplete request count fails the action.
- `watch`: opens one real ADS connection per 100 inventory objects and writes an
  atomic `.live` JSON snapshot every second. Counts, policy versions, startup
  retries, and reconnects are visible; empty type responses alone are not inventory
  convergence.
- `lifecycle`: waits up to 20 seconds for baseline access and records its latency
  and attempt count separately (a preceding bulk creation may still be converging),
  deletes one identity, waits for CONNECT
  403, recreates the same names with new UIDs, requires fresh-certificate access,
  and verifies the old certificate remains denied for 20 requests.
- `policy`: alternates GlobalSecurityProfile block/bypass four times for
  `/bench-policy`, requiring ten consecutive correct responses at each gateway.
  The selector includes `--revision`, so the preceding label update must reach EPE.
  Pass comma-separated gateway Pod endpoints to check each. Timing includes probe
  confirmation; it is not pure xDS transport latency.
- `traffic-policy`: changes a shared GlobalTrafficPolicy using `--revision` while
  preserving access to the backend. WDS version convergence is measured separately
  from the Kubernetes write acknowledgment.

## Adjust traffic without restarting clients

Server shutdowns, configured gRPC connection expiry, and network failures trigger ADS reconnects; reconnects reuse the Pod and its token until renewal, with exponential backoff and jitter.

For continuous traffic, use `--reuse-connections --traffic-rate-file=/signal/traffic-rate` in the same traffic Pod. Mount the rate file from a ConfigMap and change its value to adjust the offered QPS while preserving the traffic process and its transports.

Positive values set offered QPS, `0` pauses, and `-1` stops. Updates take effect after ConfigMap volume propagation and the current 10-second batch. Batch deadline errors are recorded and traffic continues using the same HTTP/2 transports. Inner CONNECT streams and backend TCP connections are created per operation. Review the measured throughput and errors as well as the offered rate.

## Repeatable scale run

`run.py` runs on the Linux kind host and leaves the scene intact. Its `--root`
contains `sandbox-bench`, `kubeconfig`, and `kubeconfig-internal`. The latter points
to the kind API server's Docker-network IP for clients sharing the node's network
namespace. Keep these kubeconfigs private and exclude them from result archives.

Start the node WDS simulator first (restart it with the new count after growing):

```sh
docker run --name sandbox-scale-wds --user 0 \
  --network container:agentio-sidecar-auto-control-plane \
  -v /absolute/test-root:/work --entrypoint /work/sandbox-bench \
  agentio-sandbox-bench:1018 --action=watch \
  --kubeconfig=/work/kubeconfig-internal --ca=CONTROL_PLANE_SERVICE_IP:15012 \
  --count=10000 --duration=2h --output=/work/10000-watch.json
python3 bench/sandbox/run.py --root /absolute/test-root --count 10000
```

Repeat for 50,000 and 100,000 after population and WDS convergence. A result
directory must not already exist; archive failed attempts explicitly before reruns.
The default per-scale matrix is:

1. 300 seconds at 500 new CONNECT/s: 375/s over 128 hot identities, 125/s over
   up to 20,000 cold identities. Both begin after certificate preparation.
2. While traffic runs, update labels on 10% of inventory, change shared traffic
   policy and confirm every node WDS client has the new version; change EPE policy
   and probe both gateways; recreate 1,000 Sandbox/Pod pairs and validate identity
   retirement. Destructive mutations use a separate range, so expected deletion
   denials cannot hide failures in unaffected traffic.
3. 120 seconds at 250/s while deleting/replacing one control-plane replica.
4. 120 seconds at 250/s while rolling both gateways using normal Pod termination.

The runner saves request results, timestamped actions, kubelet cumulative CPU and
working-set memory samples every five seconds, host memory/load, component
Prometheus metrics, apiserver/etcd metrics, and real Pod identities/restarts.
It also records the actual Deployment configuration and kubelet cAdvisor counters,
including CPU quota throttling. These captures were added for the 100k stage;
earlier retained runs do not retroactively acquire those measurements.
WDS convergence uses one-second snapshots, so subsecond precision is not claimed.
Use cumulative CPU deltas divided by elapsed time, not the last `kubectl top`
sample, for phase averages. A recorded completed suite is not automatically a
passing suite: individual failed results make its exit status nonzero.
An identity-check failure remains a failed result, but the runner continues the
independent replacement scenarios if the full inventory converges again.

No production code is altered by this fixture. No automatic scene deletion is
performed. Archive logs/results before any explicitly scoped cleanup.

Summarize completed evidence with `python3 bench/sandbox/summarize.py RESULT_DIRECTORY`.
The output distinguishes aggregate memory across replicas from individual process memory.
Control-plane counters and histogram buckets are differenced from the snapshot
before certificate preparation to the snapshot after mixed load, then summed
across matched replicas before calculating means and P99 bucket
upper bounds. Those bounds are not exact percentiles. Unmatched Pods or counter
resets are reported instead of producing a misleading aggregate.

The load result also reports `queue_p99_ms` (scheduled arrival to operation start) and `operation_p99_ms` (operation start to response validation, including client and network time). These quantiles do not add up to the end-to-end P99.
