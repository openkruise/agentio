# Sandbox stability fixtures

Use a small real Sandbox population alongside persistent simulated ADS clients. These tools exercise HTTPS through ztunnel, the gateway, MITM, Porter and EPE; simulated ADS connections alone do not exercise this traffic path.

## HTTPS backend

Build the backend from the repository root:

```sh
go build -o stability-upstream ./bench/sandbox/stability/upstream
```

The backend serves TLS on port 8443 and HTTP on port 8080. Mount its certificate and key at `/tls/tls.crt` and `/tls/tls.key`. The certificate must cover the test domains and be trusted by the gateway's upstream TLS configuration. Mount a text file at `/fault/mode`, containing `normal`, `slow`, `reset`, or `tls-ok`; the selected fault applies only to `/fault` requests. The backend echoes the HTTP Host, TLS SNI and request headers so clients can detect incorrect routing or identity handling. `/stream` sends 20 SSE chunks over about 10 seconds; `/download` returns 1 MiB and `/upload` verifies the received byte count.

Size the backend independently from the components being measured. Many distinct upstream TLS names can retain many connections; a backend OOM invalidates gateway capacity conclusions. Check backend restarts and memory alongside the gateway.

## Real Sandbox client

Build the Go probe for the Sandbox image architecture and run it inside each real Sandbox, with its ztunnel and claimed identity. Mount the MITM CA at `/trust/mitm.crt`, or pass `--ca`. The client validates both the issuing CA and the requested hostname. Its management HTTP port is unauthenticated and must stay inside the isolated benchmark network.

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o stability-client ./bench/sandbox/stability/client
# Inside the Sandbox:
./stability-client --ca=/trust/mitm.crt --port=8088
curl -fsS http://CLIENT:8088/health
curl -fsS -X POST http://CLIENT:8088/start -d \
  '{"duration":21600,"rate":2,"domain_count":20000,"client_index":0,"clients":100,"cold_fraction":0.2,"mixed":true,"group":"a","deny":true}'
curl -fsS http://CLIENT:8088/status
curl -fsS -X POST http://CLIENT:8088/config -d '{"rate":10,"cold_fraction":0.5}'
curl -fsS -X POST http://CLIENT:8088/probe -d '{"host":"hot-00.load.test","path":"/deny"}'
curl -fsS -X POST http://CLIENT:8088/stop -d '{}'
```

Give each client a distinct `client_index` in `[0, clients)`. Configure test DNS for `hot-00.load.test` through `hot-07.load.test` and `host-000000.load.test` through the requested domain count. Map them to a small HTTP/HTTPS backend pool, with CONNECT authority, inner TLS SNI and HTTP Host preserved by the real data path. The number of names does not establish the number of DFP cache entries: verify the actual gateway routing and DNS-cache configuration separately.

The client reuses hot connections for up to 60 seconds and creates fresh connections for long-tail requests. Rate updates through `/config` keep the same workers and connections. Set `rate` to zero to pause arrivals. `/stop` stops new arrivals and drains accepted work. Eight workers share a queue bounded at 32; queue overflow is reported under `generator`, separately from executed network requests. `rate` is per client, not aggregate QPS. Requests are not automatically retried. `mixed` adds streaming responses and 1 MiB uploads/downloads. `fault` enables requests to `/fault` for backend fault injection.

Every tenth request checks `/deny`. `deny=true` expects HTTP 451; other paths expect 200. With `group` set, allowed responses must contain the matching `X-Policy-Group` header. An unexpected allow or changed identity/group header increments `PolicyViolation`. Other statuses, TLS failures, truncation and timeouts are reported separately. `/probe` returns the observed result for the caller to validate; HTTP 200 from the management API does not mean the target request succeeded.

`/status` includes request and queue latency histograms, status/error counts, bounded recent samples and observed certificate information. The request histogram measures execution after the request leaves the queue, including DNS, TCP and TLS when opening a connection. Queue delay has its own histogram. Quantiles are bucket upper bounds. Certificate serial changes can also reflect different gateway replicas; check expiration progression before claiming certificate renewal. The client uses inner HTTP/1.1 and does not establish downstream HTTP/2 coverage.

## Scenario and result collection

Keep hot background traffic running while increasing new-domain traffic, changing scoped policies, cycling Sandbox identities, injecting DNS/upstream faults, and rolling components. Change one variable at a time when diagnosing a failure. Preserve the before/after status of identities being replaced; counters otherwise disappear with their Pods. Record component resources and restart reasons during the same windows. The tools do not create or delete cloud resources.

The summary command reads the snapshot format produced by the stability run: `probes-TIMESTAMP.json.gz` contains `time`, `phase`, and `items` with `name`, `uid` and client `data`; `retired-*.json.gz` contains `pod` identity metadata and its `final` client status. Optional `nodes-*.json.gz` snapshots contain kubelet summary `items`; `workload-certificates-*.json.gz` contains certificate samples. Resource attribution uses the benchmark deployment names `agentiod`, `agentiod-policy`, `agentio-epe` and `egress-gateway`.

```sh
python3 bench/sandbox/stability/summarize.py \
  --evidence=/results/evidence --output=/results/analysis
python3 -m unittest discover -s bench/sandbox/stability -p '*_test.py'
go test -race ./bench/load ./bench/sandbox/... ./bench/xds/...
```

The summary keeps generator drops separate, records policy violations, deduplicates cumulative counters by Pod UID and reports phase deltas. A corrupt optional resource sample is reported on stderr and excluded; corrupt request evidence fails the command. Preserve stderr with the report. Test reports, traces, certificates, tokens, kubeconfigs and cloud identifiers belong in the external result directory, outside Git.
