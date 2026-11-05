# xDS connection limits

> Design note. How `agentiod` bounds Kubernetes API and xDS stream concurrency, including recovery semantics. The user-facing defaults and a short summary live in [Agentiod environment variables](../reference/agentiod-environment-variables.md).

## Kubernetes API throttling

`agentiod` configures its Kubernetes clients with 80 QPS and a burst of 160, to avoid falling back to client-go's lower defaults during informer startup, relists, and TokenReview calls. These settings configure client-side throttling, not the API server's limits or a single aggregate budget shared by all clientsets and replicas.

## New-stream admission

`AGENTIO_MAX_REQUESTS_PER_SECOND` limits new xDS streams before authentication. Its default is `min(250 * C, 1000)`, with a burst of 1 and up to `AGENTIO_XDS_RATE_LIMIT_TIMEOUT` (default `1s`) of waiting before rejection. An explicit positive value overrides that default, including the automatic cap; zero selects the automatic default. This limit does not throttle ACKs on established streams or server-initiated pushes.

`C` is the CPU budget supplied through `AGENTIO_XDS_CPU_BUDGET`, bounded by `min(NumCPU, GOMAXPROCS)`. The budget accepts Kubernetes CPU quantities such as `500m` or `2`; the chart supplies the `agentiod` CPU limit when present, otherwise its CPU request. The default chart request of `500m` therefore selects 125 new streams/s; budgets of 1, 2, and 4 CPUs select 250, 500, and 1,000/s when the runtime allows those CPU counts. A CPU request is a planning budget, not a hard CPU limit; a CPU limit likewise does not guarantee that much CPU under host contention.

With an empty budget, including a binary run outside the chart, `C` falls back to `min(NumCPU, GOMAXPROCS)`. This fallback cannot distinguish fractional CPU quotas rounded by the Go runtime; set an explicit budget for such deployments. Startup logs record the supplied budget, effective CPU count, fallback use, and final admission rate.

New streams also acquire an initialization slot before authentication and before creating their receive queue. There are `AGENTIO_PUSH_CONCURRENCY` initialization slots, separate from response slots. The slot is released after the first request is handled, or on failure or cancellation. Admission waits at most `AGENTIO_XDS_INITIAL_ADMISSION_TIMEOUT` (default `1s`) before returning `ResourceExhausted`, bounding concurrent TokenReviews and initializers even when initial responses are backlogged. Clients should use exponential backoff with jitter for admission rejections; established streams do not pass through this gate again.

## Push concurrency pools

Initial responses, requests on established streams, and background responses use three independent pools, each sized by `AGENTIO_PUSH_CONCURRENCY` (default `min(15 + 5 * GOMAXPROCS, 100)`).

A stream becomes established after a valid ACK or NACK for a response actually sent on that stream; old valid nonces count, unknown nonces do not. Asynchronous SDS responses use the same distinction, so slow initial clients cannot exhaust capacity reserved for established demand queries.

A stream holds one slot until its outstanding responses are acknowledged or the stream closes; all response types on that stream share the slot. Pure ACK/NACK processing needs no additional slot. Client-requested responses wait for capacity without a congestion timeout that disconnects the stream. A stream waits only when it holds no response slot; its bounded receive queue applies backpressure, and pending configuration updates remain coalesced. Stream cancellation or a caller deadline cancels the wait. Background pushes retain the existing bounded scheduler queue and wait for response capacity until the stream is canceled.

A blocked send lasting `AGENTIO_XDS_SEND_TIMEOUT` or a response left unacknowledged for `AGENTIO_XDS_ACK_TIMEOUT` ends the stream with `DeadlineExceeded` and releases capacity. Both default to `5s`. Acknowledging a previously sent nonce advances that type's progress, while unknown nonces and progress on another type cannot hide a stalled response. This also bounds slow receivers when gRPC accepts a send into its internal queue before the peer reads it. Rejected streams must reconnect.

The separation protects established demand queries from slow initial clients; established clients that later become slow still share their request pool. For example, an Envoy that ACKs a small CDS response before subscribing to a large RDS response already uses the established pool for subsequent leases. These bounds do not guarantee uninterrupted queries during every overload.

## Optional Pod stream cap

`AGENTIO_XDS_MAX_POD_STREAMS` optionally caps live dedicated Pod ADS streams in each process. The default `0` disables this cap. It is checked after authentication and scope validation; a full replica rejects a new Pod stream with `ResourceExhausted` and releases capacity when an admitted stream ends. Existing Pod streams remain connected, and gateway/EPE streams do not consume the Pod quota. The value must be a non-negative integer; malformed values fail startup.

Long-lived TCP connections do not move to new replicas when the Deployment scales out. Choose any configured cap from measured resource usage, and retain spare capacity for reconnection. The cap does not guarantee recovery speed: new-stream rate limits and cold authentication still apply. Pod clients must back off and reconnect through service discovery after admission rejections.

## Cold TokenReview budget

A cold TokenReview has a 5-second budget covering both client-side API throttling and the API call. A shorter caller deadline wins; a successful cached identity returns without that wait. API failures return `Unavailable`, while rejected credentials still return `Unauthenticated`. The cache lifetime and capacity are unchanged.

After authentication, a stream can wait up to 5 seconds for its bound Pod and derived Workload to appear in local caches. This performs local key lookups, not additional API requests. A timeout returns `DeadlineExceeded`; identity mismatches still return `PermissionDenied` immediately. No configuration is sent before scope resolution completes.

The authentication, scope-readiness, capacity-wait, send, and acknowledgement budgets are separate stages, not a single end-to-end recovery deadline.

For large clusters, provision control-plane CPU, memory, and replicas, and configure the existing stream-admission and Kubernetes API limits to match the measured capacity of the deployment.
