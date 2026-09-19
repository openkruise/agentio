# EPE observability

The Egress Policy Enforcer (EPE) has separate gRPC health, Prometheus, structured-log, audit-webhook, and local admin surfaces. The chart publishes health and metrics through the headless `agentio-epe` Service; it leaves the admin listener loopback-only.

## Health

EPE serves the standard gRPC health service on port 9003. `Check` reports `SERVING` for every requested service name, and `List` includes `envoy.service.ext_proc.v3.ExternalProcessor` as `SERVING`. `Watch` returns gRPC `Unimplemented`. The chart's liveness and readiness probes use this port, so Pod readiness and restart events are the normal first health signal:

```console
$ kubectl get pods --namespace agentio-system \
    --selector app.kubernetes.io/name=agentio-epe
$ kubectl describe pod --namespace agentio-system <epe-pod>
```

For an on-demand protocol check, port-forward a Pod in one terminal:

```console
$ kubectl port-forward --namespace agentio-system <epe-pod> 9003:9003
```

While the port-forward is running, use `grpc-health-probe` from another terminal:

```console
$ grpc-health-probe -addr 127.0.0.1:9003
status: SERVING
```

EPE does not enable the gRPC reflection API. A bare `grpcurl` invocation without a health-service proto or protoset therefore cannot resolve `grpc.health.v1.Health`, even when the health listener is serving normally.

This verifies the health listener only. EPE starts the request server after its Kubernetes client cache and initial profile collection have synchronized, so a ready Pod also indicates that this initial synchronization completed.

## Prometheus endpoint

EPE serves `/metrics` on port 9090 from its own Prometheus registry. The chart adds `prometheus.io/scrape: "true"` and `prometheus.io/port: "9090"` Pod annotations. It includes standard Go and process collectors in addition to the metrics below.

```console
$ kubectl port-forward --namespace agentio-system <epe-pod> 9090:9090
$ curl --fail --silent http://127.0.0.1:9090/metrics | grep '^epe_'
```

## Implemented EPE metrics

| Metric | Type and labels | Meaning |
| --- | --- | --- |
| `epe_plugin_calls_total` | Counter; `plugin`, `phase`, `outcome` | Filter invocations. `phase` is `request_headers`, `body_finalize`, or `response_headers`; `outcome` is `continue`, `immediate`, `mutate`, `record`, or `error`. |
| `epe_plugin_duration_seconds` | Histogram; `plugin`, `phase` | Filter invocation latency. Bucket boundaries are `.01`, `.1`, `.5`, `2`, `4.5`, `5` seconds: `4.5` is the default per-phase plugin budget and `5` the chart's ext_proc message timeout, so a filter at its limit stays distinguishable from one the gateway gave up on. |
| `epe_profile_compile_failures_total` | Counter; `scope` (`namespaced`, `global`, or `pod`) | Published policy versions that EPE rejected during compilation. `pod` counts per-Sandbox annotation rule chains. |
| `epe_profile_stale` | Gauge; `scope` | How many policy sources in that scope had their newest version rejected while an earlier version remains active. |
| `epe_profile_unenforced` | Gauge; `scope` | How many policy sources in that scope have no installed version at all, so none of their rules are enforced. For `pod`, that Sandbox's own rules are absent while administrator profiles still apply. |
| `epe_profile_inputs_unavailable` | Gauge; `scope` | How many installed profiles in that scope have unresolved declared inputs (for example a missing ConfigMap). Their rules stay enforced; inputs-dependent evaluations fail per the consuming action's failure policy. |
| `epe_sandbox_policy_wait_total` | Counter; `outcome` (`ready`, `timeout`, `overloaded`) | Bounded policy-readiness waits on the request path. `ready` means the policy became observable inside the configured `--sandbox-policy-wait` window; `timeout` means the request was refused with `503 epe_policy_not_ready`; `overloaded` means the waiter limits were full and the request was refused without waiting. |
| `epe_audit_eval_dropped_total` | Counter; `reason` (`when_eval`, `no_sink`) | Audit events dropped before a sink. |
| `epe_audit_log_dropped_total` | Counter | Access-log entries dropped because their in-memory queue was full. |
| `epe_audit_webhook_dispatched_total` | Counter; `result` (`success`, `http_error`, `transport_error`, `timeout`) | Post-render audit webhook delivery outcomes. |
| `epe_audit_webhook_dropped_total` | Counter; `reason` | Audit webhooks dropped before dispatch. Reasons include `buffer_full`, `draining`, `stopped`, `shutdown_timeout`, `render_url`, `render_body`, `render_header`, `invalid_scheme`, and `body_too_large`. |
| `epe_audit_webhook_duration_seconds` | Histogram | Duration of each audit webhook HTTP call. |

Metric names and labels describe the current implementation; this page does not make a stability guarantee for dashboards or alerts.

Every label above is a fixed enum resolved at startup, so the series count does not grow with the number of profiles, Sandboxes, requests, or destinations. A full scrape is roughly 180 `epe_` series, two thirds of it the two plugin metrics. EPE runs on the data path, so a metric earns its place by answering a question someone acts on: request-path outcome and latency per filter, whether published policy is actually enforced, and whether audit records are being lost.

## Dashboard

[`manifests/charts/agentio/addons/dashboards/agentio.json`](../../manifests/charts/agentio/addons/dashboards/agentio.json) is a Grafana dashboard covering the egress gateway, EPE, and Agentiod. Import it directly; the chart does not install it. Its EPE section leads with **Policy Enforcement** and **Rejected Policy Versions**, then covers audit delivery, plugin errors, and resource use.

The enforcement panels aggregate with `max by (scope)` rather than `sum`: every EPE replica watches the same policy and publishes the same counts, so summing would multiply them by the replica count. The request-path panels sum because requests are split across replicas.

## Useful operational signals

An increase in `epe_profile_compile_failures_total` means a new policy version did not take effect. `epe_profile_stale > 0` means an older version is still enforced; `epe_profile_unenforced > 0` means that many sources have no installed policy at all. `epe_profile_inputs_unavailable > 0` means a profile is enforcing but a referenced ConfigMap input is missing, so inputs-dependent actions fail per their failure strategy.

The `scope` label separates who has to act: `namespaced` and `global` are operator-authored profiles matched by label selector, while `pod` is one tenant's own Sandbox annotation matched by verified Pod identity, so alerts on the two usually route differently. These gauges are counts on purpose — a cluster can hold tens of thousands of profiles and Sandboxes, and labelling by object identity would create a time series for each one exactly when a systematic authoring failure hits. Every transition is also logged with the object and the error, so the logs answer _which_; use `/debug/profiles` on the admin port to see what is currently installed.

High or growing `epe_audit_log_dropped_total` indicates saturation of the single-worker access log queue. `epe_audit_webhook_dropped_total` with `buffer_full` indicates webhook admission saturation; `draining`, `stopped`, and `shutdown_timeout` identify shutdown loss. `http_error`, `transport_error`, and `timeout` in dispatched webhooks distinguish receiver responses from network/TLS/request construction failures and deadline expiry. EPE does not retry webhooks, so these counters represent lost audit records rather than delayed retries.

Use plugin duration and outcome series together. A growing `error` outcome or durations approaching the configured per-phase plugin budget can explain request blocks or failures. The default EPE plugin budget is 4.5 seconds while the chart's ext_proc message timeout is 5 seconds; changes to either setting can shift the failure boundary. Metrics do not expose queue depth, individual profile compile errors, or audit webhook response bodies.

`epe_sandbox_policy_wait_total` shows whether `--sandbox-policy-wait` is sized right for the cluster. A rising `timeout` share means requests are routinely arriving before the policy has converged and are being refused; a non-zero `overloaded` means the waiter limits (1024 in flight, 64 per Sandbox) are saturated and callers are refused without waiting. Both are tuning signals, not policy verdicts — the verdicts live in the audit stream.

## Logs and audit output

EPE uses controller-runtime Zap logging in JSON production mode. By default `-v=2` controls verbosity; `--zap-log-level` takes precedence over `-v` when provided. The code uses verbosity levels 2 (default), 3 (verbose), 4 (debug), and 5 (trace). `--zap-stacktrace-level` can override the production default, which emits stack traces only at `DPanic` and above.

Every successfully handled request-header stream submits an INFO access-log record with message `egress request handled`. Its fields are `requestID`, `pod`, `method`, `host`, `path`, `units`, `outcome`, `actions`, `skipped`, and an optional `error`. This is an output surface, not a durable audit store: its bounded in-memory queue may drop entries under load.

Webhook rendering or transport failures produce audit-webhook log records at verbosity 1 where applicable. An HTTP response of 400 or higher increments the `http_error` metric but does not by itself create a delivery retry. Do not log or export raw bearer tokens, credentials, or request bodies. Audit templates can expose request headers, query parameters, labels, and profile inputs, so treat webhook payloads and debug output as potentially sensitive.

## Profiling

`--enable-pprof=false` by default. Enabling it starts Go pprof on `--pprof-addr=:6060` by default. This listener is not chart-exposed and binds all interfaces with the default address, so restrict its bind address and network access before enabling it in production.

## See also

- [EPE configuration](epe-configuration.md)
- [EPE admin API](epe-admin-api.md)
- [Configure EPE audit events](../tasks/configure-epe-audit.md)
