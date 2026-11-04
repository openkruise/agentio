# EPE audit delivery and evaluation details

> Design note. This page records the evaluation and delivery internals behind [Configure EPE audit events](../tasks/configure-epe-audit.md).

## CEL variables and result precedence

`when` must compile to a boolean. A compile error prevents that profile version from loading. A runtime evaluation error drops only that audit event and increments `epe_audit_eval_dropped_total{reason="when_eval"}`.

CEL exposes these variables:

| Variable | Fields |
| --- | --- |
| `result` | `passthrough`, `mutated`, `blocked`, `bypassed`, or `error` |
| `request` | `host`, `port`, `path`, `method`, `scheme`, lowercase `headers`, and first-value `queryParams` |
| `pod` | `name`, `namespace`, `ip`, and `labels` |
| `profile` | `name` and `namespace` |
| `rule` | Matched rule `name` |
| `inputs` | Profile-scoped inputs |
| `response` | `status`; zero when EPE did not observe a response |

`result` summarizes the final stream outcome, with precedence `error > blocked > mutated > bypassed > passthrough`. `bypassed` means a policy unit has a recorded action but the message was not modified; it does not necessarily mean a bypass action ran. A no-op filter that only continues does not add a matched-unit record. Successful destination authorization and upstream address pinning alone do not count as a mutation; explicit policy rewrites of headers, bodies, status, or upstream targets do. Authorization denials still produce `blocked` when the local reply is sent successfully.

Go templates use the same data via accessors such as `{{ .Request.Host }}`, `{{ .Request.Header "X-Request-Id" }}`, `{{ .Request.QueryParam "page" }}`, `{{ .Pod.Label "app" }}`, and `{{ .MatchedCriteria.Host }}`. `MatchedCriteria` contains the dimensions of the rule match that fired: host, method, path, port, matched headers, and matched query parameters.

## Data exposure boundaries

EPE deliberately does not expose the sandbox token, request body, credentials, or secrets in this context. Request headers, query values, Pod labels, and profile inputs can still be sensitive. Do not render them into a URL, header, or webhook body unless the receiver is authorized to retain them. Prefer a dedicated HTTPS receiver, minimal fields, and receiver-side access controls.

## Response status observation

The response status is normally zero because the chart wires response headers as `SKIP`. There are two ways to deliver response headers to EPE:

- Set the binary-only `--observe-responses=true`, which emits a per-request mode override to `SEND` even over the static chart setting.
- Configure `sandboxExtProc.response.headerMode: SEND` statically.

Either choice adds one external-processing message for every forwarded request and can add latency; neither makes the response body available to audit templates.

## Delivery and backpressure

EPE writes a separate structured access log for every successfully handled request-header stream. The log includes `requestID`, `pod`, HTTP method, host, path, matched unit count, final outcome, actions, skipped filters, and an error when present. It uses one worker and a non-blocking queue of 4,096 entries by default; a full queue drops the log entry and increments `epe_audit_log_dropped_total`.

Webhook events are rendered after the final rule outcome, then placed on a non-blocking bounded queue. The defaults are 8,192 entries and 96 workers; the `--audit-webhook-buffer-size` and `--audit-webhook-workers` flags change them. A full queue drops the event rather than delaying the request. On EPE shutdown, accepted work gets up to five seconds to drain; remaining work and late events are dropped. Track `epe_audit_webhook_dropped_total` for `buffer_full`, `draining`, `stopped`, or `shutdown_timeout`.

EPE does not retry audit webhooks. It records a `success`, `http_error`, `transport_error`, or `timeout` in `epe_audit_webhook_dispatched_total`; HTTP responses with status 400 or higher are `http_error`. Rendering failures, non-HTTP(S) URLs, and bodies larger than 64 KiB are dropped before dispatch and reported through `epe_audit_webhook_dropped_total`. EPE verifies HTTPS audit webhook certificates by default; keep `epe.auditWebhook.insecureSkipVerify=false`.

The Helm chart exposes audit-webhook TLS verification as `epe.auditWebhook.insecureSkipVerify`. Audit queue, worker, and response-observation flags still require an explicit container argument override; `epe.env` cannot set command-line flags.
