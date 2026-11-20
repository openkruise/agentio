# ContentGuard

ContentGuard is an Envoy HTTP dynamic module for auditing request and response bodies. Install the filter before the router. Configure either direction independently. At the end of each enabled direction, the module publishes a bounded JSON record to Envoy Filter State. Envoy access logging writes the record when the HTTP stream completes. A stream that terminates early publishes an `incomplete` record for the direction in progress. The filter observes Envoy's received slices and returns `Continue` without replacing them.

## Configuration

Set `contentGuard` in the global AgentioConfig to install the module and its stdout access loggers on native gateways, for forwarded cleartext HTTP and HTTP after TLS termination. With Helm, set `agentiod.config.values.contentGuard`. The gateway image must contain the module. CONNECT setup, TLS passthrough and legacy proxyv2 gateways do not run this HTTP filter. A local denial from an earlier filter ends the stream before ContentGuard sees its request headers.

```yaml
contentGuard:
  defaults: {schema: genai, maxLogBytes: 8192}
  attributes:
    agentio.sandbox.id: {filterState: agentio.sandbox.id}
    app.tenant.id: {requestHeader: x-tenant-id}
    gen_ai.conversation.id: {requestHeader: x-session-id}
    agentio.workload.namespace:
      dynamicMetadata: {namespace: agentio, path: [workload, namespace]}
  rules:
    - match: {hosts: [health.llm.example.com]}
      skip: true
    - match:
        hosts: ["*.llm.example.com"]
        filterState:
          - {key: agentio.sandbox.id, present: true}
      audit:
        schema: agentio
        parsers:
          llm:
            protocol: auto
            request: {include: [messages, toolDefinitions], maxLogBytes: 16384}
            response: {include: [toolCalls]}
          generic:
            request: {include: [body]}
    - match: {}
      audit:
        parsers:
          llm: {request: {}, response: {include: [toolCalls]}}
```

Rules run in order at request headers. The first match controls the entire stream. Within a rule any listed host may match and every Filter State condition must match. Hosts ignore ASCII case and the authority port. A leading `*.` matches one or more complete labels. Use `present: true` for existence or `values: [box-a, box-b]` for an exact serialized string match. Each rule requires either `skip: true` or `audit`. Skipped and unmatched streams emit zero records. Supply at least one rule. A catch-all `match: {}` goes last. Remove `contentGuard` to disable the module.

Each audit rule enables at least one parser. A parser needs at least one direction. Omitting a direction suppresses its record. An enabled direction with `{}` or `include: []` emits metadata only. The LLM parser still reads the document or SSE events to extract protocol metadata. The generic parser counts bytes without fetching the body slices in this mode.

| Parser direction | Allowed `include` values |
| --- | --- |
| `llm.request` | `messages`, `toolDefinitions`, `toolCalls` |
| `llm.response` | `messages`, `toolCalls` |
| `generic.request`, `generic.response` | `body` |

`llm.protocol` defaults to `auto`. It recognizes final path segments `completions`, `responses` and `messages`, ignoring query parameters and trailing slashes. Other paths use the generic parser when configured. For a custom URL, set `openai-chat-completions`, `openai-responses` or `anthropic-messages`. With both parsers configured, an explicit LLM protocol takes recognized paths and JSON requests (including `application/*+json`), leaving other custom-path media such as multipart to the generic parser. With only an explicit LLM parser it takes all paths. The selected parser owns both directions. Unsupported media or malformed LLM payloads produce a capture status. A disabled direction emits no record.

Every record identifies its `schema`. The default is `agentio`; `defaults.schema` sets the global format and `rules[].audit.schema` overrides it. The same selections feed both schemas. The Agentio schema retains normalized LLM messages, model and usage in `content`. The GenAI schema moves these to OpenTelemetry GenAI attribute names. Generic bodies retain their JSON, text or multipart representation in both schemas. A provider name is not inferred from the wire protocol.

Configured attributes appear under `attributes` in either schema. Request headers use lowercase names. Header and serialized Filter State values are sampled at request headers and carried into each enabled direction. A metadata path reads the named namespace on that HTTP stream. The controller renders an Envoy formatter and a stream-local string Filter State entry for each configured path before the module runs. Metadata values are logged as strings. Missing values are omitted. Extracted protocol values take precedence over configured attributes with the same names, including a Responses request's native conversation ID. Attribute values share the direction's final line budget with content. Oversized context entries are omitted and set `attributesTruncated: true`.

For example, a request to a custom Responses-compatible endpoint can produce the following JSON line.

```json
{"type":"content","schema":"genai","requestID":"req-7","direction":"request","path":"/invoke","status":"complete","bytesSeen":29,"attributes":{"app.tenant.id":"team-a","gen_ai.input.messages":[{"parts":[{"content":"hello","type":"text"}],"role":"user"}],"gen_ai.operation.name":"chat","gen_ai.request.model":"m"},"content":{"format":"openai-responses"}}
```

### GenAI metadata with tool references

To correlate calls without retaining message text, tool arguments or result bodies, enable the summary on each desired direction.

```yaml
contentGuard:
  defaults: {schema: genai, maxLogBytes: 4096}
  rules:
    - match: {}
      audit:
        parsers:
          llm:
            request: {include: [toolCalls]}
            response: {include: [toolCalls]}
```

| Field | Wire source |
| --- | --- |
| `gen_ai.request.stream` | Explicit boolean `stream` in any of the three protocols. |
| `gen_ai.request.max_tokens` | Chat `max_completion_tokens` (or legacy `max_tokens`), Responses `max_output_tokens`, Anthropic `max_tokens`. |
| `gen_ai.request.previous_response.id` | Responses `previous_response_id` identifies the preceding generation. `gen_ai.conversation.id` separately identifies the conversation. |
| `gen_ai.response.id` | Top-level JSON response ID, Chat chunk ID, Responses lifecycle event's response ID or Anthropic `message_start.message.id`. |
| `gen_ai.response.finish_reasons` | Reported Chat finish reasons in choice-index order or Anthropic stop reason. Available with an empty `include`. Responses reports its native `content.status` and `content.incompleteReason`. |
| `error.type`, `agentio.response.error_code` | Upstream structured error type and string code. If only a code is available, it also supplies `error.type`. The envelope's `status` describes audit capture. |
| `agentio.tool.calls` | With `toolCalls` in `include`, each entry contains `kind` (`call` or `result`), plus the ID and name when supplied. Available in both schemas. |

The summary covers Chat function calls and tool messages, Responses function calls and outputs, and Anthropic tool use, server tool use and tool results. JSON and SSE use the same representation. A result can be joined to its call by ID. Summary capture tracks up to 1,024 references and at most `maxLogBytes` bytes of names and IDs per direction. Overflow omits the summary and marks the record truncated. The serialized line budget also applies. Including response `messages` also retains provider error details in `content.error`. Other selections retain the structured error type and code.

### Standalone Envoy configuration

The following filter enables both directions. Omit the `response` member for request-only auditing. `maxLogBytes` is a per-direction limit on the serialized JSON line, including its envelope and newline, in the range 1,024 to 1,048,576 bytes.

```yaml
name: envoy.filters.http.dynamic_modules
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter
  dynamic_module_config:
    name: envoy_agentio_contentguard
    do_not_close: true
  filter_name: contentguard
  filter_config:
    "@type": type.googleapis.com/google.protobuf.StringValue
    value: '{"rules":[{"match":{},"audit":{"parsers":{"llm":{"request":{"include":["messages"],"maxLogBytes":16384},"response":{}}}}}]}'
```

Each direction accepts the following settings.

| Setting | Behavior |
| --- | --- |
| `include` | Selects content groups for the parser and direction as listed above. Defaults to an empty list. |
| `maxCaptureBytes` | When set, bounds a complete JSON/text document or a single SSE event including its framing. Exceeding it produces `too_large` and forwarding continues. When omitted, documents use streaming clipping and SSE events have a 64 KiB limit. Multipart uses the log budget. |
| `maxContentBytes` | LLM only. Bounds retained LLM messages and tool definitions. With an explicit capture limit it defaults to that limit. Otherwise SSE retains up to the available log budget and documents use the clipping behavior below. On content-budget overflow the parser drops those fields and continues collecting metadata and usage. |
| `maxLogBytes` | Bounds the serialized line including its newline. Inherits `defaults.maxLogBytes`, which defaults to 8,192 bytes. |

Both optional byte limits accept 1 through 67,108,864 bytes.

Add the corresponding entries to the HTTP connection manager's `access_log` list. This example uses Envoy's stdout logger. For request-only auditing, configure just the first entry. A file logger can use the same text format. The formatter writes the serialized record directly; the newline is included in the direction's budget.

```yaml
access_log:
  - name: envoy.access_loggers.stdout
    filter:
      extension_filter:
        name: envoy.access_loggers.extension_filters.cel
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.access_loggers.filters.cel.v3.ExpressionFilter
          expression: "'agentio.contentguard.request' in filter_state"
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
      log_format:
        text_format_source:
          inline_string: "%FILTER_STATE(agentio.contentguard.request:PLAIN)%\n"
  - name: envoy.access_loggers.stdout
    filter:
      extension_filter:
        name: envoy.access_loggers.extension_filters.cel
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.access_loggers.filters.cel.v3.ExpressionFilter
          expression: "'agentio.contentguard.response' in filter_state"
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
      log_format:
        text_format_source:
          inline_string: "%FILTER_STATE(agentio.contentguard.response:PLAIN)%\n"
```

Set `ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/usr/local/lib` and install the shared library there. The filter applies to traffic on its configured chain. It reads `x-request-id` for correlation. The log contains the direction, path without the query string, body bytes seen, capture status and retained content.

## Capture behavior

| Input | Logged content |
| --- | --- |
| LLM JSON requests | In auto mode, paths ending in `/completions`, `/responses` and `/messages` select Chat Completions, Responses and Anthropic Messages. Captures normalized messages, tool definitions, calls and results. Provider-specific blocks remain structured. |
| LLM JSON and SSE responses | Uses the same protocol selected at request headers. Reconstructs output messages, calls, arguments, finish reasons and reported usage. Responses also carries provider status, error and incomplete reason when available. |
| Generic JSON | Provider JSON, including arrays and objects. |
| UTF-8 text | The generic parser keeps a bounded prefix for text media, including SSE on generic streams. |
| Multipart form data | Ordered form fields with names and byte counts. File entries include the filename, optional content type and base64 if it fits. Oversized files carry `omitted: true`. |

When no hard document limit is set and a JSON document exceeds the available log space, the scanner bounds each string across body slices. It replaces oversized inline media with `[omitted]` and continues scanning for later text. If the JSON structure itself fills the budget, the record switches to a bounded `retainedText` projection. Long text may be shortened. The final encoder checks the serialized size after normalization and escaping. If the projected structure still cannot fit, it emits a `truncated` record with null content. A truncated record describes the retained projection and cannot establish validity or reproduce discarded bytes.

SSE framing accepts multiline data, comments, a leading UTF-8 BOM, and LF, CRLF or CR separators across body callbacks. HTTP EOF ends observation. A missing protocol terminator produces `incomplete_stream`. An unsupported delta produces a `partial` record with available metadata. Exceeding the retention budget produces `truncated`. Both cases continue parsing subsequent events for usage and errors. Invalid JSON, invalid UTF-8 framing and invalid protocol transitions have distinct error statuses. Each direction processes up to 64 MiB of SSE input and tracks up to 1,024 choices, blocks or items.

Multipart capture scans delimiters across slice boundaries. It limits part headers to 8 KiB, skips the bytes of an oversized file, then resumes capture at the next field. Unsupported encodings, unsupported media types and parse failures have distinct statuses. These statuses apply to audit output only.

The filter publishes each direction once. The native access logger owns buffering, output and file reopening. Access logging retains the bounded request record for the lifetime of a long-running response. The `contentguard_publish_errors` counter reports a Filter State publication failure. Delivery and retention after the access logger writes depend on the configured sink.

## Build

Build on Linux with Rust 1.93 or newer and libclang. The build fetches the Envoy 1.40.2 SDK to match the runtime image.

```sh
cd extensions/envoy/contentguard
./build.sh
docker build -t envoy-contentguard .
```
