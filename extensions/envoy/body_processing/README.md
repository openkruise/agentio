# ContentGuard

ContentGuard is an Envoy HTTP dynamic module for auditing request and response bodies. Install the filter before the router. Configure either direction independently. At the end of each enabled direction, the module retains a bounded JSON record. At HTTP stream completion, it publishes the records to Filter State for the Envoy access logger. A stream that terminates early publishes an `incomplete` record for the direction in progress. The filter observes Envoy's received slices and returns `Continue` without replacing them.

The Rust crate lives in `extensions/envoy/body_processing`. The Envoy filter name is `contentguard`. Each matched chain starts its configured audits directly. Audits share request decompression, small JSON document decoding and compatible SSE framing. Each audit selects its own fields and limits the size of its own records.

## Configuration

Set `bodyProcessing` in AgentioConfig (Helm: `agentiod.config.values.bodyProcessing`) to configure the audit rules on native gateways. The gateway image must contain the module. It observes forwarded cleartext HTTP and HTTP after TLS termination. CONNECT setup, TLS passthrough, legacy gateways and streams terminated by an earlier filter bypass it.

```yaml
bodyProcessing:
  filterChains:
    - name: sandbox-model-calls
      matcher:
        hosts: [api.example.com]
        paths: [/v1/chat/completions, /v1/responses, /v1/messages]
        filterState: [{key: agentio.sandbox.id}]
      parser: {llm: {}}
      filters:
        - audit:
            maxSize: 8KiB
            format:
              attributes:
                agentio.sandbox.id: "%FILTER_STATE(agentio.sandbox.id:PLAIN)%"
                app.tenant.id: "%REQ(X-TENANT-ID)%"
                agentio.workload.namespace: "%DYNAMIC_METADATA(workload:namespace)%"
            request: {include: [llm.messages, llm.toolDefinitions], maxSize: 16KiB}
            response: {include: [llm.answer]}
    - name: custom-responses
      matcher: {hosts: [api.example.com], paths: [/internal/invoke]}
      parser: {llm: {protocol: openai-responses, request: {maxItemSize: 2MiB}}}
      filters:
        - audit: {request: {include: [llm.question]}}
```

At request headers the module selects the first matching chain and fixes the protocol for both directions. All configured conditions must hold. Unmatched streams are forwarded without audit records. An omitted or empty matcher matches everything and belongs last. Each chain requires a unique, nonempty name (at most 256 bytes as a serialized JSON string, including quotes) and a nonempty list of filters. This release supports the `llm` parser and the `audit` filter.

| Match field | Semantics |
| --- | --- |
| `hosts` | Any listed host may match. Matching ignores ASCII case and the authority port. A leading `*.` matches one or more complete labels. |
| `paths` | Any listed path may match. Paths are absolute and case-sensitive. Both the matcher and LLM auto-detection ignore the request query and one trailing slash. For example, `/upload/?part=1` matches `/upload`. Configured paths must be exact, without a wildcard, query or fragment. |
| `filterState` | Every entry must match. `{key: agentio.sandbox.id}` checks for the key's existence, including an empty value. `{key: agentio.sandbox.id, values: [box-a, box-b]}` matches either serialized string exactly. An explicit `values` requires a nonempty list. |

When migrating a configuration with a top-level `defaults` block, move its size setting to the audit filters that need it, then remove the block. Remove any explicit `audit.schema` setting.

Prefix LLM content selections in `include` with `llm.`, for example `llm.messages`. Existing configurations using bare field names must add this prefix.

Each audit enables at least one direction. Omit a direction to skip it. An enabled direction with `{}` or `include: []` extracts protocol metadata. Filters run in list order and keep independent budgets and attributes. Each enabled direction emits one record per audit filter. The record identifies the selected `chain`.

| Parser type | Direction | Allowed `include` values |
| --- | --- | --- |
| `llm` | request | `llm.messages`, `llm.question`, `llm.toolDefinitions`, `llm.toolCallRefs` |
| `llm` | response | `llm.messages`, `llm.answer`, `llm.toolCallRefs` |

To audit the latest question, the visible answer and tool references, select the following fields in the audit filter:

```yaml
request: {include: [llm.question, llm.toolCallRefs]}
response: {include: [llm.answer, llm.toolCallRefs]}
```

`llm.question` contains the text from the most recent user message with a nonempty text part. A plain Responses API input string also supplies the question. Tool results, including Anthropic tool results carried in user messages, are skipped. If no user text is available, the field is omitted. `llm.answer` concatenates visible assistant text and refusals in wire order within a reply. Chat Completions uses choice index 0. A completed tool-only reply produces an empty string. Reasoning, tool arguments and tool result bodies are excluded from these two projections. Both fields share the content and log budgets with other selections. When a projection cannot be recovered after clipping, the record reports truncation.

Selections are additive. Adding `llm.messages` also records structured conversation content, including tool arguments and results carried in those messages. The `llm.toolCallRefs` selection adds the call/result references under `agentio.tool.calls`.

For `parser.llm`, `protocol` defaults to `auto`. It maps the exact paths `/v1/chat/completions`, `/v1/responses` and `/v1/messages` to their respective wire protocols. Other paths produce `captureStatus: unknown_protocol`, and the byte count for each enabled direction of a completed stream. Forwarding continues. A custom path can set `protocol` to `openai-chat-completions`, `openai-responses` or `anthropic-messages`. Responses use the protocol selected at request headers. Their content type selects JSON or SSE. Unsupported media and malformed documents produce audit statuses.

All `parser.llm` protocols record messages, model and token usage under OpenTelemetry GenAI attribute names. A provider name is not inferred from the wire protocol.

Each entry in `audit.format.attributes` maps an output name to one quoted expression. The Rust module compiles these at configuration load, and samples their string values at request headers for both audit directions. Agentio and standalone Envoy use the same expressions.

| Expression | Value |
| --- | --- |
| `%REQ(X-TENANT-ID)%` | Request header. Header names are case-insensitive. |
| `%FILTER_STATE(my.sandbox:PLAIN)%` | The Filter State object's string serialization. |
| `%DYNAMIC_METADATA(workload:namespace)%` | The top-level string field `namespace` in the stream's dynamic metadata namespace `workload`. |

Missing values are omitted. A metadata value of another type is also omitted; Envoy 1.40.2 logs a type error when its string accessor encounters such a value. The producer of a Filter State or metadata value must set it before this module runs. The three operators above are the complete expression language: CEL, interpolation, and nested metadata paths are rejected at configuration load. Replace earlier source objects such as `{requestHeader: x-tenant-id}` with `"%REQ(X-TENANT-ID)%"`. For nested metadata, a preceding Envoy filter can expose the selected leaf as a string in Filter State.

Custom fields are written directly to the root of the record. A custom name that matches a built-in field is rejected at configuration load. Move existing `audit.attributes` entries to `audit.format.attributes` and rename any conflicting entries. Attribute values share the direction's final line budget with content. Oversized context entries are omitted and set `attributesTruncated: true`.

For example, a request with a tenant header sent to the sandbox chain can produce the following JSON line.

```json
{"type":"content","chain":"sandbox-model-calls","requestID":"req-7","direction":"request","path":"/v1/responses","captureStatus":"complete","bytesSeen":29,"llm.protocol":"openai-responses","app.tenant.id":"team-a","gen_ai.input.messages":[{"parts":[{"content":"hello","type":"text"}],"role":"user"}],"gen_ai.operation.name":"chat","gen_ai.request.model":"m"}
```

Dotted keys are literal JSON property names. Query the model as `."gen_ai.request.model"` in jq. Each enabled direction produces its own line with the same request ID. `captureStatus` describes capture of the selected fields and `bytesSeen` counts observed body bytes in that direction. Update consumers of the earlier record format to read these root fields in place of `status`, `attributes` and `content`.

With `llm.messages`, top-level Anthropic system instructions and OpenAI Responses instructions are recorded in `gen_ai.system_instructions`. System messages within Chat Completions history retain their position in `gen_ai.input.messages`. Recognized images use blob, URI or file parts. A clipped inline image retains its position, modality and available MIME type. Anthropic server tool calls use a `server_tool_call` part. Cache writes use `gen_ai.usage.cache_write.input_tokens`.

### GenAI metadata with tool references

To correlate calls without retaining message text, tool arguments or result bodies, enable the summary on each desired direction.

```yaml
bodyProcessing:
  filterChains:
    - name: tool-references
      parser: {llm: {}}
      filters:
        - audit:
            maxSize: 4KiB
            request: {include: [llm.toolCallRefs]}
            response: {include: [llm.toolCallRefs]}
```

| Field | Wire source |
| --- | --- |
| `gen_ai.request.stream` | Explicit boolean `stream` in any of the three protocols. |
| `gen_ai.request.max_tokens` | Chat `max_completion_tokens` (or legacy `max_tokens`), Responses `max_output_tokens`, Anthropic `max_tokens`. |
| `gen_ai.request.previous_response.id` | Responses `previous_response_id` identifies the preceding generation. `gen_ai.conversation.id` separately identifies the conversation. |
| `gen_ai.response.id` | Top-level JSON response ID, Chat chunk ID, Responses lifecycle event's response ID or Anthropic `message_start.message.id`. |
| `gen_ai.response.finish_reasons` | Reported Chat finish reasons in choice-index order or Anthropic stop reason. Available with an empty `include`. Responses reports its native `llm.status` and `llm.incompleteReason`. |
| `error.type`, `agentio.response.error_code` | Upstream structured error type and string code. If only a code is available, it also supplies `error.type`. The envelope's `captureStatus` describes audit capture. |
| `agentio.tool.calls` | With `llm.toolCallRefs` in `include`, each entry contains `kind` (`call` or `result`), plus the ID and name when supplied. Available for requests and responses. |

The summary covers Chat function calls and tool messages (including legacy function results), Responses function and custom tool calls and their outputs, and Anthropic client, server and MCP tool use and corresponding tool results. Chat requests can omit the model when the deployment is selected by URL. JSON and SSE use the same representation. A result can be joined to its call by ID. Summary capture tracks up to 1,024 references and up to the `maxSize` budget for names and IDs per direction. Overflow omits the summary and marks the record truncated. The serialized line budget also applies. Including response `llm.messages` also retains provider error details in `llm.error`. Other selections retain the structured error type and code.

### Standalone Envoy configuration

The following filter enables both directions. Omit the `response` member for request-only auditing. `maxSize` is a per-direction limit on the serialized JSON line, including its envelope and newline, in the range 1,024 to 1,048,576 bytes.

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
    value: '{"filterChains":[{"name":"models","parser":{"llm":{}},"filters":[{"audit":{"request":{"include":["llm.messages"],"maxSize":"16KiB"},"response":{}}}]}]}'
```

Each direction accepts the following settings.

| Setting | Behavior |
| --- | --- |
| `include` | Selects the content this audit writes for this direction. Defaults to an empty list. |
| `maxCaptureBytes` | When set, bounds a complete JSON document or a single SSE event including its framing. Exceeding it produces `too_large` and forwarding continues. When omitted, documents use streaming clipping and SSE events have a 64 KiB limit. |
| `maxContentBytes` | LLM only. Bounds retained LLM messages, question, answer and tool definitions. With an explicit capture limit it defaults to that limit. Otherwise SSE retains up to the available log budget and documents use the clipping behavior below. On content-budget overflow the audit drops those fields. Parsing continues for metadata, usage and other audits. |
| `maxSize` | Bounds the serialized line including its newline. A direction inherits `audit.maxSize`. The built-in limit is `8KiB` per record. Both settings accept `1KiB` through `1MiB`. |

For `maxSize` and `maxItemSize`, use an integer byte count or a string with a whole number and a unit. Decimal `KB` (also `kB`) and `MB` use powers of 1,000. Binary `KiB` and `MiB` (also `Ki` and `Mi`) use powers of 1,024. For example, `16KB` allows 16,000 bytes, while `16KiB` allows 16,384 bytes. Bare numbers and `B` denote bytes.

`maxCaptureBytes` and `maxContentBytes` accept integer byte counts from 1 through 67,108,864.

Agentio installs one ECDS filter slot and one audit access logger on each native HTTP forwarding chain. Rule updates affect new HTTP streams, including new streams on an existing HTTP/2 connection. In-flight streams retain their selected configuration. The slot starts immediately with an empty chain list; setting `bodyProcessing.filterChains: []` disables auditing.

For standalone Envoy, install this logger alongside the module. At stream completion the module publishes the completed records under one stream-local Filter State key, in filter order, request before response. Each JSON record includes its own newline within its direction's size budget. The text formatter writes the value verbatim.

```yaml
access_log:
  - name: envoy.access_loggers.stdout
    filter:
      extension_filter:
        name: envoy.access_loggers.extension_filters.cel
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.access_loggers.filters.cel.v3.ExpressionFilter
          expression: "'agentio.body_processing.audit' in filter_state"
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
      log_format:
        text_format_source:
          inline_string: "%FILTER_STATE(agentio.body_processing.audit:PLAIN)%"
```

Set `ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/usr/local/lib` and install the shared library there. The filter applies to traffic on its configured chain. It reads `x-request-id` for correlation. The log contains the direction, path without the query string, body bytes seen, capture status and retained content.

## Capture behavior

| Input | Logged content |
| --- | --- |
| LLM JSON requests | Auto mode recognizes the three standard paths listed above. Captures normalized messages, tool definitions, calls and results. Provider-specific blocks remain structured. |
| LLM JSON and SSE responses | Uses the same protocol selected at request headers. Reconstructs output messages, calls, arguments, finish reasons and reported usage. Responses also carries provider status, error and incomplete reason when available. |

Audits in a matched chain share one LLM parser per direction. Request messages and tool definitions are delivered to each audit as they arrive. Each audit retains its own selected fields and enforces its own line limit. For example, a 2 KiB question audit can skip a long earlier turn while a second 8 KiB tool audit records a schema at the end of the same request. Changing their order only changes the order of the output lines. JSON response normalization and SSE framing and reconstruction are also shared.

The parser bounds its working JSON representation independently of any log configuration. Set `parser.llm.request.maxItemSize` to control the compaction budget per request item (default `1MiB`, range `1KiB` to `64MiB`). Each message, Responses input item, tool definition or legacy function starts a fresh budget, even when it spans several HTTP chunks. A standalone Responses input string, instructions value or Anthropic system value each count as one item. All audits on the chain see the resulting item. The budget applies to the decoded JSON for gzip requests. JSON responses retain their independent, fixed 1 MiB document budget. Oversized strings can be shortened and inline media can be omitted while later items continue to be parsed. Each audit applies its own field selection, clipping and final serialized line limit. When selected messages no longer fit, a record may contain bounded text from message parts under `llm.retainedText`. A truncated record describes the retained projection and cannot reproduce discarded bytes.

SSE framing accepts multiline data, comments, a leading UTF-8 BOM, and LF, CRLF or CR separators across body callbacks. HTTP EOF ends observation. A missing protocol terminator produces `incomplete_stream`. An unsupported delta produces a `partial` record with available metadata. Exceeding the retention budget produces `truncated`. Both cases continue parsing subsequent events for usage and errors. Invalid JSON, invalid UTF-8 framing and invalid protocol transitions have distinct error statuses. Each direction processes up to 64 MiB of SSE input and tracks up to 1,024 choices, blocks or items.

Unsupported encodings, unsupported media types and parse failures have distinct statuses. These statuses apply to audit output only. For requests with a single `Content-Encoding: gzip`, the chain incrementally decompresses an audit copy for all interested filters. Envoy forwards the original body and headers. The request record's `bytesSeen` counts compressed bytes received; `decodedBytes` counts plaintext bytes delivered to the parser chain before capture stopped. Records without gzip decoding omit `decodedBytes`. A direction's `maxCaptureBytes` applies to the decoded document. The chain enforces a separate 64 MiB ceiling across all gzip members; exceeding it produces `too_large`. A corrupt or unfinished gzip member at normal HTTP end produces `invalid_encoding`. Gzip-encoded responses and stacked encodings produce `unsupported_encoding`.

Each audit filter publishes each enabled direction once. The native access logger owns buffering, output and file reopening. Access logging retains the bounded request record for the lifetime of a long-running response. The `contentguard_publish_errors` counter reports a Filter State publication failure. Delivery and retention after the access logger writes depend on the configured sink.

## Build

Build on Linux with Rust 1.93 or newer and libclang. The build fetches the Envoy 1.40.2 SDK to match the runtime image.

```sh
cd extensions/envoy/body_processing
./build.sh
docker build -t envoy-contentguard .
```
