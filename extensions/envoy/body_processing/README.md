# ContentGuard

ContentGuard is an Envoy HTTP dynamic module for auditing request and response bodies. Install the filter before the router. Configure either direction independently. At the end of each enabled direction, the module retains a bounded JSON record. At HTTP stream completion, it publishes the records to Filter State for the Envoy access logger. A stream that terminates early publishes an `incomplete` record for the direction in progress. The filter observes Envoy's received slices and returns `Continue` without replacing them.

The Rust crate lives in `extensions/envoy/body_processing`. The Envoy filter name is `contentguard`. A matched chain runs one LLM parser per active direction and dispatches its events to filters in declaration order. Request gzip decoding and response SSE reconstruction are shared. Each audit selects its own fields and limits the size of its own records.

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
            request: {}
            response: {}
            format:
              json:
                direction: "%DIRECTION%"
                status: "%CAPTURE_STATUS%"
                requestID: "%REQ(X-REQUEST-ID)%"
                tenant: "%REQ(X-TENANT-ID)%"
                sandbox: "%FILTER_STATE(agentio.sandbox.id:PLAIN)%"
                namespace: "%DYNAMIC_METADATA(workload:namespace)%"
                prompt: "%EVENT(llm.question)%"
                answer: "%EVENT(llm.answer)%"
        - audit:
            request: {}
            maxSize: 16KiB
            format:
              json:
                tools: "%EVENT(llm.toolDefinitions)%"
                status: "%CAPTURE_STATUS%"
```

At request headers the module selects the first matching chain and fixes the protocol for both directions. All configured conditions must hold. Unmatched streams are forwarded without audit records. An omitted or empty matcher matches everything and belongs last. Each chain requires a unique, nonempty name (at most 256 bytes as a serialized JSON string, including quotes) and a nonempty list of filters. This release supports the `llm` parser and the `audit` filter.

| Match field | Semantics |
| --- | --- |
| `hosts` | Any listed host may match. Matching ignores ASCII case and the authority port. A leading `*.` matches one or more complete labels. |
| `paths` | Any listed path may match. Paths are absolute and case-sensitive. Both the matcher and LLM auto-detection ignore the request query and one trailing slash. For example, `/upload/?part=1` matches `/upload`. Configured paths must be exact, without a wildcard, query or fragment. |
| `filterState` | Every entry must match. `{key: agentio.sandbox.id}` checks for the key's existence, including an empty value. `{key: agentio.sandbox.id, values: [box-a, box-b]}` matches either serialized string exactly. An explicit `values` requires a nonempty list. |

### Audit templates

Each audit requires at least one enabled direction and one flat `format.json` map. Omit a direction to skip it. An enabled direction produces one JSON line containing the selected keys. A single operator supplies each value. JSON booleans, numbers, arrays and objects retain their types. Dots in output names are literal. Missing values and fields for the opposite direction are omitted. The configuration loader rejects unknown operators, unknown events, and events unavailable in every enabled direction.

To migrate, move header, Filter State and dynamic metadata expressions from `format.attributes` into `format.json`. Replace each `include` selection with a named `%EVENT(...)%` expression. Explicitly select envelope fields your collector uses. For example a request-only audit with `prompt: "%EVENT(llm.question)%"` and `tenant: "%REQ(X-TENANT-ID)%"` can emit `{"prompt":"hello","tenant":"team-a"}`.

| Operator | Value |
| --- | --- |
| `%REQ(X-TENANT-ID)%` | Case-insensitive request header, captured when request headers arrive. |
| `%FILTER_STATE(key:PLAIN)%` | Filter State object's string serialization at request headers. |
| `%DYNAMIC_METADATA(namespace:key)%` | Top-level string value at request headers. Other types are omitted. |
| `%CHAIN%`, `%DIRECTION%`, `%PATH%` | Rule name, request or response, and request path without the query. |
| `%BYTES_SEEN%`, `%DECODED_BYTES%` | Observed wire bytes and, for decoded gzip requests, decoded bytes. |
| `%CAPTURE_STATUS%` | Capture outcome, including parse errors, incomplete streams and size clipping. |
| `%EVENT(llm.field)%` | Value from the LLM protocol parser, projected for this audit. |

| Direction | Event names (omit the common `llm.` prefix in this table) |
| --- | --- |
| Either | `model`, `protocol`, `operation`, `messages`, `toolCallRefs`, `retainedText` |
| Request | `question`, `toolDefinitions`, `systemInstructions`, `stream`, `maxTokens`, `conversationId`, `previousResponseId` |
| Response | `answer`, `responseId`, `finishReasons`, `status`, `incompleteReason`, `error`, `errorType`, `errorCode` |
| Response usage | `usage.inputTokens`, `usage.outputTokens`, `usage.cachedInputTokens`, `usage.cacheCreationInputTokens`, `usage.reasoningTokens`, `usage.totalTokens` |

`llm.question` selects text from the latest user message with visible text, skipping tool results. `llm.answer` collects visible assistant text and refusals, using choice zero for Chat Completions. `llm.messages` preserves structured parts and provider-specific content. Tool references carry call/result IDs and names and can be selected independently of message bodies. `llm.status` is the provider's response status. Use `%CAPTURE_STATUS%` to tell whether the gateway captured the selected evidence.

Each audit has its own retention and final line budget. The encoder reserves space for selected status keys and the final newline. It visits other output names in sorted order, shortens oversized event strings at UTF-8 boundaries and omits values that cannot fit. An otherwise complete record then reports `truncated`. The other audits keep consuming the same parser events.

In `auto` mode the parser matches the paths `/v1/chat/completions`, `/v1/responses` and `/v1/messages`. For a custom path select `openai-chat-completions`, `openai-responses` or `anthropic-messages`. Unknown paths in auto mode report `unknown_protocol`. The response content type selects JSON or SSE.

### Standalone Envoy configuration

The following filter enables both directions. Omit the `response` member for request-only auditing. `maxSize` is a per-direction limit on the serialized JSON line, including its newline, in the range 1,024 to 1,048,576 bytes.

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
    value: '{"filterChains":[{"name":"models","parser":{"llm":{}},"filters":[{"audit":{"request":{"maxSize":"16KiB"},"response":{},"format":{"json":{"messages":"%EVENT(llm.messages)%","status":"%CAPTURE_STATUS%"}}}}]}]}'
```

Each direction accepts the following settings.

| Setting | Behavior |
| --- | --- |
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

Set `ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/usr/local/lib` and install the shared library there. The filter applies to traffic on its configured chain. Select `%REQ(X-REQUEST-ID)%` in both directions for correlation.

## Capture behavior

| Input | Logged content |
| --- | --- |
| LLM JSON requests | Auto mode recognizes the three standard paths listed above. Captures normalized messages, tool definitions, calls and results. Provider-specific blocks remain structured. |
| LLM JSON and SSE responses | Uses the same protocol selected at request headers. Reconstructs output messages, calls, arguments, finish reasons and reported usage. Responses also carries provider status, error and incomplete reason when available. |

Audits in a matched chain share one LLM parser per direction. Request messages and tool definitions are delivered to each audit as they arrive. Each audit retains its own selected fields and enforces its own line limit. For example, a 2 KiB question audit can skip a long earlier turn while a second 8 KiB tool audit records a schema at the end of the same request. Changing their order only changes the order of the output lines. The chain also shares JSON response normalization and SSE framing.

The parser bounds its working JSON representation independently of any log configuration. Set `parser.llm.request.maxItemSize` to control the compaction budget per request item (default `1MiB`, range `1KiB` to `64MiB`). Each message, Responses input item, tool definition or legacy function starts a fresh budget, even when it spans several HTTP chunks. A standalone Responses input string, instructions value or Anthropic system value each count as one item. All audits on the chain see the resulting item. The budget applies to the decoded JSON for gzip requests. JSON responses retain their independent, fixed 1 MiB document budget. Oversized strings can be shortened and inline media can be omitted while later items continue to be parsed. Each audit applies its own field selection, clipping and final serialized line limit. When selected messages no longer fit, a record may contain bounded text from message parts under `llm.retainedText`. A truncated record describes the retained projection and cannot reproduce discarded bytes.

During SSE, each complete frame produces borrowed protocol events in the body callback. The parser dispatches text deltas, usage updates and provider-specific changes to filters in order. Usage updates carry the latest normalized counters. A response audit can retain the answer while another records only usage. Responses text deltas are provisional. The audit takes confirmed item snapshots in output order, then replaces them if the terminal event supplies a nonempty `output`. An empty or omitted terminal `output` keeps the confirmed items. The protocol terminator delivers the completed message and metadata projection. HTTP end validates completion and finalizes one record per enabled audit. The Envoy access logger writes those records at stream completion.

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
