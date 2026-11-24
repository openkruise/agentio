# Body Processing

Body Processing is an Envoy HTTP dynamic module for request and response bodies. Install it before the router. Each matched `audit` emits one JSON line per downstream HTTP stream. Its template can combine request, response and gateway fields. The module retains the selected values within their individual limits and hands the lines to the Envoy access logger at stream completion. Forwarded body slices pass through unchanged.

Agentio delivers the `body_processing` filter configuration through the `agentio.body_processing` ECDS resource. At configuration load the module resolves each template expression to its source. A matched chain runs one LLM parser for each direction that has event consumers. Consumers share request gzip decoding and response SSE framing. The native gateway registers the module as an ADS validator for its Body Processing ECDS resource. Invalid audit rules receive an xDS NACK before Envoy updates its subscription cache. Existing and newly installed listeners continue using the last accepted rules.

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
            format:
              json:
                requestStatus: "%CAPTURE_STATUS(request)%"
                responseStatus: "%CAPTURE_STATUS(response)%"
                requestID: "%REQ(X-REQUEST-ID)%"
                tenant: "%REQ(X-TENANT-ID):128%"
                sandbox: "%FILTER_STATE(agentio.sandbox.id:PLAIN)%"
                namespace: "%FILTER_STATE(agentio.workload.namespace:PLAIN)%"
                requestedModel: "%EVENT(llm.request.model)%"
                servedModel: "%EVENT(llm.response.model)%"
                prompt: "%EVENT(llm.question)%"
                answer: "%EVENT(llm.answer):768%"
                tokens: "%EVENT(llm.usage.totalTokens)%"
        - audit:
            format:
              json:
                tools: "%EVENT(llm.toolDefinitions):16384%"
                status: "%CAPTURE_STATUS(request)%"
```

At request headers the module selects the first matching chain and fixes the protocol for both directions. All configured conditions must hold. Unmatched streams are forwarded without audit records. An omitted or empty matcher matches everything and belongs last. Each chain requires a unique, nonempty name (at most 256 bytes as a serialized JSON string, including quotes) and a nonempty list of filters. This release supports the `llm` parser and the `audit` filter.

| Match field | Semantics |
| --- | --- |
| `hosts` | Any listed host may match. Matching ignores ASCII case, the authority port and one trailing DNS root dot. A leading `*.` matches one or more complete labels. |
| `paths` | Any listed path may match. Paths are absolute and case-sensitive. Both the matcher and LLM auto-detection ignore the request query and one trailing slash. For example, `/upload/?part=1` matches `/upload`. Configured paths must be exact, without a wildcard, query or fragment. |
| `filterState` | Every entry must match. `{key: agentio.sandbox.id}` checks for the key's existence, including an empty value. `{key: agentio.sandbox.id, values: [box-a, box-b]}` matches either serialized string exactly. An explicit `values` requires a nonempty list. |

### Audit templates

An audit requires a flat `format.json` map. Each key names one output field and each value is one operator. JSON booleans, numbers, arrays and objects retain their types. Dots in output names are literal. Missing values are omitted. A template whose fields are all missing emits `{}`. Each audit in the matched chain writes its own line, in declaration order.

A template containing only headers, Filter State, dynamic metadata, the path, the chain name or the selected LLM protocol/operation collects all its values at request headers. Envoy writes the resulting line at stream completion. A request with only a question selected needs only the request parser. An answer or usage selection needs the response parser. When an audit selects fields from both bodies, they appear in the same line. For example, a question followed by two SSE answer deltas and a final usage report can produce `{"question":"retry?","answer":"retry once","tokens":14}`.

| Operator | Value |
| --- | --- |
| `%REQ(X-TENANT-ID)%` | Case-insensitive request header, captured when request headers arrive. |
| `%FILTER_STATE(key:PLAIN)%` | Filter State object's string serialization at request headers. |
| `%DYNAMIC_METADATA(namespace:key)%` | Top-level dynamic metadata string, captured at request headers. |
| `%DYNAMIC_METADATA_NUMBER(namespace:key)%` | Top-level dynamic metadata number, emitted as a JSON number. |
| `%DYNAMIC_METADATA_BOOL(namespace:key)%` | Top-level dynamic metadata boolean, emitted as JSON `true` or `false`. |
| `%CHAIN%`, `%PATH%` | Chain name and request path without the query. |
| `%BYTES_SEEN(request)%`, `%BYTES_SEEN(response)%` | Wire bytes observed in the chosen direction. A wire counter alone reads chunk lengths. |
| `%DECODED_BYTES(request)%`, `%DECODED_BYTES(response)%` | Decoded bytes when decompression ran. This version decompresses gzip requests. |
| `%CAPTURE_STATUS(request)%`, `%CAPTURE_STATUS(response)%` | Opt in to protocol validation and the capture outcome for that direction. Clipping a selected request header or other request context affects the request status. A transport interruption reports `incomplete`, including when response headers never arrived. |
| `%EVENT(llm.field)%` | Value from the LLM protocol parser, projected for this audit. |

Choose the metadata operator matching the producer's type. Body Processing reads the selected top-level key at request headers and omits missing keys. For a present value of a different type, Envoy 1.40.2 logs a type error and the audit omits that field. The number operator accepts finite values. The number and boolean operators are specific to Body Processing and reject a byte limit.

| Direction | Event names (omit the common `llm.` prefix in this table) |
| --- | --- |
| Stream | `protocol`, `operation` |
| Request or response | `request.model` / `response.model`, `request.messages` / `response.messages`, `request.toolCallRefs` / `response.toolCallRefs`, `request.retainedText` / `response.retainedText` |
| Request | `question`, `toolDefinitions`, `systemInstructions`, `stream`, `maxTokens`, `conversationId`, `previousResponseId` |
| Response | `answer`, `responseId`, `finishReasons`, `status`, `incompleteReason`, `error`, `errorType`, `errorCode` |
| Response usage | `usage.inputTokens`, `usage.outputTokens`, `usage.cachedInputTokens`, `usage.cacheCreationInputTokens`, `usage.reasoningTokens`, `usage.totalTokens` |

`llm.question` selects text from the latest user message with visible text, skipping tool results. `llm.answer` collects visible assistant text and refusals, using choice zero for Chat Completions. `llm.request.messages` and `llm.response.messages` preserve structured parts and provider-specific content. Tool references carry call/result IDs and names and can be selected independently of message bodies. `llm.status` is the provider's response status. Use the direction-specific `%CAPTURE_STATUS(...)%` operator to report a capture outcome.

### Field limits

Append `:N` before the closing `%` to limit a variable-size field. For example, `%EVENT(llm.answer):768%` keeps up to 768 bytes of the answer and `%REQ(X-TENANT-ID):128%` keeps up to 128 bytes of the header. The default for each field is 8,192 bytes. An explicit `N` is a decimal byte count from 1 to 1,048,576. The length suffix follows Envoy’s [formatter syntax](https://www.envoyproxy.io/docs/envoy/v1.40.2/configuration/advanced/substitution_formatter#config-access-log-format-req).

- Strings retain the longest UTF-8 prefix that fits after compact JSON escaping. The surrounding quotes are excluded. A newline costs two bytes and `你` costs three.
- Arrays retain a prefix of complete projected elements, counting brackets, commas and contents. An oversized object or an array whose first element cannot fit is omitted. For an oversized request message the audit reserves space for text and attachment metadata, then retains complete inline payloads in message order. If one payload does not fit, later, smaller ones can still be recorded. For a text preview of an oversized message select `llm.question` or `llm.answer`.
- Numbers and booleans retain their JSON types. The numeric operators (including `llm.maxTokens` and usage), `llm.stream`, the byte counters and `%CAPTURE_STATUS(...)%` have fixed representations and reject a length suffix. On an otherwise complete record, a clipped selection yields `truncated` when capture status is selected.

Aliases have independent limits, even if they read the same event. A long answer cannot displace the model, token count or headers. Two selected 8 KiB strings can produce a line larger than 16 KiB once the keys and JSON punctuation are included. The selected fields, their limits and the JSON envelope determine the maximum output size.

The template is compiled when ECDS loads the rule. Each operator retains its typed JSON value until encoding. Envoy also parses commands into providers and supports typed values in `json_format`. Its request header formatter limits the raw value. This module counts JSON escaping so a field limit describes the bytes written for that value. [Envoy format API](https://www.envoyproxy.io/docs/envoy/v1.40.2/api-v3/config/core/v3/substitution_format_string.proto#config-core-v3-substitutionformatstring) · [Command parsing](https://github.com/envoyproxy/envoy/blob/v1.40.2/source/common/formatter/substitution_formatter.cc#L244-L278) · [Header formatting](https://github.com/envoyproxy/envoy/blob/v1.40.2/source/common/formatter/http_specific_formatter.cc#L66-L94)

In `auto` mode the parser matches the paths `/v1/chat/completions`, `/v1/responses` and `/v1/messages`. For a custom path select `openai-chat-completions`, `openai-responses` or `anthropic-messages`. Unknown paths in auto mode report `unknown_protocol`. The response content type selects JSON or SSE.

### Standalone Envoy configuration

The following filter records the input messages and the answer in one line. A request-only audit selects request fields.

```yaml
name: envoy.filters.http.dynamic_modules
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter
  dynamic_module_config:
    name: envoy_agentio_body_processing
    do_not_close: true
  filter_name: body_processing
  filter_config:
    "@type": type.googleapis.com/google.protobuf.StringValue
    value: '{"filterChains":[{"name":"models","parser":{"llm":{}},"filters":[{"audit":{"format":{"json":{"messages":"%EVENT(llm.request.messages):16384%","answer":"%EVENT(llm.answer)%"}}}}]}]}'
```

`parser.llm.request.maxItemSize` accepts an integer byte count or a string with a whole number and a unit. Decimal `KB` (also `kB`) and `MB` use powers of 1,000. Binary `KiB` and `MiB` (also `Ki` and `Mi`) use powers of 1,024. Bare numbers and `B` denote bytes.

Adding `bodyProcessing` to the effective AgentioConfig triggers an LDS update that installs one ECDS filter slot and one audit access logger on each native HTTP forwarding chain. Removing the field uninstalls both through LDS. To keep both installed while collecting no records, set `bodyProcessing: {}` or `bodyProcessing: {filterChains: []}`.

While the field is present, adding, changing or clearing rules updates only ECDS. New HTTP streams pick up the updated rules, including streams on an existing HTTP/2 connection. In-flight streams retain their selected configuration. On first installation the filter can forward traffic with an empty chain list until it receives its rules.

For standalone Envoy, install this logger alongside the module. At stream completion the module publishes the completed records under one stream-local Filter State key, in filter declaration order. Each JSON record includes one trailing newline. The text formatter writes the value verbatim.

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

Set `ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/usr/local/lib` and install the shared library there. To correlate records from multiple audits on the same stream, select `%REQ(X-REQUEST-ID)%` in each template.

## Capture behavior

| Input | Logged content |
| --- | --- |
| LLM JSON requests | Auto mode recognizes the three standard paths listed above. Captures normalized messages, tool definitions, calls and results. Provider-specific blocks remain structured. |
| LLM JSON and SSE responses | Uses the same protocol selected at request headers. Reconstructs output messages, calls, arguments, finish reasons and reported usage. Responses also carries provider status, error and incomplete reason when available. |

The LLM parser normalizes image references from Chat Completions, Responses and Anthropic Messages. In `%EVENT(llm.request.messages)%`, audit renders them as `file` (file ID), `uri` (URL) or `blob` (inline base64). It includes `detail` when supplied. An inline image whose data exceeds the capture budget can still appear with its MIME type and detail.

For Chat files and audio, Responses files and computer screenshots, and Anthropic documents, the parser identifies inline payloads in the provider part. A request messages field that cannot fit an attachment can omit its payload and still capture the following text. The log preserves the provider's part shape and a recognized data URI's MIME prefix. A second audit with a larger field limit can retain any payload still available from the parser.

Audits in a matched chain share one LLM parser per subscribed direction. Request messages and tool definitions are delivered to each audit as they arrive. Each audit retains its selected fields separately. For example, a 2 KiB question field can capture the latest question while an 8 KiB tool field records a schema at the end of the same request, in either the same audit or a second one. Changing their order only changes the order of the output lines. The chain also shares JSON response normalization and SSE framing.

The parser bounds its working JSON representation independently of any log configuration. Set `parser.llm.request.maxItemSize` to control the compaction budget per request item (default `1MiB`, range `1KiB` to `64MiB`). Each message, Responses input item, tool definition or legacy function starts a fresh budget, even when it spans several HTTP chunks. A standalone Responses input string, instructions value or Anthropic system value each count as one item. All audits on the chain see the resulting item. The budget applies to the decoded JSON for gzip requests. JSON responses retain their independent, fixed 1 MiB document budget. Oversized strings can be shortened and inline media can be omitted while later items continue to be parsed. Each audit applies its own field selection and per-field clipping to the parser output. Select `llm.request.retainedText` or `llm.response.retainedText` for a bounded array of text previews. In each direction the preview and the structured messages have independent field limits. Tool results and inline file data are excluded from the request text preview. Question and answer scalars stop at the first missing text segment. The parser continues scanning past omitted attachments for later text and metadata. When the document structure itself exceeds the budget, only selected paths are available for validation. An audit that selects capture status reports `partial` in that case, or `truncated` if one of its selected values was clipped.

During SSE, each complete frame produces borrowed protocol events in the body callback. The parser dispatches text deltas, usage updates and provider-specific changes to filters in order. Usage updates carry the latest normalized counters. A response audit retains a bounded answer prefix in output order while another can record only usage. A terminal replacement starts a fresh prefix and clipping status for the authoritative answer. Responses text deltas are provisional. The audit takes confirmed item snapshots in output order, then replaces them if the terminal event supplies a nonempty `output`. An empty or omitted terminal `output` keeps the confirmed items. The protocol terminator delivers the completed message and metadata projection. HTTP end validates protocol completion and finalizes the selected fields for the direction. The Envoy access logger writes those records at stream completion.

SSE framing accepts multiline data, comments, a leading UTF-8 BOM, and LF, CRLF or CR separators across body callbacks. HTTP EOF ends observation. A missing protocol terminator produces `incomplete_stream`. On premature EOF or transport reset, the audit preserves already framed answer text and reported usage, within their budgets. An unfinished frame contributes no values. A malformed stream retains its parse error and omits its response body fields. An unsupported delta produces a `partial` record with available metadata. Exceeding the retention budget produces `truncated`. Both cases continue parsing subsequent events for usage and errors. Invalid JSON, invalid UTF-8 framing and invalid protocol transitions have distinct error statuses. The shared parser processes up to 64 MiB of SSE input per direction and tracks up to 1,024 choices, blocks or items. Its input limits apply to every consumer. Clipping one audit field leaves later events available, including final usage and terminal replacements.

Unsupported encodings, unsupported media types and parse failures have distinct statuses. These statuses apply to audit output only. For requests with a single `Content-Encoding: gzip`, the chain incrementally decompresses an audit copy for all interested filters. Envoy forwards the original body and headers. The request wire counter counts compressed bytes. Its decoded counter counts plaintext delivered before capture stopped. Records without gzip decoding omit `decodedBytes`. The chain enforces a separate 64 MiB ceiling across all gzip members; exceeding it produces `too_large`. A corrupt or unfinished gzip member at normal HTTP end produces `invalid_encoding`. Gzip-encoded responses and stacked encodings produce `unsupported_encoding`.

Each audit filter publishes one record per matched stream. The native access logger owns buffering, output and file reopening. Access logging retains the selected request fields for the lifetime of a long-running response. The `body_processing_publish_errors` counter reports a Filter State publication failure. Delivery and retention after the access logger writes depend on the configured sink.

## Build

Build on Linux with Rust 1.93 or newer and libclang. The build fetches the Envoy 1.40.2 SDK to match the runtime image.

```sh
cd extensions/envoy/body_processing
./build.sh
docker build -t envoy-body-processing .
```

## Streaming audit E2E

On Linux, run `python3 tests/smoke.py envoy-body-processing` after building the image. This starts a fixture upstream and Envoy, sends OpenAI Chat Completions, OpenAI Responses and Anthropic Messages requests, and checks the forwarded bytes and Envoy's stdout audit records.

The upstream and client can also run as separate processes. Use the `streaming` chain from `tests/smoke.py` and route the host `stream.llm.test` to the fixture upstream, including the client's `/_fixture/continue/` handshake. The client uses a second connection to release the Chat stream after receiving its first event and part of the next UTF-8 character.

```sh
python3 tests/llm_streaming.py serve --listen 0.0.0.0 --port 9000
# In another terminal, point the client at the gateway.
python3 tests/llm_streaming.py client --gateway 127.0.0.1:8080
python3 tests/llm_streaming.py check-logs < envoy-audit.jsonl
```

The upstream accepts streaming POST requests on the three provider paths. It replays the default fixture for each path. The test client sends `X-LLM-Case` to select individual fixtures. The log check expects one client run and verifies the answer and usage/tool audit lines separately, including a revised terminal answer, a clipped 80 KiB Chat answer with its model, late usage and a separately clipped header in the same line, missing stream termination and malformed event JSON.
