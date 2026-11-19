# ContentGuard

ContentGuard is an Envoy HTTP dynamic module for auditing request and response bodies. Install the filter before the router. Configure either direction independently. At the end of each enabled direction, the module publishes a bounded JSON record to Envoy Filter State. Envoy access logging writes the record when the HTTP stream completes. A stream that terminates early publishes an `incomplete` record for the direction in progress. The filter observes Envoy's received slices and returns `Continue` without replacing them.

## Configuration

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
    value: '{"request":{"maxLogBytes":16384},"response":{"maxLogBytes":8192}}'
```

Each direction accepts the following settings.

| Setting | Behavior |
| --- | --- |
| `format` | Defaults to `auto`. Set `json`, `text`, `openai-chat-completions`, `openai-responses`, or `anthropic-messages` to select a parser regardless of the URL. Explicit formats check the media type. LLM protocols accept JSON in both directions and SSE on responses. |
| `fields` | Omit to capture all LLM fields. Within an explicit object, only fields set to true are selected. The flags are `inputMessages`, `outputMessages` and `tools`. Use `{}` for protocol metadata and usage only. Generic JSON, text and multipart keep their own representation. |
| `maxCaptureBytes` | When set, bounds a complete JSON/text document or a single SSE event including its framing. Exceeding it produces `too_large` and forwarding continues. When omitted, documents use streaming clipping and SSE events have a 64 KiB limit. Multipart uses the log budget. |
| `maxContentBytes` | Bounds retained LLM messages and tool definitions. With an explicit capture limit it defaults to that limit. Otherwise SSE retains up to the available log budget and documents use the clipping behavior below. On content-budget overflow the parser drops those fields and continues collecting metadata and usage. |
| `maxLogBytes` | Required. Bounds the final JSON line independently of the decoder and content limits. |

Both optional byte limits accept 1 through 67,108,864 bytes. For example, `{"response":{"format":"openai-responses","maxCaptureBytes":65536,"maxContentBytes":4096,"maxLogBytes":8192,"fields":{}}}` records Responses metadata and usage on a custom URL.

Add the corresponding entries to the HTTP connection manager's `access_log` list. This example uses Envoy's stdout logger. For request-only auditing, configure just the first entry. A file logger can use the same text format. The formatter writes the serialized record directly; the newline is included in the direction's budget.

```yaml
access_log:
  - name: envoy.access_loggers.stdout
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
      log_format:
        text_format_source:
          inline_string: "%FILTER_STATE(agentio.contentguard.request:PLAIN)%\n"
  - name: envoy.access_loggers.stdout
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
| LLM JSON and SSE responses | Uses the same protocol as the path or explicit response configuration. Reconstructs output messages, calls, arguments, finish reasons and reported usage. Responses also carries provider status, error and incomplete reason when available. |
| Generic JSON | Provider JSON, including arrays and objects. |
| UTF-8 text | Explicit `text` accepts `text/plain`. Auto mode also keeps a bounded text prefix for other text media, including SSE on unrecognized paths. |
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
