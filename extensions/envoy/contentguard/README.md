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
| JSON requests to paths ending in `/completions`, `/responses` or `/messages` | OpenAI Chat Completions, OpenAI Responses or Anthropic messages and tools, respectively. Unknown provider blocks remain structured. |
| Other JSON requests and JSON responses | Provider JSON, including arrays and objects. |
| UTF-8 text, including SSE responses | A bounded text prefix. SSE retains event framing in that prefix. |
| Multipart form data | Ordered form fields with names and byte counts. File entries include the filename, optional content type and base64 if it fits. Oversized files carry `omitted: true`. |

Once a JSON document exceeds the capture budget, the scanner bounds each string across body slices. It replaces oversized inline media with `[omitted]` and continues scanning for later text. If the JSON structure itself fills the budget, the record switches to a bounded `retainedText` projection. Long text may be shortened. The final encoder checks the serialized size after normalization and escaping. If the projected structure still cannot fit, it emits a `truncated` record with null content. A truncated record describes the retained projection and cannot establish validity or reproduce discarded bytes.

Multipart capture scans delimiters across slice boundaries. It limits part headers to 8 KiB, skips the bytes of an oversized file, then resumes capture at the next field. Unsupported encodings, unsupported media types and parse failures have distinct statuses. These statuses apply to audit output only.

The filter publishes each direction once. The native access logger owns buffering, output and file reopening. Access logging retains the bounded request record for the lifetime of a long-running response. The `contentguard_publish_errors` counter reports a Filter State publication failure. Delivery and retention after the access logger writes depend on the configured sink.

## Build

Build on Linux with Rust 1.93 or newer and libclang. The build fetches the Envoy 1.40.2 SDK to match the runtime image.

```sh
cd extensions/envoy/contentguard
./build.sh
docker build -t envoy-contentguard .
```
