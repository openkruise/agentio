# Fixture sources

Input fixtures are pinned to local upstream checkouts; tests need no network.
Both projects are Apache-2.0 licensed (see the repository root LICENSE).
`*.want.json` are EPE-specific expectations: normalized content, not provider-to-provider translations.
They were authored from the input semantics, not recorded from EPE output.

## Agentgateway

Source: https://github.com/agentgateway/agentgateway/tree/6cb2e9cbcc4db1d3bdad4b2fc8d046ab52b7b29d/crates/llm/src/tests
The following inputs are byte-for-byte copies, renamed to reflect their wire format.
Upstream golden coverage is in `crates/llm/src/golden_tests.rs`.

| Local input | Upstream path under `crates/llm/src/tests` |
| --- | --- |
| `anthropic-empty-tool.sse` | `response/anthropic/stream_tool_empty_args.json` |
| `anthropic-usage.sse` | `response/anthropic/stream_message_delta_usage.json` |
| `anthropic-citations.json` | `response/anthropic/multiple_text_blocks.json` |
| `responses-tools.sse` | `response/responses/stream.json` |
| `responses-refusal.sse` | `response/responses/stream-refusal.json` |
| `responses-truncated.json` | `response/responses/truncated_tool_call.json` |
| `responses-parallel.json` | `requests/responses/parallel-tool-call.json` |
| `responses-media.json` | `requests/responses/input-media.json` |
| `chat-empty-content.sse` | `response/completions/stream_tool_empty_content.json` |
| `chat-truncated.json` | `response/completions/truncated_tool_call.json` |

## Envoy AI Gateway

Copyright Envoy AI Gateway Authors. SPDX-License-Identifier: Apache-2.0.
Source: https://github.com/envoyproxy/ai-gateway/blob/f4571d6bd8f53696c4e9105f365b556db7b249a8/internal/tracing/openinference/openai/sse_converter_test.go

- `chat-annotations.sse`: `response with annotations`.
- `chat-obfuscation.sse`: `response with obfuscation field preserves last value`.

These two inputs were extracted with two modifications: adding `index: 0` to choices
and a final blank line after `[DONE]`. The upstream converter fixtures omit choice
indices and accept EOF without the SSE event delimiter; EPE requires explicit
choice identity and blank-line event dispatch. An unterminated `[DONE]` remains
`incomplete_stream` in EPE (covered separately by decoder/protocol tests).
EPE intentionally reports unsupported annotation deltas as `partial`; it does not
claim to normalize them. Envelope obfuscation does not alter the content view.

## Expectations

Each input is tested whole and with 1-, 7-, and 64-byte chunks, with EOF both on
the last chunk and in a separate callback. Assertions cover normalized content,
usage, tool argument identity, incomplete generation status, and partial coverage.
Truncated generation arguments remain strings; successful parsing is not a claim
that the model finished generating valid tool JSON. Media blocks stay opaque.
These fixtures do not establish full provider compatibility or image decoding.
