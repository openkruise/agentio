# MCP tool policy matching details

> Design note. This page records the framing and matching internals behind [Configure MCP access control](../tasks/configure-mcp-access-control.md).

## Supported protocol versions

EPE always buffers the full request body for a matching `mcpToolPolicy`; it does not make a decision from the client-controlled version header alone. The current implementation supports MCP protocol versions `2025-06-18`, `2025-11-25`, and `2026-07-28`.

## Framing and decoding

- Only the JSON-RPC method `tools/call` is governed. `initialize`, `ping`, `tools/list`, resource, prompt, task, logging, and other methods pass through.
- Rules are considered in document order; the first matching rule wins. An empty `toolNames` list matches every tool name for that method; multiple names are ORed.
- The only permissive action is exactly `allow`. Action spelling is trimmed and case-normalized for payload compatibility, but unknown values fail closed.
- A supported `tools/call` with a missing or non-string `params.name` follows `defaultAction`.
- Missing or unsupported `MCP-Protocol-Version` follows `unsupportedVersionAction`. Set `unsupportedVersionAction: passthrough` only when intentionally accepting calls EPE does not understand.
- A single JSON object with insignificant leading or trailing whitespace is accepted. JSON-RPC batches, malformed JSON, trailing non-whitespace content, and a second JSON document are unreadable and therefore follow `defaultAction`.
- EPE normalizes UTF-8 with a BOM and BOM-marked UTF-16 text, plus `gzip`, `x-gzip`, and `deflate` content codings (at most two codings). Decoded bodies over 8 MiB, or any unsupported or invalid encoding, are unreadable and follow `defaultAction`.

## Default-action guidance

Use `defaultAction: deny` for tool whitelists. With a blacklist (`defaultAction: allow`), an unreadable body or an unnameable tool call is allowed by design; a nonconforming or unusually lenient upstream could then execute a call that EPE could not attribute. The policy does not inspect tool arguments, authorize `tools/list`, or enforce MCP sessions or server responses.
