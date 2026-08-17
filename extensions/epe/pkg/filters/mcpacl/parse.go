// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// JSON-RPC / MCP request body parsing.
package mcpacl

import (
	"bytes"
	"encoding/json"
)

// mcpProtocolVersionHeader is the HTTP header a Streamable HTTP client MUST send
// on every request (MCP 2025-06-18+). Since MCP 2026-07-28 the initialize
// handshake has been removed, so the header is required unconditionally on
// every request. Header map keys are lowercased by the request handler.
const mcpProtocolVersionHeader = "mcp-protocol-version"

// mcpMethodHeader and mcpNameHeader are the mandatory routing headers
// introduced in MCP 2026-07-28 (SEP-2243). Mcp-Method carries the JSON-RPC
// method on every request; Mcp-Name carries the tool/resource name only for
// methods that reference one (tools/call, resources/read, prompts/get).
// Header map keys are lowercased by the request handler.
const (
	mcpMethodHeader = "mcp-method"
	mcpNameHeader   = "mcp-name"
)

// gaMCPVersion is the MCP 2026-07-28 GA revision, which made Mcp-Method and
// Mcp-Name headers mandatory on every Streamable HTTP request.
const gaMCPVersion = "2026-07-28"

// supportedMCPVersions is the set of MCP revisions this ACL enforces. Traffic
// declaring any other version (or no identifiable supported version) is ignored
// and passed through — we only police the protocol versions we understand.
var supportedMCPVersions = map[string]bool{
	"2025-06-18": true,
	"2025-11-25": true,
	"2026-07-28": true,
}

// governedMethods are the JSON-RPC methods this ACL evaluates. This is a *tool*
// ACL, so only tool invocation is governed; every other method (lifecycle,
// tools/list, resources/*, prompts/*, tasks/*, logging/*, ...) passes through
// untouched. Because non-tool methods are never evaluated, there is no
// per-protocol-version allow-list to maintain. Add "tools/list" here if listing
// should also be gated.
var governedMethods = map[string]bool{
	"tools/call": true,
}

// streamingParsePartial extracts method and params.name from a possibly
// incomplete JSON body without unmarshaling all of it. Returns ("", "") when
// the target fields have not been seen yet. Exercised by the streaming parser
// tests in this package.
func streamingParsePartial(data []byte) (method, toolName string) {
	if len(data) == 0 {
		return "", ""
	}
	dec := json.NewDecoder(bytes.NewReader(data))

	t, err := dec.Token()
	if err != nil {
		return "", ""
	}
	if delim, ok := t.(json.Delim); !ok || delim != '{' {
		return "", ""
	}

	for dec.More() {
		t, err = dec.Token()
		if err != nil {
			return method, toolName
		}
		key, ok := t.(string)
		if !ok {
			return method, toolName
		}

		switch key {
		case "method":
			t, err = dec.Token()
			if err != nil {
				return method, toolName
			}
			if s, ok := t.(string); ok {
				method = s
			}
			if method != "" && !governedMethods[method] {
				return method, toolName
			}
			if method != "" && toolName != "" {
				return method, toolName
			}
		case "params":
			t, err = dec.Token()
			if err != nil {
				return method, toolName
			}
			if delim, ok := t.(json.Delim); ok && delim == '{' {
				toolName = scanParamsName(dec)
				if toolName != "" {
					if method != "" {
						return method, toolName
					}
					// params preceded method. scanParamsName stopped early to
					// avoid walking "arguments", so the decoder is parked
					// mid-object; drain it before continuing the top-level
					// scan, or the next token read would be a params key.
					drainObject(dec)
				}
			}
		default:
			skipToken(dec)
		}
	}
	return method, toolName
}

// scanParamsName reads inside an already-opened params object to find "name".
// Returns immediately once found without consuming the rest (e.g. "arguments").
func scanParamsName(dec *json.Decoder) string {
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return ""
		}
		key, ok := t.(string)
		if !ok {
			return ""
		}
		if key == "name" {
			t, err = dec.Token()
			if err != nil {
				return ""
			}
			if s, ok := t.(string); ok {
				return s
			}
			return ""
		}
		skipToken(dec)
	}
	dec.Token() // consume '}'
	return ""
}

// drainObject consumes the remainder of the object the decoder is currently
// inside, including its closing brace, leaving the decoder positioned at the
// enclosing object's next key.
func drainObject(dec *json.Decoder) {
	for dec.More() {
		if _, err := dec.Token(); err != nil {
			return
		}
		skipToken(dec)
	}
	dec.Token() // consume '}'
}

// skipToken skips a single JSON value (primitive, object, or array).
func skipToken(dec *json.Decoder) {
	t, err := dec.Token()
	if err != nil {
		return
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			for dec.More() {
				if _, err := dec.Token(); err != nil {
					return
				}
				skipToken(dec)
			}
			dec.Token()
		case '[':
			for dec.More() {
				skipToken(dec)
			}
			dec.Token()
		}
	}
}

type jsonrpcRequest struct {
	Method string `json:"method"`
	Params struct {
		// Name stays raw so a non-string value is a missing tool name rather
		// than an unmarshal error that would also swallow the method.
		Name json.RawMessage `json:"name"`
	} `json:"params"`
}

// bodyStatus classifies what the ACL can do with a request body.
type bodyStatus int

const (
	// statusAbsent means the body carries no JSON-RPC message; there is
	// nothing to govern.
	statusAbsent bodyStatus = iota
	// statusUnreadable means bytes are present but no single JSON-RPC message
	// can be read out of them — a batch, trailing content after the first
	// document, invalid JSON, or an encoding this filter cannot undo. No
	// verdict can be reached, so the caller denies.
	statusUnreadable
	// statusMessage means exactly one JSON-RPC message was read.
	statusMessage
)

// bodyRead is the outcome of reading a request body as a JSON-RPC message.
type bodyRead struct {
	status bodyStatus
	method string
	tool   string
	// hasTool is false when params.name was absent or not a string, i.e. the
	// call cannot be attributed to a tool-scoped rule.
	hasTool bool
}

// readBody normalizes body and reads the single JSON-RPC message it carries.
//
// Anything that leaves the ACL unable to name what the upstream would execute
// is statusUnreadable rather than a pass: a body that this filter cannot parse
// but a lenient upstream can is exactly how a tool call gets hidden from the
// policy. Compressed and BOM-marked bodies are therefore decoded first (see
// normalizeBody) so that only genuinely unjudgeable bodies are denied.
func readBody(headers map[string]string, raw []byte) bodyRead {
	if len(bytes.TrimSpace(raw)) == 0 {
		return bodyRead{status: statusAbsent}
	}
	body, ok := normalizeBody(headers, raw)
	if !ok {
		return bodyRead{status: statusUnreadable}
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return bodyRead{status: statusAbsent}
	}
	// A top-level array is JSON-RPC batching, removed in MCP 2025-06-18. It is
	// checked explicitly because it is valid JSON that a batching-capable
	// upstream executes while hiding every tool name in it from this ACL, and
	// because that exposure is documented against defaultAction.
	if isBatchBody(body) {
		return bodyRead{status: statusUnreadable}
	}
	var req jsonrpcRequest
	// Unmarshal is also the framing check for everything else the revision
	// forbids: it rejects a second document, and any non-whitespace trailing
	// content, after the first ("invalid character ... after top-level value"),
	// accepting only insignificant whitespace. That rejection is what makes the
	// tool name returned below the tool name the upstream would execute.
	//
	// Do NOT replace this with a json.Decoder. Decoder.Decode stops at the end
	// of the first value and reports nothing about what follows, which would let
	// a smuggled second tools/call through unseen.
	if err := json.Unmarshal(body, &req); err != nil {
		return bodyRead{status: statusUnreadable}
	}
	out := bodyRead{status: statusMessage, method: req.Method}
	if err := json.Unmarshal(req.Params.Name, &out.tool); err == nil && out.tool != "" {
		out.hasTool = true
	}
	return out
}

// isBatchBody reports whether the JSON body is a top-level array, i.e. a
// JSON-RPC batch. Only the 2025-03-26 revision allowed batching; the versions
// we support (2025-06-18, 2025-11-25, 2026-07-28) require a single JSON-RPC object.
func isBatchBody(body []byte) bool {
	b := bytes.TrimLeft(body, " \t\r\n")
	return len(b) > 0 && b[0] == '['
}

// parseJSONRPCBody reads method and tool name out of an already-normalized
// body, reporting empty strings for anything unreadable. It is the
// field-extraction view of readBody, kept for the streaming-parser comparisons
// that only care about the two field values.
func parseJSONRPCBody(body []byte) (method, toolName string) {
	r := readBody(nil, body)
	if r.status != statusMessage {
		return "", ""
	}
	return r.method, r.tool
}
