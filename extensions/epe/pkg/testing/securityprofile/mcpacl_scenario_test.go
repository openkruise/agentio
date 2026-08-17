// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Full-chain MCP policy scenarios driven through the enginetest harness; see
// extensions/epe/pkg/testing/enginetest/doc.go. These cover the
// CRD-to-filter wiring and body buffering; decision semantics are tested in
// the package unit tests.
package securityprofile

import (
	"fmt"
	"testing"

	"istio.io/istio/extensions/epe/pkg/testing/enginetest"
)

const mcpPolicyYAML = `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: mcp-whitelist
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: whitelist
    match:
    - domains:
      - "*"
      paths:
      - type: Exact
        value: /mcp
      methods:
      - POST
    actions:
      mcpToolPolicy:
        defaultAction: deny
        denyResponse:
          statusCode: 451
          body: denied-by-mcp-whitelist
        rules:
        - method: tools/call
          toolNames:
          - allowed-tool
          action: allow
`

func TestScenario_WhitelistFromCRDYAML(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(mcpPolicyYAML)

	request := func(tool string) *enginetest.RequestBuilder {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":%q}}`, tool)
		return enginetest.NewRequest("POST", "server.example.com", "/mcp").
			Peer("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"}).
			Header("content-type", "application/json").
			Header("mcp-protocol-version", "2025-11-25").
			Body([]byte(body))
	}

	h.Run(t, request("unlisted-tool")).RequireBlockedBody(t, 451, "denied-by-mcp-whitelist")

	allowed := h.Run(t, request("allowed-tool"))
	if allowed.Kind == enginetest.VerdictBlocked {
		t.Fatalf("whitelisted tool was blocked: %+v", allowed)
	}
}

// A request matching an mcpToolPolicy rule but carrying no body must still be
// audited. mcpacl asks for the body unconditionally — it cannot know the
// JSON-RPC method without it — so a bodyless POST registers a body handler.
// But ext_proc sends no body message when the headers message already ended
// the stream, so the body phase never runs; handing audit to a phase that
// never runs would lose the entry entirely.
func TestScenario_BodylessMCPRequestIsStillAudited(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(mcpPolicyYAML)

	// No .Body() call, so HeadersMsg sets EndOfStream=true
	// (enginetest/request.go:181) and Build emits only the headers message.
	verdict := h.Run(t, enginetest.NewRequest("POST", "server.example.com", "/mcp").
		Peer("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"}).
		Header("content-type", "application/json"))

	if len(verdict.AccessLog) != 1 {
		t.Fatalf("want exactly 1 accesslog entry for a bodyless request, got %d: %+v",
			len(verdict.AccessLog), verdict.AccessLog)
	}
}

// The headers phase and the body phase must not both submit. An operator
// counting denials off the accesslog double-counts every body-phase block if
// they do. A unit test on HandleRequestBody cannot catch this — only driving
// both messages through Process can.
func TestScenario_BodyPhaseDenyAuditsExactlyOnce(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(mcpPolicyYAML)

	body := `{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"unlisted-tool"}}`
	verdict := h.Run(t, enginetest.NewRequest("POST", "server.example.com", "/mcp").
		Peer("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"}).
		Header("content-type", "application/json").
		Body([]byte(body)))

	verdict.RequireBlockedBody(t, 451, "denied-by-mcp-whitelist")

	if len(verdict.AccessLog) != 1 {
		t.Fatalf("want exactly 1 accesslog entry, got %d: %+v",
			len(verdict.AccessLog), verdict.AccessLog)
	}
	got := verdict.AccessLog[0]
	if got.Outcome != "blocked" {
		t.Errorf("Outcome = %q, want \"blocked\" — the body-phase verdict must be what is recorded", got.Outcome)
	}
	if n := got.Skipped["mcpacl"]; n != 0 {
		t.Errorf("Skipped[\"mcpacl\"] = %d, want 0 — the plugin decided, it was not skipped", n)
	}
}

// Headers with end_of_stream=false and no body message ever arriving. The
// Step 5 guard hands audit to the body phase here — end_of_stream was false —
// but the body phase never runs, so only the Process stream-exit fallback
// submits. This is the test that fails if someone deletes that defer as
// redundant.
func TestScenario_StreamingHeadersWithoutBodyIsStillAudited(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(mcpPolicyYAML)

	verdict := h.Run(t, enginetest.NewRequest("POST", "server.example.com", "/mcp").
		Peer("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"}).
		Header("content-type", "application/json").
		StreamingHeaders())

	if len(verdict.AccessLog) != 1 {
		t.Fatalf("want exactly 1 accesslog entry when headers say more-to-come but no body arrives, got %d: %+v",
			len(verdict.AccessLog), verdict.AccessLog)
	}
}

// TestScenario_ChunkedBodyDelivery pins the verdict when a body arrives split
// across several messages — a shape Envoy's BUFFERED mode never produces but
// the extension must still judge, including a cut through the middle of the
// JSON-RPC "method" key.
func TestScenario_ChunkedBodyDelivery(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(mcpPolicyYAML)

	body := `{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"unlisted-tool"}}`
	for _, cut := range []int{1, 25, len(body) - 1} {
		verdict := h.Run(t, enginetest.NewRequest("POST", "server.example.com", "/mcp").
			Peer("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"}).
			Header("mcp-protocol-version", "2025-11-25").
			BodyChunks([]byte(body[:cut]), []byte(body[cut:])))
		verdict.RequireBlockedBody(t, 451, "denied-by-mcp-whitelist")
	}
}

// TestScenario_GAFastPath exercises the MCP 2026-07-28 GA fast path through
// the full engine. The mandatory Mcp-Method and Mcp-Name headers enable:
//   - Denied tools/call: blocked from headers alone (Stop, no body buffering).
//   - Allowed tools/call: NeedsBody for header/body verification, then passes.
//   - Non-governed methods: Continue immediately (no body buffering).
func TestScenario_GAFastPath(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyYAML(mcpPolicyYAML)

	peer := func() *enginetest.RequestBuilder {
		return enginetest.NewRequest("POST", "server.example.com", "/mcp").
			Peer("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"}).
			Header("content-type", "application/json").
			Header("mcp-protocol-version", "2026-07-28")
	}

	// Denied tool: fast-path deny from headers alone — body never processed.
	denied := h.Run(t, peer().
		Header("mcp-method", "tools/call").
		Header("mcp-name", "evil").
		Body([]byte(`{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"evil"}}`)))
	denied.RequireBlockedBody(t, 451, "denied-by-mcp-whitelist")

	// Allowed tool: fast-path NeedBody, then body confirms the allow.
	allowed := h.Run(t, peer().
		Header("mcp-method", "tools/call").
		Header("mcp-name", "allowed-tool").
		Body([]byte(`{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"allowed-tool"}}`)))
	if allowed.Kind == enginetest.VerdictBlocked {
		t.Fatalf("allowed tool was blocked: %+v", allowed)
	}
	if allowed.ModeOverride == nil {
		t.Fatal("expected ModeOverride for allowed tool — NeedsBody should request body buffering")
	}

	// Non-governed method: fast-path Continue, no body buffering needed.
	nonGoverned := h.Run(t, peer().
		Header("mcp-method", "tools/list").
		Body([]byte(`{"jsonrpc":"2.0","id":"1","method":"tools/list"}`)))
	if nonGoverned.Kind == enginetest.VerdictBlocked {
		t.Fatalf("non-governed method was blocked: %+v", nonGoverned)
	}
	if nonGoverned.ModeOverride != nil {
		t.Fatal("non-governed method should not request body buffering — fast-path Continue")
	}
}
