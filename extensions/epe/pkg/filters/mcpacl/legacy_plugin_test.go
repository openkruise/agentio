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
package mcpacl

import (
	"context"
	"encoding/json"
	"testing"
)

func jsonRPCBody(method, toolName string) []byte {
	m := map[string]any{"jsonrpc": "2.0", "method": method, "id": 1}
	if toolName != "" {
		m["params"] = map[string]any{"name": toolName}
	}
	b, _ := json.Marshal(m)
	return b
}

// TestOnRequestHeaders covers the headers-phase decision: rules without a
// policy skip, and everything else requests the body. Enforcement must not be
// skippable via the client-controlled version header, so the body is requested
// regardless of its value or absence; the version is checked in Finalize.
func TestOnRequestHeaders(t *testing.T) {
	governed := makeRule(&Config{
		DefaultAction: "deny",
		Rules:         []RuleEntry{{Method: "tools/call", Action: "allow"}},
	})

	tests := []struct {
		name string
		rule *legacyRule
		// version mutates the default supported header set by makeRctx:
		// "" keeps it, "absent" deletes it (may be the initialize request),
		// anything else overrides it.
		version       string
		wantAction    legacyAction
		wantNeedsBody bool
	}{
		{
			name:       "no policy action skips",
			rule:       &legacyRule{Name: "no-mcp"},
			wantAction: legacyContinue,
		},
		{
			name:          "unsupported version still requests body",
			rule:          governed,
			version:       "2025-03-26", // batch-era, unsupported
			wantAction:    legacyRecord,
			wantNeedsBody: true,
		},
		{
			name:          "supported version requests body",
			rule:          governed, // makeRctx sets version 2025-11-25
			wantAction:    legacyRecord,
			wantNeedsBody: true,
		},
		{
			name:          "no version header requests body",
			rule:          governed,
			version:       "absent",
			wantAction:    legacyRecord,
			wantNeedsBody: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newLegacyPlugin()
			rctx := makeRctx("application/json")
			switch tc.version {
			case "":
			case "absent":
				delete(rctx.Request.Headers, "mcp-protocol-version")
			default:
				rctx.Request.Headers["mcp-protocol-version"] = tc.version
			}

			result, err := p.OnRequestHeaders(context.Background(), rctx, nil, tc.rule)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Action != tc.wantAction || result.NeedsBody != tc.wantNeedsBody {
				t.Errorf("got action=%v needsBody=%v, want action=%v needsBody=%v",
					result.Action, result.NeedsBody, tc.wantAction, tc.wantNeedsBody)
			}
		})
	}
}

// TestFinalize_PolicyEvaluation drives the whitelist and blacklist verdicts
// for a governed tools/call through one table: policy shape + tool name in the
// body -> allow or deny.
func TestFinalize_PolicyEvaluation(t *testing.T) {
	whitelist := &Config{
		DefaultAction: "deny",
		Rules: []RuleEntry{
			{Method: "tools/call", ToolNames: []string{"read_file"}, Action: "allow"},
		},
	}
	blacklist := &Config{
		DefaultAction: "allow",
		Rules: []RuleEntry{
			{Method: "tools/call", ToolNames: []string{"exec_command"}, Action: "deny"},
		},
	}

	tests := []struct {
		name   string
		policy *Config
		tool   string
		want   legacyAction
	}{
		{"whitelist allows listed tool", whitelist, "read_file", legacyContinue},
		{"whitelist denies unlisted tool", whitelist, "delete_file", legacyImmediate},
		{"blacklist allows non-blacklisted tool", blacklist, "read_file", legacyContinue},
		{"blacklist denies blacklisted tool", blacklist, "exec_command", legacyImmediate},
		// A governed call with no readable tool name cannot be attributed to a
		// tool-scoped rule, so defaultAction decides — matching
		// traffix-extension. The accepted consequence is on the blacklist arm: a
		// caller evades every tool-scoped rule by omitting the name a lenient
		// upstream would still resolve. Whitelist policies still deny.
		{"empty tool name follows defaultAction under blacklist", blacklist, "", legacyContinue},
		{"empty tool name denied under whitelist", whitelist, "", legacyImmediate},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newLegacyPlugin()
			rctx := makeRctx("application/json")
			rctx.RequestBody = jsonRPCBody("tools/call", tc.tool)

			result, err := p.Finalize(context.Background(), rctx, nil, makeRule(tc.policy))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Action != tc.want {
				t.Errorf("Finalize action = %v, want %v", result.Action, tc.want)
			}
		})
	}
}

// Only tools/call is governed. Every other method — lifecycle, tools/list,
// resources/*, prompts/*, tasks/*, logging/* — passes through even under a
// strict whitelist, so no per-version allow-list is needed.
func TestFinalize_NonToolMethodsPassThrough(t *testing.T) {
	policy := &Config{
		DefaultAction: "deny",
		Rules:         []RuleEntry{},
	}
	p := newLegacyPlugin()
	rule := makeRule(policy)

	for _, method := range []string{
		"initialize", "ping", "notifications/initialized", "notifications/cancelled",
		"tools/list", "resources/read", "prompts/get", "logging/setLevel",
		"tasks/get", "tasks/result",
	} {
		t.Run(method, func(t *testing.T) {
			rctx := makeRctx("application/json")
			rctx.RequestBody = jsonRPCBody(method, "")

			result, err := p.Finalize(context.Background(), rctx, nil, rule)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Action != legacyContinue {
				t.Errorf("%s should pass through (not governed), got %v", method, result.Action)
			}
		})
	}
}

// TestFinalize_BodyParsing covers bodies that do not carry a governed call:
// an empty body and a method-less message have nothing to enforce and skip,
// while malformed JSON is denied as unreadable.
func TestFinalize_BodyParsing(t *testing.T) {
	policy := &Config{
		DefaultAction: "deny",
		Rules:         []RuleEntry{},
	}

	tests := []struct {
		name string
		body []byte
		want legacyAction
	}{
		{"empty body skips", nil, legacyContinue},
		{"malformed JSON denied as unreadable", []byte("{not valid json"), legacyImmediate},
		{"no method field skips", []byte(`{"jsonrpc":"2.0","id":1}`), legacyContinue},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newLegacyPlugin()
			rctx := makeRctx("application/json")
			rctx.RequestBody = tc.body

			result, err := p.Finalize(context.Background(), rctx, nil, makeRule(policy))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Action != tc.want {
				t.Errorf("Finalize action = %v, want %v", result.Action, tc.want)
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	policy := &Config{
		DefaultAction: "deny",
		Rules: []RuleEntry{
			{Method: "tools/call", ToolNames: []string{"read_file", "write_file"}, Action: "allow"},
			{Method: "tools/list", Action: "allow"},
			{Method: "tools/call", ToolNames: []string{"exec_command"}, Action: "deny"},
		},
	}

	tests := []struct {
		name     string
		method   string
		toolName string
		want     string
	}{
		{"allowed tool", "tools/call", "read_file", "allow"},
		{"second allowed tool", "tools/call", "write_file", "allow"},
		{"unlisted tool falls to default", "tools/call", "unknown", "deny"},
		{"tools/list no toolNames", "tools/list", "", "allow"},
		{"unmatched method falls to default", "resources/read", "", "deny"},
		{"empty toolName skips tool-specific rules", "tools/call", "", "deny"},
		{"first match wins - allow before deny", "tools/call", "read_file", "allow"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := evaluate(configOf(policy), tc.method, tc.toolName)
			if got != tc.want {
				t.Errorf("evaluate(%q, %q) = %q, want %q", tc.method, tc.toolName, got, tc.want)
			}
		})
	}
}

func TestParseJSONRPCBody(t *testing.T) {
	tests := []struct {
		name       string
		body       []byte
		wantMethod string
		wantTool   string
	}{
		{"full request", jsonRPCBody("tools/call", "read_file"), "tools/call", "read_file"},
		{"method only", jsonRPCBody("tools/list", ""), "tools/list", ""},
		{"empty body", nil, "", ""},
		{"malformed json", []byte("{bad"), "", ""},
		{"no method", []byte(`{"id":1}`), "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, tn := parseJSONRPCBody(tc.body)
			if m != tc.wantMethod || tn != tc.wantTool {
				t.Errorf("got (%q, %q), want (%q, %q)", m, tn, tc.wantMethod, tc.wantTool)
			}
		})
	}
}

// JSON-RPC batch (array) bodies are only valid in MCP 2025-03-26, which we do
// not support. A batch is a framing violation, and like every other framing
// violation it is decided by defaultAction, matching traffix-extension.
//
// The blacklist arm below pins the accepted consequence directly: wrapping a
// denied call in an array admits it, because the ACL never reads the tool name
// out of a batch. It only becomes an executed call on an upstream that still
// accepts 2025-03-26 batching; a server implementing only the revisions this
// ACL polices rejects it. Whitelist policies deny it either way.
func TestFinalize_BatchBody(t *testing.T) {
	batch := []byte(`[{"jsonrpc":"2.0","method":"tools/call","params":{"name":"delete_repo"},"id":1}]`)

	t.Run("whitelist denies batch", func(t *testing.T) {
		policy := &Config{
			DefaultAction: "deny",
			Rules:         []RuleEntry{{Method: "tools/call", ToolNames: []string{"safe"}, Action: "allow"}},
		}
		p := newLegacyPlugin()
		rctx := makeRctx("application/json")
		rctx.RequestBody = batch

		result, err := p.Finalize(context.Background(), rctx, nil, makeRule(policy))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Action != legacyImmediate {
			t.Errorf("batch under whitelist should deny (ActionImmediate), got %v", result.Action)
		}
	})

	t.Run("blacklist admits batch wrapping a denied tool", func(t *testing.T) {
		policy := &Config{
			DefaultAction: "allow",
			Rules:         []RuleEntry{{Method: "tools/call", ToolNames: []string{"delete_repo"}, Action: "deny"}},
		}
		p := newLegacyPlugin()
		rctx := makeRctx("application/json")
		rctx.RequestBody = batch

		result, err := p.Finalize(context.Background(), rctx, nil, makeRule(policy))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// delete_repo is denied by rule, yet the array hides it from the ACL and
		// defaultAction: allow decides. Asserted so the exposure cannot be
		// removed or reintroduced without this test changing.
		if result.Action != legacyContinue {
			t.Errorf("batch under defaultAction=allow must pass through, got %v", result.Action)
		}
	})
}

// When unsupportedVersionAction=passthrough, tools/call with an unsupported or
// missing version header skips ACL and passes through instead of being denied.
func TestFinalize_VersionGate_Passthrough(t *testing.T) {
	policy := &Config{
		DefaultAction:            "deny",
		UnsupportedVersionAction: "passthrough",
		Rules:                    []RuleEntry{{Method: "tools/call", ToolNames: []string{"safe"}, Action: "allow"}},
	}
	p := newLegacyPlugin()

	t.Run("unsupported version passes through", func(t *testing.T) {
		rctx := makeRctx("application/json")
		rctx.Request.Headers["mcp-protocol-version"] = "2025-03-26"
		rctx.RequestBody = jsonRPCBody("tools/call", "anything")

		result, err := p.Finalize(context.Background(), rctx, nil, makeRule(policy))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Action != legacyContinue {
			t.Errorf("unsupported version with passthrough policy should pass, got %v", result.Action)
		}
	})

	t.Run("absent version passes through", func(t *testing.T) {
		rctx := makeRctx("application/json")
		delete(rctx.Request.Headers, "mcp-protocol-version")
		rctx.RequestBody = jsonRPCBody("tools/call", "anything")

		result, err := p.Finalize(context.Background(), rctx, nil, makeRule(policy))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Action != legacyContinue {
			t.Errorf("absent version with passthrough policy should pass, got %v", result.Action)
		}
	})

	t.Run("supported version still evaluates rules", func(t *testing.T) {
		rctx := makeRctx("application/json") // 2025-11-25
		rctx.RequestBody = jsonRPCBody("tools/call", "forbidden")

		result, err := p.Finalize(context.Background(), rctx, nil, makeRule(policy))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Action != legacyImmediate {
			t.Errorf("supported version should still evaluate rules and deny unlisted tool, got %v", result.Action)
		}
	})
}

// A tool call must come from a supported protocol version. The version header
// is attacker-controlled, so it can only make enforcement stricter: a missing
// or unsupported version on a tools/call is denied, never a free pass. A
// supported version with an allowed tool must still pass (no false denial).
// Non-tool methods are unaffected (they pass regardless — see
// NonToolMethodsPassThrough).
func TestFinalize_VersionGate(t *testing.T) {
	// Whitelist that allows the "safe" tool; "delete_repo" would be denied.
	policy := &Config{
		DefaultAction: "deny",
		Rules:         []RuleEntry{{Method: "tools/call", ToolNames: []string{"safe"}, Action: "allow"}},
	}
	p := newLegacyPlugin()

	// A supported version + an allowed tool must still pass (no false denial).
	t.Run("supported version, allowed tool passes", func(t *testing.T) {
		rctx := makeRctx("application/json") // version 2025-11-25
		rctx.RequestBody = jsonRPCBody("tools/call", "safe")

		result, err := p.Finalize(context.Background(), rctx, nil, makeRule(policy))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Action != legacyContinue {
			t.Errorf("allowed tool on supported version should pass, got %v", result.Action)
		}
	})

	// The version header cannot disable enforcement: unsupported or absent
	// versions deny the call, while other supported versions still allow the
	// whitelisted tool.
	for name, version := range map[string]string{
		"unsupported (2025-03-26)": "2025-03-26",
		"absent":                   "",
		"other supported":          "2025-06-18",
		"GA (2026-07-28)":          "2026-07-28",
	} {
		t.Run("tools/call on "+name, func(t *testing.T) {
			rctx := makeRctx("application/json")
			if version == "" {
				delete(rctx.Request.Headers, "mcp-protocol-version")
			} else {
				rctx.Request.Headers["mcp-protocol-version"] = version
			}
			rctx.RequestBody = jsonRPCBody("tools/call", "safe") // allowed tool...

			result, err := p.Finalize(context.Background(), rctx, nil, makeRule(policy))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// Supported versions (2025-06-18, 2026-07-28) allow the whitelisted
			// tool; unsupported or absent versions deny the whole call.
			if version == "2025-06-18" || version == "2026-07-28" {
				if result.Action != legacyContinue {
					t.Errorf("allowed tool on supported %q should pass, got %v", version, result.Action)
				}
			} else if result.Action != legacyImmediate {
				t.Errorf("tools/call on version %q should deny, got %v", version, result.Action)
			}
		})
	}
}
