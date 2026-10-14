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

// Full-chain scenarios that verify engine mechanics (ordered rules,
// stream-end error isolation, body-mode selection) using fake filters.
// Unlike the other scenario files, most of these tests intentionally
// assemble a bespoke chain via Options.Filters: they test how
// the engine dispatches a specific chain shape, which is exactly the
// exception to the "always use the production chain" rule.
package securityprofile

import (
	"context"
	"encoding/json"
	"testing"

	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	"k8s.io/utils/ptr"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/block"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/bypass"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/mcpacl"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
)

// recordingStreamLogger stands in for an audit-style logger; StreamLogger
// implementations cannot fail the response by contract — the assertion is
// that it was invoked after the response was committed.
type recordingStreamLogger struct {
	invoked bool
}

func (f *recordingStreamLogger) Log(context.Context, *filter.Stream, *filter.StreamInfo) {
	f.invoked = true
}

// fakeTokenFilter mimics a mutation filter like tokentransform: it claims
// rules carrying a TokenTransformation and injects a header.
type fakeTokenFilter struct {
	filter.PassThrough
	headerCalls int
}

func (f *fakeTokenFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	f.headerCalls++
	return filter.Continue(filter.SetHeader("x-injected-token", "fake-token-value")), nil
}

// fakeBodyMutationFilter is the body-needing variant, forcing BUFFERED.
type fakeBodyMutationFilter struct {
	filter.PassThrough
}

func (f *fakeBodyMutationFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(filter.CompleteBody), nil
}

func (f *fakeBodyMutationFilter) OnRequestBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	return filter.Continue(filter.SetHeader("x-injected-token", "fake-token-value")), nil
}

// tokenClaimReg wraps a fixed filter instance in a registration under the
// tokentransform name: payloadsFor emits that key exactly for rules
// carrying an enabled TokenTransformation, so the fake mounts on precisely
// those rules. "Not mounted" is the absent payload key, not an error.
func tokenClaimReg(f filter.Filter) filter.Registration {
	return filter.Registration{
		Name:   tokentransform.FilterName,
		Phases: filter.PhaseRequestHeaders | filter.PhaseRequestBody,
		Parse:  func(json.RawMessage) (any, error) { return struct{}{}, nil },
		New:    func(filter.ErasedRuleConfig) filter.Filter { return f },
	}
}

// regsWith builds the given definitions in order, then appends raw
// registrations.
func regsWith(t *testing.T, definitions []filter.Definition, raw ...filter.Registration) []filter.Registration {
	t.Helper()
	regs, err := filter.Build(definitions...)
	if err != nil {
		t.Fatalf("build filters: %v", err)
	}
	return append(regs, raw...)
}

// tokenTransformationAction is a minimal, CRD-valid TokenTransformationAction
// used in test rules so the fake filter can claim them. The valueTemplate is
// required by CRD validation but never rendered.
func tokenTransformationAction() *v1alpha1.TokenTransformationAction {
	return &v1alpha1.TokenTransformationAction{
		CredentialRef: v1alpha1.CredentialRef{
			Kind: v1alpha1.CredentialRefKindSecret,
			Name: "dummy",
		},
		ApiKey: &v1alpha1.ApiKeyConfig{
			TargetHeader:  "authorization",
			ValueTemplate: "Bearer {{ .Token }}",
		},
	}
}

// tokenTransformationRule builds a rule carrying a TokenTransformation
// action for the given domains.
func tokenTransformationRule(name string, domains ...string) v1alpha1.SecurityRule {
	return v1alpha1.SecurityRule{
		Name:  name,
		Match: []v1alpha1.RuleMatch{{Domains: domains}},
		Actions: v1alpha1.SecurityRuleActions{
			TokenTransformation: tokenTransformationAction(),
		},
	}
}

func TestHandleRequestHeaders_PostResolutionErrorDoesNotAffectBlockResponse(t *testing.T) {
	body := "exact-block-response-with-unreachable-audit"
	failing := &recordingStreamLogger{}
	// Bespoke chain: the real block filter plus a stream logger standing in
	// for an audit sink whose delivery problems must not leak into the
	// response.
	h := New(t, Options{
		Filters:       regsWith(t, []filter.Definition{block.Definition()}),
		StreamLoggers: []filter.StreamLogger{failing},
	})
	h.Fixture.ApplyProfile(securityProfile("p1", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{
		{
			Name: "block-with-failing-audit",
			Match: []v1alpha1.RuleMatch{{
				Domains: []string{"*"},
				Paths:   []v1alpha1.PathMatch{{Type: v1alpha1.PathMatchTypeExact, Value: "/audit/unreachable"}},
			}},
			Actions: v1alpha1.SecurityRuleActions{
				Block: &v1alpha1.BlockAction{StatusCode: 455, Body: ptr.To(body)},
			},
		},
	}))

	verdict := h.Run(t, blockedPeerRequest("GET", "api.example.com", "/audit/unreachable"))
	if !failing.invoked {
		t.Fatal("stream logger was not invoked")
	}
	verdict.RequireBlocked(t, 455)
	if verdict.ImmediateBody != body {
		t.Errorf("body: want %q, got %q", body, verdict.ImmediateBody)
	}
}

// TestHandleRequestHeaders_BypassBeforeTokenTransformation verifies that when
// a bypass rule appears BEFORE a tokenTransformation rule (both matching),
// the token transformation does NOT run because bypass skips later rules.
func TestHandleRequestHeaders_BypassBeforeTokenTransformation(t *testing.T) {
	fake := &fakeTokenFilter{}
	h := New(t, Options{
		Filters: regsWith(t, []filter.Definition{bypass.Definition()}, tokenClaimReg(fake)),
	})
	h.Fixture.ApplyProfile(securityProfile("p1", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{
		{
			Name:    "bypass-trusted",
			Match:   []v1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}},
			Actions: v1alpha1.SecurityRuleActions{Bypass: true},
		},
		tokenTransformationRule("inject-token", "api.example.com"),
	}))

	verdict := h.Run(t, blockedPeerRequest("POST", "api.example.com", "/v1/chat"))
	if fake.headerCalls != 0 {
		t.Error("mutation filter must NOT run when bypass appears before tokenTransformation")
	}
	// Bypassed means passthrough wire shape: no header mutation possible.
	verdict.RequireBypassed(t)
	// And it was the bypass rule that got there first.
	verdict.RequireAction(t, ":bypass:")
}

// TestHandleRequestHeaders_TokenTransformationBeforeBypass verifies that when
// a tokenTransformation rule appears BEFORE a bypass rule (both matching),
// the token transformation IS applied and bypass keeps the earlier rule's
// mutation work.
func TestHandleRequestHeaders_TokenTransformationBeforeBypass(t *testing.T) {
	fake := &fakeTokenFilter{}
	h := New(t, Options{
		Filters: regsWith(t, []filter.Definition{bypass.Definition()}, tokenClaimReg(fake)),
	})
	h.Fixture.ApplyProfile(securityProfile("p1", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{
		tokenTransformationRule("inject-token", "api.example.com"),
		{
			Name:    "bypass-trusted",
			Match:   []v1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}},
			Actions: v1alpha1.SecurityRuleActions{Bypass: true},
		},
	}))

	verdict := h.Run(t, blockedPeerRequest("POST", "api.example.com", "/v1/chat"))
	if fake.headerCalls == 0 {
		t.Fatal("mutation filter MUST run when tokenTransformation appears before bypass")
	}
	verdict.RequireHeader(t, "x-injected-token", "fake-token-value")
}

// TestHandleRequestHeaders_TokenTransformationBeforeBlock verifies that an
// earlier transformation runs before the later block decides the request.
func TestHandleRequestHeaders_TokenTransformationBeforeBlock(t *testing.T) {
	fake := &fakeTokenFilter{}
	h := New(t, Options{
		Filters: regsWith(t,
			[]filter.Definition{bypass.Definition(), block.Definition()},
			tokenClaimReg(fake)),
	})
	h.Fixture.ApplyProfile(securityProfile("p1", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{
		tokenTransformationRule("inject-token", "api.example.com"),
		{
			Name:  "block-all",
			Match: []v1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}},
			Actions: v1alpha1.SecurityRuleActions{
				Block: &v1alpha1.BlockAction{StatusCode: 403},
			},
		},
	}))

	verdict := h.Run(t, blockedPeerRequest("POST", "api.example.com", "/v1/chat"))
	if fake.headerCalls != 1 {
		t.Errorf("mutation filter ran %d times, want 1 before the later block", fake.headerCalls)
	}
	verdict.RequireBlocked(t, 403)
}

// The engine constructs one filter invocation per matching rule.
func TestHandleRequestHeaders_MutationFilterRunsOncePerRule(t *testing.T) {
	fake := &fakeTokenFilter{}
	h := New(t, Options{
		Filters: regsWith(t, nil, tokenClaimReg(fake)),
	})
	h.Fixture.ApplyProfile(securityProfile("p1", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{
		tokenTransformationRule("inject-global", "*"),
		tokenTransformationRule("inject-specific", "api.example.com"),
	}))

	h.Run(t, blockedPeerRequest("POST", "api.example.com", "/v1/chat"))
	if fake.headerCalls != 2 {
		t.Fatalf("filter invocations = %d, want 2", fake.headerCalls)
	}
}

// mcpToolPolicy builds an inline MCP tool policy with a single rule.
func mcpToolPolicy(defaultAction, method, toolName, action string) *v1alpha1.MCPToolPolicySpec {
	return &v1alpha1.MCPToolPolicySpec{
		DefaultAction: defaultAction,
		Rules: []v1alpha1.MCPToolPolicyRule{
			{Method: method, ToolNames: []string{toolName}, Action: action},
		},
	}
}

// mcpRequest builds an MCP POST to /mcp with a supported protocol version.
func mcpRequest(host string, body []byte) *enginetest.RequestBuilder {
	rb := enginetest.NewRequest("POST", host, "/mcp").
		Peer("default", "pod-x", map[string]string{"app": "blocked"}).
		Header("mcp-protocol-version", "2025-11-25")
	if body != nil {
		rb.Body(body)
	}
	return rb
}

func TestHandleRequestHeaders_BodylessRequestResumesBeforeLaterBlock(t *testing.T) {
	h := New(t, Options{})
	h.Fixture.ApplyProfile(securityProfile("p1", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{
		{
			Name:  "inspect-body",
			Match: []v1alpha1.RuleMatch{{Domains: []string{"mcp-server.example.com"}}},
			Actions: v1alpha1.SecurityRuleActions{
				MCPToolPolicy: mcpToolPolicy("deny", "tools/call", "safe-tool", "allow"),
			},
		},
		{
			Name:  "block-after-body-check",
			Match: []v1alpha1.RuleMatch{{Domains: []string{"mcp-server.example.com"}}},
			Actions: v1alpha1.SecurityRuleActions{
				Block: &v1alpha1.BlockAction{StatusCode: 409},
			},
		},
	}))

	verdict := h.Run(t, mcpRequest("mcp-server.example.com", nil))
	verdict.RequireBlocked(t, 409)
	if len(verdict.AccessLog) != 1 || verdict.AccessLog[0].Outcome != "blocked" {
		t.Fatalf("accesslog = %+v, want one blocked entry", verdict.AccessLog)
	}
}

// A body handler that can short-circuit the request must never be given
// STREAMED mode. In STREAMED, Envoy releases each chunk toward the upstream as
// soon as the ext-proc server acknowledges it, so a deny at chunk N has already
// delivered chunks 1..N-1 — the enforcement decision arrives after the bytes it
// was meant to withhold. BUFFERED forwards nothing until the whole body has
// been inspected, so it is the only safe mode for an enforcing handler.
func TestHandleRequestHeaders_EnforcingBodyHandlerNeverStreamed(t *testing.T) {
	// Production chain: mcpacl is the only body handler.
	h := New(t, Options{})
	h.Fixture.ApplyProfile(securityProfile("p1", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{
		{
			Name:  "body-rule",
			Match: []v1alpha1.RuleMatch{{Domains: []string{"mcp-server.example.com"}}},
			Actions: v1alpha1.SecurityRuleActions{
				MCPToolPolicy: mcpToolPolicy("deny", "tools/call", "safe-tool", "allow"),
			},
		},
	}))

	verdict := h.Run(t, mcpRequest("mcp-server.example.com", []byte(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe-tool"}}`,
	)))
	if verdict.Err != nil {
		t.Fatalf("unexpected error: %v", verdict.Err)
	}
	if verdict.ModeOverride == nil {
		t.Fatal("expected ModeOverride")
	}
	if got := verdict.ModeOverride.RequestBodyMode; got != extProcV3.ProcessingMode_BUFFERED {
		t.Fatalf("RequestBodyMode = %v, want BUFFERED; STREAMED leaks chunks upstream before the verdict", got)
	}
}

// Whatever the mix of body handlers, the negotiated mode is BUFFERED — see
// TestHandleRequestHeaders_EnforcingBodyHandlerNeverStreamed for why. This
// covers both chain shapes to prove the mode does not depend on which optional
// behaviours the handlers happen to have.
func TestHandleRequestHeaders_BodyModeSelection(t *testing.T) {
	tests := []struct {
		name     string
		actions  v1alpha1.SecurityRuleActions
		filters  func(t *testing.T) []filter.Registration
		wantMode extProcV3.ProcessingMode_BodySendMode
	}{
		{
			name: "single body handler uses buffered mode",
			actions: v1alpha1.SecurityRuleActions{
				MCPToolPolicy: mcpToolPolicy("deny", "tools/call", "safe-tool", "allow"),
			},
			// Production chain: mcpacl is the only body handler.
			filters:  func(*testing.T) []filter.Registration { return nil },
			wantMode: extProcV3.ProcessingMode_BUFFERED,
		},
		{
			name: "mixed body handlers also use buffered mode",
			actions: v1alpha1.SecurityRuleActions{
				MCPToolPolicy:       mcpToolPolicy("deny", "tools/call", "safe-tool", "allow"),
				TokenTransformation: tokenTransformationAction(),
			},
			// Bespoke chain: a mutation-capable fake body handler must
			// force BUFFERED alongside the stream-safe mcpacl.
			filters: func(t *testing.T) []filter.Registration {
				return regsWith(t,
					[]filter.Definition{mcpacl.Definition()},
					tokenClaimReg(&fakeBodyMutationFilter{}))
			},
			wantMode: extProcV3.ProcessingMode_BUFFERED,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := New(t, Options{Filters: tt.filters(t)})
			h.Fixture.ApplyProfile(securityProfile("p1", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{
				{
					Name:    "body-rule",
					Match:   []v1alpha1.RuleMatch{{Domains: []string{"mcp-server.example.com"}}},
					Actions: tt.actions,
				},
			}))

			verdict := h.Run(t, mcpRequest("mcp-server.example.com", []byte(
				`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe-tool"}}`,
			)))
			if verdict.Err != nil {
				t.Fatalf("unexpected error: %v", verdict.Err)
			}
			if verdict.ModeOverride == nil {
				t.Fatal("expected ModeOverride")
			}
			if verdict.ModeOverride.RequestBodyMode != tt.wantMode {
				t.Fatalf("RequestBodyMode = %v, want %v", verdict.ModeOverride.RequestBodyMode, tt.wantMode)
			}
		})
	}
}

func TestHandleRequestBody_MCPACLWildcardAllowSpecificDomainDeny(t *testing.T) {
	callSafeTool := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"safe-tool"}}`)

	profile := securityProfile("p1", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{
		{
			Name:  "global-mcp",
			Match: []v1alpha1.RuleMatch{{Domains: []string{"*"}}},
			Actions: v1alpha1.SecurityRuleActions{
				MCPToolPolicy: mcpToolPolicy("deny", "tools/call", "safe-tool", "allow"),
			},
		},
		{
			Name:  "specific-mcp",
			Match: []v1alpha1.RuleMatch{{Domains: []string{"mcp-server.example.com"}}},
			Actions: v1alpha1.SecurityRuleActions{
				MCPToolPolicy: mcpToolPolicy("allow", "tools/call", "safe-tool", "deny"),
			},
		},
	})

	t.Run("specific domain runs wildcard allow then specific deny", func(t *testing.T) {
		h := New(t, Options{})
		h.Fixture.ApplyProfile(profile)

		verdict := h.Run(t, mcpRequest("mcp-server.example.com", callSafeTool))
		if verdict.ModeOverride == nil {
			t.Fatal("expected ModeOverride requesting the body")
		}
		// The wildcard rule allows safe-tool; the more specific rule's
		// deny must still fire during the body phase.
		verdict.RequireBlocked(t, 403)
	})

	t.Run("other domain only runs wildcard allow", func(t *testing.T) {
		h := New(t, Options{})
		h.Fixture.ApplyProfile(profile)

		verdict := h.Run(t, mcpRequest("other.example.com", callSafeTool))
		if verdict.ModeOverride == nil {
			t.Fatal("expected ModeOverride requesting the body")
		}
		// The wildcard rule did match and allowed the tool, so the request is
		// bypassed rather than unpoliced: nothing on the wire changed, but a
		// unit was in force.
		verdict.RequireBypassed(t)
	})
}
