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
	"testing"

	"istio.io/istio/extensions/epe/pkg/httpreq"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

func whitelistCfg() Config {
	return Config{
		DefaultAction: "deny",
		DenyStatus:    451,
		DenyBody:      "denied-by-whitelist",
		Rules:         []RuleEntry{{Method: "tools/call", ToolNames: []string{"allowed-tool"}, Action: "allow"}},
	}
}

func streamWithVersion(v string) *filter.Stream {
	headers := map[string]string{}
	if v != "" {
		headers[mcpProtocolVersionHeader] = v
	}
	return &filter.Stream{Request: httpreq.HTTPRequest{Headers: headers}}
}

func runBody(t *testing.T, cfg Config, st *filter.Stream, body string) filter.Action {
	t.Helper()
	f := New(filter.RuleConfig[Config]{ID: filter.UnitID{Scope: "ns/p", Name: "r"}, Cfg: cfg})
	act, err := f.OnRequestBody(context.Background(), st, filter.Body{Bytes: []byte(body), Complete: true})
	if err != nil {
		t.Fatalf("OnRequestBody: %v", err)
	}
	return act
}

func TestFilter_HeadersAlwaysNeedsBody(t *testing.T) {
	f := New(filter.RuleConfig[Config]{Cfg: whitelistCfg()})
	act, err := f.OnRequestHeaders(context.Background(), streamWithVersion("2025-11-25"))
	if err != nil {
		t.Fatalf("OnRequestHeaders: %v", err)
	}
	if act.Kind() != filter.KindNeedBody {
		t.Fatalf("Kind = %v, want KindNeedBody — the method is only knowable from the body", act.Kind())
	}
}

func TestFilter_WhitelistDecisions(t *testing.T) {
	st := streamWithVersion("2025-11-25")
	cases := []struct {
		name string
		body string
		want filter.ActionKind
	}{
		{"unlisted tool denied", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"evil"}}`, filter.KindStop},
		{"allowed tool passes", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"allowed-tool"}}`, filter.KindContinue},
		{"non-governed method passes", `{"jsonrpc":"2.0","method":"tools/list"}`, filter.KindContinue},
		// A body the ACL cannot read is denied, not passed: an upstream JSON
		// stack more lenient than this one would execute what the policy never
		// got to see.
		{"unreadable body denied", `not-json`, filter.KindStop},
		{"empty body passes", ``, filter.KindContinue},
		{"batch body denied as framing violation", `[{"method":"tools/call"}]`, filter.KindStop},
		{"multi-document body denied as framing violation", `{"method":"ping"}{"method":"tools/call","params":{"name":"evil"}}`, filter.KindStop},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			act := runBody(t, whitelistCfg(), st, tc.body)
			if act.Kind() != tc.want {
				t.Errorf("Kind = %v, want %v", act.Kind(), tc.want)
			}
			if tc.want == filter.KindStop {
				r, _ := act.Reply()
				if r.Status != 451 || string(r.Body) != "denied-by-whitelist" {
					t.Errorf("Reply = %+v, want the policy deny response", r)
				}
			}
		})
	}
}

func TestFilter_UnsupportedVersion(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"allowed-tool"}}`

	t.Run("deny by default", func(t *testing.T) {
		act := runBody(t, whitelistCfg(), streamWithVersion(""), body)
		if act.Kind() != filter.KindStop {
			t.Errorf("Kind = %v, want KindStop for missing version", act.Kind())
		}
	})
	t.Run("passthrough when policy opts out", func(t *testing.T) {
		cfg := whitelistCfg()
		cfg.UnsupportedVersionAction = "passthrough"
		act := runBody(t, cfg, streamWithVersion("1999-01-01"), body)
		if act.Kind() != filter.KindContinue {
			t.Errorf("Kind = %v, want KindContinue per policy", act.Kind())
		}
	})
	t.Run("supported GA version allows tool", func(t *testing.T) {
		act := runBody(t, whitelistCfg(), streamWithVersion("2026-07-28"), body)
		if act.Kind() != filter.KindContinue {
			t.Errorf("Kind = %v, want KindContinue for 2026-07-28 (GA)", act.Kind())
		}
	})
}

func TestEvaluateDefaultActionFallback(t *testing.T) {
	blacklist := Config{
		DefaultAction: "allow",
		Rules:         []RuleEntry{{Method: "tools/call", ToolNames: []string{"banned"}, Action: "deny"}},
	}
	if got := evaluate(blacklist, "tools/call", "banned"); got != "deny" {
		t.Errorf("banned tool = %q, want deny", got)
	}
	if got := evaluate(blacklist, "tools/call", "other"); got != "allow" {
		t.Errorf("other tool = %q, want allow (default)", got)
	}
	if got := evaluate(blacklist, "tools/call", ""); got != "allow" {
		t.Errorf("empty tool with tool-scoped rule = %q, want allow", got)
	}
}

// An un-defaulted DefaultAction must deny, not allow. The CRD defaults it to
// "deny" (securityprofile_types.go +kubebuilder:default:=deny), so an empty
// value means the object never went through API-server defaulting — a config
// this filter cannot serve. Failing open there would silently disable the
// ACL, so the data plane re-applies the default the way block and
// tokentransform already re-apply theirs.
// Asserted on the decision as honoured, not on evaluate's raw return: the
// fail-closed step is the call site's "only actionAllow allows", so evaluate
// reports the configured value verbatim and an empty one is simply not an
// allow.
func TestEvaluateEmptyDefaultActionDenies(t *testing.T) {
	whitelist := Config{
		Rules: []RuleEntry{{Method: "tools/call", ToolNames: []string{"allowed"}, Action: "allow"}},
	}
	if got := evaluate(whitelist, "tools/call", "unlisted"); got == actionAllow {
		t.Errorf("unlisted tool with empty DefaultAction = %q, must not be an allow", got)
	}
	if got := evaluate(whitelist, "resources/read", ""); got == actionAllow {
		t.Errorf("unmatched method with empty DefaultAction = %q, must not be an allow", got)
	}
	// An explicit allow must still win — this is not a blanket deny.
	if got := evaluate(whitelist, "tools/call", "allowed"); got != actionAllow {
		t.Errorf("explicitly allowed tool = %q, want allow", got)
	}
}
