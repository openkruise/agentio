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
package securityprofile

import (
	"net/url"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
)

// reqInfo is a one-line builder for httpreq.HTTPRequest so the test table stays
// readable.
func reqInfo(host, path, method string, port int32, headers map[string]string, query url.Values) httpreq.HTTPRequest {
	return httpreq.HTTPRequest{
		Host:    host,
		Port:    port,
		Path:    path,
		Method:  method,
		Headers: headers,
		Query:   query,
	}
}

func TestCompileRulesExcludesTLSFromHTTP(t *testing.T) {
	for _, action := range []v1alpha1.TLSActionType{v1alpha1.TLSActionDeny, v1alpha1.TLSActionPassthrough} {
		t.Run(string(action), func(t *testing.T) {
			rules := []v1alpha1.SecurityRule{
				{
					Name:    "tls",
					Match:   []v1alpha1.RuleMatch{{Domains: []string{"*"}}},
					Actions: v1alpha1.SecurityRuleActions{TLS: &v1alpha1.TLSAction{Action: action}},
				},
				matchAllRule("http"),
			}
			compiled, err := compileRules(rules)
			if err != nil || len(compiled) != 1 || compiled[0].Name != "http" {
				t.Fatalf("HTTP rules = %+v, error = %v", compiled, err)
			}
			rules[0].Actions.Bypass = true
			if _, err := compileRules(rules); err == nil {
				t.Fatal("mixed TLS/HTTP action accepted")
			}
		})
	}
}

// TestCompileRuleMatch_AndMatches drives every branch of Match.Matches
// through a table so the matcher's intent is documented alongside its
// behaviour.
func TestCompileRuleMatch_AndMatches(t *testing.T) {
	tests := []struct {
		name string
		raw  v1alpha1.RuleMatch
		req  httpreq.HTTPRequest
		want bool
	}{
		{
			name: "wildcard domain matches anything",
			raw:  v1alpha1.RuleMatch{Domains: []string{"*"}},
			req:  reqInfo("api.example.com", "/x", "GET", 0, nil, nil),
			want: true,
		},
		{
			name: "exact domain matches case-insensitively",
			raw:  v1alpha1.RuleMatch{Domains: []string{"API.example.com"}},
			req:  reqInfo("api.EXAMPLE.com", "/", "GET", 0, nil, nil),
			want: true,
		},
		{
			name: "suffix wildcard matches subdomain",
			raw:  v1alpha1.RuleMatch{Domains: []string{"*.example.com"}},
			req:  reqInfo("api.example.com", "/", "GET", 0, nil, nil),
			want: true,
		},
		{
			name: "suffix wildcard rejects bare apex",
			raw:  v1alpha1.RuleMatch{Domains: []string{"*.example.com"}},
			req:  reqInfo("example.com", "/", "GET", 0, nil, nil),
			want: false,
		},
		{
			name: "no domain match returns false",
			raw:  v1alpha1.RuleMatch{Domains: []string{"foo.com"}},
			req:  reqInfo("bar.com", "/", "GET", 0, nil, nil),
			want: false,
		},
		{
			name: "empty domains list never matches",
			raw:  v1alpha1.RuleMatch{Domains: nil},
			req:  reqInfo("any.com", "/", "GET", 0, nil, nil),
			want: false,
		},
		{
			name: "exact path match",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				Paths:   []v1alpha1.PathMatch{{Type: v1alpha1.PathMatchTypeExact, Value: "/admin"}},
			},
			req:  reqInfo("h", "/admin", "GET", 0, nil, nil),
			want: true,
		},
		{
			name: "exact path mismatch",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				Paths:   []v1alpha1.PathMatch{{Type: v1alpha1.PathMatchTypeExact, Value: "/admin"}},
			},
			req:  reqInfo("h", "/admin/keys", "GET", 0, nil, nil),
			want: false,
		},
		{
			name: "prefix path match",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				Paths:   []v1alpha1.PathMatch{{Type: v1alpha1.PathMatchTypePrefix, Value: "/v1/chat"}},
			},
			req:  reqInfo("h", "/v1/chat/completions", "POST", 0, nil, nil),
			want: true,
		},
		{
			name: "regex path match",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				Paths:   []v1alpha1.PathMatch{{Type: v1alpha1.PathMatchTypeRegex, Value: `^/v\d+/.*$`}},
			},
			req:  reqInfo("h", "/v2/foo", "GET", 0, nil, nil),
			want: true,
		},
		// An invalid path regex used to compile to a nil matcher that never
		// matched; it is now rejected outright, so the case lives in
		// TestCompileRuleMatch_InvalidRegexIsRejected instead.
		{
			name: "method match case-insensitive",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				Methods: []string{"POST"},
			},
			req:  reqInfo("h", "/", "post", 0, nil, nil),
			want: true,
		},
		{
			name: "method mismatch",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				Methods: []string{"POST"},
			},
			req:  reqInfo("h", "/", "GET", 0, nil, nil),
			want: false,
		},
		{
			name: "port match",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				Ports:   []int32{443, 8443},
			},
			req:  reqInfo("h", "/", "GET", 443, nil, nil),
			want: true,
		},
		{
			name: "port zero never matches non-empty ports",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				Ports:   []int32{443},
			},
			req:  reqInfo("h", "/", "GET", 0, nil, nil),
			want: false,
		},
		{
			name: "port mismatch",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				Ports:   []int32{443},
			},
			req:  reqInfo("h", "/", "GET", 80, nil, nil),
			want: false,
		},
		{
			name: "header exact match (header name lowercased internally)",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				Headers: []v1alpha1.HeaderMatch{{Name: "X-Foo", Type: v1alpha1.StringMatchTypeExact, Value: "bar"}},
			},
			req:  reqInfo("h", "/", "GET", 0, map[string]string{"x-foo": "bar"}, nil),
			want: true,
		},
		{
			name: "header missing returns false",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				Headers: []v1alpha1.HeaderMatch{{Name: "X-Foo", Type: v1alpha1.StringMatchTypeExact, Value: "bar"}},
			},
			req:  reqInfo("h", "/", "GET", 0, map[string]string{}, nil),
			want: false,
		},
		{
			name: "header value mismatch",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				Headers: []v1alpha1.HeaderMatch{{Name: "X-Foo", Type: v1alpha1.StringMatchTypeExact, Value: "bar"}},
			},
			req:  reqInfo("h", "/", "GET", 0, map[string]string{"x-foo": "baz"}, nil),
			want: false,
		},
		{
			name: "header prefix match",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				Headers: []v1alpha1.HeaderMatch{
					{Name: "Authorization", Type: v1alpha1.StringMatchTypePrefix, Value: "Bearer "},
				},
			},
			req:  reqInfo("h", "/", "GET", 0, map[string]string{"authorization": "Bearer xyz"}, nil),
			want: true,
		},
		{
			name: "header regex match",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				Headers: []v1alpha1.HeaderMatch{
					{Name: "X-RequestID", Type: v1alpha1.StringMatchTypeRegex, Value: `^[a-f0-9]{8}$`},
				},
			},
			req:  reqInfo("h", "/", "GET", 0, map[string]string{"x-requestid": "deadbeef"}, nil),
			want: true,
		},
		// Invalid header regex: likewise rejected at compile time now.
		{
			name: "unknown header type fails closed",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				Headers: []v1alpha1.HeaderMatch{{Name: "X-Foo", Type: "Weird", Value: "x"}},
			},
			req:  reqInfo("h", "/", "GET", 0, map[string]string{"x-foo": "x"}, nil),
			want: false,
		},
		{
			name: "query param exact match",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				QueryParams: []v1alpha1.QueryParamMatch{
					{Name: "model", Type: v1alpha1.StringMatchTypeExact, Value: "gpt-4"},
				},
			},
			req:  reqInfo("h", "/", "GET", 0, nil, url.Values{"model": {"gpt-4"}}),
			want: true,
		},
		{
			name: "query param missing fails",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				QueryParams: []v1alpha1.QueryParamMatch{
					{Name: "model", Type: v1alpha1.StringMatchTypeExact, Value: "gpt-4"},
				},
			},
			req:  reqInfo("h", "/", "GET", 0, nil, url.Values{}),
			want: false,
		},
		{
			name: "query param regex match",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"*"},
				QueryParams: []v1alpha1.QueryParamMatch{
					{Name: "v", Type: v1alpha1.StringMatchTypeRegex, Value: `^\d+$`},
				},
			},
			req:  reqInfo("h", "/", "GET", 0, nil, url.Values{"v": {"42"}}),
			want: true,
		},
		{
			name: "all match (AND) succeeds",
			raw: v1alpha1.RuleMatch{
				Domains: []string{"api.example.com"},
				Paths:   []v1alpha1.PathMatch{{Type: v1alpha1.PathMatchTypePrefix, Value: "/v1"}},
				Methods: []string{"POST"},
				Ports:   []int32{443},
				Headers: []v1alpha1.HeaderMatch{{Name: "X-K", Type: v1alpha1.StringMatchTypeExact, Value: "v"}},
				QueryParams: []v1alpha1.QueryParamMatch{
					{Name: "n", Type: v1alpha1.StringMatchTypePrefix, Value: "abc"},
				},
			},
			req: reqInfo("api.example.com", "/v1/x", "POST", 443,
				map[string]string{"x-k": "v"},
				url.Values{"n": {"abc-001"}}),
			want: true,
		},
		// Scheme matching is ANDed with the other clauses like every field
		// above.
		{
			name: "https scheme matches",
			raw:  v1alpha1.RuleMatch{Domains: []string{"*"}, Schemes: []string{"https"}},
			req:  httpreq.HTTPRequest{Host: "example.com", Scheme: "https"},
			want: true,
		},
		{
			name: "http scheme does not match https-only rule",
			raw:  v1alpha1.RuleMatch{Domains: []string{"*"}, Schemes: []string{"https"}},
			req:  httpreq.HTTPRequest{Host: "example.com", Scheme: "http"},
			want: false,
		},
		{
			name: "case-insensitive scheme match",
			raw:  v1alpha1.RuleMatch{Domains: []string{"*"}, Schemes: []string{"HTTPS"}},
			req:  httpreq.HTTPRequest{Host: "example.com", Scheme: "https"},
			want: true,
		},
		{
			name: "multiple schemes ORed",
			raw:  v1alpha1.RuleMatch{Domains: []string{"*"}, Schemes: []string{"http", "https"}},
			req:  httpreq.HTTPRequest{Host: "example.com", Scheme: "http"},
			want: true,
		},
		{
			name: "empty schemes means no filter",
			raw:  v1alpha1.RuleMatch{Domains: []string{"*"}},
			req:  httpreq.HTTPRequest{Host: "example.com", Scheme: "http"},
			want: true,
		},
		{
			name: "empty request scheme does not match non-empty rule",
			raw:  v1alpha1.RuleMatch{Domains: []string{"*"}, Schemes: []string{"https"}},
			req:  httpreq.HTTPRequest{Host: "example.com", Scheme: ""},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rm := mustCompileRuleMatch(t, tc.raw)
			if got := rm.Matches(&tc.req); got != tc.want {
				t.Errorf("Matches() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSecurityRule_MatchesRequest_OrsMatchClauses checks that multiple
// match clauses in a Rule are OR'd.
func TestSecurityRule_MatchesRequest_OrsMatchClauses(t *testing.T) {
	cr := Rule{
		Matches: []Match{
			mustCompileRuleMatch(t, v1alpha1.RuleMatch{Domains: []string{"a.com"}}),
			mustCompileRuleMatch(t, v1alpha1.RuleMatch{Domains: []string{"b.com"}}),
		},
	}
	if !cr.MatchesRequest(&httpreq.HTTPRequest{Host: "b.com"}) {
		t.Errorf("expected OR semantics: b.com should match")
	}
	if cr.MatchesRequest(&httpreq.HTTPRequest{Host: "c.com"}) {
		t.Errorf("c.com should not match either clause")
	}
}

// An uncompilable regex is a static authoring error, so it must reject the
// profile version rather than yield a matcher that never matches. Silently
// non-matching is fail-OPEN for a block rule: the rule stops firing and the
// traffic it was written to stop is forwarded.
func TestCompileRuleMatch_InvalidRegexIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  v1alpha1.RuleMatch
	}{
		{
			name: "path",
			raw: v1alpha1.RuleMatch{Paths: []v1alpha1.PathMatch{
				{Type: v1alpha1.PathMatchTypeRegex, Value: "([invalid"},
			}},
		},
		{
			name: "header",
			raw: v1alpha1.RuleMatch{Headers: []v1alpha1.HeaderMatch{
				{Name: "X-K", Type: v1alpha1.StringMatchTypeRegex, Value: "([invalid"},
			}},
		},
		{
			name: "queryParam",
			raw: v1alpha1.RuleMatch{QueryParams: []v1alpha1.QueryParamMatch{
				{Name: "q", Type: v1alpha1.StringMatchTypeRegex, Value: "([invalid"},
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compileRuleMatch(tc.raw); err == nil {
				t.Fatalf("compileRuleMatch(%s regex) returned no error", tc.name)
			}
		})
	}
}

// TestNewProfile covers the compile gate that the collection transform calls:
// a valid spec produces a *Profile, while an invalid selector or an
// uncompilable matcher regex returns an error without panicking — otherwise
// the bad version still installs.
func TestNewProfile(t *testing.T) {
	tests := []struct {
		name    string
		obj     *v1alpha1.SecurityProfile
		wantErr bool
	}{
		{
			name: "valid selector compiles",
			obj: &v1alpha1.SecurityProfile{
				Spec: v1alpha1.SecurityProfileSpec{
					Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid selector is rejected",
			obj: &v1alpha1.SecurityProfile{
				Spec: v1alpha1.SecurityProfileSpec{
					Selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "!",
						Operator: metav1.LabelSelectorOpExists,
					}}},
				},
			},
			wantErr: true,
		},
		{
			// An uncompilable path regex must reject the profile version; see
			// TestCompileRuleMatch_InvalidRegexIsRejected for why silently
			// non-matching would be fail-open.
			name: "invalid matcher regex is rejected",
			obj: &v1alpha1.SecurityProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
				Spec: v1alpha1.SecurityProfileSpec{
					Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
					Rules: []v1alpha1.SecurityRule{{
						Name: "bad-regex",
						Match: []v1alpha1.RuleMatch{{
							Domains: []string{"*"},
							Paths: []v1alpha1.PathMatch{
								{Type: v1alpha1.PathMatchTypeRegex, Value: "([invalid"},
							},
						}},
					}},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sp, err := NewProfile(tc.obj, &tc.obj.Spec)
			if tc.wantErr {
				if err == nil || sp != nil {
					t.Fatalf("expected rejection, got sp=%+v err=%v", sp, err)
				}
				return
			}
			if err != nil || sp == nil {
				t.Fatalf("expected profile, got sp=%v err=%v", sp, err)
			}
		})
	}
}

// A compiled regex matcher always carries its program. This pins the invariant
// that lets matchPath and matchValue dereference Re unguarded, so a future
// change that reintroduces a nil Re fails here rather than silently forwarding
// traffic a block rule should have stopped.
func TestCompileRuleMatch_ValidRegexAlwaysCarriesProgram(t *testing.T) {
	m := mustCompileRuleMatch(t, v1alpha1.RuleMatch{
		Domains: []string{"*"},
		Paths: []v1alpha1.PathMatch{
			{Type: v1alpha1.PathMatchTypeRegex, Value: "^/api/v[0-9]+$"},
		},
		Headers: []v1alpha1.HeaderMatch{
			{Name: "X-K", Type: v1alpha1.StringMatchTypeRegex, Value: "^v[0-9]+$"},
		},
		QueryParams: []v1alpha1.QueryParamMatch{
			{Name: "q", Type: v1alpha1.StringMatchTypeRegex, Value: "^[a-z]+$"},
		},
	})

	if m.Paths[0].Re == nil {
		t.Error("compiled path regex matcher has nil Re")
	}
	if m.Headers[0].Re == nil {
		t.Error("compiled header regex matcher has nil Re")
	}
	if m.QueryParams[0].Re == nil {
		t.Error("compiled queryParam regex matcher has nil Re")
	}

	req := httpreq.HTTPRequest{
		Host:    "any.example",
		Path:    "/api/v2",
		Headers: map[string]string{"x-k": "v2"},
		Query:   url.Values{"q": []string{"abc"}},
	}
	if !m.Matches(&req) {
		t.Error("a request satisfying every compiled regex did not match")
	}
}

// mustCompileRuleMatch compiles a matcher that the test asserts is valid.
func mustCompileRuleMatch(t testing.TB, raw v1alpha1.RuleMatch) Match {
	t.Helper()
	m, err := compileRuleMatch(raw)
	if err != nil {
		t.Fatalf("compileRuleMatch(%+v): %v", raw, err)
	}
	return m
}

// An un-defaulted path match type must behave as Prefix, mirroring the CRD's
// +kubebuilder:default:=Prefix rather than never matching.
func TestMatchPath_EmptyTypeDefaultsToPrefix(t *testing.T) {
	rm := Match{Paths: []pathMatcher{{Value: "/api"}}} // Type left empty

	if !rm.matchPath("/api/v1/things") {
		t.Error("empty path match type should behave as Prefix and match /api/v1/things")
	}
	if !rm.matchPath("/api") {
		t.Error("empty path match type should match the prefix itself")
	}
	if rm.matchPath("/other") {
		t.Error("empty path match type must not match an unrelated path")
	}
}

// The header/query counterpart already defaults to Exact; pin it so the two
// stay deliberately different rather than accidentally so.
func TestMatchValue_EmptyTypeDefaultsToExact(t *testing.T) {
	sm := stringMatcher{Name: "x-k", Value: "exact-value"}

	if !sm.matchValue("exact-value") {
		t.Error("empty string match type should behave as Exact")
	}
	if sm.matchValue("exact-value-and-more") {
		t.Error("empty string match type must not prefix-match")
	}
}

func TestMatchingIndex(t *testing.T) {
	tests := []struct {
		name      string
		domains   [][]string
		host      string
		wantIndex int
	}{
		{
			name:      "first match clause",
			domains:   [][]string{{"a.com"}, {"b.com"}},
			host:      "a.com",
			wantIndex: 0,
		},
		{
			name:      "second match clause",
			domains:   [][]string{{"a.com"}, {"b.com"}},
			host:      "b.com",
			wantIndex: 1,
		},
		{
			name:      "no match",
			domains:   [][]string{{"a.com"}, {"b.com"}},
			host:      "c.com",
			wantIndex: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := Rule{}
			for _, d := range tt.domains {
				cr.Matches = append(cr.Matches, Match{Domains: d})
			}
			got := cr.MatchingIndex(&httpreq.HTTPRequest{Host: tt.host})
			if got != tt.wantIndex {
				t.Errorf("MatchingIndex = %d, want %d", got, tt.wantIndex)
			}
		})
	}
}

// sortKey renders a profile's identity for order assertions.
func sortKey(p *Profile) string {
	return p.Meta.Namespace + "/" + p.Meta.Name
}

func TestSortProfiles(t *testing.T) {
	// prof builds a profile with the given identity and ordering keys.
	prof := func(ns, name string, priority int32, ts int64) *Profile {
		return &Profile{Meta: Meta{
			Name:              name,
			Namespace:         ns,
			Priority:          priority,
			CreationTimestamp: metav1.Unix(ts, 0),
		}}
	}

	tests := []struct {
		name  string
		input []*Profile
		want  []string // expected keys in evaluation order
	}{
		{
			name: "priority ascending wins first",
			input: []*Profile{
				prof("ns", "high", 2000, 0),
				prof("ns", "low", 100, 0),
			},
			want: []string{"ns/low", "ns/high"},
		},
		{
			name: "equal priority falls back to older timestamp",
			input: []*Profile{
				prof("ns", "newer", 1000, 200),
				prof("ns", "older", 1000, 100),
			},
			want: []string{"ns/older", "ns/newer"},
		},
		{
			name: "equal priority and timestamp fall back to name",
			input: []*Profile{
				prof("ns", "b", 1000, 100),
				prof("ns", "a", 1000, 100),
			},
			want: []string{"ns/a", "ns/b"},
		},
		{
			// A GlobalSecurityProfile (empty namespace) and a namespaced
			// Profile can share name, priority, and second-precision
			// timestamp. Namespace is the final tie-break, so empty (global)
			// sorts first and the order is total.
			name: "global and namespaced tie broken by namespace (global first)",
			input: []*Profile{
				prof("tenant-a", "shared", 1000, 100),
				prof("", "shared", 1000, 100),
			},
			want: []string{"/shared", "tenant-a/shared"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run against both input orderings to prove the comparator is a
			// total order rather than order-preserving on ties.
			for _, reversed := range []bool{false, true} {
				in := make([]*Profile, len(tt.input))
				copy(in, tt.input)
				if reversed {
					for i, j := 0, len(in)-1; i < j; i, j = i+1, j-1 {
						in[i], in[j] = in[j], in[i]
					}
				}
				SortProfiles(in)
				got := make([]string, len(in))
				for i, p := range in {
					got[i] = sortKey(p)
				}
				for i := range tt.want {
					if got[i] != tt.want[i] {
						t.Errorf("reversed=%v: order = %v, want %v", reversed, got, tt.want)
						break
					}
				}
			}
		})
	}
}

func TestSecurityProfileResourceName(t *testing.T) {
	sandbox := Profile{Meta: Meta{Name: "p1", Namespace: "ns-a", Match: MatchSandbox}}
	if got := sandbox.ResourceName(); got != "sandbox/ns-a/p1" {
		t.Errorf("Sandbox ResourceName = %q, want %q", got, "sandbox/ns-a/p1")
	}
	namespaced := Profile{Meta: Meta{Name: "p1", Namespace: "ns-a"}}
	if got := namespaced.ResourceName(); got != "ns-a/p1" {
		t.Errorf("namespaced ResourceName = %q, want %q", got, "ns-a/p1")
	}
	global := Profile{Meta: Meta{Name: "g1"}}
	if got := global.ResourceName(); got != "g1" {
		t.Errorf("cluster-scoped ResourceName = %q, want %q", got, "g1")
	}
}
