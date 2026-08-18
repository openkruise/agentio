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
	"encoding/json"
	"errors"
	"testing"

	"istio.io/istio/extensions/epe/pkg/httpreq"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/filters/block"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

type nopFilter struct{ filter.PassThrough }

// compile turns a v1alpha1 spec into the compiled model form the store
// would hand to bind.
func compile(t testing.TB, name, ns, version string, rules []v1alpha1.SecurityRule) *Profile {
	t.Helper()
	obj := &v1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, ResourceVersion: version},
		Spec: v1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
			Rules:    rules,
		},
	}
	sp, err := NewProfile(obj, &obj.Spec)
	if err != nil {
		t.Fatalf("compile profile %s: %v", name, err)
	}
	return sp
}

// matchAllRule matches every request and carries a block action whose body
// is the rule name: payloadsFor emits keys only for rules with actions, so
// the action is what mounts the claimAll filter, and its body lets the
// parsed config identify the rule it came from.
func matchAllRule(name string) v1alpha1.SecurityRule {
	return v1alpha1.SecurityRule{
		Name:  name,
		Match: []v1alpha1.RuleMatch{{Domains: []string{"*"}}},
		Actions: v1alpha1.SecurityRuleActions{
			Block: &v1alpha1.BlockAction{Body: ptr.To(name)},
		},
	}
}

// matchHostRule matches one host; see matchAllRule for the block action.
func matchHostRule(name, host string) v1alpha1.SecurityRule {
	return v1alpha1.SecurityRule{
		Name:  name,
		Match: []v1alpha1.RuleMatch{{Domains: []string{host}}},
		Actions: v1alpha1.SecurityRuleActions{
			Block: &v1alpha1.BlockAction{Body: ptr.To(name)},
		},
	}
}

func testRequest(host string) *httpreq.HTTPRequest {
	return &httpreq.HTTPRequest{Host: host, Method: "GET", Path: "/"}
}

// claimAll registers a string filter under the block name: payloadsFor
// emits that key for every rule the match helpers build, and parse returns
// the payload's body so the config identifies the rule it came from.
func claimAll(t testing.TB, calls *int) []filter.Registration {
	t.Helper()
	regs, err := filter.Build(filter.Define(filter.Descriptor[string]{
		Name:   block.FilterName,
		Phases: filter.PhaseRequestHeaders,
		New:    func(filter.RuleConfig[string]) filter.Filter { return nopFilter{} },
	}, func(raw json.RawMessage) (string, error) {
		if calls != nil {
			*calls++
		}
		var payload struct {
			Body string `json:"body"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return "", err
		}
		return payload.Body, nil
	}))
	if err != nil {
		t.Fatalf("build block: %v", err)
	}
	return regs
}

func TestBindOrdersUnitsByProfileThenRule(t *testing.T) {
	b := newBinder(claimAll(t, nil))

	p1 := compile(t, "alpha", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r1"), matchAllRule("r2")})
	p2 := compile(t, "beta", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r3")})

	units, err := b.bind([]*Profile{p1, p2}, testRequest("example.com"), inputs.Pod{Namespace: "ns"})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	want := []filter.UnitID{
		{Scope: "ns/alpha", Name: "r1", Ordinal: 0},
		{Scope: "ns/alpha", Name: "r2", Ordinal: 1},
		{Scope: "ns/beta", Name: "r3", Ordinal: 2},
	}
	if len(units) != len(want) {
		t.Fatalf("got %d units, want %d", len(units), len(want))
	}
	for i, u := range units {
		if u.ID != want[i] {
			t.Errorf("unit %d ID = %+v, want %+v", i, u.ID, want[i])
		}
		if u.Cfgs[0] == nil || u.Cfgs[0].(string) != want[i].Name {
			t.Errorf("unit %d cfg = %v, want %q", i, u.Cfgs[0], want[i].Name)
		}
		if u.Scope == nil || u.Scope.Rule().Name != want[i].Name {
			t.Errorf("unit %d scope rule = %+v", i, u.Scope)
		}
	}
}

func TestBindSkipsNonMatchingRules(t *testing.T) {
	b := newBinder(claimAll(t, nil))

	p := compile(t, "p", "ns", "1", []v1alpha1.SecurityRule{
		matchHostRule("hit", "example.com"),
		matchHostRule("miss", "other.com"),
	})
	units, err := b.bind([]*Profile{p}, testRequest("example.com"), inputs.Pod{})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if len(units) != 1 || units[0].ID.Name != "hit" {
		t.Fatalf("units = %+v, want only 'hit'", units)
	}
}

func TestBinderCopiesRegistrations(t *testing.T) {
	regs := claimAll(t, nil)
	b := newBinder(regs)

	// Mutating the caller's slice after construction must not change the
	// registration name Binder uses to project block payloads.
	regs[0].Name = "mutated"

	p := compile(t, "p", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r")})
	units, err := b.bind([]*Profile{p}, testRequest("example.com"), inputs.Pod{})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if len(units) != 1 {
		t.Fatalf("units = %d, want 1", len(units))
	}
	got, ok := units[0].Cfgs[0].(string)
	if !ok || got != "r" {
		t.Fatalf("cfg = %#v, want %q", units[0].Cfgs[0], "r")
	}
}

// Projection must run once per profile version, not once per request —
// otherwise the typed-projection design just moved the per-request cost
// instead of removing it.
func TestProjectionRunsOncePerProfileVersion(t *testing.T) {
	calls := 0
	b := newBinder(claimAll(t, &calls))

	p := compile(t, "p", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r")})
	profiles := []*Profile{p}
	req := testRequest("example.com")

	for i := 0; i < 3; i++ {
		if _, err := b.bind(profiles, req, inputs.Pod{}); err != nil {
			t.Fatalf("bind %d: %v", i, err)
		}
	}
	if calls != 1 {
		t.Fatalf("project ran %d times for one profile version, want 1", calls)
	}

	bumped := compile(t, "p", "ns", "2", []v1alpha1.SecurityRule{matchAllRule("r")})
	if _, err := b.bind([]*Profile{bumped}, req, inputs.Pod{}); err != nil {
		t.Fatalf("bind bumped: %v", err)
	}
	if calls != 2 {
		t.Fatalf("project ran %d times after version bump, want 2", calls)
	}
}

func TestProjectionRealErrorFailsClosed(t *testing.T) {
	boom := errors.New("malformed")
	regs, err := filter.Build(filter.Define(filter.Descriptor[string]{
		Name:   block.FilterName,
		Phases: filter.PhaseRequestHeaders,
		New:    func(filter.RuleConfig[string]) filter.Filter { return nopFilter{} },
	}, func(json.RawMessage) (string, error) { return "", boom }))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	b := newBinder(regs)

	p := compile(t, "p", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r")})
	if _, err := b.bind([]*Profile{p}, testRequest("example.com"), inputs.Pod{}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped projection error", err)
	}
}

// A rule carrying no action mounts no filter: payloadsFor emits no key, so
// the slot stays nil without parse ever running.
func TestUnmountedFilterYieldsNilSlot(t *testing.T) {
	regs, err := filter.Build(filter.Define(filter.Descriptor[string]{
		Name:   "none",
		Phases: filter.PhaseRequestHeaders,
		New:    func(filter.RuleConfig[string]) filter.Filter { return nopFilter{} },
	}, func(json.RawMessage) (string, error) { return "", nil }))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	b := newBinder(regs)

	rule := v1alpha1.SecurityRule{
		Name:  "r",
		Match: []v1alpha1.RuleMatch{{Domains: []string{"*"}}},
	}
	p := compile(t, "p", "ns", "1", []v1alpha1.SecurityRule{rule})
	units, err := b.bind([]*Profile{p}, testRequest("example.com"), inputs.Pod{})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if len(units) != 1 || units[0].Cfgs[0] != nil {
		t.Fatalf("units = %+v, want one unit with nil cfg slot", units)
	}
}

func TestMatchIndexMatchesRuleMatchingIndex(t *testing.T) {
	b := newBinder(claimAll(t, nil))

	rule := v1alpha1.SecurityRule{
		Name: "r",
		Match: []v1alpha1.RuleMatch{
			{Domains: []string{"other.com"}},
			{Domains: []string{"example.com"}},
		},
	}
	p := compile(t, "p", "ns", "1", []v1alpha1.SecurityRule{rule})
	units, err := b.bind([]*Profile{p}, testRequest("example.com"), inputs.Pod{})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if len(units) != 1 || units[0].MatchIndex != 1 {
		t.Fatalf("MatchIndex = %d, want 1", units[0].MatchIndex)
	}
}

// A Sandbox and a SecurityProfile in one namespace may share a name and even
// a resourceVersion. The projection cache must keep the two apart; otherwise
// whichever profile bound last would serve its projections to the other.
func TestProjectionCacheDoesNotCrossInlineAndCRProfiles(t *testing.T) {
	calls := 0
	b := newBinder(claimAll(t, &calls))

	cr := compile(t, "shared", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("cr-rule")})
	inline := compile(t, "shared", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("inline-rule")})
	inline.Meta.Source = SourceInline

	req := testRequest("example.com")
	pod := inputs.Pod{Namespace: "ns", Name: "shared"}

	for i := 0; i < 3; i++ {
		units, err := b.bind([]*Profile{cr, inline}, req, pod)
		if err != nil {
			t.Fatalf("bind %d: %v", i, err)
		}
		if len(units) != 2 {
			t.Fatalf("bind %d: got %d units, want 2", i, len(units))
		}
		for _, want := range []struct {
			scope, rule string
		}{
			{"ns/shared", "cr-rule"},
			{"ns/shared", "inline-rule"},
		} {
			idx := 0
			if want.rule == "inline-rule" {
				idx = 1
			}
			u := units[idx]
			if u.ID.Scope != want.scope || u.ID.Name != want.rule {
				t.Errorf("bind %d unit %d ID = %+v, want scope %q rule %q", i, idx, u.ID, want.scope, want.rule)
			}
			if cfg, ok := u.Cfgs[0].(string); !ok || cfg != want.rule {
				t.Errorf("bind %d unit %d cfg = %#v, want the %q projection", i, idx, u.Cfgs[0], want.rule)
			}
		}
	}

	// One projection per source: a cross-returning cache would skip one of
	// the two initial projections and stay at 1.
	if calls != 2 {
		t.Fatalf("project ran %d times, want 2 (one per source)", calls)
	}
}
