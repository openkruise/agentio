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
	"context"
	"encoding/json"
	"strconv"
	"testing"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
)

// benchSink defeats dead-code elimination.
var benchSink any

func BenchmarkNewSandboxProfile(b *testing.B) {
	for _, count := range []int{1, 16, 128} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			rules := make([]v1alpha1.SecurityRule, count)
			for i := range rules {
				rules[i] = matchAllRule("r" + strconv.Itoa(i))
				rules[i].Actions.HeaderManipulation = &v1alpha1.HeaderManipulationAction{
					Set: []v1alpha1.HeaderValue{{Name: "X-Trace", Value: "{{pod.name}}-literal"}},
				}
			}
			raw, err := json.Marshal(rules)
			if err != nil {
				b.Fatal(err)
			}
			sandbox := sandboxWithRules("bench", "ns", string(raw))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				profile, err := NewSandboxProfile(sandbox)
				if err != nil {
					b.Fatal(err)
				}
				benchSink = profile
			}
		})
	}
}

// benchStore returns a fixed profile slice, so these benchmarks measure the
// binder and the resolver adapter without the store's label matching on the
// clock. profilestore has its own benchmark for that half.
type benchStore struct{ profiles []*Profile }

func (s benchStore) ResolveProfiles(context.Context, subject.Subject) ([]*Profile, error) {
	return s.profiles, nil
}

// benchProfiles compiles nProfiles profiles of nRules rules each. Every rule
// matches, which is the worst case: each one becomes a unit.
func benchProfiles(b testing.TB, regs []filter.Registration, nProfiles, nRules int) []*Profile {
	b.Helper()
	profiles := make([]*Profile, nProfiles)
	for p := range profiles {
		rules := make([]v1alpha1.SecurityRule, nRules)
		for r := range rules {
			rules[r] = matchAllRule("r" + strconv.Itoa(r))
		}
		profiles[p] = compile(b, regs, "p"+strconv.Itoa(p), "ns", "1", rules)
	}
	return profiles
}

// benchMissProfiles compiles profiles whose rules match a host the benchmark
// request never carries, so MatchingIndex walks every clause and returns -1.
func benchMissProfiles(b testing.TB, regs []filter.Registration, nProfiles, nRules int) []*Profile {
	b.Helper()
	profiles := make([]*Profile, nProfiles)
	for p := range profiles {
		rules := make([]v1alpha1.SecurityRule, nRules)
		for r := range rules {
			rules[r] = matchHostRule("r"+strconv.Itoa(r), "no-such-host-"+strconv.Itoa(r)+".invalid")
		}
		profiles[p] = compile(b, regs, "p"+strconv.Itoa(p), "ns", "1", rules)
	}
	return profiles
}

var benchPolicyAxes = []struct{ profiles, rules int }{
	{1, 1},
	{1, 8},
	{4, 4},
	{8, 8},
}

// BenchmarkBinderBind measures rule matching plus unit construction against
// already-projected profiles, which is the whole of what a request pays: the
// projection itself happens once per profile version, in the compiler.
func BenchmarkBinderBind(b *testing.B) {
	regs := claimAll(b, nil)

	for _, a := range benchPolicyAxes {
		for _, hit := range []bool{true, false} {
			var profiles []*Profile
			outcome := "match"
			if hit {
				profiles = benchProfiles(b, regs, a.profiles, a.rules)
			} else {
				profiles = benchMissProfiles(b, regs, a.profiles, a.rules)
				outcome = "nomatch"
			}
			name := "profiles=" + strconv.Itoa(a.profiles) +
				"/rules=" + strconv.Itoa(a.rules) + "/" + outcome
			b.Run(name, func(b *testing.B) {
				binder := newBinder(regs, nil)
				req := testRequest("api.example.com")
				workload := inputs.Workload{
					Name:      "agent-pod-abc123",
					Namespace: "ns",
					IP:        "10.244.1.37",
					Labels:    map[string]string{"app": "agent", "tier": "web"},
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					units, err := binder.bind(profiles, req, workload)
					if err != nil {
						b.Fatal(err)
					}
					benchSink = units
				}
			})
		}
	}
}

// BenchmarkResolver measures the full engine.Resolver seam: store lookup,
// binding the execution plan and creating the per-stream logger. The delta
// against BenchmarkBinderBind at the same axis is what the adapter costs.
func BenchmarkResolver(b *testing.B) {
	regs := claimAll(b, nil)

	for _, a := range benchPolicyAxes {
		profiles := benchProfiles(b, regs, a.profiles, a.rules)
		name := "profiles=" + strconv.Itoa(a.profiles) + "/rules=" + strconv.Itoa(a.rules)
		b.Run(name, func(b *testing.B) {
			resolve := NewResolver(benchStore{profiles: profiles}, regs, nil, nil)
			ctx := context.Background()
			req := testRequest("api.example.com")
			subj := subject.Subject{
				Workload: subject.Workload{
					Name:      "agent-pod-abc123",
					Namespace: "ns",
					IP:        "10.244.1.37",
					Labels:    map[string]string{"app": "agent", "tier": "web"},
				},
			}
			if _, err := resolve(ctx, subj, req); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res, err := resolve(ctx, subj, req)
				if err != nil {
					b.Fatal(err)
				}
				benchSink = res
			}
		})
	}
}

// BenchmarkMatchingIndex isolates one rule's match evaluation, so the
// per-rule cost inside the binder's scan is attributable.
func BenchmarkMatchingIndex(b *testing.B) {
	regs := claimAll(b, nil)
	hit := compile(b, regs, "p", "ns", "1", []v1alpha1.SecurityRule{matchAllRule("r0")})
	miss := compile(b, regs, "p", "ns", "1", []v1alpha1.SecurityRule{
		matchHostRule("r0", "no-such-host.invalid"),
	})
	req := testRequest("api.example.com")
	for _, bc := range []struct {
		name string
		rule *Rule
	}{
		{"hit", &hit.Rules[0]},
		{"miss", &miss.Rules[0]},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchSink = bc.rule.MatchingIndex(req)
			}
		})
	}
}
