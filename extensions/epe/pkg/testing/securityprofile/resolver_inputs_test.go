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
	"reflect"
	"testing"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extensionprovider"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/block"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	policysecurityprofile "github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/extensions/epe/pkg/wiring"
)

func TestResolverMountsProfileInputsOnUnits(t *testing.T) {
	regs, err := wiring.BuildFilters(wiring.Deps{Providers: &extensionprovider.Registry{}})
	if err != nil {
		t.Fatalf("BuildFilters: %v", err)
	}
	// The store must project against the chain the resolver evaluates with,
	// exactly as the collection does in production.
	store := profilestore.MakeFakeStore(regs...)
	for _, tc := range []struct {
		name  string
		value string
	}{{name: "p1", value: "first"}, {name: "p2", value: "second"}} {
		profile := securityProfile(
			tc.name,
			"default",
			nil,
			map[string]string{"app": "blocked"},
			[]v1alpha1.SecurityRule{{
				Name:  "capture",
				Match: []v1alpha1.RuleMatch{{Domains: []string{"*"}}},
				Actions: v1alpha1.SecurityRuleActions{
					Block: &v1alpha1.BlockAction{StatusCode: 403},
				},
			}},
		)
		profile.Spec.Inputs = []v1alpha1.SecurityProfileInput{{
			Name:   "routing",
			Inline: map[string]string{"target": tc.value},
		}}
		store.ProfileSet(profile)
	}
	resolution, err := policysecurityprofile.NewResolver(store, regs, nil, nil)(
		context.Background(),
		subject.Subject{
			Workload: subject.Workload{Name: "pod", Namespace: "default", Labels: map[string]string{"app": "blocked"}},
		},
		&httpreq.HTTPRequest{Host: "api.example.com", Path: "/", Method: "GET"},
	)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(resolution.Units) != 2 {
		t.Fatalf("resolved units = %d, want 2", len(resolution.Units))
	}
	wantScopes := []string{"default/p1", "default/p2"}
	wantInputs := []map[string]any{
		{"routing": map[string]string{"target": "first"}},
		{"routing": map[string]string{"target": "second"}},
	}
	blockIndex := registrationIndex(t, regs, block.FilterName)
	for i, unit := range resolution.Units {
		if unit.ID.Scope != wantScopes[i] {
			t.Errorf("unit[%d] scope = %q, want %q", i, unit.ID.Scope, wantScopes[i])
		}
		gotInputs, err := unit.Scope.Inputs()
		if err != nil {
			t.Errorf("unit[%d] inputs unavailable: %v", i, err)
		}
		if !reflect.DeepEqual(gotInputs, wantInputs[i]) {
			t.Errorf("unit[%d] inputs = %#v, want %#v", i, gotInputs, wantInputs[i])
		}
		if unit.Cfgs[blockIndex] == nil {
			t.Errorf("unit[%d] did not project the block payload", i)
		}
	}
}

func TestResolverSkipsInitialProfileWithUnresolvedInputs(t *testing.T) {
	store := profilestore.MakeFakeStore()
	profile := securityProfile("p1", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{{
		Name:    "match",
		Match:   []v1alpha1.RuleMatch{{Domains: []string{"*"}}},
		Actions: v1alpha1.SecurityRuleActions{},
	}})
	profile.Spec.Inputs = []v1alpha1.SecurityProfileInput{{
		Name:      "routing",
		ConfigMap: &v1alpha1.ConfigMapInputRef{Name: "missing"},
	}}
	store.ProfileSet(profile)

	resolution, err := policysecurityprofile.NewResolver(store, nil, nil, nil)(
		context.Background(),
		subject.Subject{
			Workload: subject.Workload{Name: "pod", Namespace: "default", Labels: map[string]string{"app": "blocked"}},
		},
		&httpreq.HTTPRequest{Host: "api.example.com", Path: "/", Method: "GET"},
	)
	if err != nil {
		t.Fatalf("invalid initial profile should be absent from the effective snapshot: %v", err)
	}
	if len(resolution.Units) != 0 {
		t.Fatalf("resolved units = %d, want none for an invalid initial profile", len(resolution.Units))
	}
}

func registrationIndex(t *testing.T, regs []filter.Registration, name string) int {
	t.Helper()
	for i, reg := range regs {
		if reg.Name == name {
			return i
		}
	}
	t.Fatalf("registration %q not found", name)
	return -1
}
