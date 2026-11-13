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

package store

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/openkruise/agentio/pkg/model"
)

func TestAuthorizationDependenciesRetainBothSnapshots(t *testing.T) {
	resource := func(typeURL, name, wireName string, facts model.ResourceFacts) model.Resource {
		t.Helper()
		r, err := model.NewResource(model.ResourceKey{TypeURL: typeURL, Name: name}, wireName,
			model.Prebuilt(&anypb.Any{TypeUrl: typeURL, Value: []byte(wireName)}), nil, facts)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	var policies []model.Resource
	for _, namespace := range []string{"a", "b", "unrelated"} {
		policies = append(policies, resource(model.WorkloadAuthorizationType, namespace, namespace,
			model.ResourceFacts{Authorization: &model.AuthorizationResourceFacts{
				Scope:     model.AuthorizationScopeNamespace,
				Namespace: namespace,
			}}))
	}
	globalFacts := model.ResourceFacts{Authorization: &model.AuthorizationResourceFacts{
		Scope: model.AuthorizationScopeGlobal,
	}}
	before, err := model.NewResourceSet(append(slices.Clone(policies),
		resource(model.WorkloadAuthorizationType, "global", "global-old", globalFacts)))
	if err != nil {
		t.Fatal(err)
	}
	after, err := model.NewResourceSet(append(slices.Clone(policies),
		resource(model.WorkloadAuthorizationType, "global", "global-new", globalFacts)))
	if err != nil {
		t.Fatal(err)
	}
	old := resource(model.AddressType, "workload", "workload", model.ResourceFacts{
		Workload: &model.WorkloadResourceFacts{WorkloadUID: "workload", Namespace: "a"},
	})
	next := resource(model.AddressType, "workload", "workload", model.ResourceFacts{
		Workload: &model.WorkloadResourceFacts{WorkloadUID: "workload", Namespace: "b"},
	})
	for _, tc := range []struct {
		name string
		old  *model.Resource
		next *model.Resource
		want []string
	}{
		{name: "add", next: &next, want: []string{"b", "global-new", "global-old"}},
		{name: "remove", old: &old, want: []string{"a", "global-new", "global-old"}},
		{name: "move", old: &old, next: &next, want: []string{"a", "b", "global-new", "global-old"}},
		{name: "unchanged facts", old: &old, next: &old},
	} {
		t.Run(tc.name, func(t *testing.T) {
			index := make(map[model.ResourceKey]Candidate)
			indexDependencies(index, before, after, []model.ResourceChange{
				{Key: old.Key, Old: tc.old, New: tc.next},
			})
			var names []string
			for _, candidate := range index {
				for _, identity := range candidate.Identities {
					names = append(names, identity.Name)
				}
			}
			slices.Sort(names)
			if !slices.Equal(names, tc.want) {
				t.Fatalf("dependencies = %v, want %v", names, tc.want)
			}
		})
	}
}
