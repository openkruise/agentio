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

package xds

import (
	"testing"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestSecurityProfileDiscoveryScope(t *testing.T) {
	var resources []model.Resource
	for _, name := range []string{"requested", "unused"} {
		r, err := model.NewResource(
			model.ResourceKey{TypeURL: model.SecurityProfileType, Name: name},
			"",
			mustAny(&securityv1.SecurityProfile{Name: name}),
			nil,
			model.ResourceFacts{},
		)
		if err != nil {
			t.Fatal(err)
		}
		resources = append(resources, r)
	}
	snapshot, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	for _, class := range []model.ClientClass{model.ClientEPE, model.ClientEgressGateway, model.ClientAgentioEgress, model.ClientDedicatedZTunnel, model.ClientSharedZTunnel} {
		known, allowed := typeAccess(class, model.SecurityProfileType)
		if !known || allowed != (class == model.ClientEPE) {
			t.Fatalf("profile type access for %s: %v %v", class, known, allowed)
		}
		delta, err := (SecurityProfileGenerator{}).Generate(
			t.Context(),
			GenerationRequest{
				Scope:        model.ClientScope{Class: class},
				TypeURL:      model.SecurityProfileType,
				Snapshot:     snapshot,
				Full:         true,
				Subscription: SubscriptionView{names: []string{"requested"}},
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if class == model.ClientEPE {
			want = 1
		}
		if len(delta.Resources) != want || want == 1 && delta.Resources[0].Key.Name != "requested" {
			t.Fatalf("profile selection for %s: %v", class, delta.Resources)
		}
	}
}
