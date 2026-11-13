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

package compiler

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestBuildWDSAddressClientFormats(t *testing.T) {
	resource, err := buildWDSAddress(wdsProjection{
		Workload: projectionTestWorkload(),
		SNIPolicy: &extensionsv1.SniTrafficPolicy{Rules: []*extensionsv1.SniRule{{
			Match:  &extensionsv1.SniMatch{Sni: []string{"example.com"}},
			Action: extensionsv1.SniAction_SNI_ACTION_PASSTHROUGH,
		}}},
		SecurityProfileReferences: []*extensionsv1.PolicyResourceReference{{Name: "demo/profile", Uid: "profile-uid"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, class := range []model.ClientClass{model.ClientAgentioEgress, model.ClientEgressGateway, model.ClientEPE} {
		expected := &workloadv1.Address{}
		if err := resourceValue(t, *resource).UnmarshalTo(expected); err != nil {
			t.Fatal(err)
		}
		if class == model.ClientAgentioEgress || class == model.ClientEPE {
			expected.GetWorkload().Extensions = slices.DeleteFunc(
				expected.GetWorkload().Extensions,
				func(e *workloadv1.Extension) bool { return e.Name == "sni-traffic-policy" },
			)
		}
		generated, err := resource.Generate(model.ClientScope{Class: class}, model.WorkloadType)
		if err != nil {
			t.Fatal(err)
		}
		got := &workloadv1.Workload{}
		if err := generated.Value.UnmarshalTo(got); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(got, expected.GetWorkload()) {
			t.Fatalf("class %s: wrong projected fields", class)
		}
	}
}
