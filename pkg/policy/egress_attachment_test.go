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

package policy

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
)

func TestCompiledEgressPolicies(t *testing.T) {
	compiled := testCompiledEgressPolicies()
	policies, err := CompiledEgressPolicies("agentio-system", compiled)
	if err != nil {
		t.Fatalf("bindable egress policies: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("bindable policies = %d, want 2", len(policies))
	}
	if got, want := policies[0].Name, "agentio-config/egress/000000"; got != want {
		t.Fatalf("first name = %q, want %q", got, want)
	}
	if got, want := policies[1].Name, "agentio-config/egress/000001"; got != want {
		t.Fatalf("second name = %q, want %q", got, want)
	}
	if policies[0].Attachment.Priority != 0 || policies[1].Attachment.Priority != 1 {
		t.Fatalf("priorities = %d, %d, want 0, 1", policies[0].Attachment.Priority, policies[1].Attachment.Priority)
	}
	if got, want := policies[0].Attachment.Target.Namespaces, []string{"demo"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("first target namespaces = %v, want %v", got, want)
	}
	if !policies[1].Attachment.Target.Global {
		t.Fatal("second attachment is not global")
	}
	if got, want := policies[0].GatewayKey, "agentio-system/egress-a"; got != want {
		t.Fatalf("first gateway = %q, want %q", got, want)
	}
	if got, want := policies[1].GatewayKey, "agentio-system/egress-global"; got != want {
		t.Fatalf("second gateway = %q, want %q", got, want)
	}
	if policies[0].Policy == compiled.GetEgressPolicies()[0] {
		t.Fatal("bindable policy aliases the compiled input")
	}
}

func TestSelectEgressPoliciesPreservesBindingOrder(t *testing.T) {
	policies, err := CompiledEgressPolicies("agentio-system", testCompiledEgressPolicies())
	if err != nil {
		t.Fatal(err)
	}
	selected, gatewayKeys, err := SelectEgressPolicies(
		[]string{
			policies[1].Name,
			policies[0].Name,
		},
		[]CompiledEgressPolicy{
			policies[0],
			policies[1],
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := gatewayKeys, []string{
		"agentio-system/egress-a",
		"agentio-system/egress-global",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("gateway keys = %v, want %v", got, want)
	}
	if got := selected.GetEgressPolicies(); len(got) != 2 ||
		!proto.Equal(got[0], policies[1].Policy) ||
		!proto.Equal(got[1], policies[0].Policy) {
		t.Fatalf("selected policy order = %+v", got)
	}
}

func TestCompiledEgressPoliciesRejectMalformedGateway(t *testing.T) {
	for _, service := range []string{"", "egress", ".agentio-system", "egress..svc.cluster.local"} {
		t.Run(service, func(t *testing.T) {
			_, err := CompiledEgressPolicies("agentio-system", &extensionsv1.EgressPolicies{EgressPolicies: []*extensionsv1.EgressPolicy{{
				Policy:  extensionsv1.EgressPolicyAction_GATEWAY,
				Gateway: &extensionsv1.GatewayAddress{Service: service, Port: 15008},
			}}})
			if err == nil {
				t.Fatalf("gateway service %q was accepted", service)
			}
		})
	}
	if policies, err := CompiledEgressPolicies("agentio-system", &extensionsv1.EgressPolicies{EgressPolicies: []*extensionsv1.EgressPolicy{{
		Policy: extensionsv1.EgressPolicyAction_DENY,
	}}}); err != nil || len(policies) != 1 || policies[0].GatewayKey != "" {
		t.Fatalf("DENY without gateway = %+v, err %v", policies, err)
	}
}

func testCompiledEgressPolicies() *extensionsv1.EgressPolicies {
	return &extensionsv1.EgressPolicies{EgressPolicies: []*extensionsv1.EgressPolicy{
		{
			Namespaces: []string{"demo"}, MatchCidrs: []string{"203.0.113.7/32"},
			Policy:  extensionsv1.EgressPolicyAction_GATEWAY,
			Gateway: &extensionsv1.GatewayAddress{Service: "egress-a.agentio-system.svc.cluster.local", Port: 15008},
		},
		{
			Policy:  extensionsv1.EgressPolicyAction_GATEWAY,
			Gateway: &extensionsv1.GatewayAddress{Service: "egress-global.agentio-system.svc.cluster.local", Port: 15008},
		},
	}}
}
