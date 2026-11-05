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
	"fmt"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// BenchmarkWorkloadPolicyProjection measures Workload reference projection.
// Shared policy encoding is performed once upstream; no API decoding, selector matching, DNS,
// or per-client ADS work belongs in this measurement.
func BenchmarkWorkloadPolicyProjection(b *testing.B) {
	for _, count := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("rules=%d", count), func(b *testing.B) {
			stop := make(chan struct{})
			b.Cleanup(func() { close(stop) })
			opts := []krt.CollectionOption{krt.WithStop(stop)}
			workload := testWorkload("demo", "client", "10.0.0.1")
			rules := make([]*securityv1.TrafficPolicy_Rule, count)
			for i := range count {
				rules[i] = &securityv1.TrafficPolicy_Rule{Match: &securityv1.TrafficPolicy_Match{
					DestinationIps: []*securityv1.TrafficPolicy_Address{
						{Address: []byte{10, byte(i >> 8), byte(i), 0}, Length: 24},
					},
				}}
			}
			compiled := policy.CompiledTrafficPolicy{CompiledPolicy: policy.CompiledPolicy[*securityv1.TrafficPolicy]{
				Name:   "trafficPolicies/shared",
				Policy: &securityv1.TrafficPolicy{Egress: &securityv1.TrafficPolicy_RuleSet{Rules: rules}},
			}}
			var err error
			compiled.AsAuthorization, err = policy.TrafficPolicyAsAuthorizations(compiled, model.TrafficPolicy{
				Name:      "shared",
				Namespace: "demo",
				Spec: agentsv1alpha1.TrafficPolicySpec{
					Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
				},
			}, "agentio-system")
			if err != nil {
				b.Fatal(err)
			}
			policies := policyCollections{
				trafficPolicies:  krt.NewStaticCollection(nil, []policy.CompiledTrafficPolicy{compiled}, opts...),
				securityProfiles: krt.NewStaticCollection[policy.CompiledSecurityProfile](nil, nil, opts...),
				policyBindings: krt.NewStaticCollection(nil, []policy.Bindings{
					{
						TargetUID: workload.UID,
						Groups: []policy.BindingGroup{
							{Kind: policy.PolicyKindTrafficPolicy, Names: []string{compiled.Name}},
						},
					},
				}, opts...),
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				projection, err := compileWorkloadPolicies(krt.TestingDummyContext{}, workload, policies)
				if err != nil || len(projection.AuthorizationNames) != 1 {
					b.Fatalf("projection: %v", err)
				}
			}
		})
	}
}
