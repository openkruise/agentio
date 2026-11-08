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

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func benchmarkPolicySnapshot(b *testing.B, workloadCount, policyCount int, matching bool) {
	b.Helper()
	stop := make(chan struct{})
	b.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workloads := krt.NewMutableCollection[model.Workload](nil, nil, options...)
	for index := range workloadCount {
		workload := testWDSWorkload(fmt.Sprintf("workload-%d", index), "", fmt.Sprintf("10.%d.%d.%d", (index/65536)%256, (index/256)%256, index%256))
		workload.Labels = map[string]string{"app": "workload"}
		workloads.ConditionalUpdateObject(workload)
	}

	selectorValue := "workload"
	if !matching {
		selectorValue = "does-not-match"
	}
	securityProfiles := krt.NewMutableCollection[model.SecurityProfile](nil, nil, options...)
	for index := range policyCount {
		securityProfiles.ConditionalUpdateObject(model.SecurityProfile{
			Name:      fmt.Sprintf("profile-%d", index),
			Namespace: "demo",
			Spec: agentsv1alpha1.SecurityProfileSpec{
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": selectorValue}},
				Rules: []agentsv1alpha1.SecurityRule{{
					Name:  "api",
					Match: []agentsv1alpha1.RuleMatch{{Domains: []string{fmt.Sprintf("api-%d.example.com", index)}}},
				}},
			},
		})
	}

	inputs := validCompilerInputs(stop)
	inputs.Workloads = workloads.AsCollection()
	inputs.SecurityProfiles = securityProfiles.AsCollection()
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		b.Fatal(err)
	}
	waitSynced(b, compiler)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := compiler.Snapshot(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCompilerWorkloadUpdate measures propagation of one Workload edit and snapshot assembly.
func BenchmarkCompilerWorkloadUpdate(b *testing.B) {
	for _, policyCount := range []int{1, 5, 10, 100} {
		b.Run(fmt.Sprintf("workloads=10000/profiles=%d", policyCount), func(b *testing.B) {
			const workloadCount = 10_000
			stop := make(chan struct{})
			b.Cleanup(func() { close(stop) })
			options := []krt.CollectionOption{krt.WithStop(stop)}

			workloads := krt.NewMutableCollection[model.Workload](nil, nil, options...)
			for index := range workloadCount {
				workload := testWDSWorkload(fmt.Sprintf("workload-%d", index), "", fmt.Sprintf("10.%d.%d.%d", (index/65536)%256, (index/256)%256, index%256))
				workload.Labels = map[string]string{"app": "workload"}
				workloads.ConditionalUpdateObject(workload)
			}
			securityProfiles := krt.NewMutableCollection[model.SecurityProfile](nil, nil, options...)
			for index := range policyCount {
				securityProfiles.ConditionalUpdateObject(model.SecurityProfile{
					Name:      fmt.Sprintf("profile-%d", index),
					Namespace: "demo",
					Spec: agentsv1alpha1.SecurityProfileSpec{
						Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "workload"}},
						Rules: []agentsv1alpha1.SecurityRule{{
							Name:  "api",
							Match: []agentsv1alpha1.RuleMatch{{Domains: []string{fmt.Sprintf("api-%d.example.com", index)}}},
						}},
					},
				})
			}
			inputs := validCompilerInputs(stop)
			inputs.Workloads = workloads.AsCollection()
			inputs.SecurityProfiles = securityProfiles.AsCollection()
			compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
			if err != nil {
				b.Fatal(err)
			}
			waitSynced(b, compiler)

			target := "cluster//Pod/demo/workload-0"
			previous := compiler.graph.resources.GetKey(model.AddressType + "|" + target)
			if previous == nil {
				b.Fatal("target workload missing")
			}
			previousHash := previous.Hash

			b.ReportAllocs()
			b.ResetTimer()
			for iteration := range b.N {
				workload := testWDSWorkload("workload-0", "", "10.0.0.0")
				workload.Labels = map[string]string{"app": "workload"}
				workload.NodeName = fmt.Sprintf("updated-node-%d", iteration)
				workloads.ConditionalUpdateObject(workload)
				// Wait for the change to reach the joined collection, then assemble.
				testutil.Eventually(b, func() bool {
					current := compiler.graph.resources.GetKey(model.AddressType + "|" + target)
					if current == nil || current.Hash == previousHash {
						return false
					}
					previousHash = current.Hash
					return true
				}, "Workload update reached the compiled resources")
				if _, err := compiler.Snapshot(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkCompilerPolicySnapshot(b *testing.B) {
	for _, policyCount := range []int{1, 5, 10, 100} {
		for _, matching := range []bool{true, false} {
			b.Run(fmt.Sprintf("workloads=10000/profiles=%d/matching=%t", policyCount, matching), func(b *testing.B) {
				benchmarkPolicySnapshot(b, 10_000, policyCount, matching)
			})
		}
	}
	b.Run("workloads=100000/profiles=1/matching=true", func(b *testing.B) {
		benchmarkPolicySnapshot(b, 100_000, 1, true)
	})
}
