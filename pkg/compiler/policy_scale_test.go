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
	"sync/atomic"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// Benchmarks for policy attachment matching at scale.

func TestSNIRulesOnlyUpdateDoesNotRecomputeWorkloadAttachments(t *testing.T) {
	const sandboxCount = 250
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	builder := krt.NewOptionsBuilder(stop, "", nil)

	subjects := krt.NewStaticCollection[policy.SandboxSubject](nil, nil, options...)
	for index := range sandboxCount {
		subjects.ConditionalUpdateObject(policy.SandboxSubject{
			SandboxUID: fmt.Sprintf("cluster//Pod/demo/sandbox-%d", index),
			Namespace:  "demo",
			Labels:     map[string]string{"app": "sandbox"},
		})
	}
	profiles := krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...)
	profile := model.SecurityProfile{
		Name: "security-profile", Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "sandbox"}},
			Rules: []agentsv1alpha1.SecurityRule{{
				Name:  "api",
				Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}},
			}},
		},
	}
	profiles.ConditionalUpdateObject(profile)

	compiled := krt.NewCollection(profiles,
		func(_ krt.HandlerContext, profile model.SecurityProfile) *policy.CompiledSNIPolicy {
			result, err := policy.CompileSNIProfile(profile)
			if err != nil {
				t.Errorf("compile SNI profile: %v", err)
			}
			return result
		}, append(options, krt.WithName("test-sni-policies"))...)
	projected := policy.NewPolicyAttachmentsCollection(compiled, builder, "sni-policy-attachments")
	sandboxes := krt.NewStaticCollection[model.Sandbox](nil, nil, options...)
	bindings := policy.NewSandboxPolicyBindingsCollection(sandboxes, subjects, projected, builder)

	var workloadAttachmentRecomputes atomic.Int64
	workloadAttachments := krt.NewCollection(bindings,
		func(_ krt.HandlerContext, binding policy.SandboxPolicyBindings) *policy.SandboxPolicyBindings {
			workloadAttachmentRecomputes.Add(1)
			return &binding
		}, append(options, krt.WithName("test-workload-attachments"))...)
	inline := newSandboxSNIPolicies(bindings, compiled, func(name string) []krt.CollectionOption { return builder.WithName(name) })
	var inlineUpdates atomic.Int64
	resources := krt.NewCollection(inline, func(_ krt.HandlerContext, value SandboxSNIPolicy) *SandboxSNIPolicy {
		inlineUpdates.Add(1)
		return &value
	}, builder.WithName("observed-inline-policies")...)

	if !workloadAttachments.WaitUntilSynced(stop) || !resources.WaitUntilSynced(stop) {
		t.Fatal("test policy graph did not sync")
	}
	workloadAttachmentRecomputes.Store(0)
	inlineUpdates.Store(0)

	updated := profile
	updated.Spec = agentsv1alpha1.SecurityProfileSpec{
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "sandbox"}},
		Rules: []agentsv1alpha1.SecurityRule{{
			Name:  "api",
			Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"changed.example.com"}}},
		}},
	}
	profiles.ConditionalUpdateObject(updated)
	eventually(t, func() bool { return inlineUpdates.Load() == sandboxCount }, "inline SNI payloads updated")
	settle()

	if got := workloadAttachmentRecomputes.Load(); got != 0 {
		t.Fatalf("workload attachment recomputes = %d, want 0", got)
	}
	if got := inlineUpdates.Load(); got != sandboxCount {
		t.Fatalf("inline policy updates = %d, want %d", got, sandboxCount)
	}
}

func benchmarkPolicyScale(b *testing.B, sandboxCount, policyCount int, matching bool) {
	b.Helper()
	stop := make(chan struct{})
	b.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workloads := krt.NewStaticCollection[model.Workload](nil, nil, options...)
	for index := range sandboxCount {
		workload := testWDSWorkload(fmt.Sprintf("sandbox-%d", index), "", fmt.Sprintf("10.%d.%d.%d", (index/65536)%256, (index/256)%256, index%256))
		workload.Labels = map[string]string{"app": "sandbox"}
		workloads.ConditionalUpdateObject(workload)
	}

	selectorValue := "sandbox"
	if !matching {
		selectorValue = "does-not-match"
	}
	securityProfiles := krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...)
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
	inputs.Workloads = workloads
	inputs.SecurityProfiles = securityProfiles
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

func BenchmarkCompileSandboxesWithMatchingSecurityProfiles(b *testing.B) {
	benchmarkPolicyScale(b, 10_000, 100, true)
}

// Benchmarks the non-matching case: full selector evaluation against every sandbox.
func BenchmarkCompileSandboxesWithNonMatchingSecurityProfiles(b *testing.B) {
	benchmarkPolicyScale(b, 10_000, 100, false)
}

// BenchmarkIncrementalSandboxUpdate measures the cost of a single workload edit at scale.
func BenchmarkIncrementalSandboxUpdate(b *testing.B) {
	const sandboxCount = 10_000
	stop := make(chan struct{})
	b.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}

	workloads := krt.NewStaticCollection[model.Workload](nil, nil, options...)
	for index := range sandboxCount {
		workload := testWDSWorkload(fmt.Sprintf("sandbox-%d", index), "", fmt.Sprintf("10.%d.%d.%d", (index/65536)%256, (index/256)%256, index%256))
		workload.Labels = map[string]string{"app": "sandbox"}
		workloads.ConditionalUpdateObject(workload)
	}
	securityProfiles := krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...)
	for index := range 100 {
		securityProfiles.ConditionalUpdateObject(model.SecurityProfile{
			Name:      fmt.Sprintf("profile-%d", index),
			Namespace: "demo",
			Spec: agentsv1alpha1.SecurityProfileSpec{
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "sandbox"}},
				Rules: []agentsv1alpha1.SecurityRule{{
					Name:  "api",
					Match: []agentsv1alpha1.RuleMatch{{Domains: []string{fmt.Sprintf("api-%d.example.com", index)}}},
				}},
			},
		})
	}
	inputs := validCompilerInputs(stop)
	inputs.Workloads = workloads
	inputs.SecurityProfiles = securityProfiles
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		b.Fatal(err)
	}
	waitSynced(b, compiler)

	target := "cluster//Pod/demo/sandbox-0"
	previous := compiler.graph.resources.GetKey(model.AddressType + "|" + target)
	if previous == nil {
		b.Fatal("target workload missing")
	}
	previousHash := previous.Hash

	b.ReportAllocs()
	b.ResetTimer()
	for iteration := range b.N {
		workload := testWDSWorkload("sandbox-0", "", "10.0.0.0")
		workload.Labels = map[string]string{"app": "sandbox"}
		workload.NodeName = fmt.Sprintf("node-%d", iteration)
		workloads.ConditionalUpdateObject(workload)
		// Wait for the change to reach the joined collection, then assemble.
		for {
			current := compiler.graph.resources.GetKey(model.AddressType + "|" + target)
			if current != nil && current.Hash != previousHash {
				previousHash = current.Hash
				break
			}
		}
		if _, err := compiler.Snapshot(); err != nil {
			b.Fatal(err)
		}
	}
}
