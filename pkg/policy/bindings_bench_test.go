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
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// A selector can target one Workload; this benchmark prevents a selector
// policy lifecycle event from restoring namespace-wide binding recomputation.
func BenchmarkPolicyBindingsSelectorPolicyChurn(b *testing.B) {
	b.Run("workloades=10000/policies=100", benchmarkPolicyBindingsSelectorPolicyChurn)
}

func benchmarkPolicyBindingsSelectorPolicyChurn(b *testing.B) {
	const (
		workloadCount = 10_000
		policyCount   = 100
		targetUID     = "workload-42"
	)
	stop := make(chan struct{})
	b.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workloades := make([]model.Workload, workloadCount)
	for index := range workloades {
		workloades[index] = model.Workload{
			UID:       fmt.Sprintf("workload-%d", index),
			Namespace: "demo",
			Labels:    map[string]string{"app": "workload", "workload": fmt.Sprintf("workload-%d", index)},
		}
	}
	basePolicies := make([]PolicyAttachment, policyCount)
	for index := range basePolicies {
		attachment, err := NewPolicyAttachment(PolicyAttachment{
			Kind: PolicyKindTrafficPolicy,
			Name: fmt.Sprintf("demo/policy-%d", index),
			Target: AttachmentTarget{
				Namespaces: []string{"demo"},
				Selector:   metav1.LabelSelector{MatchLabels: map[string]string{"app": "workload"}},
			},
		})
		if err != nil {
			b.Fatalf("new base policy %d: %v", index, err)
		}
		basePolicies[index] = attachment
	}
	attachments := krt.NewMutableCollection(nil, basePolicies, options...)
	bindings := NewWorkloadPolicyBindingsCollection(
		krt.NewStaticCollection(nil, workloades, options...),
		attachments.AsCollection(),
		krt.NewOptionsBuilder(stop, "benchmark", nil),
	)
	if !bindings.WaitUntilSynced(stop) {
		b.Fatal("Workload policy bindings did not sync")
	}
	events := make(chan krt.Event[Bindings], 1)
	registration := bindings.RegisterBatch(func(batch []krt.Event[Bindings]) {
		for _, event := range batch {
			events <- event
		}
	}, false)
	b.Cleanup(registration.UnregisterHandler)
	selected, err := NewPolicyAttachment(PolicyAttachment{
		Kind: PolicyKindTrafficPolicy,
		Name: "demo/selected-egress",
		Target: AttachmentTarget{
			Namespaces: []string{"demo"},
			Selector:   metav1.LabelSelector{MatchLabels: map[string]string{"workload": targetUID}},
		},
	})
	if err != nil {
		b.Fatalf("new selector policy: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for iteration := range b.N {
		if iteration%2 == 0 {
			attachments.ConditionalUpdateObject(selected)
		} else {
			attachments.DeleteObject(selected.ResourceName())
		}
		if event := awaitBindingEvent(b, events); event.Latest().TargetUID != targetUID {
			b.Fatalf("binding event = %+v, want %s", event.Latest(), targetUID)
		}
	}
	b.StopTimer()
}

// Global attachment churn with one namespace policy per Workload mirrors the
// production-sized fanout without including cold compilation in the measurement.
func BenchmarkPolicyBindingsGlobalChurn(b *testing.B) {
	for _, count := range []int{1000, 2000} {
		b.Run(fmt.Sprintf("workloads=policies=%d", count), func(b *testing.B) {
			stop := make(chan struct{})
			b.Cleanup(func() { close(stop) })
			opts := []krt.CollectionOption{krt.WithStop(stop)}
			workloads := make([]model.Workload, count)
			policies := make([]PolicyAttachment, count)
			for i := range count {
				uid := fmt.Sprintf("workload-%d", i)
				workloads[i] = model.Workload{UID: uid, Namespace: "demo", Labels: map[string]string{"app": uid}}
				var err error
				policies[i], err = NewPolicyAttachment(
					PolicyAttachment{
						Kind: PolicyKindTrafficPolicy,
						Name: uid,
						Target: AttachmentTarget{
							Namespaces: []string{"demo"},
							Selector:   metav1.LabelSelector{MatchLabels: map[string]string{"app": uid}},
						},
					},
				)
				if err != nil {
					b.Fatal(err)
				}
			}
			attachments := krt.NewMutableCollection(nil, policies, opts...)
			bindings := NewWorkloadPolicyBindingsCollection(
				krt.NewStaticCollection(nil, workloads, opts...),
				attachments.AsCollection(),
				krt.NewOptionsBuilder(stop, "benchmark", nil),
			)
			if !bindings.WaitUntilSynced(stop) {
				b.Fatal("bindings did not sync")
			}
			events := make(chan krt.Event[Bindings], count)
			registration := bindings.RegisterBatch(func(batch []krt.Event[Bindings]) {
				for _, event := range batch {
					events <- event
				}
			}, false)
			b.Cleanup(registration.UnregisterHandler)
			global, err := NewPolicyAttachment(
				PolicyAttachment{Kind: PolicyKindTrafficPolicy, Name: "global", Target: AttachmentTarget{Global: true}},
			)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				if i%2 == 0 {
					attachments.ConditionalUpdateObject(global)
				} else {
					attachments.DeleteObject(global.ResourceName())
				}
				for range count {
					awaitBindingEvent(b, events)
				}
			}
			b.StopTimer()
		})
	}
}
