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
	"testing/synctest"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestTrafficPolicyBodyUpdateDoesNotRecomputeWorkloadPolicies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stop := make(chan struct{})
		defer close(stop)
		builder := krt.NewOptionsBuilder(stop, "", nil)
		client := testWorkload("demo", "client", "10.0.0.1")
		other := testWorkload("demo", "other", "10.0.0.2")
		source := model.TrafficPolicy{
			Name:      "allow",
			Namespace: "demo",
			UID:       "old",
			Spec: agents.TrafficPolicySpec{
				Selector: metav1.LabelSelector{MatchLabels: client.Labels},
				Egress: &agents.TrafficPolicyDirection{Rules: []agents.TrafficPolicyRule{{
					Action: agents.RuleActionAllow,
					To:     []agents.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
				}}},
			},
		}
		sources := krt.NewMutableCollection(nil, []model.TrafficPolicy{source}, builder.WithName("sources")...)
		inputs := validCompilerInputs(stop)
		inputs.SandboxMode = false
		inputs.Workloads = krt.NewStaticCollection(
			nil,
			[]model.Workload{client, other},
			builder.WithName("workloads")...,
		)
		inputs.TrafficPolicies = sources.AsCollection()
		failures := newFailureRecorder()
		configuration := newConfiguration(inputs, failures, builder.WithName)
		policies := newPolicyCollections(
			inputs,
			configuration,
			newTrafficPolicyInputs(inputs),
			failures,
			builder.WithName,
			builder,
		)
		workloads := newWorkloadPolicies(inputs, policies, nil, failures, builder.WithName)
		if !workloads.WaitUntilSynced(stop) {
			t.Fatal("Workload policies did not sync")
		}
		synctest.Wait()
		count := func() uint64 { return workloads.Metadata()["recomputeTotal"].(uint64) }
		name := "namespaces/demo/trafficPolicies/allow"
		before := policies.trafficPolicies.GetKey(name)
		if before == nil || len(workloads.List()) != 2 {
			t.Fatal("initial policies missing")
		}
		recomputes := count()
		source.Spec = *source.Spec.DeepCopy()
		source.Spec.Egress.Rules[0].To[0].CIDR = "10.0.0.0/8"
		sources.UpdateObject(source)
		synctest.Wait()
		current := policies.trafficPolicies.GetKey(name)
		if current == nil || proto.Equal(before.Policy, current.Policy) || count() != recomputes {
			t.Fatal("rule-body update did not compile independently of Workload references")
		}

		source.UID = "new"
		sources.UpdateObject(source)
		synctest.Wait()
		matched := workloads.GetKey(client.UID)
		if count() != recomputes+1 || matched == nil || len(matched.TrafficPolicyReferences) != 1 ||
			matched.TrafficPolicyReferences[0].Uid != "new" {
			t.Fatal("UID change did not update exactly the bound Workload")
		}
		if unrelated := workloads.GetKey(other.UID); unrelated == nil || len(unrelated.TrafficPolicyReferences) != 0 {
			t.Fatal("unrelated Workload received policy references")
		}

		source.Spec = *source.Spec.DeepCopy()
		source.Spec.Ingress = &agents.TrafficPolicyDirection{Rules: []agents.TrafficPolicyRule{{
			Action: agents.RuleActionAllow,
			From:   []agents.TrafficPolicyPeer{{CIDR: "192.0.2.0/24"}},
		}}}
		sources.UpdateObject(source)
		synctest.Wait()
		matched = workloads.GetKey(client.UID)
		if count() != recomputes+2 || matched == nil ||
			!slices.Equal(matched.AuthorizationNames, []string{"demo/allow-egress", "demo/allow-ingress"}) {
			t.Fatal("authorization reference change did not reach the bound Workload")
		}
		if got := failures.snapshot(); len(got) != 0 {
			t.Fatalf("unexpected compilation failures: %v", got)
		}
	})
}
