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

func TestSecurityProfileBodyUpdateDoesNotRecomputeWorkloadPolicies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const count = 32
		stop := t.Context().Done()
		builder := krt.NewOptionsBuilder(stop, "", nil)
		var clients []model.Workload
		for i := range count {
			clients = append(clients, testWorkload("demo", fmt.Sprintf("client-%d", i), fmt.Sprintf("10.0.0.%d", i+1)))
			clients[i].Labels = map[string]string{"app": "shared"}
		}
		source := model.SecurityProfile{
			Name:      "policy",
			Namespace: "demo",
			UID:       "old",
			Spec:      agents.SecurityProfileSpec{Selector: metav1.LabelSelector{MatchLabels: clients[0].Labels}},
		}
		sources := krt.NewMutableCollection(nil, []model.SecurityProfile{source}, builder.WithName("sources")...)
		inputs := validCompilerInputs(stop)
		inputs.SandboxMode = false
		inputs.Workloads = krt.NewStaticCollection(nil, clients, builder.WithName("workloads")...)
		inputs.SecurityProfiles = sources.AsCollection()
		failures := newFailureRecorder()
		policies := newPolicyCollections(inputs, newConfiguration(inputs, failures, builder.WithName),
			newTrafficPolicyInputs(inputs), failures, builder.WithName, builder)
		workloads := newWorkloadPolicies(inputs, policies, nil, failures, builder.WithName)
		bodies := newSecurityProfileResources(policies.securityProfiles, failures, builder.WithName)
		if !workloads.WaitUntilSynced(stop) || !bodies.WaitUntilSynced(stop) {
			t.Fatal("profile and Workload collections did not sync")
		}
		synctest.Wait()
		recomputes := workloads.Metadata()["recomputeTotal"].(uint64)
		body := bodies.GetKey(model.SecurityProfileType + "|" + source.ResourceName())
		if body == nil {
			t.Fatal("initial profile body missing")
		}
		for _, change := range []func(){
			func() { source.Spec.Rules = []agents.SecurityRule{{Name: "http"}} },
			func() {
				source.Spec.Inputs = []agents.SecurityProfileInput{{Name: "settings", Inline: map[string]string{"key": "value"}}}
			},
			func() { source.Spec.Audit = []agents.AuditAction{{Name: "audit"}} },
		} {
			source.Spec = *source.Spec.DeepCopy()
			change()
			sources.UpdateObject(source)
			synctest.Wait()
			current := bodies.GetKey(body.ResourceName())
			if current == nil || current.Hash == body.Hash {
				t.Fatal("HTTP configuration change did not publish its body")
			}
			if got := workloads.Metadata()["recomputeTotal"].(uint64); got != recomputes {
				t.Fatalf("body-only update triggered %d redundant Workload transforms", got-recomputes)
			}
			body = current
		}
		source.UID = "new"
		sources.UpdateObject(source)
		synctest.Wait()
		if got := workloads.Metadata()["recomputeTotal"].(uint64); got != recomputes+count {
			t.Fatalf("UID change recomputed %d Workloads, want %d", got-recomputes, count)
		}
		source.Spec = *source.Spec.DeepCopy()
		source.Spec.Rules = []agents.SecurityRule{{Name: "tls",
			Match:   []agents.RuleMatch{{Domains: []string{"example.com"}}},
			Actions: agents.SecurityRuleActions{TLS: &agents.TLSAction{Action: agents.TLSActionDeny}},
		}}
		sources.UpdateObject(source)
		synctest.Wait()
		for _, client := range clients {
			matched := workloads.GetKey(client.UID)
			if matched == nil || len(matched.SecurityProfileReferences) != 1 ||
				matched.SecurityProfileReferences[0].Uid != "new" || len(matched.SNIPolicy.GetRules()) != 1 {
				t.Fatal("identity or SNI change did not reach the bound Workload")
			}
		}
		if got := workloads.Metadata()["recomputeTotal"].(uint64); got != recomputes+2*count {
			t.Fatalf("SNI change did not recompute exactly the bound Workloads: %d", got)
		}
		sources.DeleteObject(source.ResourceName())
		synctest.Wait()
		for _, client := range clients {
			if matched := workloads.GetKey(client.UID); matched == nil || len(matched.SecurityProfileReferences) != 0 {
				t.Fatal("deleted profile binding retained")
			}
		}
	})
}
