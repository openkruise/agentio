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
	"context"
	"reflect"
	"testing"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
)

type staticWorkloadPolicies map[string][]string

func (p staticWorkloadPolicies) SNIPolicy(sandboxUID string) *extensionsv1.SniTrafficPolicy {
	names := p[sandboxUID]
	if len(names) == 0 {
		return nil
	}
	result := &extensionsv1.SniTrafficPolicy{}
	for _, name := range names {
		result.Rules = append(result.Rules, &extensionsv1.SniRule{Match: &extensionsv1.SniMatch{Sni: []string{name}}})
	}
	return result
}

func TestWorkloadGeneratorProjectsDirectResourceFromCanonicalAddress(t *testing.T) {
	policies := staticWorkloadPolicies{"sandbox-a": {"demo/first", "demo/second"}}
	address := selectionWorkload(t, "uid-a", "demo", "node-a", "", "demo/auth")
	facts := address.Facts
	workloadFacts := *facts.Workload
	workloadFacts.SandboxUID = "sandbox-a"
	facts.Workload = &workloadFacts
	var err error
	address, err = model.NewResource(address.Key, address.XDSName, address.Value, address.Aliases, facts)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := selectionSnapshot(t, []model.Resource{address})
	if got := len(snapshot.List(model.WorkloadType)); got != 0 {
		t.Fatalf("retained Workload resources = %d, want 0", got)
	}

	delta, err := NewWorkloadGenerator(policies).Generate(context.Background(), GenerationRequest{
		Scope:        model.ClientScope{Class: model.ClientEgressGateway},
		TypeURL:      model.WorkloadType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     snapshot,
		Full:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 1 || delta.Resources[0].Key.TypeURL != model.WorkloadType || delta.Resources[0].XDSName != "uid-a" {
		t.Fatalf("projected resources = %+v", delta.Resources)
	}
	workload := &workloadv1.Workload{}
	if err := delta.Resources[0].Value.UnmarshalTo(workload); err != nil {
		t.Fatalf("unmarshal projected Workload: %v", err)
	}
	if got := workload.GetUid(); got != "uid-a" {
		t.Fatalf("projected UID = %q, want uid-a", got)
	}
	if got, want := workload.GetAuthorizationPolicies(), []string{"demo/auth"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("projected authorization names = %v, want %v", got, want)
	}
	if len(workload.GetExtensions()) != 1 || workload.GetExtensions()[0].GetName() != "sni-traffic-policy" {
		t.Fatalf("projected extensions = %+v", workload.GetExtensions())
	}
	reference := &extensionsv1.SniTrafficPolicy{}
	if err := workload.GetExtensions()[0].GetConfig().UnmarshalTo(reference); err != nil {
		t.Fatalf("unmarshal SNI reference: %v", err)
	}
	if got, want := []string{reference.Rules[0].Match.Sni[0], reference.Rules[1].Match.Sni[0]}, []string{"demo/first", "demo/second"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SNI resource names = %v, want %v", got, want)
	}

	base := &workloadv1.Address{}
	if err := address.Value.UnmarshalTo(base); err != nil {
		t.Fatalf("unmarshal canonical Address: %v", err)
	}
	if len(base.GetWorkload().GetExtensions()) != 0 {
		t.Fatalf("canonical Address was mutated: %+v", base.GetWorkload().GetExtensions())
	}
}

func TestWorkloadGeneratorDoesNotAttachSandboxPolicyWithoutSandboxUID(t *testing.T) {
	address := selectionWorkload(t, "uid-a", "demo", "", "", "")
	facts := address.Facts
	workloadFacts := *facts.Workload
	workloadFacts.SandboxUID = ""
	workloadFacts.Principal = model.Principal{}
	facts.Workload = &workloadFacts
	var err error
	address, err = model.NewResource(address.Key, address.XDSName, address.Value, address.Aliases, facts)
	if err != nil {
		t.Fatal(err)
	}

	delta, err := NewWorkloadGenerator(staticWorkloadPolicies{"": {"demo/must-not-attach"}}).Generate(
		context.Background(), GenerationRequest{
			Scope:        model.ClientScope{Class: model.ClientEgressGateway},
			TypeURL:      model.WorkloadType,
			Subscription: SubscriptionView{wildcard: true},
			Snapshot:     selectionSnapshot(t, []model.Resource{address}),
			Full:         true,
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 1 {
		t.Fatalf("projected resources = %d, want one", len(delta.Resources))
	}
	workload := &workloadv1.Workload{}
	if err := delta.Resources[0].Value.UnmarshalTo(workload); err != nil {
		t.Fatal(err)
	}
	if got := workload.GetExtensions(); len(got) != 0 {
		t.Fatalf("discovery-only Workload extensions = %+v, want no Sandbox policy", got)
	}
}

func TestWildcardDirectWorkloadFullRegenerationOmitsUnchangedResources(t *testing.T) {
	facts := model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
		SandboxUID: "uid-a",
		NodeName:   "node-a",
		Principal:  serviceAccountPrincipal("demo", "default"),
	}}
	// Two map entries exercise deterministic marshaling of the projected value.
	address, err := model.NewResource(
		model.ResourceKey{TypeURL: model.AddressType, Name: "uid-a"}, "",
		mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{
			Uid: "uid-a", Namespace: "demo", Node: "node-a",
			Services: map[string]*workloadv1.PortList{
				"demo/svc-a": {Ports: []*workloadv1.Port{{ServicePort: 80, TargetPort: 8080}}},
				"demo/svc-b": {Ports: []*workloadv1.Port{{ServicePort: 81, TargetPort: 8081}}},
			},
		}}}), nil, facts)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := selectionSnapshot(t, []model.Resource{address})
	request := GenerationRequest{
		Scope:        model.ClientScope{Class: model.ClientEgressGateway},
		TypeURL:      model.WorkloadType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     snapshot,
		Full:         true,
	}

	first, err := (WorkloadGenerator{}).Generate(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Resources) != 1 {
		t.Fatalf("initial full push resources = %v, want one", selectedNames(first.Resources))
	}
	if first.elideSentState {
		t.Fatal("full push for direct Workloads dropped sent state")
	}

	sent := make(map[string]string, len(first.Resources))
	for _, resource := range first.Resources {
		sent[resource.XDSName] = resource.Hash
	}
	request.Subscription = SubscriptionView{wildcard: true, sent: sent}
	// Map-field marshaling order is randomized per attempt; repeat to catch a
	// nondeterministic projection hash.
	for attempt := 0; attempt < 20; attempt++ {
		second, err := (WorkloadGenerator{}).Generate(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if len(second.Resources) != 0 || len(second.Removed) != 0 {
			t.Fatalf("unchanged full regeneration resent resources=%v removed=%v",
				selectedNames(second.Resources), second.Removed)
		}
	}
}

func TestWildcardDirectWorkloadDirtyPushKeepsSentState(t *testing.T) {
	before := selectionWorkload(t, "uid-a", "demo", "node-a", "", "")
	after := selectionWorkload(t, "uid-a", "demo", "node-b", "", "")
	oldSnapshot := selectionSnapshot(t, []model.Resource{before})
	newSnapshot := selectionSnapshot(t, []model.Resource{after})
	update := updateBetween(oldSnapshot, newSnapshot, oldSnapshot.Diff(newSnapshot))

	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        model.ClientScope{Class: model.ClientEgressGateway},
		TypeURL:      model.WorkloadType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     newSnapshot,
		Update:       update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 1 {
		t.Fatalf("dirty push resources = %v, want the changed workload", selectedNames(delta.Resources))
	}
	if delta.elideSentState {
		t.Fatal("dirty push for direct Workloads dropped sent state")
	}
}

func TestWildcardDirectWorkloadIgnoresAddressServiceRemoval(t *testing.T) {
	workload := selectionWorkload(t, "uid-a", "demo", "node-a", "svc-a", "")
	service := selectionService(t, "demo/svc-a")
	oldSnapshot := selectionSnapshot(t, []model.Resource{workload, service})
	newSnapshot := selectionSnapshot(t, []model.Resource{workload})
	update := updateBetween(oldSnapshot, newSnapshot, oldSnapshot.Diff(newSnapshot))

	delta, err := (WorkloadGenerator{}).Generate(context.Background(), GenerationRequest{
		Scope:        model.ClientScope{Class: model.ClientSharedZTunnel, NodeName: "node-a"},
		TypeURL:      model.WorkloadType,
		Subscription: SubscriptionView{wildcard: true},
		Snapshot:     newSnapshot,
		Update:       update,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.Resources) != 0 || len(delta.Removed) != 0 {
		t.Fatalf("service-only Address change produced direct Workload delta: resources=%v removed=%v",
			selectedNames(delta.Resources), delta.Removed)
	}
}

func TestInlineSNIChangesProjectedWorkloadVersion(t *testing.T) {
	address := selectionWorkload(t, "uid-a", "demo", "node-a", "", "")
	facts := address.Facts
	wf := *facts.Workload
	wf.SandboxUID = "sandbox"
	facts.Workload = &wf
	var err error
	address, err = model.NewResource(address.Key, address.XDSName, address.Value, address.Aliases, facts)
	if err != nil {
		t.Fatal(err)
	}
	policies := staticWorkloadPolicies{"sandbox": {"before.example"}}
	generator := NewWorkloadGenerator(policies)
	request := GenerationRequest{Scope: model.ClientScope{Class: model.ClientEgressGateway}, TypeURL: model.WorkloadType,
		Subscription: SubscriptionView{wildcard: true}, Snapshot: selectionSnapshot(t, []model.Resource{address}), Full: true}
	initial, err := generator.Generate(context.Background(), request)
	if err != nil || len(initial.Resources) != 1 {
		t.Fatalf("initial = %v, %v", initial, err)
	}
	request.Subscription.sent = map[string]string{initial.Resources[0].XDSName: initial.Resources[0].Hash}
	policies["sandbox"] = []string{"after.example"}
	changed, err := generator.Generate(context.Background(), request)
	if err != nil || len(changed.Resources) != 1 {
		t.Fatalf("rules-only change = %v, %v", changed, err)
	}
	request.Subscription.sent[changed.Resources[0].XDSName] = changed.Resources[0].Hash
	delete(policies, "sandbox")
	removed, err := generator.Generate(context.Background(), request)
	if err != nil || len(removed.Resources) != 1 {
		t.Fatalf("policy removal = %v, %v", removed, err)
	}
	workload := &workloadv1.Workload{}
	if err := removed.Resources[0].Value.UnmarshalTo(workload); err != nil {
		t.Fatal(err)
	}
	if len(workload.Extensions) != 0 {
		t.Fatalf("stale extensions: %v", workload.Extensions)
	}
}
