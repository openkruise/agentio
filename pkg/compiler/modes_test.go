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
	"reflect"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

func TestCompilerOptionalSandboxInputs(t *testing.T) {
	for _, sandboxMode := range []bool{false, true} {
		for _, withSandbox := range []bool{false, true} {
			t.Run(fmt.Sprintf("sandboxMode=%v/bound=%v", sandboxMode, withSandbox), func(t *testing.T) {
				stop := make(chan struct{})
				t.Cleanup(func() { close(stop) })
				opts := []krt.CollectionOption{krt.WithStop(stop)}
				inputs := validCompilerInputs(stop)
				inputs.SandboxMode = sandboxMode
				if !sandboxMode {
					inputs.Sandboxes = nil // Ordinary mode requires no Sandbox source.
				}
				worker := testWorkload("demo", "client", "10.0.0.1")
				inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{worker}, opts...)
				if withSandbox {
					inputs.Sandboxes = krt.NewStaticCollection(
						nil,
						[]model.Sandbox{
							{
								UID:       "actor",
								Namespace: "demo",
								Attester:  &model.Attester{WorkloadUID: worker.UID},
								Policies: &model.SandboxPolicies{
									SecurityRules: []agentsv1alpha1.SecurityRule{
										{
											Name:  "secret",
											Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"actor.example.com"}}},
										},
									},
								},
							},
						},
						opts...)
				}
				selector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}
				inputs.TrafficPolicies = krt.NewStaticCollection(nil, []model.TrafficPolicy{{
					Name:      "allow",
					Namespace: "demo",
					Spec: agentsv1alpha1.TrafficPolicySpec{
						Selector: selector,
						Egress: &agentsv1alpha1.TrafficPolicyDirection{
							Rules: []agentsv1alpha1.TrafficPolicyRule{
								{
									Action: agentsv1alpha1.RuleActionAllow,
									To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "203.0.113.0/24"}},
								},
							},
						},
					},
				}}, opts...)
				inputs.SecurityProfiles = krt.NewStaticCollection(nil, []model.SecurityProfile{
					{
						Name:      "shared",
						Namespace: "demo",
						Spec: agentsv1alpha1.SecurityProfileSpec{
							Selector: selector,
							Rules: []agentsv1alpha1.SecurityRule{
								{
									Name:  "api",
									Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}},
								},
							},
						},
					},
				}, opts...)
				config := krt.NewStaticCollection(
					nil,
					[]model.AgentioConfiguration{
						{
							Value: &configv1.AgentioConfig{
								EgressPolicies: []*extensionsv1.EgressPolicy{
									{Policy: extensionsv1.EgressPolicyAction_PASSTHROUGH},
								},
							},
						},
					},
					opts...)
				inputs.AgentioConfig = config
				compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
				if err != nil {
					t.Fatal(err)
				}
				snapshot := compileSynced(t, compiler)
				resource, ok := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
				if !ok {
					t.Fatal("Workload missing")
				}
				address := new(workloadv1.Address)
				if err := resource.Value.UnmarshalTo(address); err != nil {
					t.Fatal(err)
				}
				wire := address.GetWorkload()
				if len(snapshot.List(model.TrafficPolicyType)) != 1 {
					t.Fatal("shared TrafficPolicy resource missing")
				}
				wantExtensions := []string{
					"workload-metadata",
					"traffic-policy-reference",
					"security-profile-reference",
					"egress-policies",
					"sni-traffic-policy",
				}
				if !reflect.DeepEqual(extensionNames(wire.Extensions), wantExtensions) {
					t.Fatalf("Workload extensions = %v, want %v", extensionNames(wire.Extensions), wantExtensions)
				}
				refs := new(extensionsv1.PolicyReference)
				if !compatibilityExtension(t, wire, "traffic-policy-reference", refs) ||
					refs.TypeUrl != model.TrafficPolicyType ||
					!reflect.DeepEqual(
						policyReferenceNames(refs.Resources),
						[]string{"namespaces/demo/trafficPolicies/allow"},
					) {
					t.Fatalf("native Workload references = %v", refs)
				}
				if len(wire.AuthorizationPolicies) != 1 || len(snapshot.List(model.WorkloadAuthorizationType)) != 1 {
					t.Fatalf(
						"shared Authorizations missing in sandboxMode=%v, bound=%v: %v",
						sandboxMode,
						withSandbox,
						wire.AuthorizationPolicies,
					)
				}
				sni := new(extensionsv1.SniTrafficPolicy)
				wantSNIRules := 1
				if sandboxMode && withSandbox {
					wantSNIRules++
				}
				if !compatibilityExtension(t, wire, "sni-traffic-policy", sni) || len(sni.Rules) != wantSNIRules {
					t.Fatalf("Workload SNI rules = %v, want %d", sni, wantSNIRules)
				}
				binding := compiler.Bindings().GetKey(worker.UID)
				if binding == nil || !reflect.DeepEqual(binding.PolicyNames(policy.PolicyKindTrafficPolicy),
					[]string{"namespaces/demo/trafficPolicies/allow"}) {
					t.Fatalf("Workload policy binding = %+v", binding)
				}
				if sandboxMode && withSandbox {
					manifest := manifestAt(t, compiler, "actor")
					if manifest == nil ||
						manifest.GetAttester().GetWorkloadUid() != worker.UID || len(manifest.Extensions) != 2 {
						t.Fatalf("Sandbox inline output = %v", manifest)
					}
					if compiler.Bindings().GetKey("actor") != nil {
						t.Fatalf("Sandbox retained system policy selection: %v", manifest)
					}
				} else if len(snapshot.List(model.SandboxType)) != 0 {
					t.Fatal("ordinary Workload published a Sandbox")
				}

			})
		}
	}
}

func TestSandboxAttesterMovePreservesWorkloads(t *testing.T) {
	fixture := newIncrementalFixture(t)
	a, b := testWorkload("demo", "a", "10.0.0.1"), testWorkload("demo", "b", "10.0.0.2")
	fixture.workloads.UpdateObject(a)
	fixture.workloads.UpdateObject(b)
	sandbox := model.Sandbox{
		UID:      "actor",
		Attester: &model.Attester{WorkloadUID: a.UID},
	}
	fixture.sandboxes.UpdateObject(sandbox)
	testutil.Eventually(t, func() bool {
		snapshot := currentSnapshot(t, fixture.compiler)
		_, hasA := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: a.UID})
		_, hasB := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: b.UID})
		return hasA && hasB && manifestAt(t, fixture.compiler, sandbox.UID) != nil
	}, "initial Workloads and Sandbox ready")
	baseline := currentSnapshot(t, fixture.compiler)
	check := func(uid string) {
		t.Helper()
		testutil.Eventually(t, func() bool {
			snapshot := currentSnapshot(t, fixture.compiler)
			for _, worker := range []model.Workload{a, b} {
				r, ok := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
				if !ok {
					return false
				}
				old, found := baseline.Get(r.Key)
				if !found || old.Hash != r.Hash {
					return false
				}
			}
			manifest := manifestAt(t, fixture.compiler, "actor")
			return manifest != nil &&
				manifest.GetAttester().GetWorkloadUid() == uid
		}, "attester changes propagate independently of policies")
	}
	check(a.UID)
	sandbox.Attester = &model.Attester{WorkloadUID: b.UID}
	fixture.sandboxes.UpdateObject(sandbox)
	check(b.UID)
	sandbox.Attester = nil
	fixture.sandboxes.UpdateObject(sandbox)
	check("")
}

func TestSandboxLifecyclePreservesWorkloadPolicies(t *testing.T) {
	fixture := newIncrementalFixture(t)
	host := testWorkload("demo", "host", "10.0.0.1")
	host.Labels = map[string]string{"app": "shared"}
	ordinary := testWorkload("demo", "ordinary", "10.0.0.2")
	ordinary.Labels = host.Labels
	fixture.workloads.UpdateObject(host)
	fixture.workloads.UpdateObject(ordinary)
	selector := metav1.LabelSelector{MatchLabels: host.Labels}
	fixture.trafficPolicies.UpdateObject(model.TrafficPolicy{
		Name:      "allow",
		Namespace: "demo",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: selector,
			Egress: &agentsv1alpha1.TrafficPolicyDirection{
				Rules: []agentsv1alpha1.TrafficPolicyRule{
					{
						Action: agentsv1alpha1.RuleActionAllow,
						To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "203.0.113.0/24"}},
					},
				},
			},
		},
	})
	fixture.securityProfiles.UpdateObject(model.SecurityProfile{
		Name:      "sni",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: selector,
			Rules: []agentsv1alpha1.SecurityRule{
				{Name: "api", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}}},
			},
		},
	})
	fixture.agentioConfig.UpdateObject(
		model.AgentioConfiguration{
			Value: &configv1.AgentioConfig{
				EgressPolicies: []*extensionsv1.EgressPolicy{{Policy: extensionsv1.EgressPolicyAction_PASSTHROUGH}},
			},
		},
	)
	checkWorkloads := func() {
		t.Helper()
		testutil.Eventually(t, func() bool {
			snapshot := currentSnapshot(t, fixture.compiler)
			for _, workload := range []model.Workload{host, ordinary} {
				r, ok := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: workload.UID})
				if !ok {
					return false
				}
				wire := new(workloadv1.Address)
				if r.Value.UnmarshalTo(wire) != nil {
					return false
				}
				binding := fixture.compiler.Bindings().GetKey(workload.UID)
				if binding == nil || len(wire.GetWorkload().AuthorizationPolicies) != 1 ||
					!reflect.DeepEqual(
						extensionNames(wire.GetWorkload().Extensions),
						[]string{
							"workload-metadata",
							"traffic-policy-reference",
							"security-profile-reference",
							"egress-policies",
							"sni-traffic-policy",
						},
					) {
					return false
				}
			}
			return true
		}, "host and ordinary Workload policy ownership")
	}
	checkWorkloads() // Shared policies apply before Sandbox discovery.
	fixture.sandboxes.UpdateObject(
		model.Sandbox{
			UID:       "actor",
			Namespace: "demo",
			Attester:  &model.Attester{WorkloadUID: host.UID},
		},
	)
	testutil.Eventually(t, func() bool {
		manifest := manifestAt(t, fixture.compiler, "actor")
		return manifest != nil && len(manifest.Extensions) == 1
	}, "Sandbox only carries its own policies")
	checkWorkloads()
	fixture.sandboxes.DeleteObject("actor")
	testutil.Eventually(t, func() bool { return manifestAt(t, fixture.compiler, "actor") == nil }, "Sandbox removed")
	checkWorkloads() // Shared policies survive Sandbox deletion.
}

func TestWorkloadOwnsOrderedTrafficPolicyBindings(t *testing.T) {
	fixture := newIncrementalFixture(t)
	worker := testWorkload("demo", "client", "10.0.0.1")
	fixture.workloads.UpdateObject(worker)
	fixture.sandboxes.UpdateObject(model.Sandbox{UID: "actor", Namespace: "demo"})
	for _, source := range []model.TrafficPolicy{
		{Name: "namespace", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 40}},
		{Name: "selector", Namespace: "demo", Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 20, Selector: metav1.LabelSelector{MatchLabels: worker.Labels}}},
		{Name: "global", Global: true, Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 10}},
		{Name: "root", Namespace: "agentio-system", Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 30}},
	} {
		source.Spec.Egress = &agentsv1alpha1.TrafficPolicyDirection{}
		fixture.trafficPolicies.UpdateObject(source)
	}
	want := []string{
		"trafficPolicies/global",
		"namespaces/demo/trafficPolicies/selector",
		"namespaces/agentio-system/trafficPolicies/root",
		"namespaces/demo/trafficPolicies/namespace",
	}
	testutil.Eventually(t, func() bool {
		binding := fixture.compiler.Bindings().GetKey(worker.UID)
		manifest := manifestAt(t, fixture.compiler, "actor")
		workload, _ := compatibilityWorkload(t, currentSnapshot(t, fixture.compiler), worker.UID)
		refs := new(extensionsv1.PolicyReference)
		return binding != nil && manifest != nil && workload != nil &&
			compatibilityExtension(t, workload, "traffic-policy-reference", refs) &&
			refs.TypeUrl == model.TrafficPolicyType && reflect.DeepEqual(policyReferenceNames(refs.Resources), want) &&
			reflect.DeepEqual(binding.PolicyNames(model.PolicyKindTrafficPolicy), want)
	}, "Workload owns ordered global, namespace and selector policies")
}

func TestWorkloadTrafficPolicyBindingUpdates(t *testing.T) {
	fixture := newIncrementalFixture(t, func(inputs *Inputs) { inputs.SandboxMode = false })
	worker := testWorkload("demo", "client", "10.0.0.1")
	fixture.workloads.UpdateObject(worker)
	global := model.TrafficPolicy{Name: "global", Global: true, Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 10}}
	selected := model.TrafficPolicy{
		Name:      "selected",
		Namespace: "demo",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Priority: 20,
			Selector: metav1.LabelSelector{MatchLabels: worker.Labels},
		},
	}
	fixture.trafficPolicies.UpdateObject(global)
	fixture.trafficPolicies.UpdateObject(selected)
	check := func(want []string) {
		t.Helper()
		testutil.Eventually(t, func() bool {
			workload, _ := compatibilityWorkload(t, currentSnapshot(t, fixture.compiler), worker.UID)
			refs := new(extensionsv1.PolicyReference)
			return workload != nil && compatibilityExtension(t, workload, "traffic-policy-reference", refs) &&
				reflect.DeepEqual(policyReferenceNames(refs.Resources), want)
		}, "native Workload references converge")
	}
	check([]string{"trafficPolicies/global", "namespaces/demo/trafficPolicies/selected"})
	global.Spec.Priority = 30
	fixture.trafficPolicies.UpdateObject(global)
	check([]string{"namespaces/demo/trafficPolicies/selected", "trafficPolicies/global"})
	worker.Labels = map[string]string{"app": "other"}
	fixture.workloads.UpdateObject(worker)
	check([]string{"trafficPolicies/global"})
	fixture.trafficPolicies.DeleteObject(global.ResourceName())
	check(nil)
}
