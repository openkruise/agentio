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

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/types/known/anypb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/model"
)

func securityReferencesAt(
	t *testing.T,
	compiler *Compiler,
	key model.ResourceKey,
) (*extensionsv1.PolicyReference, string) {
	t.Helper()
	resource, ok := currentSnapshot(t, compiler).Get(key)
	if !ok {
		return nil, ""
	}
	var extensions []*anypb.Any
	switch key.TypeURL {
	case model.AddressType:
		address := &workloadv1.Address{}
		if err := resource.Value.UnmarshalTo(address); err != nil {
			t.Fatal(err)
		}
		for _, extension := range address.GetWorkload().GetExtensions() {
			if extension.Name == "security-profile-reference" {
				extensions = append(extensions, extension.Config)
			}
		}
	case model.SandboxType:
		sandbox := &sandboxv1.Sandbox{}
		if err := resource.Value.UnmarshalTo(sandbox); err != nil {
			t.Fatal(err)
		}
		extensions = sandbox.Extensions
	default:
		t.Fatalf("unexpected resource type: %s", key.TypeURL)
	}
	for _, extension := range extensions {
		references := &extensionsv1.PolicyReference{}
		if extension.MessageIs(references) {
			if err := extension.UnmarshalTo(references); err != nil {
				t.Fatal(err)
			}
			if references.TypeUrl == model.SecurityProfileType {
				return references, resource.Hash
			}
		}
	}
	return nil, resource.Hash
}

func TestSecurityProfileBindingsLifecycle(t *testing.T) {
	// Workload bindings do not require Sandbox mode or HTTPS rules.
	fixture := newIncrementalFixture(t, func(inputs *Inputs) {
		inputs.SandboxMode = false
	})
	workload := testWorkload("demo", "client", "10.1.0.1")
	fixture.workloads.ConditionalUpdateObject(workload)
	key := model.ResourceKey{TypeURL: model.AddressType, Name: workload.UID}
	await := func(want ...string) string {
		t.Helper()
		var hash string
		testutil.Eventually(t, func() bool {
			refs, current := securityReferencesAt(t, fixture.compiler, key)
			hash = current
			return refs != nil && slices.Equal(refs.ResourceNames, want)
		}, "Workload SecurityProfile references")
		return hash
	}
	waitSynced(t, fixture.compiler)
	await()
	shared := model.SecurityProfile{
		Name:      "shared",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Rules: []agentsv1alpha1.SecurityRule{
				{
					Name:  "http",
					Match: []agentsv1alpha1.RuleMatch{{Schemes: []string{"http"}, Domains: []string{"example.com"}}},
				},
			},
		}}
	global := model.SecurityProfile{Name: "global", Global: true}
	fixture.securityProfiles.ConditionalUpdateObject(shared)
	fixture.securityProfiles.ConditionalUpdateObject(global)
	hash := await(global.ResourceName(), shared.ResourceName())
	shared.Spec = *shared.Spec.DeepCopy()
	shared.Spec.Rules[0].Name = "new-body"
	fixture.securityProfiles.ConditionalUpdateObject(shared)
	settle()
	if got := await(global.ResourceName(), shared.ResourceName()); got != hash {
		t.Fatal("body-only change altered WDS resource")
	}
	shared.Spec.Priority = new(int32(0))
	fixture.securityProfiles.ConditionalUpdateObject(shared)
	await(shared.ResourceName(), global.ResourceName())
	shared.Spec.Selector = metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: "Invalid"}},
	}
	fixture.securityProfiles.ConditionalUpdateObject(shared)
	testutil.Eventually(
		t,
		func() bool { return fixture.compiler.Failures()["SecurityProfile/"+shared.ResourceName()] != "" },
		"invalid selection diagnosed",
	)
	await(shared.ResourceName(), global.ResourceName())
	shared.Spec.Selector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "other"}}
	fixture.securityProfiles.ConditionalUpdateObject(shared)
	await(global.ResourceName())
	testutil.Eventually(
		t,
		func() bool { return fixture.compiler.Failures()["SecurityProfile/"+shared.ResourceName()] == "" },
		"valid selection clears diagnostic",
	)
	workload.Labels = map[string]string{"app": "other"}
	fixture.workloads.ConditionalUpdateObject(workload)
	await(shared.ResourceName(), global.ResourceName())
	fixture.securityProfiles.DeleteObject(shared.ResourceName())
	await(global.ResourceName())
	fixture.securityProfiles.DeleteObject(global.ResourceName())
	await()
}

func TestSandboxSecurityProfileReferences(t *testing.T) {
	fixture := newIncrementalFixture(t)
	workload := testWorkload("demo", "client", "10.1.0.1")
	fixture.workloads.ConditionalUpdateObject(workload)
	sandbox := model.Sandbox{UID: "kruise:one", Namespace: "demo", Attester: &model.Attester{WorkloadUID: workload.UID}}
	sibling := model.Sandbox{UID: "kruise:two", Namespace: "demo", Attester: &model.Attester{WorkloadUID: workload.UID}}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	fixture.sandboxes.ConditionalUpdateObject(sibling)
	profileName := model.SandboxSecurityProfileName(sandbox.UID)
	sandbox.Policies = &model.SandboxPolicies{SecurityRules: []agentsv1alpha1.SecurityRule{}}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	shared := model.SecurityProfile{Name: "shared", Namespace: "demo"}
	fixture.securityProfiles.ConditionalUpdateObject(shared)
	waitSynced(t, fixture.compiler)
	key := model.ResourceKey{TypeURL: model.SandboxType, Name: sandbox.UID}
	testutil.Eventually(t, func() bool {
		refs, _ := securityReferencesAt(t, fixture.compiler, key)
		return refs != nil && slices.Equal(refs.ResourceNames, []string{profileName})
	}, "Sandbox binds owned profile without SNI rules")
	testutil.Eventually(t, func() bool {
		refs, _ := securityReferencesAt(
			t,
			fixture.compiler,
			model.ResourceKey{TypeURL: model.SandboxType, Name: sibling.UID},
		)
		return refs != nil && len(refs.ResourceNames) == 0
	}, "sibling does not inherit dedicated profile")
	testutil.Eventually(t, func() bool {
		refs, _ := securityReferencesAt(
			t,
			fixture.compiler,
			model.ResourceKey{TypeURL: model.AddressType, Name: workload.UID},
		)
		return refs != nil && slices.Equal(refs.ResourceNames, []string{shared.ResourceName()})
	}, "host carries only shared bindings")
	sandbox.Attester = &model.Attester{WorkloadUID: "new-host"}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	testutil.Eventually(t, func() bool {
		return manifestAt(t, fixture.compiler, sandbox.UID).GetAttester().GetWorkloadUid() == "new-host"
	}, "Sandbox migration")
	refs, _ := securityReferencesAt(t, fixture.compiler, key)
	if refs == nil || !slices.Equal(refs.ResourceNames, []string{profileName}) {
		t.Fatalf("migration lost owned reference: %v", refs)
	}
	sandbox.Policies = nil
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	testutil.Eventually(t, func() bool {
		refs, _ := securityReferencesAt(t, fixture.compiler, key)
		return refs != nil && len(refs.ResourceNames) == 0
	}, "owned profile deletion publishes an explicit empty binding")
	fixture.sandboxes.DeleteObject(sandbox.UID)
	testutil.Eventually(t, func() bool { return manifestAt(t, fixture.compiler, sandbox.UID) == nil }, "Sandbox deletion")
}

func TestSecurityProfileBindingsPublishEmptyReferences(t *testing.T) {
	fixture := newIncrementalFixture(t)
	workload := testWorkload("demo", "client", "10.1.0.1")
	fixture.workloads.ConditionalUpdateObject(workload)
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "kruise:one", Namespace: "demo"})
	waitSynced(t, fixture.compiler)
	for _, key := range []model.ResourceKey{{TypeURL: model.AddressType, Name: workload.UID}, {TypeURL: model.SandboxType, Name: "kruise:one"}} {
		testutil.Eventually(t, func() bool {
			refs, hash := securityReferencesAt(t, fixture.compiler, key)
			return hash != "" && refs != nil && len(refs.ResourceNames) == 0
		}, "explicit empty SecurityProfile binding")
	}
}

func TestSecurityProfileBindingDrivesSNIProjection(t *testing.T) {
	fixture := newIncrementalFixture(t, func(inputs *Inputs) {
		inputs.SandboxMode = false
	})
	workload := testWorkload("demo", "client", "10.1.0.1")
	other := testWorkload("demo", "other", "10.1.0.2")
	fixture.workloads.ConditionalUpdateObject(workload)
	fixture.workloads.ConditionalUpdateObject(other)
	global := model.SecurityProfile{
		Name:   "global",
		Global: true,
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Rules: []agentsv1alpha1.SecurityRule{
				{Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"global.example"}}}},
			},
		}}
	selected := model.SecurityProfile{
		Name:      "selected",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Rules: []agentsv1alpha1.SecurityRule{
				{Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"selected.example"}}}},
			},
		},
	}
	fixture.securityProfiles.ConditionalUpdateObject(global)
	fixture.securityProfiles.ConditionalUpdateObject(selected)
	waitSynced(t, fixture.compiler)
	await := func(workload model.Workload, names, hosts []string) {
		t.Helper()
		testutil.Eventually(t, func() bool {
			if !slices.Equal(
				fixture.compiler.PolicyNames(workload.UID, model.PolicyKindSecurityProfile),
				names,
			) {
				return false
			}
			resource, found := currentSnapshot(
				t,
				fixture.compiler,
			).Get(model.ResourceKey{TypeURL: model.AddressType, Name: workload.UID})
			if !found {
				return false
			}
			address := &workloadv1.Address{}
			if err := resource.Value.UnmarshalTo(address); err != nil {
				t.Fatal(err)
			}
			sni := &extensionsv1.SniTrafficPolicy{}
			compatibilityExtension(t, address.GetWorkload(), "sni-traffic-policy", sni)
			var gotHosts []string
			for _, rule := range sni.Rules {
				gotHosts = append(gotHosts, rule.GetMatch().GetSni()...)
			}
			refs := &extensionsv1.PolicyReference{}
			foundRefs := compatibilityExtension(t, address.GetWorkload(), "security-profile-reference", refs)
			return slices.Equal(gotHosts, hosts) && foundRefs &&
				refs.TypeUrl == model.SecurityProfileType && slices.Equal(refs.ResourceNames, names)
		}, "one ordered binding drives references and SNI")
	}
	// Unlike the old SNI binding, specificity does not outrank the EPE name tie-break.
	both := []string{global.ResourceName(), selected.ResourceName()}
	await(workload, both, []string{"global.example", "selected.example"})
	await(other, []string{global.ResourceName()}, []string{"global.example"})
	// A bad SNI update must not move the old rules onto a newly selected Workload.
	selected.Spec = *selected.Spec.DeepCopy()
	selected.Spec.Selector.MatchLabels["app"] = "other"
	selected.Spec.Rules[0].Match[0].Domains = []string{"*invalid.example"}
	fixture.securityProfiles.ConditionalUpdateObject(selected)
	testutil.Eventually(
		t,
		func() bool { return fixture.compiler.Failures()["SecurityProfile/"+selected.ResourceName()] != "" },
		"invalid SNI diagnosed",
	)
	settle()
	await(workload, both, []string{"global.example", "selected.example"})
	await(other, []string{global.ResourceName()}, []string{"global.example"})
	selected.Spec = *selected.Spec.DeepCopy()
	selected.Spec.Rules[0].Match[0].Domains = []string{"new.example"}
	fixture.securityProfiles.ConditionalUpdateObject(selected)
	await(workload, []string{global.ResourceName()}, []string{"global.example"})
	await(other, both, []string{"global.example", "new.example"})
	// HTTP-only profiles keep their shared binding but stop contributing SNI.
	selected.Spec = *selected.Spec.DeepCopy()
	selected.Spec.Rules[0].Match[0].Schemes = []string{"http"}
	fixture.securityProfiles.ConditionalUpdateObject(selected)
	await(other, both, []string{"global.example"})
	if failures := fixture.compiler.Failures(); len(failures) != 0 {
		t.Fatalf("HTTP-only profile reported unavailable: %v", failures)
	}
	fixture.securityProfiles.DeleteObject(selected.ResourceName())
	await(other, []string{global.ResourceName()}, []string{"global.example"})
}
