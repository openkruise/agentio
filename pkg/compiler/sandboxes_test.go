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
	"net/netip"
	"reflect"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

func manifestAt(t *testing.T, compiler *Compiler, uid string) *sandboxv1.Sandbox {
	t.Helper()
	r, ok := currentSnapshot(t, compiler).Get(model.ResourceKey{TypeURL: model.SandboxType, Name: uid})
	if !ok {
		return nil
	}
	value := new(sandboxv1.Sandbox)
	if err := r.Value.UnmarshalTo(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func trafficPolicyAt(t *testing.T, compiler *Compiler, name string) *securityv1.TrafficPolicy {
	t.Helper()
	resource, ok := currentSnapshot(t, compiler).Get(model.ResourceKey{TypeURL: model.TrafficPolicyType, Name: name})
	if !ok {
		return nil
	}
	value := new(securityv1.TrafficPolicy)
	if err := resource.Value.UnmarshalTo(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSandboxInlineSecurityRulesLifecycle(t *testing.T) {
	fixture := newIncrementalFixture(t)
	shared := model.SecurityProfile{Name: "shared",
		Namespace: "tenant",
		Spec: agentsv1alpha1.SecurityProfileSpec{Rules: []agentsv1alpha1.SecurityRule{{
			Name:  "shared",
			Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"shared.example"}}},
		}}},
	}
	fixture.securityProfiles.ConditionalUpdateObject(shared)
	sandbox := model.Sandbox{UID: "inline", Namespace: "tenant"}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "other", Namespace: "tenant"})
	waitSynced(t, fixture.compiler)
	awaitHosts := func(uid string, hosts ...[]string) {
		t.Helper()
		testutil.Eventually(t, func() bool {
			manifest := manifestAt(t, fixture.compiler, uid)
			if manifest == nil || len(manifest.Extensions) != len(hosts)+1 {
				return false
			}
			for i, want := range hosts {
				payload := new(extensionsv1.SniTrafficPolicy)
				if err := manifest.Extensions[i].UnmarshalTo(payload); err != nil {
					t.Fatal(err)
				}
				if len(payload.Rules) != 1 ||
					payload.Rules[0].Action != extensionsv1.SniAction_SNI_ACTION_TLS_TERMINATION ||
					!reflect.DeepEqual(payload.Rules[0].GetMatch().GetSni(), want) {
					return false
				}
			}
			return true
		}, "Sandbox SNI extensions reflect only inline rules")
	}
	awaitHosts("inline")
	awaitHosts("other")
	other := manifestAt(t, fixture.compiler, "other")
	inline := model.SandboxPolicies{}
	inline.SecurityRules = []agentsv1alpha1.SecurityRule{{
		Name: "inline",
		Match: []agentsv1alpha1.RuleMatch{
			{Domains: []string{"API.Example.", "*.Example", "api.example"}},
			{Domains: []string{"https.example"}, Schemes: []string{"HTTPS"}},
			{Domains: []string{"http.example"}, Schemes: []string{"http"}},
		},
	}}
	sandbox.Policies = &model.SandboxPolicies{SecurityRules: inline.SecurityRules}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	awaitHosts("inline", []string{"api.example", "*.example", "https.example"})

	inline.SecurityRules = []agentsv1alpha1.SecurityRule{
		{Name: "updated", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"updated.example"}}}},
	}
	sandbox.Policies = &model.SandboxPolicies{SecurityRules: inline.SecurityRules}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	awaitHosts("inline", []string{"updated.example"})

	// Reject the whole inline policy, including valid rules preceding the bad one.
	inline.SecurityRules = []agentsv1alpha1.SecurityRule{
		{Name: "valid", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"updated.example"}}}},
		{Name: "invalid", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"*bad.example"}}}},
	}
	sandbox.Policies = &model.SandboxPolicies{SecurityRules: inline.SecurityRules}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	testutil.Eventually(t, func() bool {
		return fixture.compiler.Failures()["SandboxPolicies/"+sandbox.UID] != ""
	}, "invalid SNI records a compilation failure")
	awaitHosts("inline", []string{"updated.example"})

	inline.SecurityRules = []agentsv1alpha1.SecurityRule{
		{
			Name:  "http-only",
			Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"http.example"}, Schemes: []string{"http"}}},
		},
	}
	sandbox.Policies = &model.SandboxPolicies{SecurityRules: inline.SecurityRules}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	awaitHosts("inline")
	testutil.Eventually(
		t,
		func() bool { return fixture.compiler.Failures()["SandboxPolicies/"+sandbox.UID] == "" },
		"valid rules clear the failure",
	)

	fixture.securityProfiles.DeleteObject(shared.ResourceName())
	awaitHosts("inline")
	inline.SecurityRules = []agentsv1alpha1.SecurityRule{
		{Name: "inline", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"*"}}}},
	}
	sandbox.Policies = &model.SandboxPolicies{SecurityRules: inline.SecurityRules}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	awaitHosts("inline", []string{"*"})
	sandbox.Policies = nil
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	awaitHosts("inline")

	// Shared policy updates must not change an unrelated Sandbox.
	fixture.securityProfiles.ConditionalUpdateObject(shared)
	awaitHosts("other")
	if !proto.Equal(other, manifestAt(t, fixture.compiler, "other")) {
		t.Fatal("inline security rules changed another Sandbox")
	}
	fixture.sandboxes.DeleteObject("inline")
	testutil.Eventually(
		t,
		func() bool { return manifestAt(t, fixture.compiler, "inline") == nil },
		"Sandbox deletion removes its SNI rules",
	)
}

func TestMultiSandboxDeletionAndShrinkRetainNetworking(t *testing.T) {
	fixture := newIncrementalFixture(t)
	a := model.Sandbox{UID: "actor-a", Namespace: "tenant"}
	b := model.Sandbox{
		UID:       "actor-b",
		Namespace: "tenant",
	}
	fixture.sandboxes.ConditionalUpdateObject(a)
	fixture.sandboxes.ConditionalUpdateObject(b)
	worker := testWorkload("workers", "worker", "10.1.0.1")
	a.Attester = &model.Attester{WorkloadUID: worker.UID}
	b.Attester = &model.Attester{WorkloadUID: worker.UID}
	fixture.sandboxes.ConditionalUpdateObject(a)
	fixture.sandboxes.ConditionalUpdateObject(b)
	fixture.workloads.ConditionalUpdateObject(worker)
	waitSynced(t, fixture.compiler)
	testutil.Eventually(t, func() bool {
		ma, mb := manifestAt(t, fixture.compiler, a.UID), manifestAt(t, fixture.compiler, b.UID)
		return ma != nil && mb != nil && mb.GetAttester().GetWorkloadUid() == worker.UID && len(mb.Extensions) == 1
	}, "both Sandboxes retain their Workload binding")
	a.Attester = nil
	fixture.sandboxes.ConditionalUpdateObject(a)
	fixture.workloads.ConditionalUpdateObject(worker)
	testutil.Eventually(t, func() bool {
		r, ok := currentSnapshot(
			t,
			fixture.compiler,
		).Get(model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
		return ok && r.Facts.Workload != nil && manifestAt(t, fixture.compiler, b.UID) != nil
	}, "unbinding one Sandbox preserves networking")
	fixture.sandboxes.DeleteObject(b.UID)
	testutil.Eventually(
		t,
		func() bool { return manifestAt(t, fixture.compiler, b.UID) == nil },
		"deleted actor must not become an implicit Pod Sandbox",
	)
	settle()
	if manifestAt(t, fixture.compiler, b.UID) != nil {
		t.Fatal("deleted Sandbox reappeared")
	}
	if ma := manifestAt(t, fixture.compiler, a.UID); ma == nil {
		t.Fatal("unbound valid Sandbox must remain available for prefetch")
	}
}

func TestMalformedSandboxUIDDoesNotStopCompiler(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: " ", Namespace: "tenant"})
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "valid", Namespace: "tenant"})
	waitSynced(t, fixture.compiler)
	testutil.Eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Sandbox/ "]
		valid := manifestAt(t, fixture.compiler, "valid")
		return failed && valid != nil
	}, "invalid UID is isolated from valid Sandboxes")
	fixture.sandboxes.DeleteObject(" ")
	testutil.Eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Sandbox/ "]
		return !failed
	}, "removed malformed UID clears diagnostic")
}

func TestCompilerUsesOnlyProvidedSandboxes(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workload := testWorkload("demo", "client", "10.1.0.2")
	inputs := validCompilerInputs(stop)
	inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{workload}, options...)
	sandboxes := krt.NewMutableCollection[model.Sandbox](nil, nil, options...)
	inputs.Sandboxes = sandboxes.AsCollection()
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	waitSynced(t, compiler)
	if manifestAt(t, compiler, workload.UID) != nil {
		t.Fatal("Workload synthesized a Sandbox inside the compiler")
	}
	sandboxes.UpdateObject(
		model.Sandbox{
			UID:       workload.UID,
			Namespace: "sandbox-namespace",
		},
	)
	testutil.Eventually(t, func() bool { return manifestAt(t, compiler, workload.UID) != nil },
		"provider Sandbox appears")
	sandboxes.DeleteObject(workload.UID)
	testutil.Eventually(t, func() bool {
		return manifestAt(t, compiler, workload.UID) == nil && compiler.Bindings().GetKey(workload.UID) != nil
	}, "Sandbox deletion preserves the surviving Workload binding")
	settle()
	if manifestAt(t, compiler, workload.UID) != nil {
		t.Fatal("surviving Workload resurrected a deleted Sandbox")
	}
}

func TestWorkloadSelectorMetadataUpdateRecomputesBindings(t *testing.T) {
	fixture := newIncrementalFixture(t)
	workload := testWorkload("workload-namespace", "client", "10.1.0.1")
	sandbox := model.Sandbox{
		UID:       workload.UID,
		Namespace: "sandbox-namespace",
	}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	fixture.workloads.ConditionalUpdateObject(workload)
	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name:      "allow",
		Namespace: workload.Namespace,
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	})
	waitSynced(t, fixture.compiler)
	testutil.Eventually(t, func() bool {
		binding := fixture.compiler.Bindings().GetKey(sandbox.UID)
		return binding != nil && reflect.DeepEqual(
			binding.PolicyNames(policy.PolicyKindTrafficPolicy),
			[]string{"namespaces/workload-namespace/trafficPolicies/allow"},
		)
	}, "Workload namespace and labels select policy")

	workload.Labels = map[string]string{"app": "other"}
	fixture.workloads.ConditionalUpdateObject(workload)
	testutil.Eventually(t, func() bool {
		binding := fixture.compiler.Bindings().GetKey(sandbox.UID)
		return binding != nil && len(binding.PolicyNames(policy.PolicyKindTrafficPolicy)) == 0
	}, "Workload label update removes selector-derived binding")
}

func TestSandboxTrafficPolicyTracksPeerUpdates(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.setResolved("api.example.com", netip.MustParseAddr("192.0.2.1"))
	sandbox := model.Sandbox{
		UID:       "a",
		Namespace: "tenant",
		Policies: &model.SandboxPolicies{TrafficRules: &model.TrafficPolicyRules{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "api.example.com"}},
			}}},
		}},
	}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	waitSynced(t, fixture.compiler)
	awaitAddress := func(last byte) {
		t.Helper()
		testutil.Eventually(t, func() bool {
			rules := manifestAt(t, fixture.compiler, "a").GetTrafficPolicy().GetEgress().GetRules()
			return len(rules) == 1 && len(rules[0].Match.DestinationIps) == 1 &&
				reflect.DeepEqual(rules[0].Match.DestinationIps[0].Address, []byte{192, 0, 2, last})
		}, "inline policy follows the peer resolver dependency")
	}
	awaitAddress(1)
	refs, _ := securityReferencesAt(t, fixture.compiler, sandbox.SourceKey())
	if refs == nil || len(refs.ResourceNames) != 0 {
		t.Fatal("traffic-only Sandbox acquired a SecurityProfile reference")
	}
	if len(currentSnapshot(t, fixture.compiler).List(model.TrafficPolicyType)) != 0 {
		t.Fatal("inline traffic rules published an independent TrafficPolicy resource")
	}
	sandbox.Attester = &model.Attester{WorkloadUID: "new-worker"}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	testutil.Eventually(t, func() bool {
		return manifestAt(t, fixture.compiler, "a").GetAttester().GetWorkloadUid() == "new-worker"
	}, "binding and inline rules publish together")
	awaitAddress(1)
	fixture.setResolved("api.example.com", netip.MustParseAddr("192.0.2.2"))
	awaitAddress(2)
}
