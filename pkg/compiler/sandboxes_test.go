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
	"reflect"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
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

func TestSandboxInlinePoliciesWithoutWorkerAndBodyUpdate(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "a", Namespace: "tenant", Labels: map[string]string{"app": "a"}})
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "b", Namespace: "tenant", Labels: map[string]string{"app": "b"}})
	policy := model.TrafficPolicy{
		Name:      "allow",
		Namespace: "tenant",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
			Egress:   &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow, To: []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}}}}},
		},
	}
	fixture.trafficPolicies.ConditionalUpdateObject(policy)
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		a, b := manifestAt(t, fixture.compiler, "a"), manifestAt(t, fixture.compiler, "b")
		return a != nil && len(a.TrafficPolicies) == 1 && b != nil && len(b.TrafficPolicies) == 0
	}, "paused Sandbox manifests compiled independently")
	first := manifestAt(t, fixture.compiler, "a").TrafficPolicies[0]
	// Sandbox and Authorization resources are published by separate collections.
	eventually(t, func() bool {
		return len(currentSnapshot(t, fixture.compiler).List(model.WorkloadAuthorizationType)) == 1
	}, "Workload Authorization published independently")
	worker := testWorkload("workers", "worker", "10.1.0.1")
	for _, uid := range []string{"a", "b"} {
		sandbox := *fixture.sandboxes.GetKey(uid)
		sandbox.Attester = &model.Attester{WorkloadUID: worker.UID}
		fixture.sandboxes.ConditionalUpdateObject(sandbox)
	}
	fixture.workloads.ConditionalUpdateObject(worker)
	eventually(t, func() bool {
		_, ok := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
		return ok
	}, "multi Sandbox workload")
	settle()
	before := currentSnapshot(t, fixture.compiler)
	policy.Spec.Egress = policy.Spec.Egress.DeepCopy()
	policy.Spec.Egress.Rules[0].To[0].CIDR = "10.2.0.0/24"
	fixture.trafficPolicies.ConditionalUpdateObject(policy)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a != nil && len(a.TrafficPolicies) == 1 && !proto.Equal(a.TrafficPolicies[0], first)
	}, "manifest tracks changed payload")
	settle()
	after := currentSnapshot(t, fixture.compiler)
	var names []string
	for _, change := range before.Diff(after) {
		names = append(names, change.Key.TypeURL+"|"+change.Key.Name)
	}
	want := []string{model.SandboxType + "|a", model.WorkloadAuthorizationType + "|tenant/allow-egress"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("changed resources %v, want %v", names, want)
	}
}

func TestMultiSandboxFailureDeletionAndShrinkRetainNetworking(t *testing.T) {
	fixture := newIncrementalFixture(t)
	a := model.Sandbox{UID: "actor-a", Namespace: "tenant"}
	b := model.Sandbox{UID: "actor-b", Namespace: "tenant", PolicyRefs: []model.PolicyRef{{Kind: model.PolicyKindSNIPolicy, Name: "missing"}}}
	fixture.sandboxes.ConditionalUpdateObject(a)
	fixture.sandboxes.ConditionalUpdateObject(b)
	worker := testWorkload("workers", "worker", "10.1.0.1")
	a.Attester = &model.Attester{WorkloadUID: worker.UID}
	b.Attester = &model.Attester{WorkloadUID: worker.UID}
	fixture.sandboxes.ConditionalUpdateObject(a)
	fixture.sandboxes.ConditionalUpdateObject(b)
	fixture.workloads.ConditionalUpdateObject(worker)
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		ma, mb := manifestAt(t, fixture.compiler, a.UID), manifestAt(t, fixture.compiler, b.UID)
		return ma != nil && mb == nil
	}, "isolate invalid actor")
	a.Attester = nil
	fixture.sandboxes.ConditionalUpdateObject(a)
	fixture.workloads.ConditionalUpdateObject(worker)
	eventually(t, func() bool {
		r, ok := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
		return ok && r.Facts.Workload != nil && manifestAt(t, fixture.compiler, b.UID) == nil
	}, "last invalid actor does not remove networking")
	fixture.sandboxes.DeleteObject(b.UID)
	eventually(t, func() bool { return manifestAt(t, fixture.compiler, b.UID) == nil }, "deleted actor must not become an implicit Pod Sandbox")
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
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Sandbox/ "]
		valid := manifestAt(t, fixture.compiler, "valid")
		return failed && valid != nil
	}, "invalid UID is isolated from valid Sandboxes")
	fixture.sandboxes.DeleteObject(" ")
	eventually(t, func() bool { _, failed := fixture.compiler.Failures()["Sandbox/ "]; return !failed }, "removed malformed UID clears diagnostic")
}

func TestSandboxInlinePrioritySNIOrderAndUnavailableView(t *testing.T) {
	sniAt := func(manifest *sandboxv1.Sandbox, index int) *extensionsv1.SniTrafficPolicy {
		t.Helper()
		value := new(extensionsv1.SniTrafficPolicy)
		if err := manifest.Extensions[index].UnmarshalTo(value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{
		UID:       "a",
		Namespace: "tenant",
		PolicyRefs: []model.PolicyRef{
			{Kind: model.PolicyKindSNIPolicy, Name: "tenant/second"},
			{Kind: model.PolicyKindSNIPolicy, Name: "tenant/first"},
		},
	})
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "b", Namespace: "other"})
	global := model.TrafficPolicy{Name: "baseline", Global: true, Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 10, Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionReject}}}}}
	local := model.TrafficPolicy{Name: "local", Namespace: "tenant", Spec: agentsv1alpha1.TrafficPolicySpec{Priority: 100, Ingress: &agentsv1alpha1.TrafficPolicyDirection{}, Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow}}}}}
	fixture.trafficPolicies.ConditionalUpdateObject(global)
	fixture.trafficPolicies.ConditionalUpdateObject(local)
	profile := func(name, domain string) model.SecurityProfile {
		return model.SecurityProfile{
			Name:      name,
			Namespace: "tenant",
			Spec: agentsv1alpha1.SecurityProfileSpec{
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{"not": "selected"}},
				Rules:    []agentsv1alpha1.SecurityRule{{Name: "rule", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{domain}}}}},
			},
		}
	}
	first, second := profile("first", "first.example"), profile("second", "second.example")
	fixture.securityProfiles.ConditionalUpdateObject(first)
	fixture.securityProfiles.ConditionalUpdateObject(second)
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		a, b := manifestAt(t, fixture.compiler, "a"), manifestAt(t, fixture.compiler, "b")
		return a != nil && len(a.TrafficPolicies) == 2 && len(a.Extensions) == 2 && b != nil && len(b.TrafficPolicies) == 1
	}, "inline global/local policies and explicit SNI order")
	a := manifestAt(t, fixture.compiler, "a")
	if a.TrafficPolicies[0].Name != "globaltrafficpolicy/baseline" || a.TrafficPolicies[1].Name != "trafficpolicy/tenant/local" {
		t.Fatalf("traffic priority order: %v", a.TrafficPolicies)
	}
	if sniAt(a, 0).Rules[0].Match.Sni[0] != "second.example" || sniAt(a, 1).Rules[0].Match.Sni[0] != "first.example" {
		t.Fatal("SNI explicit order was not preserved")
	}
	local.Spec.Priority = 0
	fixture.trafficPolicies.ConditionalUpdateObject(local)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a != nil && len(a.TrafficPolicies) == 2 &&
			a.TrafficPolicies[0].Name == "trafficpolicy/tenant/local" && a.TrafficPolicies[0].Priority == 0 &&
			a.TrafficPolicies[1].Name == "globaltrafficpolicy/baseline"
	}, "lower numeric priority moves the local policy ahead of the global policy")
	local.Spec.Priority = global.Spec.Priority
	fixture.trafficPolicies.ConditionalUpdateObject(local)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a != nil && len(a.TrafficPolicies) == 2 &&
			a.TrafficPolicies[0].Name == "globaltrafficpolicy/baseline" &&
			a.TrafficPolicies[1].Name == "trafficpolicy/tenant/local" &&
			a.TrafficPolicies[1].Priority == global.Spec.Priority
	}, "equal numeric priorities use stable policy-name ordering")
	second.Spec = *second.Spec.DeepCopy()
	second.Spec.Rules[0].Match[0].Domains = []string{"updated.example"}
	fixture.securityProfiles.ConditionalUpdateObject(second)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a != nil && len(a.Extensions) == 2 && sniAt(a, 0).Rules[0].Match.Sni[0] == "updated.example"
	}, "inline SNI body follows source change")
	fixture.securityProfiles.DeleteObject(second.ResourceName())
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a == nil
	}, "missing explicit policy withdraws the manifest")
	if b := manifestAt(t, fixture.compiler, "b"); b == nil {
		t.Fatal("unrelated Sandbox was invalidated")
	}
	fixture.securityProfiles.ConditionalUpdateObject(second)
	eventually(t, func() bool {
		a := manifestAt(t, fixture.compiler, "a")
		return a != nil && len(a.TrafficPolicies) == 2 && len(a.Extensions) == 2
	}, "complete inline view recovers")
}

func TestCompilerUsesOnlyProvidedSandboxes(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workload := testWorkload("demo", "client", "10.1.0.2")
	inputs := validCompilerInputs(stop)
	inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{workload}, options...)
	sandboxes := krt.NewStaticCollection[model.Sandbox](nil, nil, options...)
	inputs.Sandboxes = sandboxes
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	waitSynced(t, compiler)
	if manifestAt(t, compiler, workload.UID) != nil {
		t.Fatal("Workload synthesized a Sandbox inside the compiler")
	}
	sandboxes.UpdateObject(model.Sandbox{UID: workload.UID, Namespace: "sandbox-namespace", Labels: map[string]string{"source": "sandbox"}})
	eventually(t, func() bool { return manifestAt(t, compiler, workload.UID) != nil }, "provider Sandbox appears")
	sandboxes.DeleteObject(workload.UID)
	eventually(t, func() bool {
		return manifestAt(t, compiler, workload.UID) == nil && compiler.Bindings().GetKey(policy.BindingsKey(policy.PolicyTargetSandbox, workload.UID)) == nil
	}, "Sandbox deletion removes resource and bindings despite surviving Workload")
	settle()
	if manifestAt(t, compiler, workload.UID) != nil {
		t.Fatal("surviving Workload resurrected a deleted Sandbox")
	}
}

func TestSandboxSelectorMetadataUpdateRecomputesBindings(t *testing.T) {
	fixture := newIncrementalFixture(t)
	workload := testWorkload("workload-namespace", "client", "10.1.0.1")
	sandbox := model.Sandbox{
		UID:       workload.UID,
		Namespace: "sandbox-namespace",
		Labels:    map[string]string{"app": "sandbox"},
	}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	fixture.workloads.ConditionalUpdateObject(workload)
	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name:      "allow",
		Namespace: sandbox.Namespace,
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "sandbox"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	})
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		binding := fixture.compiler.Bindings().GetKey(policy.BindingsKey(policy.PolicyTargetSandbox, sandbox.UID))
		return binding != nil && reflect.DeepEqual(
			binding.PolicyNames(policy.PolicyKindAuthorization),
			[]string{"trafficpolicy/sandbox-namespace/allow"},
		)
	}, "explicit Sandbox namespace and labels select policy")

	sandbox.Labels = map[string]string{"app": "other"}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	eventually(t, func() bool {
		binding := fixture.compiler.Bindings().GetKey(policy.BindingsKey(policy.PolicyTargetSandbox, sandbox.UID))
		return binding != nil && binding.Valid() && len(binding.PolicyNames(policy.PolicyKindAuthorization)) == 0
	}, "Sandbox label update removes selector-derived binding")
}
