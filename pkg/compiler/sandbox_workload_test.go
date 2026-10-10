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
	"net/netip"
	"slices"
	"strings"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func compatibilityWorkload(
	t *testing.T,
	snapshot model.ResourceSet,
	uid string,
) (*workloadv1.Workload, model.Resource) {
	t.Helper()
	r, ok := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: uid})
	if !ok {
		return nil, model.Resource{}
	}
	a := &workloadv1.Address{}
	if err := r.Value.UnmarshalTo(a); err != nil {
		t.Fatal(err)
	}
	return a.GetWorkload(), r
}

func compatibilityExtension(t *testing.T, workload *workloadv1.Workload, name string, out proto.Message) bool {
	t.Helper()
	for _, ext := range workload.GetExtensions() {
		if ext.Name == name {
			if err := ext.Config.UnmarshalTo(out); err != nil {
				t.Fatal(err)
			}
			return true
		}
	}
	return false
}

func compatibilityTraffic(
	action agentsv1alpha1.RuleAction,
	peer agentsv1alpha1.TrafficPolicyPeer,
) agentsv1alpha1.TrafficPolicySpec {
	return agentsv1alpha1.TrafficPolicySpec{Egress: &agentsv1alpha1.TrafficPolicyDirection{
		Rules: []agentsv1alpha1.TrafficPolicyRule{{Action: action, To: []agentsv1alpha1.TrafficPolicyPeer{peer}}},
	}}
}

func compatibilitySecurity(domain string) agentsv1alpha1.SecurityProfileSpec {
	return agentsv1alpha1.SecurityProfileSpec{Rules: []agentsv1alpha1.SecurityRule{{
		Name:  "https",
		Match: []agentsv1alpha1.RuleMatch{{Domains: []string{domain}}},
	}}}
}

func TestSandboxLifecycleKeepsSharedWorkloadPolicies(t *testing.T) {
	f := newIncrementalFixture(t)
	a, b := testWorkload("demo", "a", "10.0.0.1"), testWorkload("demo", "b", "10.0.0.2")
	f.workloads.UpdateObject(a)
	f.workloads.UpdateObject(b)
	s := model.Sandbox{UID: "actor", Namespace: "demo", Attester: &model.Attester{WorkloadUID: a.UID}}
	f.sandboxes.UpdateObject(s)
	f.setResolved("api.example", netip.MustParseAddr("192.0.2.1"))
	shared := model.TrafficPolicy{
		Name:      "shared",
		Namespace: "demo",
		Spec: compatibilityTraffic(
			agentsv1alpha1.RuleActionAllow,
			agentsv1alpha1.TrafficPolicyPeer{FQDN: "api.example"},
		),
	}
	shared.Spec.Selector = metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "missing", Operator: metav1.LabelSelectorOpDoesNotExist},
		},
	}
	f.trafficPolicies.UpdateObject(shared)
	security := model.SecurityProfile{
		Dedicated:  true,
		SandboxUID: s.UID,
		Namespace:  "demo",
		Spec:       compatibilitySecurity("first.example"),
	}
	f.securityProfiles.UpdateObject(security)
	await := func(uid string, sniCount int) model.ResourceSet {
		t.Helper()
		var snap model.ResourceSet
		eventually(t, func() bool {
			snap = currentSnapshot(t, f.compiler)
			w, _ := compatibilityWorkload(t, snap, uid)
			sni := &extensionsv1.SniTrafficPolicy{}
			compatibilityExtension(t, w, "sni-traffic-policy", sni)
			return len(w.GetAuthorizationPolicies()) == 1 && len(sni.Rules) == 0 &&
				len(manifestAt(t, f.compiler, s.UID).GetExtensions()) == sniCount &&
				len(snap.List(model.SniTrafficPolicyType)) == 0
		}, "Sandbox owns inline SNI while Workload retains shared policy")
		return snap
	}
	initial := await(a.UID, 1)
	m, _ := initial.Get(model.ResourceKey{TypeURL: model.SandboxType, Name: s.UID})
	wa, waResource := compatibilityWorkload(t, initial, a.UID)
	authKey := model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: wa.AuthorizationPolicies[0]}
	auth, _ := initial.Get(authKey)
	settle()
	calls := f.resolutionCount("api.example")
	shared.Spec = *shared.Spec.DeepCopy()
	shared.Spec.Egress.Rules[0].Action = agentsv1alpha1.RuleActionReject
	f.trafficPolicies.UpdateObject(shared)
	eventually(t, func() bool {
		r, ok := currentSnapshot(t, f.compiler).Get(authKey)
		return ok && r.Hash != auth.Hash
	}, "shared body updates compatibility")
	current := currentSnapshot(t, f.compiler)
	newManifest, _ := current.Get(m.Key)
	_, newWorkload := compatibilityWorkload(t, current, a.UID)
	if newManifest.Hash != m.Hash || newWorkload.Hash != waResource.Hash {
		t.Fatal("body-only update republished Sandbox or Workload references")
	}
	if got := f.resolutionCount("api.example") - calls; got != 1 {
		t.Fatalf("policy was re-resolved during projection: %d calls", got)
	}
	security.Spec = compatibilitySecurity("*bad.example")
	f.securityProfiles.UpdateObject(security)
	eventually(t, func() bool {
		return f.compiler.Failures()["SecurityProfile/"+security.ResourceName()] != ""
	}, "invalid SNI retains the last valid policy")
	await(a.UID, 1)
	if manifestAt(t, f.compiler, s.UID) == nil {
		t.Fatal("SNI failure removed Sandbox")
	}
	if _, ok := currentSnapshot(t, f.compiler).Get(authKey); !ok {
		t.Fatal("SNI failure removed TrafficPolicy compatibility")
	}
	security.Spec = compatibilitySecurity("restored.example")
	f.securityProfiles.UpdateObject(security)
	await(a.UID, 1)
	s.Attester = &model.Attester{WorkloadUID: b.UID}
	f.sandboxes.UpdateObject(s)
	await(b.UID, 1)
	eventually(t, func() bool {
		snap := currentSnapshot(t, f.compiler)
		w, _ := compatibilityWorkload(t, snap, a.UID)
		_, authExists := snap.Get(authKey)
		sniExists := compatibilityExtension(t, w, "sni-traffic-policy", &extensionsv1.SniTrafficPolicy{})
		return len(w.GetAuthorizationPolicies()) == 1 && authExists && !sniExists
	}, "move preserves shared policies on the previous Workload")
	s.Attester = nil
	f.sandboxes.UpdateObject(s)
	eventually(t, func() bool {
		w, _ := compatibilityWorkload(t, currentSnapshot(t, f.compiler), b.UID)
		return len(w.GetAuthorizationPolicies()) == 1
	}, "unbind preserves shared Workload references")
	s.Attester = &model.Attester{WorkloadUID: b.UID}
	f.sandboxes.UpdateObject(s)
	await(b.UID, 1)
	f.sandboxes.DeleteObject(s.UID)
	eventually(t, func() bool {
		snap := currentSnapshot(t, f.compiler)
		w, _ := compatibilityWorkload(t, snap, b.UID)
		for _, r := range snap.List(model.WorkloadAuthorizationType) {
			if strings.Contains(r.Key.Name, "/sandbox-") {
				return false
			}
		}
		return len(w.GetAuthorizationPolicies()) == 1 && len(snap.List(model.SandboxType)) == 0
	}, "deleting a Sandbox preserves shared Workload policies")
}

func TestMultipleSandboxesShareWorkloadWithoutProjection(t *testing.T) {
	f := newIncrementalFixture(t)
	host := testWorkload("demo", "pool", "10.0.0.1")
	f.workloads.UpdateObject(host)
	for _, uid := range []string{"a", "b"} {
		f.sandboxes.UpdateObject(
			model.Sandbox{UID: uid, Namespace: "demo", Attester: &model.Attester{WorkloadUID: host.UID}},
		)
	}
	eventually(t, func() bool {
		snapshot := currentSnapshot(t, f.compiler)
		w, _ := compatibilityWorkload(t, snapshot, host.UID)
		if w == nil || len(snapshot.List(model.SandboxType)) != 2 || len(w.GetAuthorizationPolicies()) != 0 {
			return false
		}
		return len(snapshot.List(model.WorkloadAuthorizationType)) == 0 && len(f.compiler.Failures()) == 0
	}, "multiple Sandboxes do not require Workload projection")
	f.sandboxes.DeleteObject("b")
	eventually(t, func() bool {
		w, _ := compatibilityWorkload(t, currentSnapshot(t, f.compiler), host.UID)
		refs := new(extensionsv1.PolicyReference)
		return compatibilityExtension(t, w, "traffic-policy-reference", refs) &&
			len(refs.ResourceNames) == 0 && len(f.compiler.Failures()) == 0
	}, "Sandbox deletion preserves empty native Workload binding")
}

// Shared policy rules must not be copied into one Authorization per Workload.
func TestLegacyTrafficPolicySharedAcrossWorkloads(t *testing.T) {
	f := newIncrementalFixture(t, func(i *Inputs) { i.SandboxMode = false })
	const count = 16
	var workloads []model.Workload
	for i := range count {
		w := testWorkload("demo", fmt.Sprintf("client-%d", i), fmt.Sprintf("10.0.0.%d", i+1))
		w.Labels = map[string]string{"app": "client"}
		workloads = append(workloads, w)
		f.workloads.UpdateObject(w)
		f.sandboxes.UpdateObject(testSandboxForWorkload(w))
	}
	spec := compatibilityTraffic(agentsv1alpha1.RuleActionAllow, agentsv1alpha1.TrafficPolicyPeer{CIDR: "192.0.2.0/24"})
	f.trafficPolicies.UpdateObject(model.TrafficPolicy{Name: "global", Global: true, Spec: spec})
	f.trafficPolicies.UpdateObject(model.TrafficPolicy{Name: "namespace", Namespace: "demo", Spec: spec})
	selected := model.TrafficPolicy{Name: "selected", Namespace: "demo", Spec: *spec.DeepCopy()}
	selected.Spec.Selector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}}
	f.trafficPolicies.UpdateObject(selected)
	var before model.ResourceSet
	eventually(t, func() bool {
		before = currentSnapshot(t, f.compiler)
		if len(before.List(model.WorkloadAuthorizationType)) != 3 {
			return false
		}
		for _, w := range workloads {
			wire, _ := compatibilityWorkload(t, before, w.UID)
			if !slices.Equal(wire.GetAuthorizationPolicies(), []string{"demo/selected-egress"}) {
				return false
			}
		}
		return true
	}, "all Workloads reference the same shared policy")
	key := model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: "demo/selected-egress"}
	old, _ := before.Get(key)
	selected.Spec = *selected.Spec.DeepCopy()
	selected.Spec.Egress.Rules[0].Action = agentsv1alpha1.RuleActionReject
	f.trafficPolicies.UpdateObject(selected)
	eventually(t, func() bool {
		r, found := currentSnapshot(t, f.compiler).Get(key)
		return found && r.Hash != old.Hash
	}, "body update replaces the one shared Authorization")
	settle()
	after := currentSnapshot(t, f.compiler)
	for _, w := range workloads {
		_, a := compatibilityWorkload(t, before, w.UID)
		_, b := compatibilityWorkload(t, after, w.UID)
		if a.Hash != b.Hash {
			t.Fatal("shared body update changed Workload references")
		}
	}
	f.trafficPolicies.DeleteObject(selected.ResourceName())
	eventually(t, func() bool {
		snapshot := currentSnapshot(t, f.compiler)
		if len(snapshot.List(model.WorkloadAuthorizationType)) != 2 {
			return false
		}
		for _, w := range workloads {
			wire, _ := compatibilityWorkload(t, snapshot, w.UID)
			if len(wire.GetAuthorizationPolicies()) != 0 {
				return false
			}
		}
		return true
	}, "deletion withdraws selector policy while retaining baselines")
}

func TestSandboxInlineSNIReleaseCompatibility(t *testing.T) {
	f := newIncrementalFixture(t)
	target := testWorkload("demo", "sandbox", "10.0.0.1")
	target.Source = model.SourceRef{Registry: "kubernetes/cluster", Key: "pod-uid"}
	other := testWorkload("demo", "other", "10.0.0.2")
	other.Source = model.SourceRef{Registry: target.Source.Registry, Key: "other-uid"}
	other.Labels = target.Labels
	crossNamespace := testWorkload("elsewhere", target.Name, "10.0.0.3")
	crossNamespace.Source = model.SourceRef{Registry: target.Source.Registry, Key: "cross-namespace-uid"}
	nonPod := target
	nonPod.UID, nonPod.Source = "external", model.SourceRef{Registry: "external", Key: "external"}
	for _, w := range []model.Workload{target, other, crossNamespace, nonPod} {
		f.workloads.UpdateObject(w)
	}
	// Inline rules must follow even the lowest-precedence shared profile.
	maxPriority := int32(1<<31 - 1)
	shared := model.SecurityProfile{
		Name:      target.Name,
		Namespace: target.Namespace,
		Spec:      compatibilitySecurity("shared.example"),
	}
	shared.Spec.Priority = &maxPriority
	f.securityProfiles.UpdateObject(shared)
	// Deliberately bind the native Sandbox to a different host: legacy matching uses names.
	sandbox := model.Sandbox{
		UID:       "kruise:delivery-id",
		Namespace: target.Namespace,
		Attester:  &model.Attester{WorkloadUID: other.UID},
	}
	f.sandboxes.UpdateObject(sandbox)
	inline := model.SecurityProfile{
		Dedicated:  true,
		SandboxUID: sandbox.UID,
		Name:       target.Name,
		Namespace:  target.Namespace,
	}
	check := func(host string) {
		t.Helper()
		eventually(t, func() bool {
			snapshot := currentSnapshot(t, f.compiler)
			for _, w := range []model.Workload{target, other, crossNamespace, nonPod} {
				wire, _ := compatibilityWorkload(t, snapshot, w.UID)
				if wire == nil {
					return false
				}
				payload := new(extensionsv1.SniTrafficPolicy)
				compatibilityExtension(t, wire, "sni-traffic-policy", payload)
				var want []string
				if w.Namespace == target.Namespace {
					want = append(want, "shared.example")
				}
				if w.UID == target.UID && host != "" {
					want = append(want, host)
				}
				var got []string
				for _, rule := range payload.Rules {
					if rule.Action != extensionsv1.SniAction_SNI_ACTION_TLS_TERMINATION {
						t.Fatalf("unexpected SNI action: %v", rule.Action)
					}
					got = append(got, rule.GetMatch().GetSni()...)
				}
				if !slices.Equal(got, want) {
					return false
				}
			}
			manifest := manifestAt(t, f.compiler, sandbox.UID)
			if manifest == nil {
				return false
			}
			if host == "" {
				return len(manifest.Extensions) == 0
			}
			if len(manifest.Extensions) != 1 {
				return false
			}
			payload := new(extensionsv1.SniTrafficPolicy)
			if err := manifest.Extensions[0].UnmarshalTo(payload); err != nil {
				t.Fatal(err)
			}
			return len(payload.Rules) == 1 && slices.Equal(payload.Rules[0].GetMatch().GetSni(), []string{host})
		}, "legacy Workload and native Sandbox SNI agree without leaking inline rules")
	}
	check("")
	for _, host := range []string{"first.example", "updated.example"} {
		inline.Spec = compatibilitySecurity(host)
		f.securityProfiles.UpdateObject(inline)
		check(host)
	}
	inline.Spec = compatibilitySecurity("*bad.example")
	f.securityProfiles.UpdateObject(inline)
	eventually(t, func() bool {
		return f.compiler.Failures()["SecurityProfile/"+inline.ResourceName()] != ""
	}, "invalid inline SNI was processed")
	check("updated.example")
	inline.Spec = compatibilitySecurity("http.example")
	inline.Spec.Rules[0].Match[0].Schemes = []string{"http"}
	f.securityProfiles.UpdateObject(inline)
	check("")
	inline.Spec = compatibilitySecurity("restored.example")
	f.securityProfiles.UpdateObject(inline)
	check("restored.example")
	f.securityProfiles.DeleteObject(inline.ResourceName())
	check("")
}
