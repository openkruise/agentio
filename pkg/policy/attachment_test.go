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
	"reflect"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestPolicyAttachmentTargets(t *testing.T) {
	demo := SandboxSubject{
		SandboxUID: "cluster//Pod/demo/client",
		Namespace:  "demo",
		Labels:     map[string]string{"app": "client", "tier": "trusted"},
	}
	other := SandboxSubject{
		SandboxUID: "cluster//Pod/other/client",
		Namespace:  "other",
		Labels:     map[string]string{"app": "client"},
	}

	tests := []struct {
		name      string
		target    AttachmentTarget
		wantDemo  bool
		wantOther bool
	}{
		{name: "global", target: AttachmentTarget{Global: true}, wantDemo: true, wantOther: true},
		{name: "namespace", target: AttachmentTarget{Namespaces: []string{"demo"}}, wantDemo: true},
		{name: "global selector", target: AttachmentTarget{
			Global:   true,
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"tier": "trusted"}},
		}, wantDemo: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attachment, err := NewPolicyAttachment(PolicyAttachment{
				Kind: PolicyKindSNIPolicy, Name: test.name, Target: test.target,
			})
			if err != nil {
				t.Fatalf("new policy attachment: %v", err)
			}
			if got := attachment.Selects(demo); got != test.wantDemo {
				t.Fatalf("Selects(demo) = %v, want %v", got, test.wantDemo)
			}
			if got := attachment.Selects(other); got != test.wantOther {
				t.Fatalf("Selects(other) = %v, want %v", got, test.wantOther)
			}
		})
	}
}

func TestPolicyAttachmentExactTarget(t *testing.T) {
	exact, err := NewPolicyAttachment(PolicyAttachment{
		Kind: PolicyKindAuthorization,
		Name: "demo/allow-egress",
		Target: AttachmentTarget{
			SandboxUID: "sandbox-a",
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				"tier": "trusted",
			}},
		},
		Priority: 10,
	})
	if err != nil {
		t.Fatalf("new exact policy attachment: %v", err)
	}
	for _, test := range []struct {
		name    string
		subject SandboxSubject
		want    bool
	}{
		{
			name: "exact UID and selector",
			subject: SandboxSubject{
				SandboxUID: "sandbox-a",
				Labels:     map[string]string{"tier": "trusted"},
			},
			want: true,
		},
		{
			name: "different UID",
			subject: SandboxSubject{
				SandboxUID: "sandbox-b",
				Labels:     map[string]string{"tier": "trusted"},
			},
		},
		{
			name: "selector mismatch",
			subject: SandboxSubject{
				SandboxUID: "sandbox-a",
				Labels:     map[string]string{"tier": "untrusted"},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := exact.Selects(test.subject); got != test.want {
				t.Fatalf("Selects() = %v, want %v", got, test.want)
			}
		})
	}

	selector, err := NewPolicyAttachment(PolicyAttachment{
		Kind: PolicyKindAuthorization,
		Name: "demo/selector-egress",
		Target: AttachmentTarget{
			Namespaces: []string{"demo"},
			Selector:   metav1.LabelSelector{MatchLabels: map[string]string{"tier": "trusted"}},
		},
		Priority: 10,
	})
	if err != nil {
		t.Fatalf("new selector policy attachment: %v", err)
	}
	if !policyAttachmentLess(exact, selector) {
		t.Fatal("exact Sandbox target did not sort before selector target")
	}

	for _, target := range []AttachmentTarget{
		{Global: true, SandboxUID: "sandbox-a"},
		{Namespaces: []string{"demo"}, SandboxUID: "sandbox-a"},
		{SandboxUID: " sandbox-a"},
		{SandboxUID: " "},
		{
			SandboxUID: "sandbox-a",
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				agentsv1alpha1.LabelSandboxID: "sandbox-b",
			}},
		},
	} {
		if _, err := NewPolicyAttachment(PolicyAttachment{
			Kind: PolicyKindAuthorization, Name: "invalid", Target: target,
		}); err == nil {
			t.Fatalf("invalid exact target %+v was accepted", target)
		}
	}
}

func TestSandboxPolicyBindingsExactTargetFanout(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	subjects := make([]SandboxSubject, 100)
	for index := range subjects {
		subjects[index] = SandboxSubject{
			SandboxUID: fmt.Sprintf("sandbox-%d", index),
			Namespace:  "demo",
			Labels:     map[string]string{"sandbox": fmt.Sprintf("sandbox-%d", index)},
		}
	}
	attachments := krt.NewStaticCollection[PolicyAttachment](nil, nil, options...)
	bindings := NewSandboxPolicyBindingsCollection(
		krt.NewStaticCollection[model.Sandbox](nil, nil, options...),
		krt.NewStaticCollection(nil, subjects, options...),
		attachments,
		krt.NewOptionsBuilder(stop, "test", nil),
	)
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("Sandbox policy bindings did not sync")
	}
	events := make(chan krt.Event[SandboxPolicyBindings], 1)
	registration := bindings.RegisterBatch(func(batch []krt.Event[SandboxPolicyBindings]) {
		for _, event := range batch {
			events <- event
		}
	}, false)
	t.Cleanup(registration.UnregisterHandler)

	exact, err := NewPolicyAttachment(PolicyAttachment{
		Kind: PolicyKindAuthorization,
		Name: "demo/exact-egress",
		Target: AttachmentTarget{
			SandboxUID: "sandbox-42",
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				"sandbox": "sandbox-42",
			}},
		},
	})
	if err != nil {
		t.Fatalf("new exact attachment: %v", err)
	}
	before := bindingRecomputeTotal(t, bindings)
	attachments.ConditionalUpdateObject(exact)
	if event := awaitBindingEvent(t, events); event.Latest().SandboxUID != "sandbox-42" {
		t.Fatalf("added binding event = %+v, want sandbox-42", event.Latest())
	}
	if got := bindingRecomputeTotal(t, bindings) - before; got != 1 {
		t.Fatalf("exact policy add recomputed %d Sandbox bindings, want 1", got)
	}

	before = bindingRecomputeTotal(t, bindings)
	attachments.DeleteObject(exact.ResourceName())
	if event := awaitBindingEvent(t, events); event.Latest().SandboxUID != "sandbox-42" {
		t.Fatalf("deleted binding event = %+v, want sandbox-42", event.Latest())
	}
	if got := bindingRecomputeTotal(t, bindings) - before; got != 1 {
		t.Fatalf("exact policy delete recomputed %d Sandbox bindings, want 1", got)
	}
}

func bindingRecomputeTotal(t testing.TB, bindings krt.Collection[SandboxPolicyBindings]) uint64 {
	t.Helper()
	total, ok := bindings.Metadata()["recomputeTotal"].(uint64)
	if !ok {
		t.Fatal("Sandbox binding recompute counter is unavailable")
	}
	return total
}

func awaitBindingEvent(t testing.TB, events <-chan krt.Event[SandboxPolicyBindings]) krt.Event[SandboxPolicyBindings] {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Sandbox binding event")
		return krt.Event[SandboxPolicyBindings]{}
	}
}

func TestSandboxPolicyBindings(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	builder := krt.NewOptionsBuilder(stop, "test", nil)

	demo := model.Sandbox{
		UID: "cluster//Pod/demo/client",
		PolicyRefs: []model.PolicyRef{
			{
				Kind: model.PolicyKindSNIPolicy,
				Name: "explicit",
			},
			{
				Kind: model.PolicyKindSNIPolicy,
				Name: "global",
			},
		},
	}
	demoSubject := SandboxSubject{
		SandboxUID: "cluster//Pod/demo/client",
		Namespace:  "demo",
		Labels:     map[string]string{"app": "client", "tier": "trusted"},
	}
	other := model.Sandbox{
		UID: "cluster//Pod/other/client",
	}
	otherSubject := SandboxSubject{
		SandboxUID: "cluster//Pod/other/client",
		Namespace:  "other",
		Labels:     map[string]string{"app": "client"},
	}
	attachments := []PolicyAttachment{
		{
			Kind: PolicyKindSNIPolicy,
			Name: "explicit",
			Target: AttachmentTarget{
				Namespaces: []string{"unrelated"},
			},
			Priority: 20,
		},
		{
			Kind: PolicyKindSNIPolicy,
			Name: "global",
			Target: AttachmentTarget{
				Global: true,
			},
			Priority: 20,
		},
		{
			Kind: PolicyKindSNIPolicy,
			Name: "demo",
			Target: AttachmentTarget{
				Namespaces: []string{"demo"},
			},
			Priority: 20,
		},
		{
			Kind: PolicyKindSNIPolicy,
			Name: "selector",
			Target: AttachmentTarget{
				Global: true,
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{"tier": "trusted"},
				},
			},
			Priority: 20,
		},
		{
			Kind: PolicyKindEgressPolicy,
			Name: "egress",
			Target: AttachmentTarget{
				Namespaces: []string{"demo"},
			},
			Priority: 10,
		},
	}
	for index := range attachments {
		normalized, err := NewPolicyAttachment(attachments[index])
		if err != nil {
			t.Fatalf("normalize attachment %q: %v", attachments[index].Name, err)
		}
		attachments[index] = normalized
	}

	sandboxes := krt.NewStaticCollection(nil, []model.Sandbox{demo, other}, options...)
	subjects := krt.NewStaticCollection(nil, []SandboxSubject{demoSubject, otherSubject}, options...)
	policies := krt.NewStaticCollection(nil, attachments, options...)
	bindings := NewSandboxPolicyBindingsCollection(sandboxes, subjects, policies, builder)
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("sandbox policy bindings did not sync")
	}

	demoBinding := bindings.GetKey(demo.ResourceName())
	if demoBinding == nil {
		t.Fatal("demo binding is missing")
	}
	if got, want := demoBinding.PolicyNames(PolicyKindEgressPolicy), []string{"egress"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("demo egress names = %v, want %v", got, want)
	}
	if got, want := demoBinding.PolicyNames(PolicyKindSNIPolicy), []string{"explicit", "global", "selector", "demo"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("demo SNI names = %v, want %v", got, want)
	}
	if got, want := []PolicyKind{demoBinding.Groups[0].Kind, demoBinding.Groups[1].Kind}, []PolicyKind{PolicyKindEgressPolicy, PolicyKindSNIPolicy}; !reflect.DeepEqual(got, want) {
		t.Fatalf("demo group order = %v, want %v", got, want)
	}

	otherBinding := bindings.GetKey(other.ResourceName())
	if otherBinding == nil {
		t.Fatal("other binding is missing")
	}
	if got, want := otherBinding.PolicyNames(PolicyKindSNIPolicy), []string{"global"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("other SNI names = %v, want %v", got, want)
	}
	if got := otherBinding.PolicyNames(PolicyKindEgressPolicy); len(got) != 0 {
		t.Fatalf("other egress names = %v, want none", got)
	}
}

func TestSandboxPolicyBindingsRejectUnresolvedExplicitReference(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	builder := krt.NewOptionsBuilder(stop, "test", nil)
	uid := "sandbox-a"

	bindings := NewSandboxPolicyBindingsCollection(
		krt.NewStaticCollection(nil, []model.Sandbox{{
			UID: uid,
			PolicyRefs: []model.PolicyRef{{
				Kind: model.PolicyKindSNIPolicy,
				Name: "demo/missing",
			}},
		}}, options...),
		krt.NewStaticCollection(nil, []SandboxSubject{{SandboxUID: uid}}, options...),
		krt.NewStaticCollection[PolicyAttachment](nil, nil, options...),
		builder,
	)
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("Sandbox policy bindings did not sync")
	}
	binding := bindings.GetKey(uid)
	if binding == nil || binding.Valid() || len(binding.Unresolved) != 1 {
		t.Fatalf("binding = %+v, want one unresolved reference", binding)
	}
}

func TestPolicyAttachmentValidation(t *testing.T) {
	invalidSelector := metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: "app", Operator: metav1.LabelSelectorOperator("Invalid"), Values: []string{"client"},
	}}}
	tests := []struct {
		name       string
		attachment PolicyAttachment
	}{
		{
			name: "empty kind",
			attachment: PolicyAttachment{
				Name: "policy",
				Target: AttachmentTarget{
					Global: true,
				},
			},
		},
		{
			name: "empty name",
			attachment: PolicyAttachment{
				Kind: PolicyKindSNIPolicy,
				Target: AttachmentTarget{
					Global: true,
				},
			},
		},
		{
			name: "no target",
			attachment: PolicyAttachment{
				Kind: PolicyKindSNIPolicy,
				Name: "policy",
			},
		},
		{
			name: "global and namespace",
			attachment: PolicyAttachment{
				Kind: PolicyKindSNIPolicy,
				Name: "policy",
				Target: AttachmentTarget{
					Global:     true,
					Namespaces: []string{"demo"},
				},
			},
		},
		{
			name: "invalid selector",
			attachment: PolicyAttachment{
				Kind: PolicyKindSNIPolicy,
				Name: "policy",
				Target: AttachmentTarget{
					Global:   true,
					Selector: invalidSelector,
				},
			},
		},
		{
			name: "empty namespace",
			attachment: PolicyAttachment{
				Kind: PolicyKindSNIPolicy,
				Name: "policy",
				Target: AttachmentTarget{
					Namespaces: []string{""},
				},
			},
		},
		{
			name: "duplicate namespace",
			attachment: PolicyAttachment{
				Kind: PolicyKindSNIPolicy,
				Name: "policy",
				Target: AttachmentTarget{
					Namespaces: []string{"demo", "demo"},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewPolicyAttachment(test.attachment); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestPolicyAttachmentEqualityTracksOnlyReferenceFields(t *testing.T) {
	policy, err := CompileSNIProfile(model.SecurityProfile{
		Name: "security-profile", Namespace: "demo", CreationTime: time.Unix(100, 0),
		Spec: securitySpec(nil, map[string]string{"app": "sandbox"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	attachment := policy.PolicyAttachment()
	if attachment == nil {
		t.Fatal("expected a policy attachment")
	}
	rulesOnly := *policy
	rulesOnly.Policy = &extensionsv1.SniTrafficPolicy{Rules: []*extensionsv1.SniRule{{
		Match: &extensionsv1.SniMatch{Sni: []string{"changed.example.com"}},
	}}}
	if other := rulesOnly.PolicyAttachment(); other == nil || !attachment.Equals(*other) {
		t.Fatal("rules-only policy changes must not change the attachment")
	}
	if policy.Equals(rulesOnly) {
		t.Fatal("rules-only changes must change the compiled policy")
	}
	tests := []struct {
		name   string
		mutate func(*PolicyAttachment)
	}{
		{"resource name", func(p *PolicyAttachment) { p.Name = "demo/other" }},
		{"priority", func(p *PolicyAttachment) { p.Priority++ }},
		{"creation time", func(p *PolicyAttachment) { p.CreationTime = time.Unix(200, 0) }},
		{"namespace", func(p *PolicyAttachment) { p.Target.Namespaces = []string{"other"} }},
		{"sandbox UID", func(p *PolicyAttachment) { p.Target.SandboxUID = "sandbox-a" }},
		{"global scope", func(p *PolicyAttachment) { p.Target.Global = true }},
		{"selector", func(p *PolicyAttachment) {
			p.Target.Selector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "other"}}
			p.selector = nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := *policy
			copy := *attachment
			test.mutate(&copy)
			changed.Attachment = &copy
			if attachment.Equals(*changed.PolicyAttachment()) || policy.Equals(changed) {
				t.Fatalf("%s change did not change attachment and compiled policy", test.name)
			}
		})
	}
}

func TestPolicyAttachmentRejectsIncompletePolicy(t *testing.T) {
	for _, policy := range []CompiledSNIPolicy{
		{Policy: &extensionsv1.SniTrafficPolicy{}, Attachment: &PolicyAttachment{}},
		{Name: "demo/policy", Attachment: &PolicyAttachment{}},
	} {
		if got := policy.PolicyAttachment(); got != nil {
			t.Fatalf("incomplete policy produced attachment %+v", got)
		}
	}
}
