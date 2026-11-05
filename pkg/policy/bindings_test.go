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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// This unmatched policy is examined once per binding recomputation, but is
// never changed itself. It detects unnecessary recomputation even when Equals
// suppresses the resulting binding events.
type bindingRecomputeSelector struct {
	labels.Selector
	calls *atomic.Int64
}

func (s bindingRecomputeSelector) Matches(values labels.Labels) bool {
	s.calls.Add(1)
	return s.Selector.Matches(values)
}

func TestPolicyBindingsSelectorDependencyFanout(t *testing.T) {
	for _, global := range []bool{false, true} {
		t.Run(fmt.Sprintf("global=%t", global), func(t *testing.T) {
			const count = 32
			stop := make(chan struct{})
			t.Cleanup(func() { close(stop) })
			options := []krt.CollectionOption{krt.WithStop(stop)}
			var subjects []model.Workload
			for index := range count {
				uid := fmt.Sprintf("subject-%d", index)
				values := map[string]string{"app": uid}
				subjects = append(subjects, model.Workload{UID: uid, Namespace: "demo", Labels: values})
			}
			workloads := krt.NewMutableCollection(nil, subjects, options...)
			makePolicy := func(selector metav1.LabelSelector) PolicyAttachment {
				t.Helper()
				target := AttachmentTarget{Selector: selector, Global: global}
				if !global {
					target.Namespaces = []string{"demo"}
				}
				attachment, err := NewPolicyAttachment(
					PolicyAttachment{Kind: PolicyKindTrafficPolicy, Name: "demo/selected", Target: target},
				)
				if err != nil {
					t.Fatal(err)
				}
				return attachment
			}
			selectApp := func(app string) metav1.LabelSelector {
				return metav1.LabelSelector{MatchLabels: map[string]string{"app": app}}
			}
			var recomputes atomic.Int64
			witness := makePolicy(selectApp("unmatched"))
			witness.Name = "demo/witness"
			witness.selector = bindingRecomputeSelector{Selector: witness.selector, calls: &recomputes}
			initial := makePolicy(selectApp("subject-0"))
			attachments := krt.NewMutableCollection(nil, []PolicyAttachment{initial, witness}, options...)
			bindings := NewWorkloadPolicyBindingsCollection(
				workloads.AsCollection(),
				attachments.AsCollection(),
				krt.NewOptionsBuilder(stop, "test", nil),
			)
			if !bindings.WaitUntilSynced(stop) {
				t.Fatal("bindings did not sync")
			}
			events := make(chan krt.Event[Bindings], count*2)
			registration := bindings.RegisterBatch(func(batch []krt.Event[Bindings]) {
				for _, event := range batch {
					events <- event
				}
			}, false)
			t.Cleanup(registration.UnregisterHandler)
			check := func(eventCount, wantRecomputes int, selected func(int) bool) {
				t.Helper()
				for range eventCount {
					awaitBindingEvent(t, events)
				}
				if got := recomputes.Swap(0); got != int64(wantRecomputes) {
					t.Fatalf("recomputed %d bindings, want %d", got, wantRecomputes)
				}
				for index := range count {
					binding := bindings.GetKey(fmt.Sprintf("subject-%d", index))
					if binding == nil {
						t.Fatalf("subject-%d has no valid binding", index)
					}
					var want []string
					if selected(index) {
						want = []string{initial.Name}
					}
					if got := binding.PolicyNames(PolicyKindTrafficPolicy); !reflect.DeepEqual(got, want) {
						t.Fatalf("subject-%d policies = %v, want %v", index, got, want)
					}
				}
			}
			check(0, count, func(index int) bool { return index == 0 })
			// Both the old and new selector must invalidate their matching subject.
			attachments.ConditionalUpdateObject(
				makePolicy(metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "app",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"subject-1"},
				}}}),
			)
			check(2, 0, func(index int) bool { return index == 1 })
			// A primary label update must still detach the policy.
			updated := subjects[1]
			updated.Labels = map[string]string{"app": "disabled"}
			workloads.ConditionalUpdateObject(updated)
			check(1, 1, func(int) bool { return false })
			attachments.ConditionalUpdateObject(makePolicy(selectApp("subject-2")))
			check(1, 0, func(index int) bool { return index == 2 })
			attachments.DeleteObject(initial.ResourceName())
			check(1, 0, func(int) bool { return false })
			// Empty selectors retain namespace-wide/global semantics on recreation.
			attachments.ConditionalUpdateObject(makePolicy(metav1.LabelSelector{}))
			check(count, 0, func(int) bool { return true })
		})
	}
}

func TestPolicyBindingsSelectorTargetFanout(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	subjects := make([]model.Workload, 100)
	for index := range subjects {
		subjects[index] = model.Workload{
			UID:       fmt.Sprintf("workload-%d", index),
			Namespace: "demo",
			Labels:    map[string]string{"workload": fmt.Sprintf("workload-%d", index)},
		}
	}
	attachments := krt.NewMutableCollection[PolicyAttachment](nil, nil, options...)
	bindings := NewWorkloadPolicyBindingsCollection(
		krt.NewStaticCollection(nil, subjects, options...),
		attachments.AsCollection(),
		krt.NewOptionsBuilder(stop, "test", nil),
	)
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("Workload policy bindings did not sync")
	}
	events := make(chan krt.Event[Bindings], 1)
	registration := bindings.RegisterBatch(func(batch []krt.Event[Bindings]) {
		for _, event := range batch {
			events <- event
		}
	}, false)
	t.Cleanup(registration.UnregisterHandler)

	selected, err := NewPolicyAttachment(PolicyAttachment{
		Kind: PolicyKindTrafficPolicy,
		Name: "demo/selected-egress",
		Target: AttachmentTarget{
			Namespaces: []string{"demo"},
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				"workload": "workload-42",
			}},
		},
	})
	if err != nil {
		t.Fatalf("new selector attachment: %v", err)
	}
	attachments.ConditionalUpdateObject(selected)
	if event := awaitBindingEvent(t, events); event.Latest().TargetUID != "workload-42" {
		t.Fatalf("added binding event = %+v, want workload-42", event.Latest())
	}

	attachments.DeleteObject(selected.ResourceName())
	if event := awaitBindingEvent(t, events); event.Latest().TargetUID != "workload-42" {
		t.Fatalf("deleted binding event = %+v, want workload-42", event.Latest())
	}
}

func awaitBindingEvent(t testing.TB, events <-chan krt.Event[Bindings]) krt.Event[Bindings] {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Workload binding event")
		return krt.Event[Bindings]{}
	}
}

func TestPolicyBindings(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	builder := krt.NewOptionsBuilder(stop, "test", nil)

	demo := model.Workload{
		UID: "cluster//Pod/demo/client",
	}
	demo.Namespace = "demo"
	demo.Labels = map[string]string{"app": "client", "tier": "trusted"}
	other := model.Workload{
		UID:       "cluster//Pod/other/client",
		Namespace: "other",
		Labels:    map[string]string{"app": "client"},
	}
	attachments := []PolicyAttachment{
		{
			Kind: PolicyKindSecurityProfile,
			Name: "explicit",
			Target: AttachmentTarget{
				Namespaces: []string{"unrelated"},
			},
			Priority: 20,
		},
		{
			Kind: PolicyKindSecurityProfile,
			Name: "global",
			Target: AttachmentTarget{
				Global: true,
			},
			Priority: 20,
		},
		{
			Kind: PolicyKindSecurityProfile,
			Name: "demo",
			Target: AttachmentTarget{
				Namespaces: []string{"demo"},
			},
			Priority: 20,
		},
		{
			Kind: PolicyKindSecurityProfile,
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

	workloads := krt.NewStaticCollection(nil, []model.Workload{demo, other}, options...)
	policies := krt.NewStaticCollection(nil, attachments, options...)
	bindings := NewWorkloadPolicyBindingsCollection(workloads, policies, builder)
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("workload policy bindings did not sync")
	}

	demoBinding := bindings.GetKey(demo.UID)
	if demoBinding == nil {
		t.Fatal("demo binding is missing")
	}
	if got, want := demoBinding.PolicyNames(PolicyKindEgressPolicy), []string{"egress"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("demo egress names = %v, want %v", got, want)
	}
	if got, want := demoBinding.PolicyNames(
		PolicyKindSecurityProfile,
	), []string{
		"demo",
		"global",
		"selector",
	}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("demo SecurityProfile names = %v, want %v", got, want)
	}
	if got, want := []PolicyKind{
		demoBinding.Groups[0].Kind,
		demoBinding.Groups[1].Kind,
	}, []PolicyKind{
		PolicyKindEgressPolicy,
		PolicyKindSecurityProfile,
	}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("demo group order = %v, want %v", got, want)
	}

	otherBinding := bindings.GetKey(other.UID)
	if otherBinding == nil {
		t.Fatal("other binding is missing")
	}
	if got, want := otherBinding.PolicyNames(
		PolicyKindSecurityProfile,
	), []string{
		"global",
	}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("other SecurityProfile names = %v, want %v", got, want)
	}
	if got := otherBinding.PolicyNames(PolicyKindEgressPolicy); len(got) != 0 {
		t.Fatalf("other egress names = %v, want none", got)
	}
}

// A policy change must not re-evaluate selectors in the other attachment scope.
func TestPolicyBindingsReuseUnchangedScope(t *testing.T) {
	for _, global := range []bool{false, true} {
		t.Run(fmt.Sprintf("changed_global=%t", global), func(t *testing.T) {
			const count = 32
			stop := make(chan struct{})
			t.Cleanup(func() { close(stop) })
			opts := []krt.CollectionOption{krt.WithStop(stop)}
			workloads := make([]model.Workload, count)
			for i := range workloads {
				workloads[i] = model.Workload{
					UID:       fmt.Sprintf("workload-%d", i),
					Namespace: "demo",
					Labels:    map[string]string{"app": "selected"},
				}
			}
			makeAttachment := func(name string, global bool, selector metav1.LabelSelector) PolicyAttachment {
				t.Helper()
				target := AttachmentTarget{Global: global, Selector: selector}
				if !global {
					target.Namespaces = []string{"demo"}
				}
				a, err := NewPolicyAttachment(
					PolicyAttachment{Kind: PolicyKindTrafficPolicy, Name: name, Target: target},
				)
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			var scans atomic.Int64
			witness := makeAttachment(
				"witness",
				!global,
				metav1.LabelSelector{MatchLabels: map[string]string{"app": "unmatched"}},
			)
			witness.selector = bindingRecomputeSelector{Selector: witness.selector, calls: &scans}
			retained := makeAttachment("retained", !global, metav1.LabelSelector{})
			attachments := krt.NewMutableCollection(nil, []PolicyAttachment{witness, retained}, opts...)
			subjects := krt.NewMutableCollection(nil, workloads, opts...)
			bindings := NewWorkloadPolicyBindingsCollection(
				subjects.AsCollection(),
				attachments.AsCollection(),
				krt.NewOptionsBuilder(stop, "test", nil),
			)
			if !bindings.WaitUntilSynced(stop) {
				t.Fatal("bindings did not sync")
			}
			if got := scans.Swap(0); got != count {
				t.Fatalf("initial witness evaluations = %d, want %d", got, count)
			}
			events := make(chan krt.Event[Bindings], count*2)
			registration := bindings.RegisterBatch(func(batch []krt.Event[Bindings]) {
				for _, event := range batch {
					events <- event
				}
			}, false)
			t.Cleanup(registration.UnregisterHandler)
			updated := workloads[0]
			updated.Ready = true
			updated.Addresses = []string{"10.0.0.2"}
			subjects.ConditionalUpdateObject(updated)
			select {
			case event := <-events:
				t.Fatalf("non-selector Workload change altered bindings: %+v", event)
			case <-time.After(100 * time.Millisecond):
			}
			if got := scans.Swap(0); got != 0 {
				t.Fatalf("non-selector Workload change re-evaluated %d selectors", got)
			}
			changed := makeAttachment("changed", global, metav1.LabelSelector{})
			for _, present := range []bool{true, false, true} {
				if present {
					attachments.ConditionalUpdateObject(changed)
				} else {
					attachments.DeleteObject(changed.ResourceName())
				}
				want := []string{"retained"}
				if present {
					want = []string{"changed", "retained"}
				}
				for range count {
					got := awaitBindingEvent(t, events).Latest().PolicyNames(PolicyKindTrafficPolicy)
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("policies = %v, want %v", got, want)
					}
				}
				if got := scans.Swap(0); got != 0 {
					t.Fatalf("re-evaluated %d selectors in unchanged scope", got)
				}
			}
		})
	}
}

type bindingGateSelector struct {
	labels.Selector
	once    *sync.Once
	entered chan struct{}
	release <-chan struct{}
}

func (s bindingGateSelector) Matches(values labels.Labels) bool {
	if values.Get("app") == "new" {
		s.once.Do(func() {
			close(s.entered)
			if s.release != nil {
				<-s.release
			}
		})
	}
	return s.Selector.Matches(values)
}

func TestPolicyBindingsLabelUpdateDoesNotMixScopes(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	opts := []krt.CollectionOption{krt.WithStop(stop)}
	workload := model.Workload{UID: "client", Namespace: "demo", Labels: map[string]string{"app": "old"}}
	workloads := krt.NewMutableCollection(nil, []model.Workload{workload}, opts...)
	localEntered, globalEntered, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(release) }) })
	var attachments []PolicyAttachment
	for _, global := range []bool{false, true} {
		for _, app := range []string{"old", "new"} {
			target := AttachmentTarget{
				Global:   global,
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": app}},
			}
			scope := "global"
			if !global {
				target.Namespaces = []string{"demo"}
				scope = "local"
			}
			a, err := NewPolicyAttachment(
				PolicyAttachment{Kind: PolicyKindTrafficPolicy, Name: scope + "-" + app, Target: target},
			)
			if err != nil {
				t.Fatal(err)
			}
			if app == "new" {
				gate := bindingGateSelector{Selector: a.selector, once: new(sync.Once), entered: globalEntered}
				if !global {
					gate.entered, gate.release = localEntered, release
				}
				a.selector = gate
			}
			attachments = append(attachments, a)
		}
	}
	bindings := NewWorkloadPolicyBindingsCollection(
		workloads.AsCollection(),
		krt.NewStaticCollection(nil, attachments, opts...),
		krt.NewOptionsBuilder(stop, "test", nil),
	)
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("bindings did not sync")
	}
	events := make(chan krt.Event[Bindings], 10)
	registration := bindings.RegisterBatch(func(batch []krt.Event[Bindings]) {
		for _, event := range batch {
			events <- event
		}
	}, false)
	t.Cleanup(registration.UnregisterHandler)
	workload.Labels = map[string]string{"app": "new"}
	workloads.ConditionalUpdateObject(workload)
	for _, entered := range []chan struct{}{localEntered, globalEntered} {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("selector evaluation did not start")
		}
	}
	select {
	case event := <-events:
		t.Fatalf("published incomplete label transition: %+v", event)
	case <-time.After(100 * time.Millisecond):
	}
	if got := bindings.GetKey(workload.UID).
		PolicyNames(PolicyKindTrafficPolicy); !reflect.DeepEqual(
		got,
		[]string{"global-old", "local-old"},
	) {
		t.Fatalf("binding while local computation blocked = %v", got)
	}
	unblock.Do(func() { close(release) })
	if got := awaitBindingEvent(
		t,
		events,
	).Latest().
		PolicyNames(PolicyKindTrafficPolicy); !reflect.DeepEqual(
		got,
		[]string{"global-new", "local-new"},
	) {
		t.Fatalf("completed label transition = %v", got)
	}
}

func TestPolicyBindingsScopeMovesAndOrdering(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	opts := []krt.CollectionOption{krt.WithStop(stop)}
	workload := model.Workload{UID: "client", Namespace: "demo"}
	workloads := krt.NewMutableCollection(nil, []model.Workload{workload, {UID: "other", Namespace: "other"}}, opts...)
	makeAttachment := func(name string, priority int32, target AttachmentTarget) PolicyAttachment {
		t.Helper()
		a, err := NewPolicyAttachment(
			PolicyAttachment{Kind: PolicyKindTrafficPolicy, Name: name, Priority: priority, Target: target},
		)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	local := makeAttachment("local", 10, AttachmentTarget{Namespaces: []string{"demo"}})
	global := makeAttachment("global", 20, AttachmentTarget{Global: true})
	attachments := krt.NewMutableCollection(nil, []PolicyAttachment{local, global}, opts...)
	bindings := NewWorkloadPolicyBindingsCollection(
		workloads.AsCollection(),
		attachments.AsCollection(),
		krt.NewOptionsBuilder(stop, "test", nil),
	)
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("bindings did not sync")
	}
	check := func(uid string, want []string) {
		t.Helper()
		if got := bindings.GetKey(uid).PolicyNames(PolicyKindTrafficPolicy); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s policies = %v, want %v", uid, got, want)
		}
	}
	check("client", []string{"local", "global"})
	check("other", []string{"global"})
	events := make(chan krt.Event[Bindings], 20)
	registration := bindings.RegisterBatch(func(batch []krt.Event[Bindings]) {
		for _, event := range batch {
			events <- event
		}
	}, false)
	t.Cleanup(registration.UnregisterHandler)
	global.Priority = 5
	attachments.ConditionalUpdateObject(global)
	awaitBindingEvent(t, events)
	check("client", []string{"global", "local"})
	// Moving an attachment out of global scope must withdraw its old membership.
	global = makeAttachment("global", 5, AttachmentTarget{Namespaces: []string{"other"}})
	attachments.ConditionalUpdateObject(global)
	awaitBindingEvent(t, events)
	check("client", []string{"local"})
	check("other", []string{"global"})
	workload.Namespace = "other"
	workloads.ConditionalUpdateObject(workload)
	awaitBindingEvent(t, events)
	check("client", []string{"global"})
	attachments.DeleteObject(global.ResourceName())
	for range 2 {
		awaitBindingEvent(t, events)
	}
	check("client", nil)
	check("other", nil)
	workloads.DeleteObject(workload.UID)
	if event := awaitBindingEvent(t, events); event.New != nil {
		t.Fatalf("expected Workload binding deletion: %+v", event)
	}
	workload.Namespace = "demo"
	workloads.ConditionalUpdateObject(workload)
	awaitBindingEvent(t, events)
	check("client", []string{"local"})
}
