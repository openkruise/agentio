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

package kruise

import (
	"context"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"slices"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

func TestSandboxResourceVersionDoesNotChangeModel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		options := []krt.CollectionOption{krt.WithStop(t.Context().Done())}
		source := &agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{
			Namespace:       "demo",
			Name:            "sandbox",
			UID:             "source",
			ResourceVersion: "1",
			Labels:          map[string]string{agentsv1alpha1.LabelSandboxID: "delivery"},
		}}
		objects := krt.NewMutableCollection(nil, []*agentsv1alpha1.Sandbox{source}, options...)
		pods := krt.NewStaticCollection[*corev1.Pod](nil, nil, options...)
		groups := newSandboxesByUID(objects.AsCollection()).AsCollection(options...)
		sandboxes := newSandboxes(groups, pods, newPodsByUID(pods), "cluster", options...)
		synctest.Wait()
		before := sandboxes.GetKey("kruise:delivery")
		if before == nil {
			t.Fatal("initial Sandbox model missing")
		}
		updates := 0
		registration := sandboxes.RegisterBatch(func(events []krt.Event[model.Sandbox]) {
			updates += len(events)
		}, false)
		defer registration.UnregisterHandler()
		changed := source.DeepCopy()
		changed.ResourceVersion = "2"
		objects.UpdateObject(changed)
		synctest.Wait()
		after := sandboxes.GetKey("kruise:delivery")
		if after == nil || !before.Equals(*after) || updates != 0 {
			t.Fatalf(
				"resourceVersion-only update changed Sandbox model: updates=%d, before=%+v, after=%+v",
				updates,
				before,
				after,
			)
		}
	})
}

func TestSandboxSecurityRulesProjection(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	source := &agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{
		Namespace: "demo",
		Name:      "sandbox",
		UID:       "object-uid",
		Labels:    map[string]string{agentsv1alpha1.LabelSandboxID: "delivery-uid"},
	}}
	objects := krt.NewMutableCollection[*agentsv1alpha1.Sandbox](nil, nil, options...)
	pods := krt.NewStaticCollection[*corev1.Pod](nil, nil, options...)
	groups := newSandboxesByUID(objects.AsCollection()).AsCollection(options...)
	sandboxes := newSandboxes(groups, pods, newPodsByUID(pods), "cluster", options...)
	for _, step := range []struct {
		raw     string
		host    string
		invalid bool
	}{
		{},
		{raw: `[{"name":"inline","match":[{"domains":["first.example"]}],"actions":{"block":{}}}]`, host: "first.example"},
		{raw: `[{"name":`, host: "first.example", invalid: true},
		{raw: `[{"name":"inline","match":[{"domains":["second.example"]}],"actions":{"block":{}}}]`, host: "second.example"},
		{},
	} {
		changed := source.DeepCopy()
		changed.Annotations = map[string]string{"unrelated": "drop"}
		var wantAnnotations map[string]string
		var want []agentsv1alpha1.SecurityRule
		if step.raw != "" {
			changed.Annotations[agentsv1alpha1.AnnotationSecurityRules] = step.raw
			wantAnnotations = map[string]string{agentsv1alpha1.AnnotationSecurityRules: step.raw}
		}
		if step.host != "" {
			want = []agentsv1alpha1.SecurityRule{{
				Name:    "inline",
				Match:   []agentsv1alpha1.RuleMatch{{Domains: []string{step.host}}},
				Actions: agentsv1alpha1.SecurityRuleActions{Block: &agentsv1alpha1.BlockAction{}},
			}}
		}
		stripped, err := stripSandbox(changed)
		if err != nil {
			t.Fatal(err)
		}
		obj := stripped.(*agentsv1alpha1.Sandbox)
		if !reflect.DeepEqual(obj.Annotations, wantAnnotations) {
			t.Fatalf("stripped annotations = %v", obj.Annotations)
		}
		changed.Annotations[agentsv1alpha1.AnnotationSecurityRules] = "mutated"
		if obj.Annotations[agentsv1alpha1.AnnotationSecurityRules] != step.raw {
			t.Fatal("stripped annotations alias the original object")
		}
		objects.UpdateObject(obj)
		if !sandboxes.WaitUntilSynced(stop) {
			t.Fatal("Sandbox collection did not sync")
		}
		err = wait.PollUntilContextTimeout(
			t.Context(),
			time.Millisecond,
			time.Second,
			true,
			func(context.Context) (bool, error) {
				current := sandboxes.GetKey("kruise:delivery-uid")
				if current == nil {
					return false, nil
				}
				inline := current.Policies
				valid := inline == nil && step.raw == ""
				if inline != nil {
					valid = (step.invalid && inline.InputError != "") ||
						(!step.invalid && inline.InputError == "" && reflect.DeepEqual(inline.SecurityRules, want))
				}
				return current.Attester == nil && valid, nil
			},
		)
		if err != nil {
			t.Fatalf("annotation %q: Sandbox = %+v, error = %v", step.raw, sandboxes.GetKey("kruise:delivery-uid"), err)
		}
	}
	source.Annotations = map[string]string{
		agentsv1alpha1.AnnotationSecurityRules: `[{"match":[{"domains":["last.example"]}]}]`,
	}
	objects.UpdateObject(source)
	if err := wait.PollUntilContextTimeout(
		t.Context(),
		time.Millisecond,
		time.Second,
		true,
		func(context.Context) (bool, error) {
			current := sandboxes.GetKey("kruise:delivery-uid")
			return current != nil && current.Policies != nil && current.Policies.InputError == "", nil
		},
	); err != nil {
		t.Fatal("inline profile did not recover before deletion")
	}
	objects.DeleteObject("demo/sandbox")
	err := wait.PollUntilContextTimeout(
		t.Context(),
		time.Millisecond,
		time.Second,
		true,
		func(context.Context) (bool, error) {
			return sandboxes.GetKey("kruise:delivery-uid") == nil, nil
		},
	)
	if err != nil {
		t.Fatal("deleted Sandbox retained inline rules")
	}
}

func TestSandboxSecurityRulesRejectInvalidAnnotation(t *testing.T) {
	for _, raw := range []string{
		`[]`, `null`, `{}`, `[{"name":`,
		`[{"unknown":true}]`,
		`[{"match":[{"domains":["api.example"],"unknown":true}]}]`,
		`[{"match":[{"domains":["api.example"]}]}] []`,
	} {
		sandbox := &agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{agentsv1alpha1.AnnotationSecurityRules: raw},
		}}
		if _, err := sandboxSecurityRules(sandbox); err == nil {
			t.Errorf("invalid security-rules accepted: %s", raw)
		}
	}
}

func TestSandboxUIDHonorsDeliveryIdentity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sandbox *agentsv1alpha1.Sandbox
		want    string
		found   bool
	}{
		{
			name: "delivery identity",
			sandbox: &agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{
				Namespace: "demo",
				Name:      "sandbox",
				Labels: map[string]string{
					agentsv1alpha1.LabelSandboxID: "delivery-uid",
				},
			}},
			want:  "kruise:delivery-uid",
			found: true,
		},
		{
			name: "ordinary compatibility identity",
			sandbox: &agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{
				Namespace: "demo",
				Name:      "sandbox",
			}},
			want:  "kruise:demo--sandbox",
			found: true,
		},
		{
			name: "pooled sandbox requires delivery identity",
			sandbox: &agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{
				Namespace: "demo",
				Name:      "sandbox",
				Labels: map[string]string{
					agentsv1alpha1.LabelSandboxPool: "pool",
				},
			}},
		},
		{
			name: "nil",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, found := sandboxUID(tc.sandbox)
			if got != tc.want || found != tc.found {
				t.Fatalf("sandboxUID() = %q, %v, want %q, %v", got, found, tc.want, tc.found)
			}
		})
	}
}

func TestKruiseSandboxProducesPodAttesterBinding(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	controller := true
	futureInternalLabel := agentsv1alpha1.InternalPrefix + "future-controller-state"
	podCreatedByLabel := agentsv1alpha1.InternalPrefix + "created-by"
	sandbox := &agentsv1alpha1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "demo",
			Name:       "sandbox",
			UID:        "sandbox-object-uid",
			Generation: 3,
			Labels: map[string]string{
				agentsv1alpha1.LabelSandboxID:           "delivery-uid",
				agentsv1alpha1.LabelSandboxIsClaimed:    agentsv1alpha1.True,
				agentsv1alpha1.LabelAllowInternetAccess: agentsv1alpha1.False,
				"app":                                   "sandbox-value",
				"sandbox-only":                          "kept",
			},
		},
		Status: agentsv1alpha1.SandboxStatus{
			ObservedGeneration: 3,
			Phase:              agentsv1alpha1.SandboxRunning,
			Conditions: []metav1.Condition{
				{
					Type:   string(agentsv1alpha1.SandboxConditionReady),
					Status: metav1.ConditionTrue,
				},
			},
			PodInfo: agentsv1alpha1.PodInfo{
				PodUID: "pod-uid",
			},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "sandbox-runtime",
			UID:       "pod-uid",
			Labels: map[string]string{
				agentsv1alpha1.LabelSandboxID:           "spoofed-delivery-uid",
				agentsv1alpha1.LabelSandboxIsClaimed:    agentsv1alpha1.False,
				agentsv1alpha1.LabelSandboxUpdateOps:    "spoofed-update",
				agentsv1alpha1.LabelSandboxName:         "sandbox",
				agentsv1alpha1.LabelAllowInternetAccess: agentsv1alpha1.True,
				agentsv1alpha1.AnnotationOwner:          "claim-uid",
				podCreatedByLabel:                       "sandbox",
				futureInternalLabel:                     "stale",
				"app":                                   "pod-value",
				"pod-only":                              "included",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: agentsv1alpha1.GroupVersion.String(),
					Kind:       "Sandbox",
					Name:       sandbox.Name,
					UID:        sandbox.UID,
					Controller: &controller,
				},
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			NodeName:           "node-a",
		},
		Status: corev1.PodStatus{
			Phase:  corev1.PodRunning,
			PodIP:  "10.0.0.10",
			PodIPs: []corev1.PodIP{{IP: "10.0.0.10"}},
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}
	sandboxObjects := krt.NewMutableCollection(
		nil,
		[]*agentsv1alpha1.Sandbox{sandbox},
		options...,
	)
	sandboxGroups := newSandboxesByUID(sandboxObjects.AsCollection()).AsCollection(options...)
	pods := krt.NewStaticCollection(nil, []*corev1.Pod{pod}, options...)
	podsByUID := newPodsByUID(pods)
	sandboxes := newSandboxes(sandboxGroups, pods, podsByUID, "cluster", options...)
	workloads := podsource.NewWorkloads(pods, "cluster", options...)
	if !sandboxes.WaitUntilSynced(stop) || !workloads.WaitUntilSynced(stop) {
		t.Fatal("Kruise runtime collections did not synchronize")
	}

	policySubject := sandboxes.GetKey("kruise:delivery-uid")
	if policySubject == nil || policySubject.UID != "kruise:delivery-uid" {
		t.Fatalf("Sandbox = %+v, want delivery identity", policySubject)
	}
	if policySubject.Namespace != "demo" {
		t.Fatalf("Sandbox namespace = %q, want demo", policySubject.Namespace)
	}
	workload := workloads.GetKey("cluster//Pod/demo/sandbox-runtime")
	if workload == nil {
		t.Fatal("Kruise runtime produced no Workload attester")
	}
	if workload.Source.Registry != "kubernetes/cluster" || workload.Source.Key != "pod-uid" {
		t.Fatalf("Workload attester = %+v", workload)
	}
	if policySubject.Attester == nil || policySubject.Attester.WorkloadUID != workload.UID {
		t.Fatalf("Sandbox runtime = %+v", policySubject)
	}

	if !workload.Ready || !OwnsPod(pod) {
		t.Fatalf("Workload ready = %v, OwnsPod = %v", workload.Ready, OwnsPod(pod))
	}

	// Phase and generation observations may lag the running Pod. Its attester
	// must remain available throughout Pending transitions and timeout updates.
	for _, tc := range []struct {
		name       string
		phase      agentsv1alpha1.SandboxPhase
		generation int64
		observed   int64
	}{
		{"pending", agentsv1alpha1.SandboxPending, 3, 3},
		{"running", agentsv1alpha1.SandboxRunning, 3, 3},
		{"timeout extended", agentsv1alpha1.SandboxRunning, 4, 3},
		{"timeout observed", agentsv1alpha1.SandboxRunning, 4, 4},
	} {
		changed := sandbox.DeepCopy()
		changed.Status.Phase = tc.phase
		changed.Generation = tc.generation
		changed.Status.ObservedGeneration = tc.observed
		stripped, err := stripSandbox(changed)
		if err != nil {
			t.Fatal(err)
		}
		projected := stripped.(*agentsv1alpha1.Sandbox)
		wantStatus := agentsv1alpha1.SandboxStatus{PodInfo: agentsv1alpha1.PodInfo{PodUID: pod.UID}}
		if !reflect.DeepEqual(projected.Status, wantStatus) {
			t.Fatalf("runtime status must retain only the host Pod UID: %+v", projected.Status)
		}
		sandboxObjects.UpdateObject(projected)
		err = wait.PollUntilContextTimeout(
			t.Context(),
			time.Millisecond,
			time.Second,
			true,
			func(context.Context) (bool, error) {
				current := sandboxes.GetKey("kruise:delivery-uid")
				return current != nil &&
					current.Attester != nil &&
					current.Attester.WorkloadUID == workload.UID, nil
			},
		)
		if err != nil {
			t.Fatalf(
				"%s did not retain the Pod binding: Sandbox = %+v, error = %v",
				tc.name,
				sandboxes.GetKey("kruise:delivery-uid"),
				err,
			)
		}
	}
}

func TestKruiseClassifiesHostWithoutSandboxDiscovery(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	controller := true
	host := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "host",
			Namespace: "demo",
			UID:       "pod-uid",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: agentsv1alpha1.GroupVersion.String(),
				Kind:       "Sandbox",
				Name:       "not-yet-discovered",
				UID:        "sandbox-uid",
				Controller: &controller,
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.1"},
	}
	ordinary := host.DeepCopy()
	ordinary.Name = "ordinary"
	ordinary.OwnerReferences = nil
	// A label alone cannot turn an ordinary Pod into a Sandbox host.
	ordinary.Labels = map[string]string{agentsv1alpha1.LabelSandboxID: "claimed"}
	pods := krt.NewStaticCollection(nil, []*corev1.Pod{host, ordinary}, krt.WithStop(stop))
	workloads := podsource.NewWorkloads(pods, "cluster", krt.WithStop(stop))
	if !workloads.WaitUntilSynced(stop) {
		t.Fatal("Workloads did not sync")
	}
	for _, pod := range []*corev1.Pod{host, ordinary} {
		got := workloads.GetKey(podsource.WorkloadUID("cluster", pod))
		if got == nil || OwnsPod(pod) != (pod.Name == "host") {
			t.Fatalf("Pod %s classification = %+v", pod.Name, got)
		}
	}
}

func TestSourceDeleteNotifications(t *testing.T) {
	for _, action := range []string{"delete", "unclaim", "rename", "terminating", "update"} {
		t.Run(action, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				source := &agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{
					Namespace:       "demo",
					Name:            "sandbox",
					UID:             "source",
					ResourceVersion: "1",
					Annotations:     map[string]string{agentsv1alpha1.AnnotationSecurityRules: "[]"},
					Labels: map[string]string{
						agentsv1alpha1.LabelSandboxPool:      "pool",
						agentsv1alpha1.LabelSandboxIsClaimed: agentsv1alpha1.True,
						agentsv1alpha1.LabelSandboxID:        "delivery",
					},
				}}
				objects := krt.NewMutableCollection(
					nil,
					[]*agentsv1alpha1.Sandbox{source},
					krt.WithStop(t.Context().Done()),
				)
				notifications := make(chan []model.ResourceKey, 2)
				config := newSandboxSources(objects.AsCollection())
				synctest.Wait()
				unregister := config.RegisterDeletes(func(changed []model.ResourceKey) {
					notifications <- changed
				})
				defer unregister()
				key := model.ResourceKey{TypeURL: model.SandboxType, Name: "kruise:delivery"}
				if identity, found := config.Lookup(
					key,
				); !found ||
					identity != (model.SourceIdentity{UID: "source"}) {
					t.Fatalf("source lookup failed before deletion: %v, %v", identity, found)
				}
				changed := source.DeepCopy()
				changed.ResourceVersion = "2"
				switch action {
				case "delete":
					objects.DeleteObject("demo/sandbox")
				case "unclaim":
					delete(changed.Labels, agentsv1alpha1.LabelSandboxIsClaimed)
				case "rename":
					changed.Labels[agentsv1alpha1.LabelSandboxID] = "replacement"
				case "terminating":
					now := metav1.Now()
					changed.DeletionTimestamp = &now
				}
				if action != "delete" {
					objects.UpdateObject(changed)
				}
				synctest.Wait()
				var keys []model.ResourceKey
				for len(notifications) > 0 {
					keys = append(keys, (<-notifications)...)
				}
				if action == "update" {
					if len(keys) != 0 {
						t.Fatalf("ordinary update invalidated source: %v", keys)
					}
					return
				}
				want := []model.ResourceKey{
					{TypeURL: model.SandboxType, Name: "kruise:delivery"},
				}
				if len(keys) != len(want) || !slices.Contains(keys, want[0]) {
					t.Fatalf("source invalidations = %v, want %v", keys, want)
				}
				if _, found := config.Lookup(keys[0]); found {
					t.Fatal("deleted key remains observable")
				}
			})
		})
	}
}

func TestSandboxSourceConflictAndInlineAbsence(t *testing.T) {
	first := &agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{
		Name:            "first",
		Namespace:       "demo",
		UID:             "first",
		ResourceVersion: "1",
		Labels:          map[string]string{agentsv1alpha1.LabelSandboxID: "duplicate"},
	}}
	second := first.DeepCopy()
	second.Name, second.UID = "second", "second"
	objects := krt.NewMutableCollection(nil, []*agentsv1alpha1.Sandbox{first, second}, krt.WithStop(t.Context().Done()))
	sandboxes := newSandboxSources(objects.AsCollection())
	key := model.ResourceKey{TypeURL: model.SandboxType, Name: "kruise:duplicate"}
	if got, found := sandboxes.Lookup(key); !found || got != (model.SourceIdentity{}) {
		t.Fatalf("ambiguous source must stay present without a selected identity: %v, %v", got, found)
	}
	if _, found := sandboxes.Lookup(
		model.ResourceKey{
			TypeURL: model.SecurityProfileType,
			Name:    "sandboxes/kruise:duplicate/securityProfiles/inline",
		},
	); found {
		t.Fatal("absent inline policy reported as present")
	}
	objects.DeleteObject("demo/second")
	if got, found := sandboxes.Lookup(key); !found || got != (model.SourceIdentity{UID: "first"}) {
		t.Fatalf("resolved source not visible: %v, %v", got, found)
	}
}
