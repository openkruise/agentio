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
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

func TestSandboxUIDHonorsDeliveryIdentity(t *testing.T) {
	for _, test := range []struct {
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
			want:  "delivery-uid",
			found: true,
		},
		{
			name: "ordinary compatibility identity",
			sandbox: &agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{
				Namespace: "demo",
				Name:      "sandbox",
			}},
			want:  "demo--sandbox",
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
		t.Run(test.name, func(t *testing.T) {
			got, found := sandboxUID(test.sandbox)
			if got != test.want || found != test.found {
				t.Fatalf("sandboxUID() = %q, %v, want %q, %v", got, found, test.want, test.found)
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
	sandboxObjects := krt.NewStaticCollection(
		nil,
		[]*agentsv1alpha1.Sandbox{sandbox},
		options...,
	)
	sandboxGroups := newSandboxesByUID(sandboxObjects).AsCollection(options...)
	pods := krt.NewStaticCollection(nil, []*corev1.Pod{pod}, options...)
	podsByUID := newPodsByUID(pods)
	sandboxes := newSandboxes(sandboxGroups, pods, podsByUID, "cluster", options...)
	workloads := podsource.NewWorkloads(pods, "cluster", "cluster.local", OwnsPod, options...)
	if !sandboxes.WaitUntilSynced(stop) || !workloads.WaitUntilSynced(stop) {
		t.Fatal("Kruise runtime collections did not synchronize")
	}

	policySubject := sandboxes.GetKey("delivery-uid")
	if policySubject == nil || policySubject.UID != "delivery-uid" {
		t.Fatalf("Sandbox = %+v, want delivery identity", policySubject)
	}
	if policySubject.Namespace != "demo" {
		t.Fatalf("Sandbox namespace = %q, want demo", policySubject.Namespace)
	}
	if got := policySubject.Labels["app"]; got != "pod-value" {
		t.Fatalf("Sandbox app label = %q, want pod-value", got)
	}
	if got := policySubject.Labels["sandbox-only"]; got != "kept" {
		t.Fatalf("Sandbox-only label = %q, want kept", got)
	}
	if got := policySubject.Labels["pod-only"]; got != "included" {
		t.Fatalf("Pod-only label = %q, want included", got)
	}
	if got := policySubject.Labels[agentsv1alpha1.LabelSandboxID]; got != "delivery-uid" {
		t.Fatalf("Sandbox ID label = %q, want delivery-uid", got)
	}
	if got := policySubject.Labels[agentsv1alpha1.LabelSandboxIsClaimed]; got != agentsv1alpha1.True {
		t.Fatalf("Sandbox claimed label = %q, want true", got)
	}
	if got, found := policySubject.Labels[agentsv1alpha1.LabelSandboxUpdateOps]; found {
		t.Fatalf("Pod-only protected label leaked into Sandbox: %q", got)
	}
	if got := policySubject.Labels[agentsv1alpha1.LabelSandboxName]; got != "sandbox" {
		t.Fatalf("Sandbox name label = %q, want sandbox", got)
	}
	if got := policySubject.Labels[agentsv1alpha1.LabelAllowInternetAccess]; got != agentsv1alpha1.True {
		t.Fatalf("Allow internet label = %q, want true", got)
	}
	if got := policySubject.Labels[agentsv1alpha1.AnnotationOwner]; got != "claim-uid" {
		t.Fatalf("Owner label = %q, want claim-uid", got)
	}
	if got := policySubject.Labels[podCreatedByLabel]; got != "sandbox" {
		t.Fatalf("Created-by label = %q, want sandbox", got)
	}
	if got, found := policySubject.Labels[futureInternalLabel]; found {
		t.Fatalf("Unknown Pod-only internal label leaked into Sandbox: %q", got)
	}
	sandbox.Labels["sandbox-only"] = "mutated"
	pod.Labels["pod-only"] = "mutated"
	if got := policySubject.Labels["sandbox-only"]; got != "kept" {
		t.Fatalf("published Sandbox labels aliased Sandbox source map: sandbox-only = %q", got)
	}
	if got := policySubject.Labels["pod-only"]; got != "included" {
		t.Fatalf("published Sandbox labels aliased Pod source map: pod-only = %q", got)
	}
	workload := workloads.GetKey("cluster//Pod/demo/sandbox-runtime")
	if workload == nil {
		t.Fatal("Kruise runtime produced no Workload attester")
	}
	if workload.SourceUID != "pod-uid" || workload.Principal.String() != "spiffe://cluster.local/ns/demo/sa/default" {
		t.Fatalf("Workload attester = %+v", workload)
	}
	if policySubject.Attester == nil || policySubject.Attester.WorkloadUID != workload.UID || policySubject.State != model.SandboxStateRunning {
		t.Fatalf("Sandbox runtime = %+v", policySubject)
	}

	if !workload.Ready || !workload.SandboxManaged || !OwnsPod(pod) {
		t.Fatalf("Workload ready = %v, OwnsPod = %v", workload.Ready, OwnsPod(pod))
	}

	// Phase and generation observations may lag the running Pod. Its attester
	// must remain available throughout Pending transitions and timeout updates.
	for _, test := range []struct {
		name       string
		phase      agentsv1alpha1.SandboxPhase
		state      model.SandboxState
		generation int64
		observed   int64
	}{
		{"pending", agentsv1alpha1.SandboxPending, model.SandboxStatePending, 3, 3},
		{"running", agentsv1alpha1.SandboxRunning, model.SandboxStateRunning, 3, 3},
		{"timeout extended", agentsv1alpha1.SandboxRunning, model.SandboxStateRunning, 4, 3},
		{"timeout observed", agentsv1alpha1.SandboxRunning, model.SandboxStateRunning, 4, 4},
	} {
		changed := sandbox.DeepCopy()
		changed.Status.Phase = test.phase
		changed.Generation = test.generation
		changed.Status.ObservedGeneration = test.observed
		// Wait for this specific projection, not the preceding same-phase result.
		changed.Labels["test-step"] = test.name
		sandboxObjects.UpdateObject(changed)
		err := wait.PollUntilContextTimeout(t.Context(), time.Millisecond, time.Second, true, func(context.Context) (bool, error) {
			current := sandboxes.GetKey("delivery-uid")
			return current != nil && current.Labels["test-step"] == test.name && current.State == test.state && current.Attester != nil &&
				current.Attester.WorkloadUID == workload.UID, nil
		})
		if err != nil {
			t.Fatalf("%s did not retain the Pod binding: Sandbox = %+v, error = %v", test.name, sandboxes.GetKey("delivery-uid"), err)
		}
	}
}

func TestKruiseRuntimeStateRequiresCompletedPause(t *testing.T) {
	for _, test := range []struct {
		phase  agentsv1alpha1.SandboxPhase
		paused bool
		want   model.SandboxState
	}{
		{agentsv1alpha1.SandboxPending, false, model.SandboxStatePending},
		{agentsv1alpha1.SandboxRunning, false, model.SandboxStateRunning},
		{agentsv1alpha1.SandboxPaused, false, model.SandboxStateUnspecified},
		{agentsv1alpha1.SandboxPaused, true, model.SandboxStatePaused},
		{agentsv1alpha1.SandboxSucceeded, false, model.SandboxStateStopped},
		{agentsv1alpha1.SandboxFailed, false, model.SandboxStateStopped},
	} {
		sandbox := &agentsv1alpha1.Sandbox{Status: agentsv1alpha1.SandboxStatus{Phase: test.phase}}
		if test.paused {
			sandbox.Status.Conditions = []metav1.Condition{{Type: string(agentsv1alpha1.SandboxConditionPaused), Status: metav1.ConditionTrue}}
		}
		if got := runtimeState(sandbox); got != test.want {
			t.Fatalf("phase %s paused %v: state %v, want %v", test.phase, test.paused, got, test.want)
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
	workloads := podsource.NewWorkloads(pods, "cluster", "cluster.local", OwnsPod, krt.WithStop(stop))
	if !workloads.WaitUntilSynced(stop) {
		t.Fatal("Workloads did not sync")
	}
	for _, pod := range []*corev1.Pod{host, ordinary} {
		got := workloads.GetKey(podsource.WorkloadUID("cluster", pod))
		if got == nil || got.SandboxManaged != (pod.Name == "host") {
			t.Fatalf("Pod %s classification = %+v", pod.Name, got)
		}
	}
}
