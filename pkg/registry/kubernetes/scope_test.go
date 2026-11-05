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

package kubernetes

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestResolveScopeAuthorizesTrustedEPEIdentities(t *testing.T) {
	for _, tc := range []struct {
		name       string
		namespace  string
		account    string
		configured string
		want       model.ClientClass
	}{
		{"authorized", "agentio-system", "processor", "[spiffe://cluster.local/ns/agentio-system/sa/processor]", model.ClientEPE},
		{"custom namespace", "tenant", "processor", "[spiffe://cluster.local/ns/tenant/sa/processor]", model.ClientEPE},
		{"multiple identities", "tenant", "processor", "[spiffe://cluster.local/ns/agentio-system/sa/processor, spiffe://cluster.local/ns/tenant/sa/processor]", model.ClientEPE},
		{"wrong account", "agentio-system", "other", "[spiffe://cluster.local/ns/agentio-system/sa/processor]", model.ClientDedicatedZTunnel},
		{"wrong namespace", "tenant", "processor", "[spiffe://cluster.local/ns/agentio-system/sa/processor]", model.ClientDedicatedZTunnel},
		{"wrong trust domain", "agentio-system", "processor", "[spiffe://other.local/ns/agentio-system/sa/processor]", model.ClientDedicatedZTunnel},
		{"disabled", "agentio-system", "processor", "[]", model.ClientDedicatedZTunnel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := egressPod(tc.namespace, "processor", tc.account, "10.0.0.1")
			pod.UID = "epe-pod"
			pod.Spec.ServiceAccountName = tc.account
			pod.Labels = map[string]string{"app.kubernetes.io/name": "agentio-epe"}
			config := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
				Data:       map[string]string{"config": "trustedEPEIdentities: " + tc.configured},
			}
			r := newTestRegistry(t, t.Context(), []runtime.Object{pod, config}, nil)
			resolver := r.PodScopeResolver(r.Workloads)
			scope, err := resolver.ResolveScope(gatewayTestPeer(pod), "")
			if err != nil || scope.Class != tc.want {
				t.Fatalf("scope=%+v err=%v", scope, err)
			}
			if err := scope.Validate(); err != nil {
				t.Fatal(err)
			}
			stale := gatewayTestPeer(pod)
			stale.Kubernetes.WorkloadUID = "old-pod"
			if _, err := resolver.ResolveScope(stale, ""); err == nil {
				t.Fatal("stale Pod token accepted")
			}
		})
	}
}

func TestResolveScopeUpdatesTrustedEPEIdentities(t *testing.T) {
	pod := egressPod("tenant", "processor", "processor", "10.0.0.1")
	pod.UID = "epe-pod"
	pod.Spec.ServiceAccountName = "processor"
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
		Data: map[string]string{
			"config": "trustedEPEIdentities: [spiffe://cluster.local/ns/tenant/sa/processor]",
		},
	}
	r := newTestRegistry(t, t.Context(), []runtime.Object{pod, config}, nil)
	resolver := r.PodScopeResolver(r.Workloads)
	if scope, err := resolver.ResolveScope(gatewayTestPeer(pod), ""); err != nil || scope.Class != model.ClientEPE {
		t.Fatalf("initial scope=%+v err=%v", scope, err)
	}
	for _, update := range []struct {
		config string
		want   model.ClientClass
	}{
		{"trustedEPEIdentities: []", model.ClientDedicatedZTunnel},
		{"trustedEPEIdentities: [spiffe://cluster.local/ns/tenant/sa/processor]", model.ClientEPE},
	} {
		config.Data["config"] = update.config
		var err error
		config, err = r.client.CoreV1().ConfigMaps(config.Namespace).Update(t.Context(), config, metav1.UpdateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := wait.PollUntilContextTimeout(
			t.Context(),
			10*time.Millisecond,
			time.Second,
			true,
			func(context.Context) (bool, error) {
				scope, err := resolver.ResolveScope(gatewayTestPeer(pod), "")
				return scope.Class == update.want, err
			},
		); err != nil {
			t.Fatalf("scope did not change to %s: %v", update.want, err)
		}
	}
}

func TestResolveScopeAuthorizesEnrolledGatewayPods(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "agentio-config",
		},
		Data: map[string]string{"config": `egressGateways:
- namespace: demo
  name: egress
`},
	}
	valid := egressPod("demo", "egress-rollout-a", "egress", "10.0.0.1")
	valid.UID = "valid-uid"
	implicit := egressPod("demo", "egress-rollout-b", "egress", "10.0.0.2")
	implicit.UID = "implicit-uid"
	implicit.Labels = nil
	spoofed := egressPod("demo", "attacker", "egress", "10.0.0.3")
	spoofed.UID = "spoofed-uid"
	spoofed.Spec.ServiceAccountName = "attacker"
	unconfigured := egressPod("demo", "missing", "missing", "10.0.0.4")
	unconfigured.UID = "unconfigured-uid"
	valid.Labels["member"] = "egress"
	implicit.Labels = map[string]string{"member": "egress"}
	r := newTestRegistry(
		t,
		ctx,
		[]runtime.Object{config, valid, implicit, spoofed, unconfigured, gatewayTestService("demo", "egress")},
		nil,
	)

	for _, tc := range []struct {
		name           string
		pod            *corev1.Pod
		serviceAccount string
		wantClass      model.ClientClass
		wantKey        string
		wantSandboxUID string
	}{
		{name: "explicit config with standard label", pod: valid, serviceAccount: "egress", wantClass: model.ClientEgressGateway, wantKey: "demo/egress"},
		{name: "manual deployment without gateway label", pod: implicit, serviceAccount: "egress", wantClass: model.ClientEgressGateway, wantKey: "demo/egress"},
		{name: "label cannot grant gateway scope", pod: spoofed, serviceAccount: "attacker", wantClass: model.ClientDedicatedZTunnel, wantSandboxUID: "test//Pod/demo/attacker"},
		{name: "unregistered identity gets only sandbox scope", pod: unconfigured, serviceAccount: "missing", wantClass: model.ClientDedicatedZTunnel, wantSandboxUID: "test//Pod/demo/missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			principal := model.KubernetesPeer{Namespace: tc.pod.Namespace, ServiceAccount: tc.serviceAccount}
			peer := model.PeerIdentity{
				AttestedBy: model.AttestationKubernetes,
				Kubernetes: model.KubernetesPeer{
					WorkloadName:   tc.pod.Name,
					WorkloadUID:    string(tc.pod.UID),
					Namespace:      principal.Namespace,
					ServiceAccount: principal.ServiceAccount,
				},
			}
			scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, "")
			if err != nil {
				t.Fatalf("ResolveScope(): %v", err)
			}
			if scope.Class != tc.wantClass || scope.GatewayKey != tc.wantKey ||
				(tc.wantClass != model.ClientEgressGateway && scope.WorkloadUID != tc.wantSandboxUID) {
				t.Fatalf(
					"ResolveScope() = %+v, want class %s gateway %q sandbox %q",
					scope,
					tc.wantClass,
					tc.wantKey,
					tc.wantSandboxUID,
				)
			}
		})
	}
}

func TestResolveScopeAuthorizesEnrolledGatewayAPIPod(t *testing.T) {
	ctx := t.Context()
	watcher := newFakeGatewayCRDWatcher()
	pod := egressPod("demo", "egress-rollout-a", "egress", "10.0.0.1")
	pod.UID = "gateway-uid"
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
		Data:       map[string]string{"config": "{}"},
	}
	r := newGatewayTestRegistry(t, ctx, watcher, ownedGatewayClass(), ownedGateway(), pod, config)
	watcher.install(gatewayResource, ctx.Done())
	watcher.install(gatewayClassResource, ctx.Done())
	testutil.Eventually(t, func() bool { return r.Gateways.GetKey("demo/egress") != nil }, "Gateway API registration")

	peer := model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			WorkloadName:   pod.Name,
			WorkloadUID:    string(pod.UID),
			Namespace:      "demo",
			ServiceAccount: "egress",
		},
	}
	scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, "")
	if err != nil {
		t.Fatalf("ResolveScope(): %v", err)
	}
	if scope.Class != model.ClientEgressGateway || scope.GatewayKey != "demo/egress" {
		t.Fatalf("ResolveScope() = %+v, want Gateway API-owned gateway demo/egress", scope)
	}
}

// Unbound tokens cannot establish Pod or node ownership.
func TestResolveScopeRejectsUnboundTokensForPodScopes(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "agentio-config",
		},
		Data: map[string]string{"config": `egressGateways:
- namespace: demo
  name: egress
`},
	}
	gateway := egressPod("demo", "egress-rollout-a", "egress", "10.0.0.1")
	gateway.UID = "gateway-uid"
	sandbox := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "sandbox",
			UID:       "sandbox-uid",
		},
		Spec:   corev1.PodSpec{ServiceAccountName: "app", NodeName: "node-a"},
		Status: corev1.PodStatus{PodIP: "10.0.0.5"},
	}
	gateway.Labels["member"] = "egress"
	r := newTestRegistry(t, ctx, []runtime.Object{config, gateway, sandbox, gatewayTestService("demo", "egress")}, nil)
	testutil.Eventually(t, func() bool { return len(r.Pods.List()) == 2 }, "pods loaded")

	gatewayPrincipal := model.KubernetesPeer{Namespace: "demo", ServiceAccount: "egress"}
	sandboxPrincipal := model.KubernetesPeer{Namespace: "demo", ServiceAccount: "app"}

	for _, tc := range []struct {
		name      string
		principal model.KubernetesPeer
		bound     bool
		podName   string
		podUID    string
		wantClass model.ClientClass
		wantKey   string
	}{
		{name: "unbound token claiming gateway pod", principal: gatewayPrincipal, podName: "egress-rollout-a"},
		{name: "unbound token asserting gateway pod UID", principal: gatewayPrincipal, podName: "egress-rollout-a", podUID: "gateway-uid"},
		{name: "unbound token claiming sandbox pod", principal: sandboxPrincipal, podName: "sandbox"},
		{
			name:      "bound token resolves gateway scope",
			principal: gatewayPrincipal,
			bound:     true,
			podName:   "egress-rollout-a",
			podUID:    "gateway-uid",
			wantClass: model.ClientEgressGateway,
			wantKey:   "demo/egress",
		},
		{
			name:      "bound token resolves sandbox scope",
			principal: sandboxPrincipal,
			bound:     true,
			podName:   "sandbox",
			podUID:    "sandbox-uid",
			wantClass: model.ClientDedicatedZTunnel,
			wantKey:   "test//Pod/demo/sandbox",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := model.PeerIdentity{AttestedBy: model.AttestationKubernetes, Kubernetes: tc.principal}
			if tc.bound {
				peer.Kubernetes.WorkloadName = tc.podName
				peer.Kubernetes.WorkloadUID = tc.podUID
			}
			scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, "")
			if !tc.bound {
				if err == nil {
					t.Fatalf("ResolveScope() = %+v, want unbound token rejection", scope)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveScope(): %v", err)
			}
			if scope.Class != tc.wantClass {
				t.Fatalf("ResolveScope() class = %v, want %v", scope.Class, tc.wantClass)
			}
			if tc.wantClass == model.ClientEgressGateway && scope.GatewayKey != tc.wantKey {
				t.Fatalf("ResolveScope() gateway key = %q, want %q", scope.GatewayKey, tc.wantKey)
			}
			if tc.wantClass == model.ClientDedicatedZTunnel && scope.WorkloadUID != tc.wantKey {
				t.Fatalf("ResolveScope() sandbox UID = %q, want %q", scope.WorkloadUID, tc.wantKey)
			}
		})
	}
}

func TestResolveSharedZTunnelRequiresPodBoundToken(t *testing.T) {
	ctx := t.Context()
	ztunnel := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "ztunnel-abc",
			UID:       "ztunnel-uid",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "ztunnel",
			NodeName:           "node-b",
		},
		Status: corev1.PodStatus{
			PodIP: "10.9.0.1",
		},
	}
	elsewhere := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "ztunnel-xyz",
			UID:       "elsewhere-uid",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "ztunnel",
			NodeName:           "node-c",
		},
		Status: corev1.PodStatus{
			PodIP: "10.9.0.2",
		},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{ztunnel, elsewhere}, nil)
	testutil.Eventually(t, func() bool { return len(r.Pods.List()) == 2 }, "pods loaded")

	principal := model.KubernetesPeer{Namespace: "agentio-system", ServiceAccount: "ztunnel"}
	unbound := model.PeerIdentity{AttestedBy: model.AttestationKubernetes, Kubernetes: principal}
	if scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(unbound, "node-b"); err == nil {
		t.Fatalf("ResolveScope() = %+v, want unbound node token rejection", scope)
	}

	bound := unbound
	bound.Kubernetes = model.KubernetesPeer{
		Namespace:      "agentio-system",
		ServiceAccount: "ztunnel",
		WorkloadName:   ztunnel.Name,
		WorkloadUID:    string(ztunnel.UID),
	}
	scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(bound, "node-b")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if scope.Class != model.ClientSharedZTunnel || scope.NodeName != "node-b" {
		t.Fatalf("scope = %+v", scope)
	}
}

// A token bound to a Pod UID must not grant a same-name replacement Pod.
func TestResolveScopeRejectsReplacedPodUID(t *testing.T) {
	ctx := t.Context()
	live := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "sandbox",
			UID:       "replacement-uid",
		},
		Spec:   corev1.PodSpec{ServiceAccountName: "app", NodeName: "node-a"},
		Status: corev1.PodStatus{PodIP: "10.0.0.10"},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{live}, nil)
	testutil.Eventually(t, func() bool { return len(r.Pods.List()) == 1 }, "replacement pod loaded")

	for _, tc := range []struct {
		name      string
		uid       string
		wantError bool
	}{
		{name: "stale bound UID", uid: "original-uid", wantError: true},
		{name: "matching bound UID", uid: "replacement-uid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peer := model.PeerIdentity{
				AttestedBy: model.AttestationKubernetes,
				Kubernetes: model.KubernetesPeer{
					WorkloadName:   "sandbox",
					WorkloadUID:    tc.uid,
					NodeName:       "node-a",
					Namespace:      "demo",
					ServiceAccount: "app",
				},
			}

			scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, "node-a")
			if tc.wantError {
				if err == nil {
					t.Fatalf("ResolveScope() = %+v, want stale bound UID rejection", scope)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveScope() matching UID: %v", err)
			}
			if scope.Class != model.ClientDedicatedZTunnel || scope.WorkloadUID != "test//Pod/demo/sandbox" {
				t.Fatalf("ResolveScope() = %+v, want live replacement sandbox scope", scope)
			}
		})
	}
}

func TestResolveScopeUsesFinalWorkloadCollection(t *testing.T) {
	ctx := t.Context()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "sandbox",
			UID:       "sandbox-uid",
		},
		Spec:   corev1.PodSpec{ServiceAccountName: "app", NodeName: "node-a"},
		Status: corev1.PodStatus{PodIP: "10.0.0.10"},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{pod}, nil)
	workload := r.Workloads.GetKey("test//Pod/demo/sandbox")
	if workload == nil {
		t.Fatal("default Pod workload was not created")
	}
	finalWorkloads := krt.NewStaticCollection[model.Workload](
		nil,
		[]model.Workload{*workload},
		krt.WithStop(ctx.Done()),
	)

	peer := model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			WorkloadName:   pod.Name,
			WorkloadUID:    string(pod.UID),
			Namespace:      pod.Namespace,
			ServiceAccount: pod.Spec.ServiceAccountName,
		},
	}
	scope, err := r.PodScopeResolver(finalWorkloads).ResolveScope(peer, "")
	if err != nil {
		t.Fatal(err)
	}
	if scope.WorkloadUID != workload.UID {
		t.Fatalf("sandbox scope = %q, want final Workload binding", scope.WorkloadUID)
	}
}

// Missing Kubernetes evidence cannot prove Pod ownership.
func TestResolveScopeRejectsMissingKubernetesEvidence(t *testing.T) {
	ctx := t.Context()
	r := newTestRegistry(t, ctx, nil, nil)

	peer := model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{Namespace: "", ServiceAccount: ""},
	}
	if _, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, ""); err == nil {
		t.Fatal("missing Kubernetes evidence resolved a scope")
	}
}

func TestResolveScopeAuthenticatesEmptyWorker(t *testing.T) {
	ctx := t.Context()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "worker", UID: "worker-pod"},
		Spec:       corev1.PodSpec{ServiceAccountName: "app", NodeName: "node-a"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.10"},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{pod}, nil)
	workload := r.Workloads.GetKey("test//Pod/demo/worker")
	if workload == nil {
		t.Fatal("worker missing")
	}

	workloads := krt.NewStaticCollection[model.Workload](nil, []model.Workload{*workload}, krt.WithStop(ctx.Done()))
	resolver := r.PodScopeResolver(workloads)
	peer := model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			WorkloadName:   pod.Name,
			WorkloadUID:    string(pod.UID),
			Namespace:      pod.Namespace,
			ServiceAccount: pod.Spec.ServiceAccountName,
		},
	}
	scope, err := resolver.ResolveScope(peer, "")
	if err != nil {
		t.Fatal(err)
	}
	if scope.WorkloadUID != workload.UID || scope.Source.Key != string(pod.UID) {
		t.Fatalf("scope %+v", scope)
	}
	if err := scope.Validate(); err != nil {
		t.Fatal(err)
	}
	peer.Kubernetes.WorkloadUID = "spoofed"
	if _, err := resolver.ResolveScope(peer, ""); err == nil {
		t.Fatal("unbound Pod UID gained worker scope")
	}
}

func gatewayTestService(namespace, name string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"member": name}},
	}
}

// Local cache lag may be retried, but stale or invalid ownership must not be.
func TestResolveScopeDistinguishesPendingFromDenied(t *testing.T) {
	peer := model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			Namespace:      "demo",
			ServiceAccount: "worker",
			WorkloadName:   "worker",
			WorkloadUID:    "pod-uid",
		},
	}
	for _, tc := range []struct {
		name    string
		missing bool
		mutate  func(*corev1.Pod)
		pending bool
	}{
		{name: "Pod not observed", missing: true, pending: true},
		{name: "Workload not computed", pending: true},
		{name: "replacement Pod", mutate: func(p *corev1.Pod) { p.UID = "replacement" }},
		{name: "different service account", mutate: func(p *corev1.Pod) { p.Spec.ServiceAccountName = "other" }},
		{
			name: "deleted Pod",
			mutate: func(p *corev1.Pod) {
				now := metav1.Now()
				p.DeletionTimestamp = &now
			},
		},
		{name: "completed Pod", mutate: func(p *corev1.Pod) { p.Status.Phase = corev1.PodSucceeded }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "worker", UID: "pod-uid"},
				Spec:       corev1.PodSpec{ServiceAccountName: "worker"},
			}
			if tc.mutate != nil {
				tc.mutate(pod)
			}
			var pods []*corev1.Pod
			if !tc.missing {
				pods = append(pods, pod)
			}
			resolver := &PodScopeResolver{
				pods:      krt.NewStaticCollection(nil, pods, krt.WithStop(t.Context().Done())),
				workloads: krt.NewStaticCollection[model.Workload](nil, nil, krt.WithStop(t.Context().Done())),
				synced:    func() bool { return true },
			}
			_, err := resolver.ResolveScope(peer, "")
			if err == nil || errors.Is(err, model.ErrScopeNotReady) != tc.pending {
				t.Fatalf("ResolveScope() = %v, want pending=%t", err, tc.pending)
			}
		})
	}
}
