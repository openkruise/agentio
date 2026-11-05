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

// SPDX-License-Identifier: Apache-2.0

package kubernetes

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/attestation"
)

func gatewayTestPeer(pod *corev1.Pod) model.PeerIdentity {
	return model.PeerIdentity{
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			WorkloadName:   pod.Name,
			WorkloadUID:    string(pod.UID),
			Namespace:      pod.Namespace,
			ServiceAccount: pod.Spec.ServiceAccountName,
		},
	}
}

func TestGatewayMembershipIgnoresServiceSelectionAndTracksPodLifecycle(t *testing.T) {
	ctx := t.Context()
	pod := delegationPod("system", "gateway", "egress", "node-a")
	pod.UID = "first-pod"
	pod.Labels = map[string]string{"app": "egress", "gateway.networking.k8s.io/gateway-name": "egress"}
	// The proxy needs a certificate before readiness.
	pod.Status.Phase = corev1.PodPending
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "system", Name: "egress"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "egress"}},
	}
	// Service termination does not affect gateway membership.
	now := metav1.Now()
	service.DeletionTimestamp = &now
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
		Data: map[string]string{
			"config": "egressGateways:\n- namespace: system\n  name: egress\n- namespace: system\n  name: other\n",
		},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{pod, service, config}, nil)
	auth := r.DelegatedIdentityAuthorizer()
	scopeResolver := r.PodScopeResolver(r.Workloads)
	sds := r.GatewayCertificateAuthorizer()
	gid := model.MustServiceAccountPrincipal("system", "egress")
	oldPeer := gatewayTestPeer(pod)
	if err := authorizeCertificate(auth, ctx, oldPeer, attestation.CertificateTarget{Principal: gid}); err != nil {
		t.Fatal(err)
	}
	scope, err := scopeResolver.ResolveScope(oldPeer, "")
	if err != nil || scope.Principal != gid || sds.Authorize(scope) != nil {
		t.Fatalf("scope: %+v %v", scope, err)
	}

	// Replacing a Pod with the same name requires no configuration edits.
	if err := r.client.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	replacement := pod.DeepCopy()
	replacement.UID = "replacement-pod"
	replacement.Status.Phase = corev1.PodRunning
	replacement.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if _, err := r.client.CoreV1().Pods(pod.Namespace).Create(ctx, replacement, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	peer := gatewayTestPeer(replacement)
	testutil.Eventually(t, func() bool {
		current, err := scopeResolver.ResolveScope(peer, "")
		return authorizeCertificate(auth, ctx, peer, attestation.CertificateTarget{Principal: gid}) == nil &&
			authorizeCertificate(auth, ctx, oldPeer, attestation.CertificateTarget{Principal: gid}) != nil &&
			err == nil && current.GatewayKey == "system/egress"
	}, "replacement joins automatically and old token loses authorization")
	if err := sds.Authorize(scope); err != nil {
		t.Fatalf("existing scope unexpectedly rechecked Pod membership: %v", err)
	}

	// Service selectors control routing independently of gateway membership.
	for _, selector := range []map[string]string{nil, {"app": "other"}, {"app": "egress"}} {
		changed := service.DeepCopy()
		changed.Spec.Selector = selector
		if _, err := r.client.CoreV1().
			Services(service.Namespace).
			Update(ctx, changed, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		testutil.Eventually(t, func() bool {
			scope, err := scopeResolver.ResolveScope(peer, "")
			return authorizeCertificate(auth, ctx, peer, attestation.CertificateTarget{Principal: gid}) == nil &&
				err == nil &&
				scope.Class == model.ClientEgressGateway
		}, "selector changes do not affect gateway membership")
	}
	established, err := scopeResolver.ResolveScope(peer, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "unknown", "other", "egress"} {
		replacement.Labels["gateway.networking.k8s.io/gateway-name"] = name
		if _, err := r.client.CoreV1().
			Pods(replacement.Namespace).
			Update(ctx, replacement, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		testutil.Eventually(t, func() bool {
			current, err := scopeResolver.ResolveScope(peer, "")
			return err == nil && current.Class == model.ClientEgressGateway &&
				current.GatewayKey == "system/egress" &&
				sds.Authorize(established) == nil
		}, "label updates cannot change the gateway selected by the ServiceAccount")
	}
	replacement.DeletionTimestamp = &now
	if _, err := r.client.CoreV1().
		Pods(replacement.Namespace).
		Update(ctx, replacement, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, func() bool {
		w := r.Workloads.GetKey("test//Pod/system/gateway")
		return w != nil && w.Principal == gid && w.GatewayKey == "system/egress" && !w.Ready &&
			authorizeCertificate(auth, ctx, peer, attestation.CertificateTarget{Principal: gid}) != nil
	}, "terminating gateway retains its discovery identity without new issuance")
	if err := r.client.CoreV1().
		Services(service.Namespace).
		Delete(ctx, service.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(
		t,
		func() bool {
			w := r.Workloads.GetKey("test//Pod/system/gateway")
			return w != nil && w.GatewayKey == "system/egress"
		},
		"Service deletion does not withdraw membership",
	)
}

func TestGatewayMembershipRejectsAmbiguousAndUnregisteredPods(t *testing.T) {
	cases := []struct {
		name                     string
		configure                func(*corev1.Pod, *corev1.Service, *corev1.ConfigMap) []runtime.Object
		allowWorkloadCertificate bool
		allowGatewayScope        bool
	}{
		{
			name:                     "same SA without gateway label",
			allowWorkloadCertificate: true,
			allowGatewayScope:        true,
			configure: func(p *corev1.Pod, _ *corev1.Service, _ *corev1.ConfigMap) []runtime.Object {
				p.Labels = nil
				return nil
			}},
		{
			name:                     "gateway label without service selection",
			allowWorkloadCertificate: true,
			allowGatewayScope:        true,
			configure: func(p *corev1.Pod, s *corev1.Service, _ *corev1.ConfigMap) []runtime.Object {
				s.Spec.Selector = nil
				p.Labels = map[string]string{"gateway.networking.k8s.io/gateway-name": "egress"}
				return nil
			}},
		{
			name:                     "cross namespace",
			allowWorkloadCertificate: true,
			configure: func(p *corev1.Pod, _ *corev1.Service, _ *corev1.ConfigMap) []runtime.Object {
				p.Namespace = "tenant"
				return nil
			}},
		{
			name:                     "ExternalName Service does not determine membership",
			allowWorkloadCertificate: true,
			allowGatewayScope:        true,
			configure: func(_ *corev1.Pod, s *corev1.Service, _ *corev1.ConfigMap) []runtime.Object {
				s.Spec.Type = corev1.ServiceTypeExternalName
				s.Spec.ExternalName = "external.example"
				return nil
			}},
		{
			name:                     "unregistered Service",
			allowWorkloadCertificate: true,
			configure: func(_ *corev1.Pod, _ *corev1.Service, c *corev1.ConfigMap) []runtime.Object {
				c.Data["config"] = "{}"
				return nil
			}},
		{
			name:                     "label references unregistered gateway",
			allowWorkloadCertificate: true,
			allowGatewayScope:        true,
			configure: func(p *corev1.Pod, _ *corev1.Service, _ *corev1.ConfigMap) []runtime.Object {
				p.Labels["gateway.networking.k8s.io/gateway-name"] = "other"
				return nil
			}},
		{
			name:                     "overlapping Services do not grant multiple memberships",
			allowWorkloadCertificate: true,
			allowGatewayScope:        true,
			configure: func(_ *corev1.Pod, s *corev1.Service, c *corev1.ConfigMap) []runtime.Object {
				other := s.DeepCopy()
				other.Name = "other"
				c.Data["config"] += "- namespace: system\n  name: other\n"
				return []runtime.Object{other}
			}},
		{
			name:                     "gateway label with unrelated SA",
			allowWorkloadCertificate: true,
			configure: func(p *corev1.Pod, _ *corev1.Service, _ *corev1.ConfigMap) []runtime.Object {
				p.Spec.ServiceAccountName = "unrelated"
				return nil
			}},
		{
			name: "terminating Pod",
			configure: func(p *corev1.Pod, _ *corev1.Service, _ *corev1.ConfigMap) []runtime.Object {
				now := metav1.Now()
				p.DeletionTimestamp = &now
				return nil
			}},
		{
			name: "completed Pod",
			configure: func(p *corev1.Pod, _ *corev1.Service, _ *corev1.ConfigMap) []runtime.Object {
				p.Status.Phase = corev1.PodSucceeded
				return nil
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := delegationPod("system", "candidate", "egress", "node-a")
			p.UID = "candidate-pod"
			p.Labels = map[string]string{"app": "egress", "gateway.networking.k8s.io/gateway-name": "egress"}
			s := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Namespace: "system", Name: "egress"},
				Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "egress"}},
			}
			c := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
				Data:       map[string]string{"config": "egressGateways:\n- namespace: system\n  name: egress\n"},
			}
			extra := tc.configure(p, s, c)
			r := newTestRegistry(t, t.Context(), append([]runtime.Object{p, s, c}, extra...), nil)
			err := authorizeCertificate(
				r.DelegatedIdentityAuthorizer(),
				t.Context(),
				gatewayTestPeer(p),
				attestation.CertificateTarget{
					Principal: model.MustServiceAccountPrincipal(p.Namespace, p.Spec.ServiceAccountName),
					Workload:  &attestation.WorkloadReference{Namespace: p.Namespace, Name: p.Name},
				},
			)
			if (err == nil) != tc.allowWorkloadCertificate {
				t.Fatalf("workload certificate: %v, want allow=%v", err, tc.allowWorkloadCertificate)
			}
			scope, scopeErr := r.PodScopeResolver(r.Workloads).ResolveScope(gatewayTestPeer(p), "")
			gotGateway := scopeErr == nil && scope.Class == model.ClientEgressGateway
			if gotGateway != tc.allowGatewayScope {
				t.Fatalf("gateway scope: %+v %v, want allow=%v", scope, scopeErr, tc.allowGatewayScope)
			}
			if scopeErr == nil && (r.GatewayCertificateAuthorizer().Authorize(scope) == nil) != tc.allowGatewayScope {
				t.Fatalf("gateway certificate authorization does not match membership: %+v", scope)
			}
			if p.Status.Phase != corev1.PodSucceeded {
				w := r.Workloads.GetKey("test//Pod/" + p.Namespace + "/" + p.Name)
				if w == nil {
					t.Fatal("identity rejection removed the network discovery record")
				}

			}
		})
	}
}

func TestGatewayAPIMembershipTracksGatewayAndClass(t *testing.T) {
	ctx := t.Context()
	gateway := ownedGateway()
	gateway.UID = "gateway-resource"
	gateway.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{
		ParametersRef: &gatewayv1.LocalParametersReference{Kind: "ConfigMap", Name: "params"},
	}
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "params"},
		Data:       map[string]string{"config": "{}"},
	}
	pod := delegationPod("demo", "gateway", "egress", "node-a")
	pod.UID = "gateway-pod"
	pod.Labels = map[string]string{"gateway.networking.k8s.io/gateway-name": "egress"}
	class := ownedGatewayClass()
	// Pending finalization must not withdraw configuration or membership.
	now := metav1.Now()
	gateway.DeletionTimestamp, class.DeletionTimestamp = &now, &now
	client := &fakeKubeClient{
		Client:  kube.NewFakeClient(gateway, class, pod, config),
		watcher: newFakeGatewayCRDWatcher(gatewayResource, gatewayClassResource),
	}
	r, err := New(
		client,
		Options{ClusterID: "test", TrustDomain: "cluster.local", RootNamespace: "agentio-system"},
		ctx.Done(),
	)
	if err != nil {
		t.Fatal(err)
	}
	client.Run(ctx.Done())
	testutil.Eventually(t, r.HasSynced, "registry sync")
	gid := model.MustServiceAccountPrincipal("demo", "egress")
	auth := r.DelegatedIdentityAuthorizer()
	peer := gatewayTestPeer(pod)
	testutil.Eventually(
		t,
		func() bool {
			return authorizeCertificate(auth, ctx, peer, attestation.CertificateTarget{Principal: gid}) == nil
		},
		"Gateway without status addresses authorizes its member",
	)
	for _, controller := range []gatewayv1.GatewayController{"example.org/foreign", agentioGatewayController} {
		changed := class.DeepCopy()
		changed.Spec.ControllerName = controller
		if _, err := client.GatewayAPI().
			GatewayV1().
			GatewayClasses().
			Update(ctx, changed, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		want := controller == agentioGatewayController
		testutil.Eventually(t, func() bool {
			scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, "")
			return err == nil && (scope.Class == model.ClientEgressGateway) == want &&
				authorizeCertificate(auth, ctx, peer, attestation.CertificateTarget{Principal: gid}) == nil
		}, "GatewayClass ownership changes membership")
	}
	// Conflicting declarations remove gateway scope but preserve the principal.
	collision := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
		Data:       map[string]string{"config": "egressGateways:\n- namespace: demo\n  name: egress\n"},
	}
	if _, err := client.Kube().
		CoreV1().
		ConfigMaps(collision.Namespace).
		Create(ctx, collision, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, func() bool {
		w := r.Workloads.GetKey("test//Pod/demo/gateway")
		return w != nil && w.Principal == gid && w.GatewayKey == "" &&
			authorizeCertificate(auth, ctx, peer, attestation.CertificateTarget{Principal: gid}) == nil
	}, "conflicting declarations withdraw gateway scope without changing logical identity")
	if err := client.Kube().
		CoreV1().
		ConfigMaps(collision.Namespace).
		Delete(ctx, collision.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(
		t,
		func() bool {
			return authorizeCertificate(auth, ctx, peer, attestation.CertificateTarget{Principal: gid}) == nil
		},
		"conflict removal restores membership",
	)
	if err := client.GatewayAPI().
		GatewayV1().
		Gateways(gateway.Namespace).
		Delete(ctx, gateway.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(
		t,
		func() bool {
			w := r.Workloads.GetKey("test//Pod/demo/gateway")
			return w != nil && w.GatewayKey == ""
		},
		"deleted Gateway leaves no membership",
	)
}
