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
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apitypes "k8s.io/apimachinery/pkg/types"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/attestation"
)

func delegationPod(namespace, name, serviceAccount, node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: apitypes.UID(namespace + "-" + name)},
		Spec:       corev1.PodSpec{ServiceAccountName: serviceAccount, NodeName: node},
		Status:     corev1.PodStatus{PodIP: "10.0.0.1"},
	}
}

func TestCertificateSourceDistinguishesPodsSharingPrincipal(t *testing.T) {
	a := delegationPod("demo", "a", "shared", "node-a")
	a.Status.PodIP = "" // CA authorization must not depend on network discovery.
	b := delegationPod("demo", "b", "shared", "node-a")
	remote := delegationPod("demo", "remote", "shared", "node-b")
	node := delegationPod("agentio-system", "ztunnel", "ztunnel", "node-a")
	for _, p := range []*corev1.Pod{a, b, remote} {
		p.Annotations = map[string]string{"ambient.istio.io/redirection": "enabled"}
	}
	r := newTestRegistry(t, t.Context(), []runtime.Object{a, b, remote, node}, nil)
	authorizer := r.DelegatedIdentityAuthorizer()
	principal := mustTestPrincipal("cluster.local", "ns/demo/sa/shared")
	for _, tc := range []struct {
		name   string
		caller *corev1.Pod
		target *corev1.Pod
		allow  bool
	}{
		{"self", a, a, true},
		{"other Pod with same SA", a, b, false},
		{"other Pod self", b, b, true},
		{"local delegation a", node, a, true},
		{"local delegation b", node, b, true},
		{"remote delegation", node, remote, false},
		{"unknown instance", node, delegationPod("demo", "unknown", "shared", "node-a"), false},
		{"different principal", node, node, false},
		{"principal-only self", a, nil, true},
		{"principal-only delegation", node, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := attestation.CertificateTarget{Principal: principal}
			if tc.target != nil {
				target.Workload = &attestation.WorkloadReference{Namespace: tc.target.Namespace, Name: tc.target.Name}
			}
			source, err := authorizer.Authorize(t.Context(), gatewayTestPeer(tc.caller), target)
			if (err == nil) != tc.allow {
				t.Fatalf("Authorize() = %v, want allow=%v", err, tc.allow)
			}
			if err == nil && tc.target != nil &&
				source != (attestation.WorkloadIdentity{Registry: "kubernetes/test", UID: string(tc.target.UID)}) {
				t.Fatalf("source = %+v, want Pod UID %s", source, tc.target.UID)
			}
			if err == nil && tc.target == nil && source != (attestation.WorkloadIdentity{}) {
				t.Fatalf("principal-only source = %+v", source)
			}
		})
	}
}

func authorizeCertificate(
	a *DelegatedIdentityAuthorizer,
	ctx context.Context,
	caller model.PeerIdentity,
	target attestation.CertificateTarget,
) error {
	_, err := a.Authorize(ctx, caller, target)
	return err
}

func TestDelegatedAuthorizationPreservesIdentityRules(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.PeerIdentity, *model.Principal, *corev1.Pod, *corev1.Pod)
		allow  bool
	}{
		{name: "node-local ambient workload", allow: true},
		{
			name: "untrusted caller service account",
			mutate: func(caller *model.PeerIdentity, _ *model.Principal, _, _ *corev1.Pod) {
				caller.Kubernetes.ServiceAccount = "attacker"
			},
		},
		{
			name: "unbound caller token",
			mutate: func(caller *model.PeerIdentity, _ *model.Principal, _, _ *corev1.Pod) {
				caller.Kubernetes.WorkloadUID = ""
			},
		},
		{
			name: "stale caller UID",
			mutate: func(_ *model.PeerIdentity, _ *model.Principal, ztunnel, _ *corev1.Pod) {
				ztunnel.UID = "replacement-uid"
			},
		},
		{
			name: "caller pod service account mismatch",
			mutate: func(_ *model.PeerIdentity, _ *model.Principal, ztunnel, _ *corev1.Pod) {
				ztunnel.Spec.ServiceAccountName = "other"
			},
		},
		{
			name: "target on another node",
			mutate: func(_ *model.PeerIdentity, _ *model.Principal, _, target *corev1.Pod) {
				target.Spec.NodeName = "node-b"
			},
		},
		{
			name: "target namespace mismatch",
			mutate: func(_ *model.PeerIdentity, requested *model.Principal, _, _ *corev1.Pod) {
				*requested = mustTestPrincipal("cluster.local", "ns/other/sa/app")
			},
		},
		{
			name: "target service account mismatch",
			mutate: func(_ *model.PeerIdentity, requested *model.Principal, _, _ *corev1.Pod) {
				*requested = mustTestPrincipal("cluster.local", "ns/demo/sa/other")
			},
		},
		{
			name: "unsupported requested identity kind",
			mutate: func(_ *model.PeerIdentity, requested *model.Principal, _, _ *corev1.Pod) {
				*requested = model.Principal{}
			},
		},
		{
			name: "unsupported caller identity kind",
			mutate: func(caller *model.PeerIdentity, _ *model.Principal, _, _ *corev1.Pod) {
				caller.Kubernetes = model.KubernetesPeer{}
			},
		},
		{
			name: "target outside ambient",
			mutate: func(_ *model.PeerIdentity, _ *model.Principal, _, target *corev1.Pod) {
				delete(target.Annotations, "ambient.istio.io/redirection")
			},
		},
		{
			name: "terminating target",
			mutate: func(_ *model.PeerIdentity, _ *model.Principal, _, target *corev1.Pod) {
				now := metav1.Now()
				target.DeletionTimestamp = &now
			},
		},
		{
			name: "completed target",
			mutate: func(_ *model.PeerIdentity, _ *model.Principal, _, target *corev1.Pod) {
				target.Status.Phase = corev1.PodSucceeded
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			ztunnel := delegationPod("agentio-system", "ztunnel-abc", "ztunnel", "node-a")
			target := delegationPod("demo", "workload", "app", "node-a")
			target.Annotations = map[string]string{"ambient.istio.io/redirection": "enabled"}
			caller := model.PeerIdentity{
				AttestedBy: model.AttestationKubernetes,
				Kubernetes: model.KubernetesPeer{
					WorkloadName:   ztunnel.Name,
					WorkloadUID:    string(ztunnel.UID),
					Namespace:      "agentio-system",
					ServiceAccount: "ztunnel",
				},
			}
			requested := mustTestPrincipal("cluster.local", "ns/demo/sa/app")
			if test.mutate != nil {
				test.mutate(&caller, &requested, ztunnel, target)
			}
			r := newTestRegistry(t, ctx, []runtime.Object{ztunnel, target}, nil)

			err := authorizeCertificate(
				r.DelegatedIdentityAuthorizer(),
				ctx,
				caller,
				attestation.CertificateTarget{Principal: requested},
			)
			if test.allow && err != nil {
				t.Fatalf("Authorize denied valid delegation: %v", err)
			}
			if !test.allow && err == nil {
				t.Fatal("Authorize allowed invalid delegation")
			}
		})
	}
}

func TestGatewayCertificateAuthorizationUsesEffectiveConfiguration(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
		Data: map[string]string{
			"config": "egressGateways:\n- name: egress\n  namespace: agentio-system\n",
		},
	}
	member := delegationPod("agentio-system", "gateway", "egress", "node-a")
	member.Labels = map[string]string{"gateway.networking.k8s.io/gateway-name": "egress"}
	r := newTestRegistry(t, ctx, []runtime.Object{config, member, gatewayTestService("agentio-system", "egress")}, nil)
	authorizer := r.GatewayCertificateAuthorizer()
	scope := model.ClientScope{
		Class:       model.ClientEgressGateway,
		GatewayKey:  "agentio-system/egress",
		WorkloadUID: "test//Pod/agentio-system/gateway",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: string(member.UID)},
		Principal:   mustTestPrincipal("cluster.local", "ns/agentio-system/sa/egress"),
	}

	if err := authorizer.Authorize(scope); err != nil {
		t.Fatalf("Authorize denied configured gateway: %v", err)
	}
	consumer := scope
	consumer.Class = model.ClientResourceConsumer
	consumer.Access = &configv1.XDSClient{Principal: scope.Principal.String(), Resources: []string{"*"}}
	if err := authorizer.Authorize(consumer); err == nil {
		t.Fatal("wildcard type grant bypassed gateway certificate authorization")
	}

	scope.GatewayKey = "agentio-system/other"
	if err := authorizer.Authorize(scope); err == nil {
		t.Fatal("Authorize allowed an unregistered gateway")
	}
	scope.GatewayKey = "agentio-system/egress"
	scope.Principal = model.Principal{}
	if err := authorizer.Authorize(scope); err == nil {
		t.Fatal("Authorize allowed an empty principal")
	}
}

func TestGatewayCertificateAuthorizationUsesProvidedConfigurationSource(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	gateways := krt.NewMutableCollection[model.Gateway](nil, []model.Gateway{{
		Namespace: "agentio-system",
		Name:      "external-egress",
		Config:    &configv1.EgressGateway{},
		Source:    model.GatewaySourceGatewayAPI,
	}}, krt.WithStop(stop))
	member := delegationPod("agentio-system", "gateway", "external-egress", "node-a")
	member.Labels = map[string]string{"gateway.networking.k8s.io/gateway-name": "external-egress"}
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
		Data: map[string]string{
			"config": "egressGateways:\n- name: external-egress\n  namespace: agentio-system\n",
		},
	}
	_ = newTestRegistry(t, t.Context(), []runtime.Object{config, member}, nil)
	authorizer := NewGatewayCertificateAuthorizer(gateways.AsCollection())
	scope := model.ClientScope{
		Class:       model.ClientEgressGateway,
		GatewayKey:  "agentio-system/external-egress",
		WorkloadUID: "test//Pod/agentio-system/gateway",
		Source:      model.SourceRef{Registry: "kubernetes/test", Key: string(member.UID)},
		Principal:   mustTestPrincipal("cluster.local", "ns/"+("agentio-system")+"/sa/"+("external-egress")),
	}

	if err := authorizer.Authorize(scope); err != nil {
		t.Fatalf("Authorize denied gateway from provided configuration source: %v", err)
	}
	conflict := *gateways.GetKey(scope.GatewayKey)
	conflict.Config = nil
	conflict.Source = model.GatewaySourceConflict
	gateways.ConditionalUpdateObject(conflict)
	if err := authorizer.Authorize(scope); err == nil {
		t.Fatal("Authorize allowed a conflicting gateway declaration")
	}
}

func TestGatewayCertificateAuthorizationRequiresMatchingServiceAccount(t *testing.T) {
	gateways := krt.NewStaticCollection[model.Gateway](nil, []model.Gateway{{
		Namespace: "system",
		Name:      "egress",
		Config:    &configv1.EgressGateway{},
		Source:    model.GatewaySourceGatewayAPI,
	}}, krt.WithStop(t.Context().Done()))
	authorizer := NewGatewayCertificateAuthorizer(gateways)
	for _, tc := range []struct {
		name      string
		principal string
		allow     bool
	}{
		{"matching ServiceAccount", "ns/system/sa/egress", true},
		{"unrelated ServiceAccount", "ns/system/sa/attacker", false},
		{"same ServiceAccount in another namespace", "ns/tenant/sa/egress", false},
		{"non-ServiceAccount principal", "workloads/egress", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scope := model.ClientScope{
				Class:       model.ClientEgressGateway,
				GatewayKey:  "system/egress",
				WorkloadUID: "test//Pod/system/gateway",
				Source:      model.SourceRef{Registry: "kubernetes/test", Key: "gateway-pod"},
				Principal:   mustTestPrincipal("cluster.local", tc.principal),
			}
			if err := authorizer.Authorize(scope); (err == nil) != tc.allow {
				t.Fatalf("Authorize() = %v, want allow=%v", err, tc.allow)
			}
		})
	}
}

func TestCertificateRolesUseRegistryMembership(t *testing.T) {
	app := delegationPod("demo", "app", "shared", "node-a")
	gateway := delegationPod("agentio-system", "gateway", "egress", "node-a")
	gateway.Labels = map[string]string{"gateway.networking.k8s.io/gateway-name": "egress"}
	lookalike := delegationPod("demo", "lookalike", "shared", "node-a")
	lookalike.Labels = map[string]string{
		"role":                                   "sandbox-attester",
		"app.kubernetes.io/name":                 "agentio-epe",
		"gateway.networking.k8s.io/gateway-name": "missing",
	}
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
		Data:       map[string]string{"config": "egressGateways:\n- name: egress\n  namespace: agentio-system\n"},
	}
	r := newTestRegistryWithOptions(
		t,
		t.Context(),
		[]runtime.Object{app, gateway, lookalike, config},
		nil,
		Options{EnableKruise: true},
	)
	r.Sandboxes = krt.NewStaticCollection[model.Sandbox](nil, []model.Sandbox{
		{UID: "kruise:sandbox", Namespace: app.Namespace, Attester: &model.Attester{WorkloadUID: "test//Pod/demo/app"}},
	})
	auth := r.DelegatedIdentityAuthorizer()
	resolve := func(p *corev1.Pod) attestation.WorkloadIdentity {
		t.Helper()
		result, err := auth.Authorize(t.Context(), gatewayTestPeer(p), attestation.CertificateTarget{
			Principal: mustTestPrincipal("cluster.local", "ns/"+p.Namespace+"/sa/"+p.Spec.ServiceAccountName),
			Workload:  &attestation.WorkloadReference{Namespace: p.Namespace, Name: p.Name},
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if role := resolve(app).Role; role != "" {
		t.Fatalf("Sandbox binding granted role = %q", role)
	}
	if role := resolve(lookalike).Role; role != "" {
		t.Fatalf("labels granted role = %q", role)
	}
	eventually(
		t,
		func() bool { return resolve(gateway).Role == attestation.RoleEgressGateway },
		"registered gateway role",
	)
}

func TestKruiseAttesterRoleWithoutSandboxBinding(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		podIP   string
		want    string
	}{
		{"host without Sandbox", true, "10.0.0.1", attestation.RoleSandboxAttester},
		{"host before network discovery", true, "", attestation.RoleSandboxAttester},
		{"runtime disabled", false, "10.0.0.1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := delegationPod("demo", "host", "shared", "node-a")
			pod.Status.PodIP = tc.podIP
			pod.Labels = map[string]string{agentsv1alpha1.LabelSandboxIsClaimed: agentsv1alpha1.False}
			controller := true
			pod.OwnerReferences = []metav1.OwnerReference{{
				APIVersion: agentsv1alpha1.GroupVersion.String(),
				Kind:       "Sandbox",
				Name:       "not-yet-discovered",
				UID:        "sandbox-uid",
				Controller: &controller,
			}}
			r := newTestRegistryWithOptions(
				t,
				t.Context(),
				[]runtime.Object{pod},
				nil,
				Options{EnableKruise: tc.enabled},
			)
			identity, err := r.DelegatedIdentityAuthorizer().
				Authorize(t.Context(), gatewayTestPeer(pod), attestation.CertificateTarget{
					Principal: mustTestPrincipal("cluster.local", "ns/demo/sa/shared"),
					Workload:  &attestation.WorkloadReference{Namespace: pod.Namespace, Name: pod.Name},
				})
			if err != nil || identity.Role != tc.want {
				t.Fatalf("identity=%+v err=%v, want role %q", identity, err, tc.want)
			}
		})
	}
}
