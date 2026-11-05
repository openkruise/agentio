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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/attestation"
)

func TestCertificateAttestationBindsSourceAndGatewayMembership(t *testing.T) {
	a := delegationPod("demo", "a", "shared", "node-a")
	b := delegationPod("demo", "b", "shared", "node-a")
	node := delegationPod("agentio-system", "ztunnel", "ztunnel", "node-a")
	gateway := delegationPod("agentio-system", "gateway", "egress", "node-a")
	lookalike := delegationPod("agentio-system", "lookalike", "unrelated-bootstrap-sa", "node-a")
	lookalike.Labels = map[string]string{"gateway.networking.k8s.io/gateway-name": "different-gateway"}
	a.UID, b.UID, node.UID, gateway.UID, lookalike.UID = "pod-a", "pod-b", "node-pod", "gateway-pod", "lookalike-pod"
	for _, p := range []*corev1.Pod{a, b, node, gateway, lookalike} {
		p.Status.PodIP = "10.0.0.1"
		p.Status.Phase = corev1.PodRunning
		p.Annotations = map[string]string{"ambient.istio.io/redirection": "enabled"}
	}
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
		Data: map[string]string{"config": `egressGateways:
- name: egress
  namespace: agentio-system
`},
	}
	gateway.Labels = map[string]string{"gateway-member": "egress", "gateway.networking.k8s.io/gateway-name": "egress"}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "egress"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"gateway-member": "egress"}},
	}
	r := newTestRegistry(t, t.Context(), []runtime.Object{a, b, node, gateway, lookalike, config, service}, nil)
	caller := func(p *corev1.Pod) model.PeerIdentity {
		return model.PeerIdentity{
			AttestedBy: model.AttestationKubernetes,
			Kubernetes: model.KubernetesPeer{
				WorkloadName:   p.Name,
				WorkloadUID:    string(p.UID),
				Namespace:      p.Namespace,
				ServiceAccount: p.Spec.ServiceAccountName,
			},
		}
	}
	auth := r.DelegatedIdentityAuthorizer()
	target := func(p *corev1.Pod) attestation.CertificateTarget {
		return attestation.CertificateTarget{
			Principal: model.MustServiceAccountPrincipal(p.Namespace, p.Spec.ServiceAccountName),
			Workload:  &attestation.WorkloadReference{Namespace: p.Namespace, Name: p.Name},
		}
	}
	aid, bid, gid := target(a), target(b), target(gateway)
	for _, tc := range []struct {
		name  string
		peer  model.PeerIdentity
		id    attestation.CertificateTarget
		allow bool
	}{
		{"own pod", caller(a), aid, true},
		{"unregistered principal", caller(a), attestation.CertificateTarget{Principal: model.MustServiceAccountPrincipal("demo", "app"), Workload: aid.Workload}, false},
		{"same SA different pod", caller(a), bid, false},
		{"gateway role forgery", caller(a), gid, false},
		{"bound gateway with matching SA", caller(gateway), gid, true},
		{"non-member cannot claim gateway instance", caller(lookalike), gid, false},
		{"non-member retains own workload identity", caller(lookalike), target(lookalike), true},
		{"node-local delegation", caller(node), bid, true},
		{"node-local eligible gateway delegation", caller(node), gid, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := authorizeCertificate(auth, t.Context(), tc.peer, tc.id)
			if (err == nil) != tc.allow {
				t.Fatalf("allow=%v, error=%v", tc.allow, err)
			}
		})
	}
	unbound := caller(a)
	unbound.Kubernetes.WorkloadUID = ""
	if err := authorizeCertificate(auth, t.Context(), unbound, aid); err == nil {
		t.Fatal("accepted unbound token")
	}
	stale := caller(a)
	stale.Kubernetes.WorkloadUID = "replaced"
	if err := authorizeCertificate(auth, t.Context(), stale, aid); err == nil {
		t.Fatal("accepted stale token")
	}
	scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(caller(gateway), "")
	if err != nil || scope.Principal != gid.Principal || scope.Source.Key != string(gateway.UID) {
		t.Fatalf("gateway scope: %v %v", scope, err)
	}
	if err := r.GatewayCertificateAuthorizer().Authorize(scope); err != nil {
		t.Fatal(err)
	}
	if scope, err := r.PodScopeResolver(r.Workloads).
		ResolveScope(caller(lookalike), ""); err != nil ||
		scope.Class == model.ClientEgressGateway {
		t.Fatal("non-member acquired gateway scope")
	}
	unboundGateway := model.ClientScope{
		Class:      model.ClientEgressGateway,
		Principal:  gid.Principal,
		GatewayKey: "agentio-system/egress",
	}
	if err := r.GatewayCertificateAuthorizer().Authorize(unboundGateway); err == nil {
		t.Fatal("gateway scope without source binding acquired MITM authority")
	}
	b.Spec.NodeName = "node-b"
	if _, err := r.client.CoreV1().Pods(b.Namespace).Update(t.Context(), b, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, func() bool {
		return authorizeCertificate(auth, t.Context(), caller(node), bid) != nil
	}, "cross-node delegation denied")
}
