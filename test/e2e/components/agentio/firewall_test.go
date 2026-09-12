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

package agentio

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func TestVerifyFirewallBackendFindsSidecarInEnrolledNamespace(t *testing.T) {
	client := fake.NewClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name:   "sandbox",
			Labels: map[string]string{DataplaneModeLabel: ProfileSidecar},
		}},
		firewallPod("sandbox", "client", "agentio-proxy", "iptables"),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "uninjected", Namespace: "sandbox"}},
	)
	if err := verifyFirewallBackend(context.Background(), client, Config{
		Profile:         ProfileSidecar,
		FirewallBackend: "iptables",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFirewallBackendFindsNativeSidecar(t *testing.T) {
	pod := firewallPod("sandbox", "native", "agentio-proxy", "iptables")
	pod.Spec.InitContainers = pod.Spec.Containers
	pod.Spec.Containers = []corev1.Container{{Name: "application"}}
	client := fake.NewClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sandbox", Labels: map[string]string{DataplaneModeLabel: ProfileSidecar}}}, pod,
	)
	if err := verifyFirewallBackend(context.Background(), client, Config{Profile: ProfileSidecar, FirewallBackend: "iptables"}); err != nil {
		t.Fatal(err)
	}
	if err := verifyFirewallBackend(context.Background(), client, Config{Profile: ProfileSidecar, FirewallBackend: "auto"}); err == nil {
		t.Fatal("accepted native sidecar with the wrong backend")
	}
}

func TestVerifyFirewallBackendFindsAmbientZtunnel(t *testing.T) {
	pod := firewallPod("agentio-system", "ztunnel-worker", "ztunnel", "auto")
	pod.Labels = map[string]string{"app.kubernetes.io/name": "ztunnel"}
	client := fake.NewClientset(pod)
	if err := verifyFirewallBackend(context.Background(), client, Config{
		Profile:         ProfileAmbient,
		Namespace:       "agentio-system",
		FirewallBackend: "auto",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFirewallBackendRejectsMismatchAndMissingInjection(t *testing.T) {
	tests := []struct {
		name    string
		objects []runtime.Object
		config  Config
		want    string
	}{
		{
			name: "mismatch",
			objects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sandbox", Labels: map[string]string{DataplaneModeLabel: ProfileSidecar}}},
				firewallPod("sandbox", "client", "agentio-proxy", "auto"),
			},
			config: Config{Profile: ProfileSidecar, FirewallBackend: "iptables"},
			want:   `FIREWALL_BACKEND="auto", want "iptables"`,
		},
		{
			name: "missing injection",
			objects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sandbox", Labels: map[string]string{DataplaneModeLabel: ProfileSidecar}}},
				&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "sandbox"}},
			},
			config: Config{Profile: ProfileSidecar, FirewallBackend: "auto"},
			want:   "no agentio-proxy container",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewClientset(test.objects...)
			err := verifyFirewallBackend(context.Background(), client, test.config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verifyFirewallBackend() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func firewallPod(namespace, name, container, backend string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: container,
			Env:  []corev1.EnvVar{{Name: "FIREWALL_BACKEND", Value: backend}},
		}}},
	}
}
