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

package pod

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPodWorkloadEligibility(t *testing.T) {
	deleting := metav1.NewTime(time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC))
	for _, tc := range []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{
			name: "succeeded",
			pod:  workloadTestPod(corev1.PodSucceeded, "10.0.0.1"),
		},
		{
			name: "failed",
			pod:  workloadTestPod(corev1.PodFailed, "10.0.0.1"),
		},
		{
			name: "addressless",
			pod:  workloadTestPod(corev1.PodRunning, ""),
		},
		{
			name: "malformed primary",
			pod:  workloadTestPod(corev1.PodRunning, "not-an-ip"),
		},
		{
			name: "malformed secondary",
			pod: &corev1.Pod{Status: corev1.PodStatus{PodIPs: []corev1.PodIP{
				{IP: "10.0.0.1"},
				{IP: "not-an-ip"},
			}}},
		},
		{
			name: "valid IPv4",
			pod:  workloadTestPod(corev1.PodRunning, "10.0.0.1"),
			want: true,
		},
		{
			name: "valid IPv6",
			pod:  workloadTestPod(corev1.PodRunning, "2001:db8::1"),
			want: true,
		},
		{
			name: "deleting",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					DeletionTimestamp: &deleting,
				},
				Status: corev1.PodStatus{
					PodIP: "10.0.0.1",
				},
			},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsEligible(tc.pod); got != tc.want {
				t.Fatalf("IsEligible() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPodWorkloadDoesNotInferGatewayRoleFromLabels(t *testing.T) {
	pod := egressPod("agentio-system", "egress-a-abc", "egress-a", "10.0.0.1")
	pod.Labels["networking.agents.kruise.io/sandbox-egress"] = "true"

	got := BaseWorkloadFromPod("cluster", pod)
	if got.GatewayKey != "" {
		t.Fatalf("GatewayKey = %q, want labels to carry no gateway authority", got.GatewayKey)
	}
}

func TestPodProducesWorkloadWithoutSandbox(t *testing.T) {
	pod := workloadTestPod(corev1.PodRunning, "10.0.0.1")
	pod.Namespace, pod.Name, pod.UID = "demo", "client", "pod-uid"
	pod.Spec.ServiceAccountName = "client"
	pod.Labels = map[string]string{"app": "client"}
	pod.Spec.Containers = []corev1.Container{dedicatedZTunnelContainer()}

	workload := BaseWorkloadFromPod("cluster", pod)
	if workload.UID != "cluster//Pod/demo/client" {
		t.Fatalf("ordinary Pod workload identity = %q", workload.UID)
	}
	if workload.Source.Key != "pod-uid" || workload.TunnelProtocol != "HBONE" || !workload.NativeTunnel {
		t.Fatalf("workload = %+v", workload)
	}
}

func TestPodWorkloadCanonicalIdentity(t *testing.T) {
	for _, tc := range []struct {
		name         string
		labels       map[string]string
		wantName     string
		wantRevision string
	}{
		{
			name: "recommended Kubernetes labels",
			labels: map[string]string{
				"app.kubernetes.io/name":    "canonical-client",
				"app.kubernetes.io/version": "v2",
				"app":                       "legacy-client",
				"version":                   "legacy-v1",
			},
			wantName:     "canonical-client",
			wantRevision: "v2",
		},
		{
			name: "common labels",
			labels: map[string]string{
				"app":     "client-app",
				"version": "v1",
			},
			wantName:     "client-app",
			wantRevision: "v1",
		},
		{
			name:         "workload fallback",
			wantName:     "client",
			wantRevision: "latest",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := workloadTestPod(corev1.PodRunning, "10.0.0.1")
			pod.Name = "client"
			pod.Labels = tc.labels

			workload := BaseWorkloadFromPod("cluster", pod)
			if workload.CanonicalName != tc.wantName || workload.CanonicalRevision != tc.wantRevision {
				t.Fatalf("canonical identity = %q/%q, want %q/%q",
					workload.CanonicalName, workload.CanonicalRevision, tc.wantName, tc.wantRevision)
			}
		})
	}
}

func TestHasInjectedZTunnelUsesRuntimeMode(t *testing.T) {
	container := workloadTestPod(corev1.PodRunning, "10.0.0.2")
	container.Spec.Containers = []corev1.Container{dedicatedZTunnelContainer()}
	nativeSidecar := workloadTestPod(corev1.PodRunning, "10.0.0.3")
	nativeSidecar.Spec.InitContainers = []corev1.Container{dedicatedZTunnelContainer()}
	sharedMode := workloadTestPod(corev1.PodRunning, "10.0.0.4")
	sharedMode.Spec.Containers = []corev1.Container{{Name: "agentio-proxy", Args: []string{"proxy", "ztunnel"}}}
	legacyContainer := workloadTestPod(corev1.PodRunning, "10.0.0.5")
	legacy := dedicatedZTunnelContainer()
	legacy.Name = "istio-proxy"
	legacyContainer.Spec.Containers = []corev1.Container{legacy}
	kruiseContainer := dedicatedZTunnelContainer()
	kruiseContainer.Name = "traffic-proxy"
	kruisePod := workloadTestPod(corev1.PodRunning, "10.0.0.6")
	kruisePod.Spec.InitContainers = []corev1.Container{kruiseContainer}
	nonZTunnel := kruisePod.DeepCopy()
	nonZTunnel.Spec.InitContainers[0].Args = []string{"proxy", "sidecar"}
	sharedKruise := kruisePod.DeepCopy()
	sharedKruise.Spec.InitContainers[0].Env = nil

	for _, tc := range []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{name: "dedicated container", pod: container, want: true},
		{name: "dedicated native sidecar", pod: nativeSidecar, want: true},
		{name: "shared runtime mode", pod: sharedMode},
		{name: "legacy dedicated container", pod: legacyContainer, want: true},
		{name: "Kruise dedicated native sidecar", pod: kruisePod, want: true},
		{name: "Kruise name without ztunnel args", pod: nonZTunnel},
		{name: "Kruise name without dedicated runtime", pod: sharedKruise},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasInjectedZTunnel(tc.pod); got != tc.want {
				t.Fatalf("HasInjectedZTunnel() = %v, want %v", got, tc.want)
			}
		})
	}
}

func dedicatedZTunnelContainer() corev1.Container {
	return corev1.Container{
		Name: "agentio-proxy",
		Args: []string{"proxy", "ztunnel"},
		Env: []corev1.EnvVar{
			{Name: "ENABLE_SIDECAR_MODE", Value: "true"},
			{Name: "PROXY_MODE", Value: "dedicated"},
		},
	}
}

func TestTerminatingReadyPodProducesUnhealthyWorkload(t *testing.T) {
	pod := workloadTestPod(corev1.PodRunning, "10.0.0.1")
	pod.Status.Conditions = []corev1.PodCondition{
		{
			Type:   corev1.PodReady,
			Status: corev1.ConditionTrue,
		},
	}
	deleting := metav1.NewTime(time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC))
	pod.DeletionTimestamp = &deleting

	workload := BaseWorkloadFromPod("cluster", pod)
	if workload.Ready {
		t.Fatal("terminating Pod produced a ready Workload")
	}
}

func TestPodHostNetworkIsPreserved(t *testing.T) {
	pod := workloadTestPod(corev1.PodRunning, "10.0.0.1")
	pod.Spec.HostNetwork = true

	workload := BaseWorkloadFromPod("cluster", pod)
	if !workload.HostNetwork {
		t.Fatal("host-network Pod produced a standard-network Workload")
	}
}

func workloadTestPod(phase corev1.PodPhase, address string) *corev1.Pod {
	return &corev1.Pod{
		Status: corev1.PodStatus{
			Phase: phase,
			PodIP: address,
		},
	}
}

func egressPod(namespace, name, gatewayName, address string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    map[string]string{LabelGatewayName: gatewayName},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: gatewayName,
			NodeName:           "node-a",
		},
		Status: corev1.PodStatus{
			PodIP:  address,
			PodIPs: []corev1.PodIP{{IP: address}},
		},
	}
}
