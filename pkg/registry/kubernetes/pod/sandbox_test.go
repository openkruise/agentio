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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPodSandboxEligibility(t *testing.T) {
	for _, tc := range []struct {
		name   string
		update func(*corev1.Pod)
		want   bool
	}{
		{name: "unmanaged"},
		{name: "enrollment intent only", update: func(p *corev1.Pod) { p.Labels["istio.io/dataplane-mode"] = "ambient" }},
		{name: "injected", update: func(p *corev1.Pod) { p.Spec.Containers = []corev1.Container{dedicatedZTunnelContainer()} }, want: true},
		{name: "native sidecar", update: func(p *corev1.Pod) { p.Spec.InitContainers = []corev1.Container{dedicatedZTunnelContainer()} }, want: true},
		{name: "ambient", update: func(p *corev1.Pod) { p.Annotations[ambientRedirectionAnnotation] = "enabled" }, want: true},
		{name: "pending",
			update: func(p *corev1.Pod) {
				p.Annotations[ambientRedirectionAnnotation] = "enabled"
				p.Status.Phase = corev1.PodPending
			},
			want: true},
		{name: "terminating",
			update: func(p *corev1.Pod) {
				p.Annotations[ambientRedirectionAnnotation] = "enabled"
				now := metav1.Now()
				p.DeletionTimestamp = &now
			},
			want: true},
		{name: "finished",
			update: func(p *corev1.Pod) {
				p.Annotations[ambientRedirectionAnnotation] = "enabled"
				p.Status.Phase = corev1.PodSucceeded
			}},
		{name: "missing address",
			update: func(p *corev1.Pod) {
				p.Annotations[ambientRedirectionAnnotation] = "enabled"
				p.Status.PodIP, p.Status.PodIPs = "", nil
			}},
		{name: "missing incarnation",
			update: func(p *corev1.Pod) {
				p.Annotations[ambientRedirectionAnnotation] = "enabled"
				p.UID = ""
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := workloadTestPod(corev1.PodRunning, "10.0.0.1")
			p.Namespace, p.Name, p.UID = "demo", "app", "pod-uid"
			p.Labels, p.Annotations = map[string]string{"app": "client"}, map[string]string{}
			if tc.update != nil {
				tc.update(p)
			}
			s := sandboxFromPod("cluster", p)
			if (s != nil) != tc.want {
				t.Fatalf("Sandbox = %+v, want present = %t", s, tc.want)
			}
			if s == nil {
				return
			}
			if s.UID != "workload:pod-uid" || s.Namespace != p.Namespace ||
				s.Attester.WorkloadUID != WorkloadUID("cluster", p) {
				t.Fatalf("Sandbox identity = %+v", s)
			}
			p.UID = "replacement-uid"
			replacement := sandboxFromPod("cluster", p)
			if replacement.UID == s.UID || replacement.Attester.WorkloadUID != s.Attester.WorkloadUID {
				t.Fatal("Sandbox identity must separate Pod incarnations")
			}
		})
	}
}
