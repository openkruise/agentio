// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package repair

import (
	"istio.io/istio/cni/pkg/config"
	"istio.io/istio/pkg/config/agentio"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestAgentioRepairMatchesLegacyAndNewPods(t *testing.T) {
	controller := &Controller{cfg: config.RepairConfig{SidecarAnnotation: agentio.SidecarStatus, InitContainerName: "agentio-validation"}}
	for _, tc := range []struct {
		annotation, container string
		want                  bool
	}{
		{agentio.SidecarStatus, "agentio-validation", true},
		{"sidecar.istio.io/status", "istio-validation", true},
		{"unrelated/status", "agentio-validation", false},
		{agentio.SidecarStatus, "app-init", false},
	} {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{tc.annotation: "{}"}}, Status: corev1.PodStatus{InitContainerStatuses: []corev1.ContainerStatus{{Name: tc.container, LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 126}}}}}}
		if got := controller.matchesFilter(pod); got != tc.want {
			t.Fatalf("%s / %s: got %v, want %v", tc.annotation, tc.container, got, tc.want)
		}
	}
}
