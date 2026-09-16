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
package plugin

import (
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func TestAgentioTrafficAnnotations(t *testing.T) {
	for _, tc := range []struct {
		name, key, value string
		invalid          bool
	}{
		{"excludeOutboundPorts", "exclude-outbound-ports", "8080,8443", false},
		{"excludeOutboundPorts", "exclude-outbound-ports", "", false},
		{"excludeOutboundPorts", "exclude-outbound-ports", "bad-port", true},
		{"includeOutboundIPRanges", "include-outbound-ip-ranges", "10.0.0.0/8", false},
	} {
		name := tc.name
		if name == "includeOutboundIPRanges" {
			name = "includeIPCidrs"
		}
		found, got, err := getAnnotationOrDefault(name, map[string]string{
			annotationRegistry[name].key:                  "legacy-invalid",
			"traffic.sidecar.agentio.kruise.io/" + tc.key: tc.value,
		})
		if !found || (err != nil) != tc.invalid || (!tc.invalid && got != tc.value) {
			t.Fatalf("%s=%q: found=%v, value=%q, error=%v", tc.name, tc.value, found, got, err)
		}
	}
}

func TestCmdAddExcludePodWithAgentioInitContainer(t *testing.T) {
	pod, ns := buildFakePodAndNSForClient()
	pod.ObjectMeta.Annotations[sidecarStatusKey] = "true"
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, corev1.Container{Name: "agentio-init"})
	mockIntercept := testDoAddRun(t, buildMockConf(true), testNSName, pod, ns)
	if len(mockIntercept.lastRedirect) != 0 {
		t.Fatal("CNI must skip pods with agentio-init")
	}
}
