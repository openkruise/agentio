// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package charts_test

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/yaml"
)

func TestKubernetesWorkloadAuthenticationMode(t *testing.T) {
	for _, mode := range []string{"local", "tokenreview"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{}
			if mode != "local" {
				args = []string{"--set", "agentiod.kubernetesWorkloadAuthMode=" + mode}
			}
			manifest := renderAgentio(t, args...)
			for document := range strings.SplitSeq(manifest, "\n---") {
				var deployment appsv1.Deployment
				if err := yaml.Unmarshal([]byte(document), &deployment); err != nil {
					t.Fatal(err)
				}
				if deployment.Kind != "Deployment" || deployment.Name != "agentiod" {
					continue
				}
				for _, container := range deployment.Spec.Template.Spec.Containers {
					for _, env := range container.Env {
						if env.Name == "AGENTIO_KUBERNETES_WORKLOAD_AUTH_MODE" {
							if env.Value != mode {
								t.Fatalf("authentication mode = %q, want %q", env.Value, mode)
							}
							return
						}
					}
				}
				t.Fatal("missing authentication environment variable")
			}
			t.Fatal("missing agentiod Deployment")
		})
	}
	requireRenderError(t, "kubernetesWorkloadAuthMode", "--set", "agentiod.kubernetesWorkloadAuthMode=invalid")
}
