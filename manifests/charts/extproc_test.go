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

package charts_test

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
)

func TestExtProcServiceReferenceRendering(t *testing.T) {
	for _, tc := range []struct {
		name        string
		args        []string
		namespace   string
		serviceName string
		dns         string
		port        uint32
	}{
		{"managed", []string{"--set", "epe.mode=managed"}, "agentio-system", "agentio-epe", "agentio-epe.agentio-system.svc.cluster.local", 9002},
		{"renamed", []string{"--set", "epe.mode=managed,epe.fullnameOverride=processor,epe.service.grpcPort=9102", "--namespace", "custom"}, "custom", "processor", "processor.custom.svc.cluster.local", 9102},
		{"external DNS", []string{"--set", "epe.mode=external,epe.external.address=epe.example.org"}, "", "", "epe.example.org", 9002},
		{"external reference", []string{"--set", "epe.mode=external,epe.external.address=epe.example.org,agentiod.config.values.sandboxExtProc.serviceRef.namespace=other,agentiod.config.values.sandboxExtProc.serviceRef.name=processor"}, "other", "processor", "epe.example.org", 9002},
		{"explicit DNS", []string{"--set", "epe.mode=managed", "--set-json", "agentiod.config.values.sandboxExtProc.serviceRef=null"}, "", "", "agentio-epe.agentio-system.svc.cluster.local", 9002},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append(tc.args, "--show-only", "templates/agentiod/configmaps.yaml")
			manifest := renderAgentio(t, args...)
			var cm corev1.ConfigMap
			if err := yaml.Unmarshal([]byte(strings.Split(manifest, "\n---")[0]), &cm); err != nil {
				t.Fatal(err)
			}
			decoded, err := config.Apply(cm.Data["config"], &configv1.AgentioConfig{})
			if err != nil {
				t.Fatal(err)
			}
			provider := decoded.GetSandboxExtProc()
			if provider.GetService() != tc.dns || provider.GetPort() != tc.port {
				t.Fatalf("provider=%v, want service=%s port=%d", provider, tc.dns, tc.port)
			}
			ref := provider.GetServiceRef()
			if ref.GetNamespace() != tc.namespace || ref.GetName() != tc.serviceName ||
				(ref == nil) != (tc.serviceName == "") {
				t.Fatalf("serviceRef=%v, want %s/%s", ref, tc.namespace, tc.serviceName)
			}
		})
	}
}
