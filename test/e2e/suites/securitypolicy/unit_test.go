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

package securitypolicy

import (
	"reflect"
	"strings"
	"testing"

	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func TestSNIEchoFixtureManifest(t *testing.T) {
	tests := []struct {
		name, namespace, policyValue string
	}{
		{name: "selected", namespace: "sni-policy", policyValue: "selected"},
		{name: "global", namespace: "sni-policy-global", policyValue: "global"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := sniEchoConfig(tc.name, tc.namespace, tc.policyValue)
			if config.Name != tc.name || config.Namespace != tc.namespace {
				t.Fatalf("SNI echo identity = %s/%s", config.Namespace, config.Name)
			}
			if config.Image != echo.DefaultImage || !strings.Contains(config.Image, "@sha256:") {
				t.Fatalf("SNI echo image = %q, want immutable default", config.Image)
			}
			wantLabels := map[string]string{"app": tc.name, sniPolicyLabel: tc.policyValue}
			if !reflect.DeepEqual(config.Labels, wantLabels) {
				t.Fatalf("SNI echo labels = %#v, want %#v", config.Labels, wantLabels)
			}
			if len(config.PodAnnotations) != 0 {
				t.Fatalf("SNI echo annotations contain dataplane enrollment: %#v", config.PodAnnotations)
			}
			if !reflect.DeepEqual(config.Ports, echo.DefaultPorts()) {
				t.Fatalf("SNI echo ports = %#v, want default protocol fixture ports", config.Ports)
			}
			if !reflect.DeepEqual(config.Capabilities, harness.ClientCapabilities()) {
				t.Fatalf("SNI echo capabilities = %#v, want %#v", config.Capabilities, harness.ClientCapabilities())
			}
		})
	}
}

func TestSetupOrder(t *testing.T) {
	digest := "registry.example/test@sha256:" + strings.Repeat("b", 64)
	setups := suiteSetupGraph(agentiocomponent.Config{
		Namespace:         "agentio-system",
		AgentiodImage:     digest,
		ZtunnelImage:      digest,
		ProxyInitImage:    digest,
		GatewayImage:      digest,
		EPEImage:          digest,
		ExtProcImage:      digest,
		ForwardProxyImage: digest,
	})
	names := make([]string, len(setups))
	for index := range setups {
		names[index] = setups[index].name
	}
	want := []string{
		"agentio", "agentio-baseline", "sni-policy-namespace", "sni-policy-global-namespace",
		"sni-policy-selected", "sni-policy-unselected", "sni-policy-global", "fixture-readiness",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("setup order = %v, want %v", names, want)
	}
}
