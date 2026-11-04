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

package gatewaydeployer

import (
	"strings"
	"testing"
)

const testInjectorConfig = `defaultTemplates: [ztunnel]
templates:
  ztunnel: |
    ignored by the gateway deployer
  egress-gateway: |
    apiVersion: v1
    kind: Service
    metadata:
      name: {{ .DeploymentName }}
      annotations:
        config-source: {{ .Values.global.hub | quote }}
        discovery-address: {{ .ProxyConfig.DiscoveryAddress | quote }}
`

func TestMergeMapsOverlayWinsAndRecurses(t *testing.T) {
	base := map[string]any{"global": map[string]any{"hub": "old", "tag": "keep"}}
	overlay := map[string]any{"global": map[string]any{"hub": "new"}}
	merged := mergeMaps(base, overlay)
	global := merged["global"].(map[string]any)
	if global["hub"] != "new" || global["tag"] != "keep" {
		t.Fatalf("unexpected merge result: %v", merged)
	}
}

func TestProviderLoadsOnlyEgressGatewayFromInjectorConfig(t *testing.T) {
	provider, err := newTemplateProvider(Options{
		SystemNamespace: "agentio-system",
		TrustDomain:     "td",
		ClusterDomain:   "cluster.local",
		CAAddress:       "fallback:15012",
	}, defaultProxyConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.updateFromInjectorConfig(testInjectorConfig, `global:
  hub: injector.example
  xdsAddress: configured:15012
`); err != nil {
		t.Fatal(err)
	}
	docs, err := provider.Renderer().Render(egressGatewayTemplateName, TemplateInput{DeploymentName: "egress"})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(docs, "\n")
	for _, want := range []string{`config-source: "injector.example"`, `discovery-address: "configured:15012"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered gateway missing %s:\n%s", want, got)
		}
	}
	if _, err := provider.Renderer().Render("waypoint", TemplateInput{}); err == nil {
		t.Fatal("provider unexpectedly exposed a waypoint template")
	}
}

func TestProviderNotifiesActiveHandlersAfterValidConfigUpdate(t *testing.T) {
	provider, err := newTemplateProvider(Options{}, defaultProxyConfig())
	if err != nil {
		t.Fatal(err)
	}
	var first, second int
	unregisterFirst := provider.AddHandler(func() { first++ })
	provider.AddHandler(func() { second++ })

	if err := provider.updateFromInjectorConfig(testInjectorConfig, `global: {hub: first}`); err != nil {
		t.Fatal(err)
	}
	if first != 1 || second != 1 {
		t.Fatalf("handlers after first update = %d, %d; want 1, 1", first, second)
	}
	unregisterFirst()
	if err := provider.updateFromInjectorConfig(testInjectorConfig, `global: {hub: second}`); err != nil {
		t.Fatal(err)
	}
	if first != 1 || second != 2 {
		t.Fatalf("handlers after deregistration = %d, %d; want 1, 2", first, second)
	}
}

func TestProviderKeepsLastKnownGoodConfig(t *testing.T) {
	provider, err := newTemplateProvider(Options{}, defaultProxyConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.updateFromInjectorConfig(testInjectorConfig, `global: {hub: good}`); err != nil {
		t.Fatal(err)
	}
	if err := provider.updateFromInjectorConfig(`templates: {ztunnel: ignored}`, `global: {hub: bad}`); err == nil {
		t.Fatal("missing egress-gateway template was accepted")
	}
	docs, err := provider.Renderer().Render(egressGatewayTemplateName, TemplateInput{DeploymentName: "egress"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(docs, "\n"); !strings.Contains(got, `config-source: "good"`) {
		t.Fatalf("invalid update replaced last known good config:\n%s", got)
	}
}

func TestProviderSeparatesGatewayAndProxyEndpoints(t *testing.T) {
	provider, err := newTemplateProvider(Options{CAAddress: "agentiod:15012"}, defaultProxyConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.updateFromInjectorConfig(testInjectorConfig, `global:
  hub: injector.example
  xdsAddress: agentiod:15012
  gatewayXdsAddress: agentiod-policy:15012
`); err != nil {
		t.Fatal(err)
	}
	docs, err := provider.Renderer().Render(egressGatewayTemplateName, TemplateInput{DeploymentName: "egress"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(docs, "\n"), `discovery-address: "agentiod-policy:15012"`) {
		t.Fatalf("gateway endpoint did not switch: %v", docs)
	}
	values := provider.currentValues()
	if got := nestedString(values, "global", "caAddress"); got != "agentiod-policy:15012" {
		t.Fatalf("gateway CA = %q", got)
	}
	if got := nestedString(values, "global", "xdsAddress"); got != "agentiod:15012" {
		t.Fatalf("proxy address changed to %q", got)
	}
}
