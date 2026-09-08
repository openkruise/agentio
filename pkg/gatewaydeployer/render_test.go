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
	"os"
	"strings"
	"testing"
	"time"

	meshv1alpha1 "istio.io/api/mesh/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/google/go-cmp/cmp"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"
)

func testValues(t testing.TB, overlay map[string]any) map[string]any {
	t.Helper()
	content, err := os.ReadFile("testdata/gateway-values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defaults := map[string]any{}
	if err := yaml.Unmarshal(content, &defaults); err != nil {
		t.Fatal(err)
	}
	return mergeMaps(defaults, overlay)
}

func testRenderer(t testing.TB, values map[string]any) *renderer {
	t.Helper()
	r, err := newRenderer(func() map[string]any { return values }, defaultProxyConfig(), "cluster.local")
	if err != nil {
		t.Fatal(err)
	}
	templateContent, err := os.ReadFile("templates/egress-gateway.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.update(egressGatewayTemplateName, string(templateContent), values, defaultProxyConfig()); err != nil {
		t.Fatal(err)
	}
	return r
}

func testInjectorConfigWithEgressTemplate(t testing.TB) string {
	t.Helper()
	content, err := os.ReadFile("templates/egress-gateway.yaml")
	if err != nil {
		t.Fatal(err)
	}
	indented := "    " + strings.ReplaceAll(strings.TrimRight(string(content), "\n"), "\n", "\n    ")
	return "defaultTemplates: [ztunnel]\ntemplates:\n  ztunnel: ignored\n  egress-gateway: |\n" + indented + "\n"
}

// TestRendererMatchesEgressGoldens pins the complete Agentio-managed output,
// including the production class, controller, and proxy naming.
func TestRendererMatchesEgressGoldens(t *testing.T) {
	r := testRenderer(t, testValues(t, parityValuesOverlay()))
	for _, fixture := range parityFixtures() {
		t.Run(fixture.Name, func(t *testing.T) {
			input := templateInputForTest(fixture.Gateway, parityKubeVersion)
			docs, err := r.Render(fixture.TemplateName, input)
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(docs, "\n---\n")
			goldenPath := "testdata/parity/" + fixture.Name + ".golden.yaml"
			if os.Getenv("REFRESH_EGRESS_GOLDENS") != "" {
				if err := os.WriteFile(goldenPath, []byte(got+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			golden, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatal(err)
			}
			want := strings.TrimSuffix(string(golden), "\n")
			if got != want {
				t.Fatalf("render diverges from egress golden:\n%s",
					cmp.Diff(want, got))
			}
		})
	}
}

func TestExtractServicePortsAddsStatusPortAndDedupes(t *testing.T) {
	gw := gatewayv1.Gateway{Spec: gatewayv1.GatewaySpec{Listeners: []gatewayv1.Listener{
		{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
		{Name: "http-dup", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
		{Name: gatewayv1.SectionName("very." + strings.Repeat("x", 70)), Port: 443, Protocol: gatewayv1.HTTPSProtocolType},
	}}}
	ports := extractServicePorts(gw)
	if ports[0].Name != "status-port" || ports[0].Port != 15021 {
		t.Fatalf("missing status-port, got %+v", ports[0])
	}
	if len(ports) != 3 {
		t.Fatalf("duplicate port not collapsed: %+v", ports)
	}
	if strings.Contains(ports[2].Name, ".") || len(ports[2].Name) > 63 {
		t.Fatalf("listener name not sanitized: %q", ports[2].Name)
	}
}

// Upstream injection templates use any image value containing "/" verbatim.
func TestProxyImage(t *testing.T) {
	tests := []struct {
		name    string
		hub     string
		tag     string
		variant string
		image   string
		want    string
	}{
		{
			name: "bare image joins hub and tag",
			hub:  "example.com/agentio", tag: "1.0.0", image: "proxyv2",
			want: "example.com/agentio/proxyv2:1.0.0",
		},
		{
			name: "fully qualified image with tag preserved",
			hub:  "docker.io/openkruise", tag: "latest", image: "registry.example/agentio/proxyv2:1.0.0",
			want: "registry.example/agentio/proxyv2:1.0.0",
		},
		{
			name: "fully qualified image with digest preserved",
			hub:  "docker.io/openkruise", tag: "latest",
			image: "registry.example/agentio/proxyv2@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			want:  "registry.example/agentio/proxyv2@sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name: "fully qualified image without tag preserved",
			hub:  "docker.io/openkruise", tag: "latest", image: "registry.example/proxyv2",
			want: "registry.example/proxyv2",
		},
		{
			name: "bare image joins default hub and tag",
			hub:  "docker.io/openkruise", tag: "latest", image: "proxyv2",
			want: "docker.io/openkruise/proxyv2:latest",
		},
		{
			name: "variant replaces tag suffix",
			hub:  "example.com/agentio/", tag: "1.0.0-distroless", variant: "debug", image: "customproxy",
			want: "example.com/agentio/customproxy:1.0.0-debug",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			global := map[string]any{
				"hub": tt.hub, "tag": tt.tag, "proxy": map[string]any{"image": tt.image},
			}
			if tt.variant != "" {
				global["variant"] = tt.variant
			}
			if got := proxyImage(map[string]any{"global": global}); got != tt.want {
				t.Fatalf("proxyImage(image=%q) = %q, want %q", tt.image, got, tt.want)
			}
		})
	}
}

// The proxy image must be built exclusively from operator-controlled values; see proxyImage in render.go.
func TestRenderIgnoresProxyImageAnnotation(t *testing.T) {
	merged := testValues(t, parityValuesOverlay())
	rend := testRenderer(t, merged)
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name: "egress", Namespace: "demo", UID: "uid-img",
			Annotations: map[string]string{
				"sidecar.agentio.kruise.io/proxy-image":      "evil.example/attacker:latest",
				"sidecar.agentio.kruise.io/proxy-image-type": "evil",
			},
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "agentio-egress",
			Listeners: []gatewayv1.Listener{
				{Name: "mesh", Port: 15008, Protocol: gatewayv1.ProtocolType("HBONE")},
			},
		},
	}
	out, err := rend.Render(egressGatewayTemplateName, templateInputForTest(gw, parityKubeVersion))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(out, "\n")
	// Annotations remain object metadata, but the container image must come from values alone.
	imageLines := 0
	for line := range strings.SplitSeq(joined, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "image: ") {
			continue
		}
		imageLines++
		if trimmed != `image: "example.com/agentio/proxyv2:1.0.0-test"` {
			t.Fatalf("container image not derived from values: %s", trimmed)
		}
	}
	if imageLines == 0 {
		t.Fatalf("rendered output has no container image:\n%s", joined)
	}
}

func TestRenderEnablesPolicyStoreWhenSNIEnabled(t *testing.T) {
	overlay := mergeMaps(parityValuesOverlay(), map[string]any{
		"agentio": map[string]any{"env": map[string]any{
			"AGENTIO_ENABLE_SNI_TRAFFIC_POLICY": true,
		}},
	})
	merged := testValues(t, overlay)
	rend := testRenderer(t, merged)
	gw := gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "egress", Namespace: "demo", UID: "uid-egress"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "agentio-egress",
			Listeners:        []gatewayv1.Listener{{Name: "mesh", Port: 15008, Protocol: gatewayv1.ProtocolType("HBONE")}},
		},
	}
	input := buildTemplateInput(gw, builtinClasses["agentio-egress"], "test-cluster", parityKubeVersion, "")
	docs, err := rend.Render("egress-gateway", input)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(docs, "\n---\n")
	for _, want := range []string{
		"name: PEER_METADATA_DISCOVERY\n          value: \"true\"",
		"name: ENABLE_POLICY_STORE\n          value: \"true\"",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered gateway does not advertise the SNI policy runtime; want %q in:\n%s", want, got)
		}
	}
}

func TestRenderUsesAgentioProxyContainerName(t *testing.T) {
	merged := testValues(t, parityValuesOverlay())
	rend := testRenderer(t, merged)
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "egress", Namespace: "demo", UID: "uid-egress"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "agentio-egress",
			Listeners:        []gatewayv1.Listener{{Name: "mesh", Port: 15008, Protocol: gatewayv1.ProtocolType("HBONE")}},
		},
	}
	docs, err := rend.Render(egressGatewayTemplateName, buildTemplateInput(*gw, builtinClasses["agentio-egress"], "test-cluster", parityKubeVersion, ""))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(docs, "\n---\n")
	if !strings.Contains(got, "\n      - name: agentio-proxy\n") || strings.Contains(got, "\n      - name: istio-proxy\n") {
		t.Fatalf("rendered gateway does not use agentio-proxy:\n%s", got)
	}
}

func TestRenderPrefersEgressGatewayValuesAndAcceptsLegacyWaypointValues(t *testing.T) {
	for _, test := range []struct {
		name   string
		values map[string]any
		want   string
	}{
		{
			name: "egress gateway values take precedence",
			values: map[string]any{
				"egressGateway": map[string]any{"nodeSelector": map[string]any{"pool": "egress"}},
				"waypoint":      map[string]any{"nodeSelector": map[string]any{"pool": "legacy"}},
			},
			want: "pool: egress",
		},
		{
			name: "legacy waypoint values remain supported",
			values: map[string]any{
				"waypoint": map[string]any{"nodeSelector": map[string]any{"pool": "legacy"}},
			},
			want: "pool: legacy",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := testValues(t, parityValuesOverlay())
			global := values["global"].(map[string]any)
			delete(global, "waypoint")
			delete(global, "egressGateway")
			for key, value := range test.values {
				global[key] = value
			}
			rend := testRenderer(t, values)
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "egress", Namespace: "demo", UID: "uid-egress"},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "agentio-egress",
					Listeners:        []gatewayv1.Listener{{Name: "mesh", Port: 15008, Protocol: gatewayv1.ProtocolType("HBONE")}},
				},
			}
			docs, err := rend.Render(egressGatewayTemplateName, buildTemplateInput(*gw, builtinClasses["agentio-egress"], "test-cluster", parityKubeVersion, ""))
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(docs, "\n---\n"); !strings.Contains(got, test.want) {
				t.Fatalf("rendered gateway missing %q:\n%s", test.want, got)
			}
		})
	}
}

func TestEmptyMatchesSprigDefaultSemantics(t *testing.T) {
	var ptr *int
	var iface any = ptr
	tests := []struct {
		name string
		in   any
		want bool
	}{
		{name: "nil", in: nil, want: true},
		{name: "empty map", in: map[string]string{}, want: true},
		{name: "non-empty map", in: map[string]string{"k": "v"}, want: false},
		{name: "empty slice", in: []int{}, want: true},
		{name: "non-empty slice", in: []int{1}, want: false},
		{name: "empty array", in: [0]int{}, want: true},
		{name: "non-empty array", in: [1]int{}, want: false},
		{name: "zero float", in: float64(0), want: true},
		{name: "non-zero float", in: float32(0.1), want: false},
		{name: "zero uint", in: uint(0), want: true},
		{name: "non-zero uint", in: uint64(1), want: false},
		{name: "nil pointer", in: ptr, want: true},
		{name: "nil pointer interface", in: iface, want: true},
		{name: "struct", in: struct{}{}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := empty(tt.in); got != tt.want {
				t.Fatalf("empty(%#v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestSerializationHelpersReturnErrors(t *testing.T) {
	if _, err := toYAML(map[string]any{"bad": func() {}}); err == nil {
		t.Fatal("toYAML accepted an unmarshalable value")
	}
	if _, err := toJSON(map[string]any{"bad": func() {}}); err == nil {
		t.Fatal("toJSON accepted an unmarshalable value")
	}
}

func TestSanitizeListenerNameForPort(t *testing.T) {
	tests := map[string]string{
		"HTTP.One":                     "http-one",
		"-bad__name--":                 "bad-name",
		"...":                          "",
		strings.Repeat("a", 62) + ".Z": strings.Repeat("a", 62),
	}
	for in, want := range tests {
		if got := sanitizeListenerNameForPort(in); got != want {
			t.Fatalf("sanitizeListenerNameForPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTemplateFuncReviewFindings(t *testing.T) {
	funcs := templateFuncs()
	if contains := funcs["contains"].(func(string, string) bool); !contains("needle", "haystack needle") || contains("haystack needle", "needle") {
		t.Fatal("contains does not use upstream needle, haystack order")
	}
	if got := upstreamIndent(2, "a\nb"); got != "a\n  b" {
		t.Fatalf("indent() = %q", got)
	}
	if got := funcs["nindent"].(func(int, string) string)(2, "a\nb"); got != "\n  a\n  b" {
		t.Fatalf("nindent() = %q", got)
	}
	vod := funcs["valueOrDefault"].(func(any, any) any)
	if got := vod(false, true); got != false {
		t.Fatalf("valueOrDefault(false, true) = %#v", got)
	}
	if got := vod(0, 1); got != 0 {
		t.Fatalf("valueOrDefault(0, 1) = %#v", got)
	}
	if got := vod("", "fallback"); got != "fallback" {
		t.Fatalf("valueOrDefault empty string = %#v", got)
	}
	if got := annotationValue(metav1.ObjectMeta{}, "missing", 3); got != "3" {
		t.Fatalf("annotation default = %q", got)
	}
	if got := strdict("a", "b", "c"); got["c"] != "" {
		t.Fatalf("strdict odd key = %#v", got)
	}
}

func TestOmitNilRecursesThroughMapsAndSlices(t *testing.T) {
	in := map[string]any{"drop": nil, "nested": map[string]any{"x": nil, "y": "z"}, "slice": []any{nil, map[string]any{"n": nil}, "keep"}}
	got := omitNil(in)
	want := map[string]any{"nested": map[string]any{"y": "z"}, "slice": []any{"keep"}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("omitNil mismatch (-want +got):\n%s", diff)
	}
	if got := omitNil(map[string]any{"x": nil}); got != nil {
		t.Fatalf("empty map should become nil, got %#v", got)
	}
	if got := omitNil([]any{nil, map[string]any{"x": nil}}); got != nil {
		t.Fatalf("empty slice should become nil, got %#v", got)
	}
}

func TestProtoToJSONCleansDefaultProxyConfig(t *testing.T) {
	// Pin the expected proxy defaults as fixed literals.
	pc := defaultProxyConfig()
	if pc.ConfigPath != "./etc/istio/proxy" {
		t.Fatalf("ConfigPath = %q, want %q", pc.ConfigPath, "./etc/istio/proxy")
	}
	if pc.BinaryPath != "/usr/local/bin/envoy" {
		t.Fatalf("BinaryPath = %q, want %q", pc.BinaryPath, "/usr/local/bin/envoy")
	}
	if sc, ok := pc.GetClusterName().(*meshv1alpha1.ProxyConfig_ServiceCluster); !ok || sc.ServiceCluster != "agentio-proxy" {
		t.Fatalf("ServiceCluster = %v, want %q", pc.GetClusterName(), "agentio-proxy")
	}
	if pc.DrainDuration == nil || pc.DrainDuration.AsDuration() != 45*time.Second {
		t.Fatalf("DrainDuration = %v, want 45s", pc.DrainDuration)
	}
	if pc.TerminationDrainDuration == nil || pc.TerminationDrainDuration.AsDuration() != 5*time.Second {
		t.Fatalf("TerminationDrainDuration = %v, want 5s", pc.TerminationDrainDuration)
	}
	if pc.ProxyAdminPort != 15000 {
		t.Fatalf("ProxyAdminPort = %d, want 15000", pc.ProxyAdminPort)
	}
	if pc.StatNameLength != 189 {
		t.Fatalf("StatNameLength = %d, want 189", pc.StatNameLength)
	}
	if pc.StatusPort != 15020 {
		t.Fatalf("StatusPort = %d, want 15020", pc.StatusPort)
	}
	if pc.DiscoveryAddress != "istiod.istio-system.svc:15012" {
		t.Fatalf("DiscoveryAddress = %q, want %q", pc.DiscoveryAddress, "istiod.istio-system.svc:15012")
	}
	if pc.ControlPlaneAuthPolicy != meshv1alpha1.AuthenticationPolicy_MUTUAL_TLS {
		t.Fatalf("ControlPlaneAuthPolicy = %v, want MUTUAL_TLS", pc.ControlPlaneAuthPolicy)
	}

	// protoToJSON must omit fields whose value equals the default.
	got, err := protoToJSON(pc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "configPath") || strings.Contains(got, "config_path") {
		t.Fatalf("protoToJSON did not clean default configPath: %s", got)
	}

	// A non-default value must appear in the JSON output.
	pc2 := defaultProxyConfig()
	pc2.ConfigPath = "/custom/path"
	got2, err := protoToJSON(pc2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got2, "configPath") && !strings.Contains(got2, "config_path") {
		t.Fatalf("protoToJSON dropped non-default configPath: %s", got2)
	}
}

// templateInputForTest builds the input for Agentio's production egress class.
func templateInputForTest(gw *gatewayv1.Gateway, kubeVersion int) TemplateInput {
	ci, ok := builtinClasses[string(gw.Spec.GatewayClassName)]
	if !ok {
		panic("templateInputForTest: unknown builtin class " + gw.Spec.GatewayClassName)
	}
	return buildTemplateInput(*gw, ci, "test-cluster", kubeVersion, "")
}
