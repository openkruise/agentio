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

package kubernetes

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	kubeclient "k8s.io/client-go/kubernetes"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/kube"
)

func applyAgentioConfig(content string, base *configv1.AgentioConfig) (*configv1.AgentioConfig, error) {
	if base == nil {
		base = &configv1.AgentioConfig{}
	}
	value, err := config.Apply(content, base)
	if err != nil {
		return nil, err
	}
	return value, validateAgentioConfig(value)
}

func TestAgentioConfigStartsFromDefaults(t *testing.T) {
	ctx := t.Context()
	r := newTestRegistry(t, ctx, nil, nil)

	config := r.AgentioConfig.GetKey("effective")
	if config == nil || config.Value == nil {
		t.Fatalf("effective config = %+v, want defaults", config)
	}
	want := []string{
		"agentio.kruise.io/dataplane-mode",
		"pod-template-hash",
		"pod-template-generation",
		"controller-revision-hash",
	}
	if got := config.Value.GetSandboxIgnoredLabels(); !reflect.DeepEqual(got, want) {
		t.Fatalf("sandbox ignored labels = %v, want %v", got, want)
	}
}

func TestAgentioConfigTrustedEPEIdentities(t *testing.T) {
	for _, tc := range []struct {
		name    string
		yaml    string
		invalid bool
	}{
		{"omitted", "{}", false},
		{"empty", "trustedEPEIdentities: []", false},
		{"multiple", "trustedEPEIdentities: [spiffe://cluster.local/ns/system/sa/epe, spiffe://example.org/custom-processor]", false},
		{"empty identity", "trustedEPEIdentities: ['']", true},
		{"wrong scheme", "trustedEPEIdentities: [https://example.org/epe]", true},
		{"wildcard", "trustedEPEIdentities: [spiffe://cluster.local/ns/system/sa/*]", true},
		{"noncanonical", "trustedEPEIdentities: [spiffe://CLUSTER.local/ns/system/sa/epe]", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := applyAgentioConfig(tc.yaml, nil)
			if (err != nil) != tc.invalid {
				t.Fatalf("applyAgentioConfig() error=%v, want invalid=%t", err, tc.invalid)
			}
		})
	}
	base, err := applyAgentioConfig("trustedEPEIdentities: [spiffe://cluster.local/ns/system/sa/epe]", nil)
	if err != nil {
		t.Fatal(err)
	}
	cleared, err := applyAgentioConfig("trustedEPEIdentities: []", base)
	if err != nil || len(cleared.GetTrustedEpeIdentities()) != 0 {
		t.Fatalf("empty override did not clear identities: %v, %v", cleared, err)
	}
}

func TestAgentioConfigEgressAuthorizationOverlay(t *testing.T) {
	base, err := applyAgentioConfig("egressAuthorization: {deniedCIDRs: [100.100.100.200/32]}", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		content string
		count   int
		invalid bool
	}{
		{"{}", 1, false},
		{"egressAuthorization: null", 1, false},
		{"egressAuthorization: {deniedCIDRs: []}", 0, false},
		{"egressAuthorization: {deniedCIDRs: [192.0.2.0/24]}", 1, false},
		{"egressAuthorization: {deniedCIDRs: [invalid]}", 0, true},
		{"egressAuthorization: {deniedCIDRs: ['::ffff:192.0.2.0/120']}", 0, true},
	} {
		t.Run(tc.content, func(t *testing.T) {
			got, err := applyAgentioConfig(tc.content, base)
			if (err != nil) != tc.invalid {
				t.Fatalf("error=%v, want invalid=%v", err, tc.invalid)
			}
			if err == nil && len(got.GetEgressAuthorization().GetDeniedCidrs()) != tc.count {
				t.Fatalf("unexpected overlay: %v", got)
			}
			if base.GetEgressAuthorization().GetDeniedCidrs()[0] != "100.100.100.200/32" {
				t.Fatal("overlay mutated base")
			}
		})
	}
}

func TestAgentioConfigMapNamesAreConfigurable(t *testing.T) {
	ctx := t.Context()
	objects := []runtime.Object{
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
			Data: map[string]string{
				"config": "sandboxExtProc:\n  service: ignored.agentio-system.svc.cluster.local\n",
			},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "custom-base"},
			Data: map[string]string{
				"config": "sandboxExtProc:\n  service: custom.agentio-system.svc.cluster.local\n  port: 9002\n",
			},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "custom-primary"},
			Data: map[string]string{
				"config": "egressGateways:\n- name: egress\n  namespace: agentio-system\n",
			},
		},
	}
	r := newTestRegistryWithOptions(t, ctx, objects, nil, Options{AgentioConfigMaps: &AgentioConfigMapOptions{
		BaseName:    "custom-base",
		PrimaryName: "custom-primary",
	}})

	config := r.AgentioConfig.GetKey("effective")
	if config == nil || config.Value == nil {
		t.Fatalf("effective config = %+v", config)
	}
	if got := config.Value.GetSandboxExtProc().GetService(); got != "custom.agentio-system.svc.cluster.local" {
		t.Fatalf("sandbox ext-proc service = %q, want custom ConfigMap value", got)
	}
	if got := len(config.Value.GetEgressGateways()); got != 1 {
		t.Fatalf("egress gateways = %d, want primary ConfigMap overlay", got)
	}
}

func TestEmptyPrimaryAgentioConfigMapNameDisablesOverlay(t *testing.T) {
	ctx := t.Context()
	objects := []runtime.Object{
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "custom-base"},
			Data: map[string]string{
				"config": "sandboxExtProc:\n  service: base.agentio-system.svc.cluster.local\n",
			},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config-primary"},
			Data: map[string]string{
				"config": "sandboxExtProc:\n  service: must-not-apply.agentio-system.svc.cluster.local\n",
			},
		},
	}
	r := newTestRegistryWithOptions(t, ctx, objects, nil, Options{AgentioConfigMaps: &AgentioConfigMapOptions{
		BaseName:    "custom-base",
		PrimaryName: "",
	}})

	config := r.AgentioConfig.GetKey("effective")
	if config == nil || config.Value == nil {
		t.Fatalf("effective config = %+v", config)
	}
	if got := config.Value.GetSandboxExtProc().GetService(); got != "base.agentio-system.svc.cluster.local" {
		t.Fatalf("sandbox ext-proc service = %q, want base value with primary disabled", got)
	}
}

func TestAgentioConfigIgnoredLabelsNullPreservesDefaultsAndEmptyClears(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want []string
	}{
		{name: "null preserves defaults", yaml: "sandboxIgnoredLabels: null", want: defaultAgentioConfiguration().GetSandboxIgnoredLabels()},
		{name: "empty clears defaults", yaml: "sandboxIgnoredLabels: []"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := applyAgentioConfig(tc.yaml, defaultAgentioConfiguration())
			if err != nil {
				t.Fatal(err)
			}
			if labels := got.GetSandboxIgnoredLabels(); !reflect.DeepEqual(labels, tc.want) {
				t.Fatalf("sandbox ignored labels = %v, want %v", labels, tc.want)
			}
		})
	}
}

func TestAgentioConfigPrimaryReplacesFullSubmessage(t *testing.T) {
	for _, tc := range []struct {
		name        string
		primary     string
		wantService string
		wantPort    uint32
	}{
		{
			name: "partially specified message resets omitted fields",
			primary: `sandboxExtProc:
  service: primary.agentio-system.svc.cluster.local
`,
			wantService: "primary.agentio-system.svc.cluster.local",
		},
		{
			name:    "explicit empty message resets every field",
			primary: "sandboxExtProc: {}",
		},
		{
			name:        "omitted message leaves the lower layer intact",
			primary:     "{}",
			wantService: "base.agentio-system.svc.cluster.local",
			wantPort:    9002,
		},
		{
			name:        "null leaves the lower layer intact",
			primary:     "sandboxExtProc: null",
			wantService: "base.agentio-system.svc.cluster.local",
			wantPort:    9002,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			base := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
				Data: map[string]string{
					"config": "sandboxExtProc:\n  service: base.agentio-system.svc.cluster.local\n  port: 9002\n",
				},
			}
			primary := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config-primary"},
				Data: map[string]string{
					"config": tc.primary,
				},
			}
			r := newTestRegistry(t, ctx, []runtime.Object{base, primary}, nil)

			config := r.AgentioConfig.GetKey("effective")
			if config == nil || config.Value == nil {
				t.Fatalf("effective config = %+v", config)
			}
			extProc := config.Value.GetSandboxExtProc()
			if extProc == nil {
				t.Fatal("sandbox ext-proc is nil")
			}
			if extProc.GetService() != tc.wantService || extProc.GetPort() != tc.wantPort {
				t.Fatalf("sandbox ext-proc = service %q port %d, want service %q port %d",
					extProc.GetService(), extProc.GetPort(), tc.wantService, tc.wantPort)
			}
		})
	}
}

func TestApplyAgentioConfigNormalizesStaticServiceEntries(t *testing.T) {
	got, err := applyAgentioConfig(`
egressGateways:
- name: egress
  namespace: agentio-system
  serviceEntries:
  - hosts: [" API.Example.COM. "]
    endpoints:
    - address: " 10.10.20.30 "
    - address: 10.10.20.31
`, nil)
	if err != nil {
		t.Fatalf("applyAgentioConfig(): %v", err)
	}
	entries := got.GetEgressGateways()[0].GetServiceEntries()
	if len(entries) != 1 {
		t.Fatalf("service entries = %d, want 1", len(entries))
	}
	if hosts := entries[0].GetHosts(); !reflect.DeepEqual(hosts, []string{"api.example.com"}) {
		t.Fatalf("hosts = %v, want canonical host", hosts)
	}
	addresses := []string{entries[0].GetEndpoints()[0].GetAddress(), entries[0].GetEndpoints()[1].GetAddress()}
	if !reflect.DeepEqual(addresses, []string{"10.10.20.30", "10.10.20.31"}) {
		t.Fatalf("endpoint addresses = %v, want canonical IPv4 addresses", addresses)
	}
}

func TestApplyAgentioConfigRejectsInvalidStaticServiceEntries(t *testing.T) {
	tests := []struct {
		name    string
		entries string
	}{
		{name: "missing hosts", entries: "- endpoints:\n  - address: 10.10.20.30"},
		{name: "missing endpoints", entries: "- hosts: [api.example.com]"},
		{name: "wildcard host", entries: "- hosts: ['*.example.com']\n  endpoints:\n  - address: 10.10.20.30"},
		{name: "IPv6 endpoint", entries: "- hosts: [api.example.com]\n  endpoints:\n  - address: '2001:db8::1'"},
		{
			name:    "duplicate endpoint",
			entries: "- hosts: [api.example.com]\n  endpoints:\n  - address: 10.10.20.30\n  - address: ' 10.10.20.30 '",
		},
		{name: "nil endpoint", entries: "- hosts: [api.example.com]\n  endpoints:\n  - null"},
		{
			name:    "duplicate host across entries",
			entries: "- hosts: [API.example.com.]\n  endpoints:\n  - address: 10.10.20.30\n- hosts: [api.example.com]\n  endpoints:\n  - address: 10.10.20.31",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content := "egressGateways:\n- name: egress\n  namespace: agentio-system\n  serviceEntries:\n  " +
				strings.ReplaceAll(tc.entries, "\n", "\n  ") + "\n"
			if _, err := applyAgentioConfig(content, nil); err == nil {
				t.Fatal("applyAgentioConfig() accepted an invalid static service entry")
			}
		})
	}
}

func TestPolicyCollectionsTrackTypedResources(t *testing.T) {
	ctx := t.Context()
	traffic := &agentsv1alpha1.TrafficPolicy{ObjectMeta: metav1.ObjectMeta{
		Namespace:   "demo",
		Name:        "traffic",
		Annotations: map[string]string{agentsv1alpha1.AnnotationSandboxID: "sandbox-a"},
	}}
	globalTraffic := &agentsv1alpha1.GlobalTrafficPolicy{ObjectMeta: metav1.ObjectMeta{
		Name:        "global-traffic",
		Annotations: map[string]string{agentsv1alpha1.AnnotationSandboxID: "sandbox-b"},
	}}
	security := &agentsv1alpha1.SecurityProfile{ObjectMeta: metav1.ObjectMeta{
		Namespace:   "demo",
		Name:        "security",
		Annotations: map[string]string{agentsv1alpha1.AnnotationSandboxID: "sandbox-c"},
	}}
	globalSecurity := &agentsv1alpha1.GlobalSecurityProfile{ObjectMeta: metav1.ObjectMeta{
		Name:        "global-security",
		Annotations: map[string]string{agentsv1alpha1.AnnotationSandboxID: "sandbox-d"},
	}}
	r := newTestRegistry(t, ctx, nil, []runtime.Object{traffic, globalTraffic, security, globalSecurity})

	if got := r.TrafficPolicies.List(); len(got) != 2 {
		t.Fatalf("traffic policy collection size = %d, want 2", len(got))
	}
	if got := r.SecurityProfiles.List(); len(got) != 2 {
		t.Fatalf("security profile collection size = %d, want 2", len(got))
	}
	if got := r.TrafficPolicies.GetKey("namespaced/demo/traffic"); got == nil || got.Namespace != "demo" || got.Global {
		t.Fatalf("namespaced traffic policy = %+v", got)
	}
	if got := r.TrafficPolicies.GetKey("global/global-traffic"); got == nil || !got.Global {
		t.Fatalf("global traffic policy = %+v", got)
	}
	if got := r.SecurityProfiles.GetKey("namespaced/demo/security"); got == nil || got.Global {
		t.Fatalf("namespaced security profile = %+v", got)
	}
	if got := r.SecurityProfiles.GetKey("global/global-security"); got == nil || !got.Global {
		t.Fatalf("global security profile = %+v", got)
	}
}

func TestAgentioConfigRetainsLastKnownGoodOverlay(t *testing.T) {
	ctx := t.Context()
	base := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
		Data: map[string]string{
			"config": "sandboxExtProc:\n  service: base.agentio-system.svc.cluster.local\n  port: 9002\n",
		},
	}
	primary := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config-primary"},
		Data: map[string]string{
			"config": "egressGateways:\n- name: egress\n  namespace: agentio-system\n",
		},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{base, primary}, nil)

	config := r.AgentioConfig.GetKey("effective")
	if config == nil || config.Value.GetSandboxExtProc().GetService() != "base.agentio-system.svc.cluster.local" ||
		len(config.Value.GetEgressGateways()) != 1 {
		t.Fatalf("effective config = %+v", config)
	}

	primary.Data["config"] = "egressGateways: ["
	if _, err := r.client.CoreV1().
		ConfigMaps(primary.Namespace).
		Update(ctx, primary, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update malformed primary ConfigMap: %v", err)
	}
	if err := wait.PollUntilContextTimeout(
		ctx,
		10*time.Millisecond,
		time.Second,
		true,
		func(context.Context) (bool, error) {
			current := r.AgentioConfig.GetKey("effective")
			return current != nil &&
				current.Value.GetSandboxExtProc().GetService() == "base.agentio-system.svc.cluster.local" &&
				len(current.Value.GetEgressGateways()) == 1, nil
		},
	); err != nil {
		t.Fatalf("last known good config was not retained: %v", err)
	}
}

type testRegistry struct {
	*Registry
	client kubeclient.Interface
}

func newTestRegistry(t *testing.T, ctx context.Context, kubeObjects, policyObjects []runtime.Object) *testRegistry {
	return newTestRegistryWithOptions(t, ctx, kubeObjects, policyObjects, Options{})
}

func newTestRegistryWithOptions(
	t *testing.T,
	ctx context.Context,
	kubeObjects, policyObjects []runtime.Object,
	options Options,
) *testRegistry {
	t.Helper()
	objects := append(append([]runtime.Object(nil), kubeObjects...), policyObjects...)
	client := &fakeKubeClient{
		Client: kube.NewFakeClient(objects...),
		watcher: newFakeGatewayCRDWatcher(
			trafficPolicyResource,
			globalTrafficPolicyResource,
			securityProfileResource,
			globalSecurityProfileResource,
		),
	}
	options.ClusterID = "test"
	options.TrustDomain = "cluster.local"
	options.RootNamespace = "agentio-system"
	options.DebounceAfter = time.Millisecond
	options.DebounceMax = 5 * time.Millisecond
	r, err := New(client, options, ctx.Done())
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	client.Run(ctx.Done())
	if err := wait.PollUntilContextTimeout(
		ctx,
		10*time.Millisecond,
		time.Second,
		true,
		func(context.Context) (bool, error) {
			return r.HasSynced(), nil
		},
	); err != nil {
		t.Fatalf("registry did not sync: %v", err)
	}
	return &testRegistry{
		Registry: r,
		client:   client.Kube(),
	}
}

func TestGatewayConfigurationAccessLogFormat(t *testing.T) {
	for _, tc := range []struct {
		name, format string
		invalid      bool
	}{
		{"defaults", "{}", false},
		{"JSON", "{json: {scheme: '%REQ(:SCHEME)%', context: {authority: '%REQ(:AUTHORITY)%'}, version: 1}}", false},
		{"text", "{text: '%REQ(:METHOD)% %REQ(:SCHEME)% %RESPONSE_CODE%'}", false},
		{"empty JSON", "{json: {}}", true},
		{"blank text", "{text: '  '}", true},
		{"both formats", "{text: '%PROTOCOL%', json: {scheme: '%REQ(:SCHEME)%'}}", true},
		{"wrong JSON type", "{json: []}", true},
		{"unknown field", "{labels: {scheme: '%REQ(:SCHEME)%'}}", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, decode := range map[string]func() (*configv1.EgressGateway, error){
				"AgentioConfig": func() (*configv1.EgressGateway, error) {
					config := "egressGateways:\n" +
						"- name: egress\n" +
						"  namespace: agentio-system\n" +
						"  accessLogFormat: " + tc.format
					got, err := applyAgentioConfig(config, nil)
					if err != nil {
						return nil, err
					}
					return got.GetEgressGateways()[0], nil
				},
				"Gateway API parameters": func() (*configv1.EgressGateway, error) {
					return decodeEgressGateway("accessLogFormat: " + tc.format)
				},
			} {
				t.Run(name, func(t *testing.T) {
					got, err := decode()
					invalid := tc.invalid && !(name == "AgentioConfig" && tc.name == "unknown field")
					if (err != nil) != invalid {
						t.Fatalf("config error = %v, want invalid=%v", err, invalid)
					}
					if !invalid && got.GetAccessLogFormat() == nil {
						t.Fatal("missing access-log format")
					}
				})
			}
		})
	}
}

func TestGatewayConfigurationUpstreamTLS(t *testing.T) {
	for _, tc := range []struct {
		name, settings string
		invalid        bool
	}{
		{"defaults", "{}", false},
		{"explicit defaults", "{minProtocolVersion: DEFAULT, maxProtocolVersion: DEFAULT}", false},
		{"negative min", "{minProtocolVersion: -1}", true},
		{"negative max", "{maxProtocolVersion: -1}", true},
		{"TLS12", "{maxProtocolVersion: TLSV1_2}", false},
		{"TLS13", "{minProtocolVersion: TLSV1_3}", false},
		{"replacement", "{cipherSuites: [ECDHE-RSA-AES128-GCM-SHA256]}", false},
		{"empty list", "{cipherSuites: []}", false},
		{"reversed", "{minProtocolVersion: TLSV1_3, maxProtocolVersion: TLSV1_2}", true},
		{"unknown min", "{minProtocolVersion: 99}", true},
		{"unknown max", "{maxProtocolVersion: 99}", true},
		{"old protocol", "{minProtocolVersion: TLSV1_1}", true},
		{"unknown cipher", "{cipherSuites: [invalid]}", true},
		{"expression", "{cipherSuites: [ALL]}", true},
		{"empty cipher", "{cipherSuites: ['']}", true},
		{"duplicate", "{cipherSuites: [AES128-GCM-SHA256, AES128-GCM-SHA256]}", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := "egressGateways:\n" +
				"- name: egress-gw\n" +
				"  namespace: agentio-system\n" +
				"  tls:\n" +
				"    origination: " + tc.settings
			for name, decode := range map[string]func() (*configv1.EgressGateway, error){
				"AgentioConfig": func() (*configv1.EgressGateway, error) {
					got, err := applyAgentioConfig(config, defaultAgentioConfiguration())
					if err != nil {
						return nil, err
					}
					return got.GetEgressGateways()[0], nil
				},
				"Gateway API parameters": func() (*configv1.EgressGateway, error) {
					return decodeEgressGateway("tls:\n  origination: " + tc.settings)
				},
			} {
				t.Run(name, func(t *testing.T) {
					got, err := decode()
					if (err != nil) != tc.invalid {
						t.Fatalf("config error = %v, want invalid=%v", err, tc.invalid)
					}
					if !tc.invalid && got.GetTls().GetOrigination() == nil {
						t.Fatal("missing upstream TLS settings")
					}
				})
			}
		})
	}
}

func TestAdditionalExtProcOverlay(t *testing.T) {
	base, err := applyAgentioConfig(
		"additionalExtProcs: [{name: first, service: first}, {name: second, service: second}]",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		yaml  string
		names []string
	}{
		{"{}", []string{"first", "second"}},
		{"additionalExtProcs: null", []string{"first", "second"}},
		{"additionalExtProcs: []", []string{}},
		{"additionalExtProcs: [{name: second, service: replacement}]", []string{"second"}},
	} {
		got, err := applyAgentioConfig(tc.yaml, base)
		if err != nil {
			t.Fatal(err)
		}
		names := []string{}
		for _, p := range got.AdditionalExtProcs {
			names = append(names, p.Name)
		}
		if !reflect.DeepEqual(names, tc.names) {
			t.Fatalf("%s: got %v, want %v", tc.yaml, names, tc.names)
		}
	}
	if len(base.AdditionalExtProcs) != 2 {
		t.Fatal("overlay mutated base")
	}
	if _, err := applyAgentioConfig(
		"additionalExtProcs: [{name: first, service: a}, {name: first, service: b}]",
		base,
	); err == nil {
		t.Fatal("duplicate names accepted")
	}
}
