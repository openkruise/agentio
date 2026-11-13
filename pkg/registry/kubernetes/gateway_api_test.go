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
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestGatewayDnsCacheSettings(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    *configv1.DnsCacheSettings
		invalid bool
	}{
		{name: "null", content: "dnsCache: null"},
		{name: "empty", content: "dnsCache: {}", want: &configv1.DnsCacheSettings{}},
		{name: "capacity only", content: "dnsCache: {maxHosts: 16384}", want: &configv1.DnsCacheSettings{MaxHosts: new(uint32(16384))}},
		{name: "pending only", content: "dnsCache: {maxPendingRequests: 4096}", want: &configv1.DnsCacheSettings{MaxPendingRequests: new(uint32(4096))}},
		{name: "TTL only", content: "dnsCache: {hostTtl: 120s}", want: &configv1.DnsCacheSettings{HostTtl: durationpb.New(2 * time.Minute)}},
		{
			name:    "configured",
			content: "dnsCache: {maxHosts: 16384, maxPendingRequests: 4096, hostTtl: 300s}",
			want: &configv1.DnsCacheSettings{
				MaxHosts:           new(uint32(16384)),
				MaxPendingRequests: new(uint32(4096)),
				HostTtl:            durationpb.New(5 * time.Minute),
			},
		},
		{name: "zero hosts", content: "dnsCache: {maxHosts: 0}", invalid: true},
		{name: "zero pending", content: "dnsCache: {maxPendingRequests: 0}", invalid: true},
		{name: "negative hosts", content: "dnsCache: {maxHosts: -1}", invalid: true},
		{name: "overflow hosts", content: "dnsCache: {maxHosts: 4294967296}", invalid: true},
		{name: "zero TTL", content: "dnsCache: {hostTtl: 0s}", invalid: true},
		{name: "negative TTL", content: "dnsCache: {hostTtl: -1s}", invalid: true},
		{name: "invalid TTL", content: "dnsCache: {hostTtl: invalid}", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, decode := range map[string]func() (*configv1.EgressGateway, error){
				"AgentioConfig": func() (*configv1.EgressGateway, error) {
					got, err := applyAgentioConfig("egressGateways:\n- name: egress\n  namespace: demo\n  "+tc.content, nil)
					if err != nil {
						return nil, err
					}
					return got.GetEgressGateways()[0], nil
				},
				"Gateway API parameters": func() (*configv1.EgressGateway, error) {
					return decodeEgressGateway(tc.content)
				},
			} {
				t.Run(name, func(t *testing.T) {
					got, err := decode()
					if (err != nil) != tc.invalid {
						t.Fatalf("decode() = %v, %v; invalid=%t", got, err, tc.invalid)
					}
					if err == nil && !proto.Equal(got.GetDnsCache(), tc.want) {
						t.Fatalf("dnsCache = %v, want %v", got.GetDnsCache(), tc.want)
					}
				})
			}
		})
	}
}

func TestGatewayUpstreamTrustSources(t *testing.T) {
	for _, tc := range []struct {
		name              string
		bundle            string
		invalid           bool
		parametersInvalid bool
	}{
		{"empty", "{}", false, false},
		{"empty sources", "{additionalSources: []}", false, false},
		{"ConfigMap", "{additionalSources: [{configMapRef: {name: company-ca, key: ca.crt}}]}", false, false},
		{"Secret", "{additionalSources: [{secretRef: {name: partner-ca, key: ca.pem}}]}", false, false},
		{"missing source", "{additionalSources: [{}]}", true, true},
		{"null source", "{additionalSources: [null]}", true, true},
		{"missing name", "{additionalSources: [{configMapRef: {key: ca.crt}}]}", true, true},
		{"missing key", "{additionalSources: [{secretRef: {name: company-ca}}]}", true, true},
		{"invalid name", "{additionalSources: [{configMapRef: {name: 'bad/name', key: ca.crt}}]}", true, true},
		{"invalid key", "{additionalSources: [{secretRef: {name: company-ca, key: 'bad/key'}}]}", true, true},
		{"unknown namespace", "{additionalSources: [{configMapRef: {name: company-ca, namespace: other, key: ca.crt}}]}", false, true},
		{"unknown secret namespace", "{additionalSources: [{secretRef: {name: company-ca, namespace: other, key: ca.crt}}]}", false, true},
		{"conflicting sources", "{additionalSources: [{configMapRef: {name: a, key: ca.crt}, secretRef: {name: b, key: ca.crt}}]}", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := "upstreamTrustBundle: " + tc.bundle
			for name, decode := range map[string]func() (*configv1.EgressGateway, error){
				"AgentioConfig": func() (*configv1.EgressGateway, error) {
					got, err := applyAgentioConfig("egressGateways:\n- name: egress\n  namespace: demo\n  "+content, nil)
					if err != nil {
						return nil, err
					}
					return got.GetEgressGateways()[0], nil
				},
				"Gateway API parameters": func() (*configv1.EgressGateway, error) {
					return decodeEgressGateway(content)
				},
			} {
				t.Run(name, func(t *testing.T) {
					got, err := decode()
					invalid := tc.invalid
					if name == "Gateway API parameters" {
						invalid = tc.parametersInvalid
					}
					if (err != nil) != invalid {
						t.Fatalf("decode() = %v, %v; invalid=%t", got, err, invalid)
					}
					if err == nil && got.GetUpstreamTrustBundle() == nil {
						t.Fatal("upstreamTrustBundle was not decoded")
					}
				})
			}
		})
	}
}

func TestGatewayConfigurationProtocolSettings(t *testing.T) {
	const content = `
tlsTermination:
  includeHosts: ["*.example.com"]
extProc:
  service: gateway-ext-proc.agentio-system.svc.cluster.local
  port: 9003
http:
  acceptHttp10: false
  streamIdleTimeout: 90s
  routing:
    fallback: {timeout: 45s}
    hostOverrides:
    - hosts: [api.example.com]
      settings: {timeout: 10s, retries: {attempts: 2}}
tcp:
  idleTimeout: 120s
  maxConnectionDuration: 600s
tls:
  origination:
    minProtocolVersion: TLSV1_2
    maxProtocolVersion: TLSV1_3
connectRateLimit:
  tokenBucket:
    maxTokens: 20
    tokensPerFill: 5
    fillInterval: 1s
serviceEntries:
- hosts: [" API.Example.COM. "]
  endpoints:
  - address: " 10.10.20.30 "
`
	for name, decode := range map[string]func() (*configv1.EgressGateway, error){
		"AgentioConfig": func() (*configv1.EgressGateway, error) {
			got, err := applyAgentioConfig("egressGateways:\n- name: egress\n  namespace: agentio-system\n  "+
				strings.ReplaceAll(strings.TrimSpace(content), "\n", "\n  "), nil)
			if err != nil {
				return nil, err
			}
			return got.GetEgressGateways()[0], nil
		},
		"Gateway API parameters": func() (*configv1.EgressGateway, error) {
			return decodeEgressGateway(content)
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, err := decode()
			if err != nil {
				t.Fatal(err)
			}
			if got := config.GetTlsTermination().GetIncludeHosts(); len(got) != 1 || got[0] != "*.example.com" {
				t.Fatalf("TLS termination hosts = %v", got)
			}
			if http := config.GetHttp(); http == nil || http.AcceptHttp_10 == nil || http.GetAcceptHttp_10() {
				t.Fatalf("explicit HTTP/1.0 disable lost: %v", http)
			}
			if config.GetExtProc().GetService() != "gateway-ext-proc.agentio-system.svc.cluster.local" ||
				config.GetExtProc().GetPort() != 9003 {
				t.Fatalf("ext_proc = %+v", config.GetExtProc())
			}
			if got := config.GetHttp().GetStreamIdleTimeout().AsDuration(); got != 90*time.Second {
				t.Fatalf("stream idle timeout = %s", got)
			}
			routing := config.GetHttp().GetRouting()
			if routing.GetFallback().GetTimeout().AsDuration() != 45*time.Second ||
				len(routing.GetHostOverrides()) != 1 {
				t.Fatalf("HTTP routing = %v", routing)
			}
			override := config.GetHttp().GetRouting().GetHostOverrides()[0]
			if len(override.GetHosts()) != 1 || override.GetHosts()[0] != "api.example.com" ||
				override.GetSettings().GetTimeout().AsDuration() != 10*time.Second ||
				override.GetSettings().GetRetries().GetAttempts() != 2 {
				t.Fatalf("host override = %v", override)
			}
			if tcp := config.GetTcp(); tcp.GetIdleTimeout().AsDuration() != 120*time.Second ||
				tcp.GetMaxConnectionDuration().AsDuration() != 600*time.Second {
				t.Fatalf("TCP timeouts = %v", tcp)
			}
			tls := config.GetTls().GetOrigination()
			if tls.GetMinProtocolVersion() != configv1.UpstreamTlsSettings_TLSV1_2 ||
				tls.GetMaxProtocolVersion() != configv1.UpstreamTlsSettings_TLSV1_3 {
				t.Fatalf("TLS origination = %v", tls)
			}
			if got := config.GetConnectRateLimit().GetTokenBucket().GetMaxTokens(); got != 20 {
				t.Fatalf("connect rate max tokens = %d", got)
			}
			entry := config.GetServiceEntries()[0]
			if got := entry.GetHosts()[0]; got != "api.example.com" {
				t.Fatalf("static service host = %q, want canonical host", got)
			}
			if got := entry.GetEndpoints()[0].GetAddress(); got != "10.10.20.30" {
				t.Fatalf("static endpoint address = %q, want canonical IPv4 address", got)
			}
		})
	}
}

func TestExtProcServiceReferenceConfiguration(t *testing.T) {
	for _, tc := range []struct {
		ref     string
		invalid bool
	}{
		{"{namespace: agentio-system, name: agentio-epe}", false},
		{"{}", true},
		{"{name: agentio-epe}", true},
		{"{namespace: agentio-system}", true},
		{"{namespace: agentio-system, name: epe.invalid}", true},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			provider := "    service: legacy.invalid\n    serviceRef: " + tc.ref + "\n    port: 9002\n"
			for _, raw := range []string{
				"sandboxExtProc:\n" + provider,
				"egressGateways:\n- name: egress\n  namespace: agentio-system\n  extProc:\n" + provider,
			} {
				if _, err := applyAgentioConfig(raw, nil); (err != nil) != tc.invalid {
					t.Fatalf("AgentioConfig error=%v, want invalid=%v", err, tc.invalid)
				}
			}
			if _, err := decodeEgressGateway("extProc:\n" + provider); (err != nil) != tc.invalid {
				t.Fatalf("Gateway parameters error=%v, want invalid=%v", err, tc.invalid)
			}
		})
	}
	if _, err := decodeEgressGateway("extProc: {serviceRef: {namespace: system, name: epe}}"); err != nil {
		t.Fatalf("reference-only Gateway parameters: %v", err)
	}
}

func TestGatewayConfigurationRemovedPaths(t *testing.T) {
	for _, content := range []string{
		"connectionPool: {tcp: {idleTimeout: 30s}}",
		"upstreamTls: {minProtocolVersion: TLSV1_2}",
		"http: {defaultRoute: {timeout: 30s}}",
		"http: {routeOverrides: []}",
	} {
		t.Run(content, func(t *testing.T) {
			if _, err := decodeEgressGateway(content); err == nil {
				t.Fatal("Gateway API parameters accepted a removed path")
			}
			if _, err := applyAgentioConfig(
				"egressGateways:\n- name: egress\n  namespace: agentio-system\n  "+content,
				nil,
			); err != nil {
				t.Fatalf("AgentioConfig must ignore removed fields: %v", err)
			}
		})
	}
}

func TestDecodeEgressGatewayRejectsEmbeddedIdentity(t *testing.T) {
	for _, content := range []string{
		"name: egress",
		"namespace: agentio-system",
	} {
		if _, err := decodeEgressGateway(content); err == nil {
			t.Fatalf("decodeEgressGateway(%q) accepted embedded identity", content)
		}
	}
}

func TestDecodeEgressGatewayRejectsWhitespaceExtProcService(t *testing.T) {
	if _, err := decodeEgressGateway(`extProc: {service: " "}`); err == nil {
		t.Fatal("decodeEgressGateway accepted a whitespace-only ext_proc service")
	}
}

func TestGatewayAPIConfigurationsResolveSameNamespaceParameters(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	gateways := krt.NewMutableCollection[*gatewayv1.Gateway](nil, nil, options...)
	classes := krt.NewMutableCollection[*gatewayv1.GatewayClass](nil, nil, options...)
	configMaps := krt.NewMutableCollection[*corev1.ConfigMap](nil, nil, options...)
	configurations := newGatewayAPIConfigurations(
		gateways.AsCollection(),
		classes.AsCollection(),
		configMaps.AsCollection(),
		options...)

	classes.ConditionalUpdateObject(&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "agentio-egress"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: agentioGatewayController,
		},
	})
	configMaps.ConditionalUpdateObject(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "egress-parameters",
		},
		Data: map[string]string{
			gatewayConfigKey: `extProc:
  service: gateway-ext-proc.demo.svc.cluster.local
  port: 9003
`,
		},
	})
	configMaps.ConditionalUpdateObject(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "other",
			Name:      "egress-parameters",
		},
		Data: map[string]string{
			gatewayConfigKey: "name: must-not-be-read",
		},
	})
	gateways.ConditionalUpdateObject(&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "egress",
			Labels:    map[string]string{"istio.io/rev": "canary"},
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "agentio-egress",
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				ParametersRef: &gatewayv1.LocalParametersReference{
					Kind: "ConfigMap",
					Name: "egress-parameters",
				},
			},
		},
	})

	if !configurations.WaitUntilSynced(stop) {
		t.Fatal("Gateway API configuration collection did not sync")
	}
	testutil.Eventually(t, func() bool {
		gateway := configurations.GetKey("demo/egress")
		return gateway != nil &&
			gateway.Source == model.GatewaySourceGatewayAPI &&
			gateway.Config.GetExtProc().GetService() == "gateway-ext-proc.demo.svc.cluster.local"
	}, "same-namespace Gateway parameters")

	for _, content := range []string{"extProc: {}", "{}"} {
		configMaps.ConditionalUpdateObject(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "egress-parameters"},
			Data:       map[string]string{gatewayConfigKey: content},
		})
		testutil.Eventually(t, func() bool {
			gateway := configurations.GetKey("demo/egress")
			if gateway == nil || gateway.ValidateForUse() != nil {
				return false
			}
			provider := gateway.Config.GetExtProc()
			if content == "extProc: {}" {
				return provider != nil && provider.GetService() == ""
			}
			return provider == nil
		}, "Gateway parameters update to "+content)
	}
	configMaps.ConditionalUpdateObject(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "egress-parameters"},
		Data:       map[string]string{gatewayConfigKey: "extProc: {service: before-overlay.demo.svc.cluster.local}"},
	})
	testutil.Eventually(t, func() bool {
		gateway := configurations.GetKey("demo/egress")
		return gateway != nil && gateway.Config.GetExtProc().GetService() == "before-overlay.demo.svc.cluster.local"
	}, "proxy configuration before switching to deployment-only parameters")
	configMaps.ConditionalUpdateObject(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "egress-parameters"},
		Data:       map[string]string{"deployment": "spec: {replicas: 2}"},
	})
	testutil.Eventually(t, func() bool {
		gateway := configurations.GetKey("demo/egress")
		return gateway != nil && gateway.ValidateForUse() == nil && gateway.Config.GetExtProc() == nil
	}, "deployment-only parameters use default proxy configuration")
}

func TestGatewayAPIConfigurationsRetainLastKnownGoodParameters(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	gateways := krt.NewMutableCollection[*gatewayv1.Gateway](nil, nil, options...)
	classes := krt.NewMutableCollection[*gatewayv1.GatewayClass](nil, nil, options...)
	configMaps := krt.NewMutableCollection[*corev1.ConfigMap](nil, nil, options...)
	configurations := newGatewayAPIConfigurations(
		gateways.AsCollection(),
		classes.AsCollection(),
		configMaps.AsCollection(),
		options...)
	classes.ConditionalUpdateObject(&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "agentio-egress"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: agentioGatewayController,
		},
	})
	parameters := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "parameters",
		},
		Data: map[string]string{
			gatewayConfigKey: "extProc:\n  service: valid.demo.svc.cluster.local\n",
		},
	}
	configMaps.ConditionalUpdateObject(parameters)
	gateways.ConditionalUpdateObject(&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "egress",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "agentio-egress",
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				ParametersRef: &gatewayv1.LocalParametersReference{
					Kind: "ConfigMap",
					Name: "parameters",
				},
			},
		},
	})
	if !configurations.WaitUntilSynced(stop) {
		t.Fatal("Gateway API configuration collection did not sync")
	}
	testutil.Eventually(t, func() bool {
		gateway := configurations.GetKey("demo/egress")
		return gateway != nil && gateway.Config.GetExtProc().GetService() == "valid.demo.svc.cluster.local"
	}, "valid initial Gateway parameters")

	invalid := parameters.DeepCopy()
	invalid.Data[gatewayConfigKey] = "extProc: ["
	configMaps.ConditionalUpdateObject(invalid)
	time.Sleep(100 * time.Millisecond)
	gateway := configurations.GetKey("demo/egress")
	if gateway == nil || gateway.Config.GetExtProc().GetService() != "valid.demo.svc.cluster.local" {
		t.Fatalf("invalid parameters replaced last-known-good Gateway: %+v", gateway)
	}

	invalidStaticEntry := parameters.DeepCopy()
	invalidStaticEntry.Data[gatewayConfigKey] = `serviceEntries:
- hosts: ["*.example.com"]
  endpoints:
  - address: 10.10.20.30
`
	configMaps.ConditionalUpdateObject(invalidStaticEntry)
	time.Sleep(100 * time.Millisecond)
	gateway = configurations.GetKey("demo/egress")
	if gateway == nil || gateway.Config.GetExtProc().GetService() != "valid.demo.svc.cluster.local" {
		t.Fatalf("invalid static service entry replaced last-known-good Gateway: %+v", gateway)
	}
}
