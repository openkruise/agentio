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

package model

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
)

func TestGatewaysFromAgentioConfigNormalizesAndClones(t *testing.T) {
	source := &configv1.EgressGateway{
		Namespace: "agentio-system",
		Name:      "egress",
		ExtProc: &configv1.ExtProcProvider{
			Service: "gateway-ext-proc.agentio-system.svc.cluster.local",
			Port:    9002,
		},
	}
	gateways := GatewaysFromAgentioConfig(&configv1.AgentioConfig{
		EgressGateways: []*configv1.EgressGateway{source},
	})
	if len(gateways) != 1 {
		t.Fatalf("GatewaysFromAgentioConfig() returned %d gateways, want 1", len(gateways))
	}
	gateway := gateways[0]
	if gateway.ResourceName() != "agentio-system/egress" || gateway.Source != GatewaySourceAgentioConfig {
		t.Fatalf("gateway projection = %+v", gateway)
	}
	if gateway.Config.GetName() != "" || gateway.Config.GetNamespace() != "" {
		t.Fatalf("normalized payload retains identity: %+v", gateway.Config)
	}
	if got := gateway.Config.GetExtProc().GetService(); got != "gateway-ext-proc.agentio-system.svc.cluster.local" {
		t.Fatalf("gateway ext_proc = %q", got)
	}
	gateway.Config.ExtProc.Service = "changed"
	if source.GetExtProc().GetService() != "gateway-ext-proc.agentio-system.svc.cluster.local" {
		t.Fatal("normalization mutated the source protobuf")
	}
}

func TestGatewayValidateForUseRejectsDuplicateRouteOverrideHosts(t *testing.T) {
	for _, hosts := range [][]string{
		{"api.example.com", "API.EXAMPLE.COM"},
		{"*.example.com", "*.example.com"},
		{"*", "*"},
	} {
		gateway := Gateway{
			Namespace: "demo",
			Name:      "egress",
			Config: &configv1.EgressGateway{
				Http: &configv1.GatewayHttpSettings{
					Routing: &configv1.HttpRoutingSettings{
						HostOverrides: []*configv1.HttpRouteOverride{{Hosts: hosts[:1]}, {Hosts: hosts[1:]}},
					},
				},
			},
		}
		if err := gateway.ValidateForUse(); err == nil ||
			!strings.Contains(err.Error(), "duplicate route override host") {
			t.Fatalf("hosts %v: expected duplicate host error, got %v", hosts, err)
		}
	}
}

func TestGatewayValidateForUseAllowsExtProcDisable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		provider *configv1.ExtProcProvider
		wantErr  bool
	}{
		{name: "inherit"},
		{name: "disable", provider: &configv1.ExtProcProvider{}},
		{name: "empty service with settings", provider: &configv1.ExtProcProvider{Port: 9002}},
		{name: "override", provider: &configv1.ExtProcProvider{Service: "epe.demo.svc"}},
		{name: "whitespace is invalid", provider: &configv1.ExtProcProvider{Service: " \t"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateway := Gateway{Namespace: "demo", Name: "egress", Config: &configv1.EgressGateway{ExtProc: tc.provider}}
			if err := gateway.ValidateForUse(); (err != nil) != tc.wantErr {
				t.Fatalf("ValidateForUse() = %v, want error = %v", err, tc.wantErr)
			}
		})
	}
}

func TestGatewayDnsCacheValidation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		settings *configv1.DnsCacheSettings
		wantErr  string
	}{
		{name: "omitted"},
		{name: "empty", settings: &configv1.DnsCacheSettings{}},
		{
			name: "configured",
			settings: &configv1.DnsCacheSettings{
				MaxHosts:           new(uint32(16384)),
				MaxPendingRequests: new(uint32(4096)),
				HostTtl:            durationpb.New(5 * time.Minute),
			},
		},
		{name: "zero hosts", settings: &configv1.DnsCacheSettings{MaxHosts: new(uint32)}, wantErr: "dnsCache.maxHosts"},
		{name: "zero pending", settings: &configv1.DnsCacheSettings{MaxPendingRequests: new(uint32)}, wantErr: "dnsCache.maxPendingRequests"},
		{name: "zero TTL", settings: &configv1.DnsCacheSettings{HostTtl: durationpb.New(0)}, wantErr: "dnsCache.hostTtl"},
		{name: "negative TTL", settings: &configv1.DnsCacheSettings{HostTtl: durationpb.New(-time.Second)}, wantErr: "dnsCache.hostTtl"},
		{name: "invalid TTL", settings: &configv1.DnsCacheSettings{HostTtl: &durationpb.Duration{Nanos: 1000000000}}, wantErr: "dnsCache.hostTtl"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateway := Gateway{
				Namespace: "demo",
				Name:      "egress",
				Config:    &configv1.EgressGateway{DnsCache: tc.settings},
			}
			err := gateway.ValidateForUse()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateForUse() = %v, want %s", err, tc.wantErr)
			}
		})
	}
}

func TestGatewayTCPPassthroughValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		match   *configv1.TcpPassthroughMatch
		wantErr bool
	}{
		{name: "all TCP", match: &configv1.TcpPassthroughMatch{}},
		{name: "CIDRs and ports", match: &configv1.TcpPassthroughMatch{Cidrs: []string{"10.20.1.2/16", "2001:db8::/32"}, Ports: []uint32{1, 65535}}},
		{name: "nil entry", wantErr: true},
		{name: "invalid CIDR", match: &configv1.TcpPassthroughMatch{Cidrs: []string{"example.com"}}, wantErr: true},
		{name: "invalid IPv6 prefix", match: &configv1.TcpPassthroughMatch{Cidrs: []string{"::/129"}}, wantErr: true},
		{name: "zero port", match: &configv1.TcpPassthroughMatch{Ports: []uint32{0}}, wantErr: true},
		{name: "port overflow", match: &configv1.TcpPassthroughMatch{Ports: []uint32{65536}}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateway := Gateway{
				Namespace: "demo",
				Name:      "egress",
				Config:    &configv1.EgressGateway{TcpPassthrough: []*configv1.TcpPassthroughMatch{tc.match}},
			}
			if err := gateway.ValidateForUse(); (err != nil) != tc.wantErr {
				t.Fatalf("ValidateForUse()=%v, wantErr=%t", err, tc.wantErr)
			}
		})
	}
}

func TestGatewaysFromAgentioConfigMarksDuplicateIdentityAsConflict(t *testing.T) {
	gateways := GatewaysFromAgentioConfig(&configv1.AgentioConfig{
		EgressGateways: []*configv1.EgressGateway{
			{
				Namespace: "agentio-system",
				Name:      "egress",
			},
			{
				Namespace: "agentio-system",
				Name:      "egress",
			},
		},
	})
	if len(gateways) != 1 {
		t.Fatalf("GatewaysFromAgentioConfig() returned %d gateways, want 1", len(gateways))
	}
	if gateways[0].Source != GatewaySourceConflict || gateways[0].Config != nil {
		t.Fatalf("duplicate gateway projection = %+v", gateways[0])
	}
}

func TestMergeGatewaySources(t *testing.T) {
	source := Gateway{
		Namespace: "agentio-system",
		Name:      "egress",
		Config: &configv1.EgressGateway{
			ExtProc: &configv1.ExtProcProvider{
				Service: "ext-proc.agentio-system.svc.cluster.local",
			},
		},
		Source: GatewaySourceAgentioConfig,
	}
	merged := MergeGatewaySources([]Gateway{source})
	if merged == nil || !merged.Equals(source) {
		t.Fatalf("single-source merge = %+v", merged)
	}
	if merged.Config == source.Config {
		t.Fatal("single-source merge retained the mutable protobuf pointer")
	}

	gatewayAPI := source
	gatewayAPI.Source = GatewaySourceGatewayAPI
	conflict := MergeGatewaySources([]Gateway{source, gatewayAPI})
	if conflict == nil || conflict.Source != GatewaySourceConflict || conflict.Config != nil {
		t.Fatalf("cross-source merge = %+v", conflict)
	}
	if got := MergeGatewaySources(nil); got != nil {
		t.Fatalf("empty merge = %+v", got)
	}
	if !proto.Equal(source.Config, merged.Config) {
		t.Fatalf("cloned payload = %+v, want %+v", merged.Config, source.Config)
	}

	legacy := Gateway{
		Namespace: "agentio-system",
		Name:      "egress",
		Config:    &configv1.EgressGateway{},
		Source:    GatewaySourceLegacyFallback,
	}
	selected := MergeGatewaySources([]Gateway{legacy, gatewayAPI})
	if selected == nil || selected.Source != GatewaySourceGatewayAPI ||
		!proto.Equal(selected.Config, gatewayAPI.Config) {
		t.Fatalf("legacy fallback plus Gateway API declaration = %+v, want Gateway API declaration", selected)
	}
	if selected.Config == gatewayAPI.Config {
		t.Fatal("fallback merge retained the mutable Gateway API protobuf pointer")
	}
	legacyOnly := MergeGatewaySources([]Gateway{legacy, legacy})
	if legacyOnly == nil || legacyOnly.Source != GatewaySourceLegacyFallback || legacyOnly.Config == nil {
		t.Fatalf("duplicate inferred fallbacks = %+v, want one fallback", legacyOnly)
	}
}

func TestGatewaysFromAgentioConfigPreservesLegacyAgentioGatewayPolicy(t *testing.T) {
	config := &configv1.AgentioConfig{
		EgressPolicies: []*extensionsv1.EgressPolicy{{
			Policy: extensionsv1.EgressPolicyAction_GATEWAY,
			Gateway: &extensionsv1.GatewayAddress{
				Service: "egress-gateway.agentio-system.svc.cluster.local",
			},
		}},
	}

	gateways := GatewaysFromAgentioConfig(config)
	if len(gateways) != 1 {
		t.Fatalf("GatewaysFromAgentioConfig() returned %d gateways, want 1", len(gateways))
	}
	gateway := gateways[0]
	if gateway.ResourceName() != "agentio-system/egress-gateway" || gateway.Source != GatewaySourceLegacyFallback {
		t.Fatalf("legacy gateway projection = %+v", gateway)
	}
	if gateway.Config == nil || !proto.Equal(gateway.Config, &configv1.EgressGateway{}) {
		t.Fatalf("legacy gateway config = %+v", gateway.Config)
	}
}

func TestGatewayValidateForUseRejectsInvalidStaticServiceEntries(t *testing.T) {
	endpoint := func(address string) *configv1.EgressServiceEntryEndpoint {
		return &configv1.EgressServiceEntryEndpoint{Address: address}
	}
	entry := func(hosts []string, endpoints ...*configv1.EgressServiceEntryEndpoint) *configv1.EgressServiceEntry {
		return &configv1.EgressServiceEntry{Hosts: hosts, Endpoints: endpoints}
	}
	validEntry := func() *configv1.EgressServiceEntry {
		return entry([]string{"api.example.com"}, endpoint("10.10.20.30"))
	}
	tests := []struct {
		name    string
		entries []*configv1.EgressServiceEntry
	}{
		{name: "nil service entry", entries: []*configv1.EgressServiceEntry{nil}},
		{name: "missing hosts", entries: []*configv1.EgressServiceEntry{entry(nil, endpoint("10.10.20.30"))}},
		{name: "missing endpoints", entries: []*configv1.EgressServiceEntry{entry([]string{"api.example.com"})}},
		{
			name:    "noncanonical host",
			entries: []*configv1.EgressServiceEntry{entry([]string{"API.Example.COM."}, endpoint("10.10.20.30"))},
		},
		{
			name:    "wildcard host",
			entries: []*configv1.EgressServiceEntry{entry([]string{"*.example.com"}, endpoint("10.10.20.30"))},
		},
		{
			name:    "numeric top-level domain",
			entries: []*configv1.EgressServiceEntry{entry([]string{"api.123"}, endpoint("10.10.20.30"))},
		},
		{name: "duplicate host", entries: []*configv1.EgressServiceEntry{validEntry(), validEntry()}},
		{name: "nil endpoint", entries: []*configv1.EgressServiceEntry{entry([]string{"api.example.com"}, nil)}},
		{
			name:    "IPv6 endpoint",
			entries: []*configv1.EgressServiceEntry{entry([]string{"api.example.com"}, endpoint("2001:db8::1"))},
		},
		{
			name: "duplicate endpoint",
			entries: []*configv1.EgressServiceEntry{
				entry([]string{"api.example.com"}, endpoint("10.10.20.30"), endpoint("10.10.20.30")),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gateway := Gateway{
				Namespace: "demo",
				Name:      "egress",
				Source:    GatewaySourceGatewayAPI,
				Config:    &configv1.EgressGateway{ServiceEntries: tc.entries},
			}
			if err := gateway.ValidateForUse(); err == nil {
				t.Fatal("ValidateForUse() accepted invalid static service entries")
			}
		})
	}
}

func TestGatewayKeyFromService(t *testing.T) {
	tests := []struct {
		service string
		want    string
		valid   bool
	}{
		{service: "egress.agentio-system", want: "agentio-system/egress", valid: true},
		{service: "egress.agentio-system.svc.cluster.local", want: "agentio-system/egress", valid: true},
		{service: " egress.agentio-system.svc.cluster.local. ", want: "agentio-system/egress", valid: true},
		{service: ""},
		{service: "egress"},
		{service: ".agentio-system"},
		{service: "egress..svc.cluster.local"},
	}
	for _, tc := range tests {
		t.Run(tc.service, func(t *testing.T) {
			got, valid := GatewayKeyFromService(tc.service)
			if got != tc.want || valid != tc.valid {
				t.Fatalf("GatewayKeyFromService(%q) = %q, %v; want %q, %v",
					tc.service, got, valid, tc.want, tc.valid)
			}
		})
	}
}
