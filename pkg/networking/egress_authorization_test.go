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

package networking

import (
	"fmt"
	"slices"
	"testing"

	matching "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"

	udpatypev1 "github.com/cncf/xds/go/udpa/type/v1"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	state "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestEgressTargetFilterStateWritersCompatible(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, terminatedTLS := range []bool{false, true} {
			t.Run(fmt.Sprintf("legacy=%t/tls=%t", legacy, terminatedTLS), func(t *testing.T) {
				b := &resourceBuilder{legacyGateway: legacy}
				h, err := b.buildForwardHCM(HTTPForwardProxy, effectiveConfig{
					gateway: &configv1.EgressGateway{ServiceEntries: []*configv1.EgressServiceEntry{{
						Hosts:     []string{"test.invalid"},
						Endpoints: []*configv1.EgressServiceEntryEndpoint{{Address: "192.0.2.1"}},
					}}},
					extProc: &configv1.ExtProcProvider{Service: "epe", Port: 9002},
				}, terminatedTLS)
				if err != nil {
					t.Fatal(err)
				}
				writes := map[string]bool{}
				lastWriter := map[string]string{}
				for _, filter := range h.HttpFilters {
					cfg := &state.Config{}
					typed := filter.GetTypedConfig()
					if typed.MessageIs(&matching.ExtensionWithMatcher{}) {
						wrapped := &matching.ExtensionWithMatcher{}
						if err := typed.UnmarshalTo(wrapped); err != nil {
							t.Fatal(err)
						}
						typed = wrapped.GetExtensionConfig().GetTypedConfig()
					}
					if !typed.MessageIs(cfg) {
						continue
					}
					if err := typed.UnmarshalTo(cfg); err != nil {
						t.Fatal(err)
					}
					for _, value := range cfg.OnRequestHeaders {
						key := value.GetObjectKey()
						if key != dynamicHostKey && key != dynamicPortKey && key != model.FilterStateRouteUpstream {
							continue
						}
						if previous, exists := writes[key]; exists && (previous || previous != value.ReadOnly) {
							t.Fatalf(
								"%s conflicts with %s writing %s: readOnly=%t -> %t",
								filter.Name, lastWriter[key], key, previous, value.ReadOnly,
							)
						}
						writes[key], lastWriter[key] = value.ReadOnly, filter.Name
					}
				}
				if legacy && (lastWriter[dynamicHostKey] != "agentio.egress_target" ||
					lastWriter[dynamicPortKey] != "agentio.egress_target") {
					t.Fatal("EPE must select the final DFP address")
				}
				if !legacy && lastWriter[model.FilterStateRouteUpstream] != "agentio.egress_target" {
					t.Fatal("missing native upstream writer")
				}
			})
		}
	}
}

func TestEgressAuthorizationPinsOriginalDstTarget(t *testing.T) {
	in := Inputs{
		Gateway: testGateway(
			&configv1.EgressGateway{
				ServiceEntries: []*configv1.EgressServiceEntry{
					{
						Hosts:     []string{"test.invalid"},
						Endpoints: []*configv1.EgressServiceEntryEndpoint{{Address: "192.0.2.1"}},
					},
				},
			},
		),
		DiscoveryAddress: "agentiod:15012",
		TrustDomain:      "cluster.local",
	}
	if _, err := Build(in); err != nil {
		t.Fatal(err)
	}
	in.GlobalExtProc = &configv1.ExtProcProvider{
		Service:          "epe",
		Port:             9002,
		FailureModeAllow: true,
		Request:          &configv1.ProcessingModeOptions{HeaderMode: configv1.HeaderSendMode_SKIP}}
	resources, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	listeners := messagesOf(t, resources, model.ListenerType, func() *listener.Listener { return &listener.Listener{} })
	for _, name := range []string{MainInternal, MainForward} {
		h := findHCM(t, &listener.Listener{FilterChains: []*listener.FilterChain{
			findFilterChain(t, listeners[name], "service-entry|192.0.2.1|http"),
		}})
		names := []string{}
		for _, f := range h.HttpFilters {
			names = append(names, f.Name)
			if f.Name == "agentio.egress_target_guard" {
				t.Error("unexpected rejection when EPE returns no target")
			}
			if f.Name == "agentio.egress_target" {
				cfg := &state.Config{}
				wrapped := &matching.ExtensionWithMatcher{}
				if err := f.GetTypedConfig().UnmarshalTo(wrapped); err != nil {
					t.Fatal(err)
				}
				if err := wrapped.GetExtensionConfig().GetTypedConfig().UnmarshalTo(cfg); err != nil {
					t.Fatal(err)
				}
				for _, value := range cfg.OnRequestHeaders {
					if !value.SkipIfEmpty || !value.GetFormatString().GetOmitEmptyValues() {
						t.Error("missing target must leave DFP filter state unchanged")
					}
				}
			}
			if f.Name == "envoy.filters.http.ext_proc" {
				cfg := &extproc.ExternalProcessor{}
				if err := f.GetTypedConfig().UnmarshalTo(cfg); err != nil {
					t.Fatal(err)
				}
				if !cfg.GetFailureModeAllow() ||
					cfg.GetProcessingMode().GetRequestHeaderMode() != extproc.ProcessingMode_SKIP {
					t.Fatal("provider failure and header modes must be preserved")
				}
				if !slices.Contains(cfg.RequestAttributes, model.AttributeRouteUpstream) {
					t.Fatal("route candidate not forwarded")
				}
				if !slices.Contains(cfg.GetMetadataOptions().GetReceivingNamespaces().GetUntyped(), "agentio.route") {
					t.Fatal("route metadata discarded")
				}
			}
		}
		if slices.Index(names, "agentio.endpoint_upstream") < 0 ||
			slices.Index(names, "agentio.endpoint_upstream") >= slices.Index(names, "envoy.filters.http.ext_proc") {
			t.Fatalf("candidate must precede EPE: %v", names)
		}

		if slices.Index(names, "agentio.egress_target") <= slices.Index(names, "envoy.filters.http.ext_proc") ||
			slices.Index(
				names,
				"agentio.egress_target",
			) >= slices.Index(
				names,
				"agentio.egress_authorization",
			) {
			t.Fatalf("filter order %v", names)
		}
	}
}

func TestNativeForwardingWithoutEPEOrServiceEntries(t *testing.T) {
	b := &resourceBuilder{}
	h, err := b.buildForwardHCM(HTTPForwardProxy, effectiveConfig{gateway: &configv1.EgressGateway{}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := httpFilterNames(
		h,
	); !slices.Equal(
		got,
		[]string{"agentio.egress_authorization", bodyProcessingName, "envoy.filters.http.router"},
	) {
		t.Fatalf("unexpected filters: %v", got)
	}
}

// CIDR updates belong in RDS, so requests on existing HCM connections see them.
func TestHTTPAuthorizationUsesRouteSnapshots(t *testing.T) {
	b := &resourceBuilder{}
	cfg := effectiveConfig{gateway: &configv1.EgressGateway{}}
	before, err := b.buildForwardHCM(HTTPForwardProxy, cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	oldRoute := b.buildForwardRoute(HTTPForwardProxy, cfg.gateway)
	b.egressAuthorization = &configv1.EgressAuthorization{DeniedCidrs: []string{"192.0.2.0/24"}}
	after, err := b.buildForwardHCM(HTTPForwardProxy, cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(before, after) {
		t.Fatal("CIDR update changed HTTP listener configuration")
	}
	decode := func(value *anypb.Any) map[string]any {
		t.Helper()
		config := &udpatypev1.TypedStruct{}
		if err := value.UnmarshalTo(config); err != nil {
			t.Fatal(err)
		}
		return config.Value.AsMap()["filter_config"].(map[string]any)["value"].(map[string]any)
	}
	for _, name := range []string{HTTPForwardProxy, TLSConnectOriginate} {
		route := b.buildForwardRoute(name, cfg.gateway)
		policy := route.TypedPerFilterConfig["agentio.egress_authorization"]
		if proto.Equal(oldRoute.TypedPerFilterConfig["agentio.egress_authorization"], policy) {
			t.Fatal("CIDR update missing from RDS")
		}
		settings := decode(policy)
		if settings["mode"] != "DYNAMIC_FORWARD" ||
			!slices.Contains(settings["denied_cidrs"].([]any), any("192.0.2.0/24")) {
			t.Fatalf("route policy = %v", settings)
		}
		port := float64(80)
		if name == TLSConnectOriginate {
			port = 443
		}
		if settings["default_port"] != port {
			t.Fatalf("default port = %v", settings)
		}
		for _, host := range route.VirtualHosts {
			override := host.Routes[0].TypedPerFilterConfig["agentio.egress_authorization"]
			if name == TLSConnectOriginate {
				if override != nil {
					t.Fatal("HTTPS proxy CONNECT must inherit dynamic forwarding")
				}
			} else if decode(override)["mode"] != "ORIGINAL_DST" {
				t.Fatal("HTTP proxy CONNECT must authorize the original proxy endpoint")
			}
		}
	}
}
