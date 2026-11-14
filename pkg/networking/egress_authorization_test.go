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

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	state "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestEgressTargetFilterStateWritersCompatible(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, terminatedTLS := range []bool{false, true} {
			t.Run(fmt.Sprintf("legacy=%t/tls=%t", legacy, terminatedTLS), func(t *testing.T) {
				b := &resourceBuilder{legacyGateway: legacy}
				h, err := b.buildForwardHCM(HTTPDynamicForwardProxy, effectiveConfig{
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
					if !filter.GetTypedConfig().MessageIs(cfg) {
						continue
					}
					if err := filter.GetTypedConfig().UnmarshalTo(cfg); err != nil {
						t.Fatal(err)
					}
					for _, value := range cfg.OnRequestHeaders {
						key := value.GetObjectKey()
						if key != dynamicHostKey && key != dynamicPortKey {
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
				if lastWriter[dynamicHostKey] != "agentio.egress_target" ||
					lastWriter[dynamicPortKey] != "agentio.egress_target" {
					t.Fatal("EPE must select the final DFP address")
				}
			})
		}
	}
}

func TestEgressAuthorizationPinsDFPTarget(t *testing.T) {
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
				if err := f.GetTypedConfig().UnmarshalTo(cfg); err != nil {
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
		if slices.Index(names, "agentio.route_upstream") <= slices.Index(names, "envoy.filters.http.ext_proc") ||
			slices.Index(names, "agentio.route_upstream") >= slices.Index(names, "agentio.egress_target") {
			t.Fatalf("explicit target consumption must follow EPE and precede authorized override: %v", names)
		}
		if slices.Index(names, "agentio.egress_target") <= slices.Index(names, "envoy.filters.http.ext_proc") ||
			slices.Index(
				names,
				"agentio.egress_target",
			) >= slices.Index(
				names,
				"envoy.filters.http.dynamic_forward_proxy",
			) {
			t.Fatalf("filter order %v", names)
		}
	}
}

func TestRouteUpstreamConsumerWithoutEPEOrServiceEntries(t *testing.T) {
	b := &resourceBuilder{}
	h, err := b.buildForwardHCM(HTTPDynamicForwardProxy, effectiveConfig{gateway: &configv1.EgressGateway{}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := httpFilterNames(h); !slices.Equal(got, []string{
		"agentio.route_upstream",
		"agentio.connect_proxy_authorization",
		"envoy.filters.http.dynamic_forward_proxy",
		"envoy.filters.http.router",
	}) {
		t.Fatalf("unexpected filters: %v", got)
	}
	cfg := &state.Config{}
	if err := h.HttpFilters[0].GetTypedConfig().UnmarshalTo(cfg); err != nil {
		t.Fatal(err)
	}
	value := cfg.OnRequestHeaders[0]
	if value.GetObjectKey() != dynamicHostKey || !value.SkipIfEmpty || value.ReadOnly ||
		value.GetFormatString().
			GetTextFormatSource().
			GetInlineString() !=
			"%FILTER_STATE(agentio.route.upstream:PLAIN)%" {
		t.Fatalf("explicit target must allow EPE overrides and leave absent targets alone: %v", value)
	}
}
