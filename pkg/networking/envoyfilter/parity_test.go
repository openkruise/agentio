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

package envoyfilter

import (
	"slices"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/openkruise/agentio/pkg/model"
)

func TestAgentioReplaceAndInsertParity(t *testing.T) {
	replacement := func(value int) (bool, int) {
		if value == 1 {
			return true, 10
		}
		return false, 0
	}
	tests := []struct {
		name         string
		input        []int
		replace      []int
		insertBefore []int
		insertAfter  []int
		applied      bool
	}{
		{name: "nil slice"},
		{
			name:         "the first",
			input:        []int{1, 2, 3},
			replace:      []int{10, 2, 3},
			insertBefore: []int{10, 1, 2, 3},
			insertAfter:  []int{1, 10, 2, 3},
			applied:      true,
		},
		{
			name:         "the middle",
			input:        []int{0, 1, 2, 3},
			replace:      []int{0, 10, 2, 3},
			insertBefore: []int{0, 10, 1, 2, 3},
			insertAfter:  []int{0, 1, 10, 2, 3},
			applied:      true,
		},
		{
			name:         "the last",
			input:        []int{3, 2, 1},
			replace:      []int{3, 2, 10},
			insertBefore: []int{3, 2, 10, 1},
			insertAfter:  []int{3, 2, 1, 10},
			applied:      true,
		},
		{
			name:         "match multiple",
			input:        []int{1, 2, 1},
			replace:      []int{10, 2, 1},
			insertBefore: []int{10, 1, 2, 1},
			insertAfter:  []int{1, 10, 2, 1},
			applied:      true,
		},
		{
			name:         "not found",
			input:        []int{2, 3},
			replace:      []int{2, 3},
			insertBefore: []int{2, 3},
			insertAfter:  []int{2, 3},
			applied:      false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, applied := replaceFirst(slices.Clone(tc.input), replacement)
			if !slices.Equal(got, tc.replace) || applied != tc.applied {
				t.Fatalf("replaceFirst() = %v, %v, want %v, %v", got, applied, tc.replace, tc.applied)
			}
			got, applied = insertBefore(slices.Clone(tc.input), replacement)
			if !slices.Equal(got, tc.insertBefore) || applied != tc.applied {
				t.Fatalf("insertBefore() = %v, %v, want %v, %v", got, applied, tc.insertBefore, tc.applied)
			}
			got, applied = insertAfter(slices.Clone(tc.input), replacement)
			if !slices.Equal(got, tc.insertAfter) || applied != tc.applied {
				t.Fatalf("insertAfter() = %v, %v, want %v, %v", got, applied, tc.insertAfter, tc.applied)
			}
		})
	}
}

func TestAgentioClusterMatchParity(t *testing.T) {
	tests := []struct {
		name    string
		cluster string
		match   *model.ClusterMatch
		want    bool
	}{
		{name: "nil match", cluster: "main_forward", want: true},
		{name: "name match", cluster: "main_forward", match: &model.ClusterMatch{Name: "main_forward"}, want: true},
		{name: "name mismatch", cluster: "scrappy", match: &model.ClusterMatch{Name: "scooby"}},
		{name: "subset mismatch", cluster: "outbound|80|v2|foo.bar", match: &model.ClusterMatch{PortNumber: 80, Service: "foo.bar", Subset: "v1"}},
		{name: "service mismatch", cluster: "outbound|80|v1|google.com", match: &model.ClusterMatch{PortNumber: 80, Service: "foo.bar", Subset: "v1"}},
		{name: "port mismatch", cluster: "outbound|90|v1|foo.bar", match: &model.ClusterMatch{PortNumber: 80, Service: "foo.bar", Subset: "v1"}},
		{name: "full match", cluster: "outbound|80|v1|foo.bar", match: &model.ClusterMatch{PortNumber: 80, Service: "foo.bar", Subset: "v1"}, want: true},
		{name: "legacy separator full match", cluster: "outbound_.80_.v1_.foo.bar", match: &model.ClusterMatch{PortNumber: 80, Service: "foo.bar", Subset: "v1"}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			patch := Patch{Target: model.ClusterPatch{Match: tc.match}}
			if got := clusterMatches(&clusterv3.Cluster{Name: tc.cluster}, patch); got != tc.want {
				t.Fatalf("clusterMatches() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAgentioListenerMatchParity(t *testing.T) {
	listener := &listenerv3.Listener{
		Name: "main",
		Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
			Address:       "0.0.0.0",
			PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: 15001},
		}}},
		ListenerFilters: []*listenerv3.ListenerFilter{{Name: "listener-a"}},
		FilterChains: []*listenerv3.FilterChain{{
			Name: "chain-a",
			FilterChainMatch: &listenerv3.FilterChainMatch{
				ServerNames:          []string{"example.com", "*.example.com"},
				TransportProtocol:    "tls",
				ApplicationProtocols: []string{"h2", "http/1.1"},
				DestinationPort:      wrapperspb.UInt32(443),
			},
			Filters: []*listenerv3.Filter{{Name: "network-a"}},
		}},
	}
	chain := listener.FilterChains[0]
	tests := []struct {
		name  string
		match *model.ListenerMatch
		want  bool
	}{
		{name: "nil match", want: true},
		{name: "listener name and port", match: &model.ListenerMatch{Name: "main", PortNumber: 15001}, want: true},
		{name: "listener name mismatch", match: &model.ListenerMatch{Name: "other"}},
		{name: "listener port mismatch", match: &model.ListenerMatch{PortNumber: 15002}},
		{
			name: "filter chain full match",
			match: &model.ListenerMatch{FilterChain: &model.FilterChainMatch{
				Name:                 "chain-a",
				SNI:                  "example.com",
				TransportProtocol:    "tls",
				ApplicationProtocols: "h2,http/1.1",
				DestinationPort:      443,
			}},
			want: true,
		},
		{name: "filter chain name mismatch", match: &model.ListenerMatch{FilterChain: &model.FilterChainMatch{Name: "chain-b"}}},
		{name: "SNI mismatch", match: &model.ListenerMatch{FilterChain: &model.FilterChainMatch{SNI: "other.example.com"}}},
		{name: "transport mismatch", match: &model.ListenerMatch{FilterChain: &model.FilterChainMatch{TransportProtocol: "raw_buffer"}}},
		{name: "one application protocol missing", match: &model.ListenerMatch{FilterChain: &model.FilterChainMatch{ApplicationProtocols: "h2,http/3"}}},
		{name: "destination port mismatch", match: &model.ListenerMatch{FilterChain: &model.FilterChainMatch{DestinationPort: 8443}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			patch := Patch{Target: model.NetworkFilterPatch{Match: tc.match}}
			got := listenerMatches(listener, patch)
			if got && tc.match != nil && tc.match.FilterChain != nil {
				got = filterChainMatches(listener, chain, patch)
			}
			if got != tc.want {
				t.Fatalf("listener/filterChain match = %v, want %v", got, tc.want)
			}
		})
	}

	listenerFilterPatch := Patch{Target: model.ListenerFilterPatch{Match: &model.ListenerMatch{ListenerFilter: "listener-a"}}}
	if !listenerFilterMatches(listener.ListenerFilters[0], listenerFilterPatch) {
		t.Fatal("listener filter name did not match")
	}
	networkPatch := Patch{Target: model.NetworkFilterPatch{Match: &model.ListenerMatch{FilterChain: &model.FilterChainMatch{
		Filter: &model.FilterMatch{Name: "network-a"},
	}}}}
	if !networkFilterMatches(chain.Filters[0], networkPatch) {
		t.Fatal("network filter name did not match")
	}
	httpPatch := Patch{Target: model.HTTPFilterPatch{Match: &model.ListenerMatch{FilterChain: &model.FilterChainMatch{
		Filter: &model.FilterMatch{Name: httpConnectionManagerFilter, SubFilter: &model.SubFilterMatch{Name: "http-a"}},
	}}}}
	if !httpFilterMatches(&hcmv3.HttpFilter{Name: "http-a"}, httpPatch) || httpFilterMatches(&hcmv3.HttpFilter{Name: "http-b"}, httpPatch) {
		t.Fatal("HTTP sub-filter matching diverged from Agentio")
	}
}

func TestAgentioListenerFilterOperationParity(t *testing.T) {
	baseConfig := mustStructAny(t, map[string]any{"base": true})
	patchConfig := mustStructAny(t, map[string]any{"patch": true})
	tests := []struct {
		name      string
		operation model.PatchOperation
		matched   string
		value     *listenerv3.ListenerFilter
		want      []string
		wantMerge bool
	}{
		{name: "add", operation: model.PatchAdd, value: &listenerv3.ListenerFilter{Name: "x"}, want: []string{"a", "b", "x"}},
		{name: "insert first", operation: model.PatchInsertFirst, value: &listenerv3.ListenerFilter{Name: "x"}, want: []string{"x", "a", "b"}},
		{name: "insert before", operation: model.PatchInsertBefore, matched: "b", value: &listenerv3.ListenerFilter{Name: "x"}, want: []string{"a", "x", "b"}},
		{name: "insert after", operation: model.PatchInsertAfter, matched: "a", value: &listenerv3.ListenerFilter{Name: "x"}, want: []string{"a", "x", "b"}},
		{name: "replace", operation: model.PatchReplace, matched: "b", value: &listenerv3.ListenerFilter{Name: "x"}, want: []string{"a", "x"}},
		{name: "remove", operation: model.PatchRemove, matched: "a", want: []string{"b"}},
		{
			name:      "merge typed config",
			operation: model.PatchMerge,
			matched:   "a",
			value: &listenerv3.ListenerFilter{
				ConfigType: &listenerv3.ListenerFilter_TypedConfig{TypedConfig: patchConfig},
			},
			want:      []string{"a", "b"},
			wantMerge: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match := &model.ListenerMatch{Name: "main", ListenerFilter: tc.matched}
			policy := parityPolicy(t, tc.name, model.EnvoyPatch{
				Operation: tc.operation,
				Target: model.ListenerFilterPatch{
					Match: match,
					Value: tc.value,
				},
			})
			input := []*listenerv3.Listener{{
				Name: "main",
				ListenerFilters: []*listenerv3.ListenerFilter{
					{Name: "a", ConfigType: &listenerv3.ListenerFilter_TypedConfig{TypedConfig: baseConfig}},
					{Name: "b"},
				},
			}}
			got, err := ApplyListeners(NewPatchSet([]model.GatewayPatch{policy}), input)
			if err != nil {
				t.Fatal(err)
			}
			if names := listenerFilterNames(got[0].ListenerFilters); !slices.Equal(names, tc.want) {
				t.Fatalf("listener filters = %v, want %v", names, tc.want)
			}
			if tc.wantMerge {
				configuration := &structpb.Struct{}
				if err := got[0].ListenerFilters[0].GetTypedConfig().UnmarshalTo(configuration); err != nil {
					t.Fatal(err)
				}
				if configuration.GetFields()["base"] == nil || configuration.GetFields()["patch"] == nil {
					t.Fatalf("merged listener filter config = %v", configuration)
				}
			}
			if listenerFilterNames(input[0].ListenerFilters)[0] != "a" {
				t.Fatal("input listener filters were mutated")
			}
		})
	}
}

func TestAgentioListenerOperationParity(t *testing.T) {
	tests := []struct {
		name      string
		operation model.PatchOperation
		match     *model.ListenerMatch
		value     *listenerv3.Listener
		wantNames []string
		wantMerge bool
	}{
		{
			name:      "add",
			operation: model.PatchAdd,
			value:     &listenerv3.Listener{Name: "added"},
			wantNames: []string{"main", "other", "added"},
		},
		{
			name:      "merge",
			operation: model.PatchMerge,
			match:     &model.ListenerMatch{Name: "main"},
			value:     &listenerv3.Listener{TrafficDirection: corev3.TrafficDirection_INBOUND},
			wantNames: []string{"main", "other"},
			wantMerge: true,
		},
		{
			name:      "remove",
			operation: model.PatchRemove,
			match:     &model.ListenerMatch{Name: "main"},
			wantNames: []string{"other"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := parityPolicy(t, "listener-"+tc.name, model.EnvoyPatch{
				Operation: tc.operation,
				Target: model.ListenerPatch{
					Match: tc.match,
					Value: tc.value,
				},
			})
			input := []*listenerv3.Listener{{Name: "main"}, {Name: "other"}}
			got, err := ApplyListeners(NewPatchSet([]model.GatewayPatch{policy}), input)
			if err != nil {
				t.Fatal(err)
			}
			if names := listenerNames(got); !slices.Equal(names, tc.wantNames) {
				t.Fatalf("listeners = %v, want %v", names, tc.wantNames)
			}
			if tc.wantMerge && got[0].GetTrafficDirection() != corev3.TrafficDirection_INBOUND {
				t.Fatalf("merged traffic direction = %v", got[0].GetTrafficDirection())
			}
			if input[0].GetTrafficDirection() != corev3.TrafficDirection_UNSPECIFIED {
				t.Fatal("input listener was mutated")
			}
		})
	}
}

func TestAgentioFilterChainOperationParity(t *testing.T) {
	tests := []struct {
		name      string
		operation model.PatchOperation
		matched   string
		value     *listenerv3.FilterChain
		wantNames []string
		wantMerge bool
	}{
		{
			name:      "add",
			operation: model.PatchAdd,
			value:     &listenerv3.FilterChain{Name: "added", Filters: []*listenerv3.Filter{{Name: "network-added"}}},
			wantNames: []string{"a", "b", "added"},
		},
		{
			name:      "merge",
			operation: model.PatchMerge,
			matched:   "a",
			value:     &listenerv3.FilterChain{FilterChainMatch: &listenerv3.FilterChainMatch{TransportProtocol: "tls"}},
			wantNames: []string{"a", "b"},
			wantMerge: true,
		},
		{name: "remove", operation: model.PatchRemove, matched: "a", wantNames: []string{"b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := parityPolicy(t, "filter-chain-"+tc.name, model.EnvoyPatch{
				Operation: tc.operation,
				Target: model.FilterChainPatch{
					Match: &model.ListenerMatch{Name: "main", FilterChain: &model.FilterChainMatch{Name: tc.matched}},
					Value: tc.value,
				},
			})
			input := []*listenerv3.Listener{{
				Name: "main",
				FilterChains: []*listenerv3.FilterChain{
					{Name: "a", Filters: []*listenerv3.Filter{{Name: "network-a"}}},
					{Name: "b", Filters: []*listenerv3.Filter{{Name: "network-b"}}},
				},
			}}
			got, err := ApplyListeners(NewPatchSet([]model.GatewayPatch{policy}), input)
			if err != nil {
				t.Fatal(err)
			}
			if names := filterChainNames(got[0].FilterChains); !slices.Equal(names, tc.wantNames) {
				t.Fatalf("filter chains = %v, want %v", names, tc.wantNames)
			}
			if tc.wantMerge && got[0].FilterChains[0].GetFilterChainMatch().GetTransportProtocol() != "tls" {
				t.Fatalf("merged filter chain = %+v", got[0].FilterChains[0])
			}
			if input[0].FilterChains[0].GetFilterChainMatch().GetTransportProtocol() != "" {
				t.Fatal("input filter chain was mutated")
			}
		})
	}
}

func TestAgentioNetworkFilterOperationParity(t *testing.T) {
	baseConfig := mustStructAny(t, map[string]any{"base": true})
	patchConfig := mustStructAny(t, map[string]any{"patch": true})
	tests := []struct {
		name      string
		operation model.PatchOperation
		matched   string
		value     *listenerv3.Filter
		want      []string
		wantMerge bool
	}{
		{name: "add", operation: model.PatchAdd, value: &listenerv3.Filter{Name: "x"}, want: []string{"a", "b", "x"}},
		{name: "insert first", operation: model.PatchInsertFirst, value: &listenerv3.Filter{Name: "x"}, want: []string{"x", "a", "b"}},
		{name: "insert before", operation: model.PatchInsertBefore, matched: "b", value: &listenerv3.Filter{Name: "x"}, want: []string{"a", "x", "b"}},
		{name: "insert after", operation: model.PatchInsertAfter, matched: "a", value: &listenerv3.Filter{Name: "x"}, want: []string{"a", "x", "b"}},
		{name: "replace", operation: model.PatchReplace, matched: "b", value: &listenerv3.Filter{Name: "x"}, want: []string{"a", "x"}},
		{name: "remove", operation: model.PatchRemove, matched: "a", want: []string{"b"}},
		{
			name:      "merge typed config",
			operation: model.PatchMerge,
			matched:   "a",
			value: &listenerv3.Filter{
				ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: patchConfig},
			},
			want:      []string{"a", "b"},
			wantMerge: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match := &model.ListenerMatch{Name: "main", FilterChain: &model.FilterChainMatch{Name: "chain"}}
			if tc.matched != "" {
				match.FilterChain.Filter = &model.FilterMatch{Name: tc.matched}
			}
			policy := parityPolicy(t, "network-"+tc.name, model.EnvoyPatch{
				Operation: tc.operation,
				Target: model.NetworkFilterPatch{
					Match: match,
					Value: tc.value,
				},
			})
			input := []*listenerv3.Listener{{
				Name: "main",
				FilterChains: []*listenerv3.FilterChain{{
					Name: "chain",
					Filters: []*listenerv3.Filter{
						{Name: "a", ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: baseConfig}},
						{Name: "b"},
					},
				}},
			}}
			got, err := ApplyListeners(NewPatchSet([]model.GatewayPatch{policy}), input)
			if err != nil {
				t.Fatal(err)
			}
			filters := got[0].FilterChains[0].Filters
			if names := networkFilterNames(filters); !slices.Equal(names, tc.want) {
				t.Fatalf("network filters = %v, want %v", names, tc.want)
			}
			if tc.wantMerge {
				configuration := &structpb.Struct{}
				if err := filters[0].GetTypedConfig().UnmarshalTo(configuration); err != nil {
					t.Fatal(err)
				}
				if configuration.GetFields()["base"] == nil || configuration.GetFields()["patch"] == nil {
					t.Fatalf("merged network filter config = %v", configuration)
				}
			}
			if names := networkFilterNames(input[0].FilterChains[0].Filters); !slices.Equal(names, []string{"a", "b"}) {
				t.Fatalf("input network filters were mutated: %v", names)
			}
		})
	}
}

func TestAgentioHTTPFilterOperationParity(t *testing.T) {
	baseConfig := mustStructAny(t, map[string]any{"base": true})
	patchConfig := mustStructAny(t, map[string]any{"patch": true})
	tests := []struct {
		name      string
		operation model.PatchOperation
		matched   string
		value     *hcmv3.HttpFilter
		want      []string
		wantMerge bool
	}{
		{name: "add", operation: model.PatchAdd, value: &hcmv3.HttpFilter{Name: "x"}, want: []string{"a", "b", "x"}},
		{name: "insert first", operation: model.PatchInsertFirst, value: &hcmv3.HttpFilter{Name: "x"}, want: []string{"x", "a", "b"}},
		{name: "insert before", operation: model.PatchInsertBefore, matched: "b", value: &hcmv3.HttpFilter{Name: "x"}, want: []string{"a", "x", "b"}},
		{name: "insert after", operation: model.PatchInsertAfter, matched: "a", value: &hcmv3.HttpFilter{Name: "x"}, want: []string{"a", "x", "b"}},
		{name: "replace", operation: model.PatchReplace, matched: "b", value: &hcmv3.HttpFilter{Name: "x"}, want: []string{"a", "x"}},
		{name: "remove", operation: model.PatchRemove, matched: "a", want: []string{"b"}},
		{
			name:      "merge typed config",
			operation: model.PatchMerge,
			matched:   "a",
			value: &hcmv3.HttpFilter{
				ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: patchConfig},
			},
			want:      []string{"a", "b"},
			wantMerge: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match := &model.ListenerMatch{
				Name: "main",
				FilterChain: &model.FilterChainMatch{
					Name:   "chain",
					Filter: &model.FilterMatch{Name: httpConnectionManagerFilter},
				},
			}
			if tc.matched != "" {
				match.FilterChain.Filter.SubFilter = &model.SubFilterMatch{Name: tc.matched}
			}
			policy := parityPolicy(t, "http-"+tc.name, model.EnvoyPatch{
				Operation: tc.operation,
				Target: model.HTTPFilterPatch{
					Match: match,
					Value: tc.value,
				},
			})
			input := listenerWithHTTPFilters(t, []*hcmv3.HttpFilter{
				{Name: "a", ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: baseConfig}},
				{Name: "b"},
			})
			got, err := ApplyListeners(NewPatchSet([]model.GatewayPatch{policy}), input)
			if err != nil {
				t.Fatal(err)
			}
			manager := unmarshalHCM(t, got[0].FilterChains[0].Filters[0])
			if names := httpFilterNamesForParity(manager.HttpFilters); !slices.Equal(names, tc.want) {
				t.Fatalf("HTTP filters = %v, want %v", names, tc.want)
			}
			if tc.wantMerge {
				configuration := &structpb.Struct{}
				if err := manager.HttpFilters[0].GetTypedConfig().UnmarshalTo(configuration); err != nil {
					t.Fatal(err)
				}
				if configuration.GetFields()["base"] == nil || configuration.GetFields()["patch"] == nil {
					t.Fatalf("merged HTTP filter config = %v", configuration)
				}
			}
			original := unmarshalHCM(t, input[0].FilterChains[0].Filters[0])
			if names := httpFilterNamesForParity(original.HttpFilters); !slices.Equal(names, []string{"a", "b"}) {
				t.Fatalf("input HTTP filters were mutated: %v", names)
			}
		})
	}
}

func TestAgentioRouteMatchParity(t *testing.T) {
	t.Run("route configuration", func(t *testing.T) {
		tests := []struct {
			name          string
			configuration string
			match         *model.RouteConfigurationMatch
			want          bool
		}{
			{name: "nil match", configuration: "anything", want: true},
			{name: "name match", configuration: "http_dynamic_forward_proxy", match: &model.RouteConfigurationMatch{Name: "http_dynamic_forward_proxy"}, want: true},
			{name: "name mismatch", configuration: "scooby.90", match: &model.RouteConfigurationMatch{Name: "scooby.80"}},
			{name: "HTTP published port", configuration: "http.8080", match: &model.RouteConfigurationMatch{PortNumber: 8080}, want: true},
			{name: "HTTP port mismatch", configuration: "http.8080", match: &model.RouteConfigurationMatch{PortNumber: 80}},
			{
				name:          "gateway fields match",
				configuration: "https.443.app1.gw1.ns1",
				match: &model.RouteConfigurationMatch{
					PortNumber: 443,
					PortName:   "app1",
					Gateway:    "ns1/gw1",
				},
				want: true,
			},
			{
				name:          "gateway fields mismatch",
				configuration: "http.80",
				match: &model.RouteConfigurationMatch{
					PortNumber: 443,
					PortName:   "app1",
					Gateway:    "ns1/gw1",
				},
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				patch := Patch{Target: model.RouteConfigurationPatch{Match: tc.match}}
				if got := routeConfigurationMatches(&routev3.RouteConfiguration{Name: tc.configuration}, patch); got != tc.want {
					t.Fatalf("routeConfigurationMatches() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("virtual host", func(t *testing.T) {
		tests := []struct {
			name  string
			host  *routev3.VirtualHost
			match *model.VirtualHostMatch
			want  bool
		}{
			{name: "nil virtual host", match: &model.VirtualHostMatch{}},
			{name: "name match", host: &routev3.VirtualHost{Name: "scooby"}, match: &model.VirtualHostMatch{Name: "scooby"}, want: true},
			{name: "name mismatch", host: &routev3.VirtualHost{Name: "scoobydoo"}, match: &model.VirtualHostMatch{Name: "scooby"}},
			{name: "domain match", host: &routev3.VirtualHost{Name: "scoobydoo", Domains: []string{"*.scooby", "*.com"}}, match: &model.VirtualHostMatch{DomainName: "*.scooby"}, want: true},
			{name: "name and domain match", host: &routev3.VirtualHost{Name: "scoobydoo", Domains: []string{"*.scooby", "*.com"}}, match: &model.VirtualHostMatch{Name: "scoobydoo", DomainName: "*.scooby"}, want: true},
			{name: "domain mismatch", host: &routev3.VirtualHost{Name: "scoobydoo", Domains: []string{"*.scooby", "*.com"}}, match: &model.VirtualHostMatch{DomainName: "*.invalid"}},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				patch := Patch{Target: model.VirtualHostPatch{Match: &model.RouteConfigurationMatch{VirtualHost: tc.match}}}
				if got := virtualHostMatches(tc.host, patch); got != tc.want {
					t.Fatalf("virtualHostMatches() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("HTTP route action", func(t *testing.T) {
		tests := []struct {
			name   string
			route  *routev3.Route
			match  model.RouteMatch
			wanted bool
		}{
			{name: "nil route", match: model.RouteMatch{}},
			{name: "name match", route: &routev3.Route{Name: "scooby"}, match: model.RouteMatch{Name: "scooby"}, wanted: true},
			{name: "route action", route: &routev3.Route{Action: &routev3.Route_Route{Route: &routev3.RouteAction{}}}, match: model.RouteMatch{Action: model.RouteActionRoute}, wanted: true},
			{name: "redirect action", route: &routev3.Route{Action: &routev3.Route_Redirect{Redirect: &routev3.RedirectAction{}}}, match: model.RouteMatch{Action: model.RouteActionRedirect}, wanted: true},
			{name: "direct response action", route: &routev3.Route{Action: &routev3.Route_DirectResponse{DirectResponse: &routev3.DirectResponseAction{}}}, match: model.RouteMatch{Action: model.RouteActionDirectResponse}, wanted: true},
			{name: "action mismatch", route: &routev3.Route{Action: &routev3.Route_Redirect{Redirect: &routev3.RedirectAction{}}}, match: model.RouteMatch{Action: model.RouteActionRoute}},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				patch := Patch{Target: model.HTTPRoutePatch{Match: &model.RouteConfigurationMatch{VirtualHost: &model.VirtualHostMatch{Route: &tc.match}}}}
				if got := httpRouteMatches(tc.route, patch); got != tc.wanted {
					t.Fatalf("httpRouteMatches() = %v, want %v", got, tc.wanted)
				}
			})
		}
	})
}

func TestAgentioHTTPRouteOperationParity(t *testing.T) {
	tests := []struct {
		name      string
		operation model.PatchOperation
		matched   string
		value     *routev3.Route
		want      []string
	}{
		{name: "add", operation: model.PatchAdd, value: &routev3.Route{Name: "x"}, want: []string{"a", "b", "x"}},
		{name: "insert first", operation: model.PatchInsertFirst, matched: "b", value: &routev3.Route{Name: "x"}, want: []string{"x", "a", "b"}},
		{name: "insert before", operation: model.PatchInsertBefore, matched: "b", value: &routev3.Route{Name: "x"}, want: []string{"a", "x", "b"}},
		{name: "insert after", operation: model.PatchInsertAfter, matched: "a", value: &routev3.Route{Name: "x"}, want: []string{"a", "x", "b"}},
		{name: "merge", operation: model.PatchMerge, matched: "a", value: &routev3.Route{Name: "merged"}, want: []string{"merged", "b"}},
		{name: "remove", operation: model.PatchRemove, matched: "a", want: []string{"b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match := &model.RouteConfigurationMatch{Name: "routes", VirtualHost: &model.VirtualHostMatch{Name: "host"}}
			if tc.matched != "" {
				match.VirtualHost.Route = &model.RouteMatch{Name: tc.matched}
			}
			policy := parityPolicy(t, "route-"+tc.name, model.EnvoyPatch{
				Operation: tc.operation,
				Target: model.HTTPRoutePatch{
					Match: match,
					Value: tc.value,
				},
			})
			input := []*routev3.RouteConfiguration{{
				Name: "routes",
				VirtualHosts: []*routev3.VirtualHost{{
					Name:   "host",
					Routes: []*routev3.Route{{Name: "a"}, {Name: "b"}},
				}},
			}}
			got, err := ApplyRoutes(NewPatchSet([]model.GatewayPatch{policy}), input)
			if err != nil {
				t.Fatal(err)
			}
			if names := routeNames(got[0].VirtualHosts[0].Routes); !slices.Equal(names, tc.want) {
				t.Fatalf("HTTP routes = %v, want %v", names, tc.want)
			}
			if names := routeNames(input[0].VirtualHosts[0].Routes); !slices.Equal(names, []string{"a", "b"}) {
				t.Fatalf("input HTTP routes were mutated: %v", names)
			}
		})
	}
}

func TestAgentioVirtualHostOperationParity(t *testing.T) {
	tests := []struct {
		name      string
		operation model.PatchOperation
		matched   string
		value     *routev3.VirtualHost
		want      []string
	}{
		{name: "add", operation: model.PatchAdd, value: &routev3.VirtualHost{Name: "x"}, want: []string{"a", "b", "x"}},
		{name: "merge", operation: model.PatchMerge, matched: "a", value: &routev3.VirtualHost{Name: "merged"}, want: []string{"merged", "b"}},
		{name: "replace", operation: model.PatchReplace, matched: "b", value: &routev3.VirtualHost{Name: "x"}, want: []string{"a", "x"}},
		{name: "remove", operation: model.PatchRemove, matched: "a", want: []string{"b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			match := &model.RouteConfigurationMatch{Name: "routes"}
			if tc.matched != "" {
				match.VirtualHost = &model.VirtualHostMatch{Name: tc.matched}
			}
			policy := parityPolicy(t, "vhost-"+tc.name, model.EnvoyPatch{
				Operation: tc.operation,
				Target: model.VirtualHostPatch{
					Match: match,
					Value: tc.value,
				},
			})
			input := []*routev3.RouteConfiguration{{Name: "routes", VirtualHosts: []*routev3.VirtualHost{{Name: "a"}, {Name: "b"}}}}
			got, err := ApplyRoutes(NewPatchSet([]model.GatewayPatch{policy}), input)
			if err != nil {
				t.Fatal(err)
			}
			if names := virtualHostNames(got[0].VirtualHosts); !slices.Equal(names, tc.want) {
				t.Fatalf("virtual hosts = %v, want %v", names, tc.want)
			}
		})
	}
}

func TestAgentioExtensionConfigurationParity(t *testing.T) {
	policy := parityPolicy(t, "extensions",
		model.EnvoyPatch{Operation: model.PatchAdd, Target: model.ExtensionConfigurationPatch{Value: &corev3.TypedExtensionConfig{Name: "extension-a"}}},
		model.EnvoyPatch{Operation: model.PatchAdd, Target: model.ExtensionConfigurationPatch{Value: &corev3.TypedExtensionConfig{Name: "extension-b"}}},
	)
	input := []*corev3.TypedExtensionConfig{{Name: "existing"}}
	got, err := ApplyExtensionConfigurations(NewPatchSet([]model.GatewayPatch{policy}), input)
	if err != nil {
		t.Fatal(err)
	}
	if names := extensionNames(got); !slices.Equal(names, []string{"existing", "extension-a", "extension-b"}) {
		t.Fatalf("extension configurations = %v", names)
	}
	got[0].Name = "mutated"
	if input[0].GetName() != "existing" {
		t.Fatal("input extension configuration was mutated")
	}

	duplicate := parityPolicy(t, "duplicate-extension", model.EnvoyPatch{
		Operation: model.PatchAdd,
		Target:    model.ExtensionConfigurationPatch{Value: &corev3.TypedExtensionConfig{Name: "existing"}},
	})
	if _, err := ApplyExtensionConfigurations(NewPatchSet([]model.GatewayPatch{duplicate}), input); err == nil {
		t.Fatal("duplicate extension configuration accepted")
	}
}

func parityPolicy(t *testing.T, name string, patches ...model.EnvoyPatch) model.GatewayPatch {
	t.Helper()
	policy, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "demo",
		Name:      name,
		Source:    "agentio-parity-test",
	}, 0, []string{"demo/gateway"}, patches)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func mustStructAny(t *testing.T, fields map[string]any) *anypb.Any {
	t.Helper()
	configuration, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatal(err)
	}
	result, err := anypb.New(configuration)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func listenerFilterNames(filters []*listenerv3.ListenerFilter) []string {
	result := make([]string, 0, len(filters))
	for _, filter := range filters {
		result = append(result, filter.GetName())
	}
	return result
}

func listenerNames(listeners []*listenerv3.Listener) []string {
	result := make([]string, 0, len(listeners))
	for _, listener := range listeners {
		result = append(result, listener.GetName())
	}
	return result
}

func filterChainNames(chains []*listenerv3.FilterChain) []string {
	result := make([]string, 0, len(chains))
	for _, chain := range chains {
		result = append(result, chain.GetName())
	}
	return result
}

func networkFilterNames(filters []*listenerv3.Filter) []string {
	result := make([]string, 0, len(filters))
	for _, filter := range filters {
		result = append(result, filter.GetName())
	}
	return result
}

func listenerWithHTTPFilters(t *testing.T, filters []*hcmv3.HttpFilter) []*listenerv3.Listener {
	t.Helper()
	manager, err := anypb.New(&hcmv3.HttpConnectionManager{HttpFilters: filters})
	if err != nil {
		t.Fatal(err)
	}
	return []*listenerv3.Listener{{
		Name: "main",
		FilterChains: []*listenerv3.FilterChain{{
			Name: "chain",
			Filters: []*listenerv3.Filter{{
				Name:       httpConnectionManagerFilter,
				ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: manager},
			}},
		}},
	}}
}

func unmarshalHCM(t *testing.T, filter *listenerv3.Filter) *hcmv3.HttpConnectionManager {
	t.Helper()
	manager := &hcmv3.HttpConnectionManager{}
	if err := filter.GetTypedConfig().UnmarshalTo(manager); err != nil {
		t.Fatal(err)
	}
	return manager
}

func httpFilterNamesForParity(filters []*hcmv3.HttpFilter) []string {
	result := make([]string, 0, len(filters))
	for _, filter := range filters {
		result = append(result, filter.GetName())
	}
	return result
}

func routeNames(routes []*routev3.Route) []string {
	result := make([]string, 0, len(routes))
	for _, route := range routes {
		result = append(result, route.GetName())
	}
	return result
}

func virtualHostNames(hosts []*routev3.VirtualHost) []string {
	result := make([]string, 0, len(hosts))
	for _, host := range hosts {
		result = append(result, host.GetName())
	}
	return result
}

func extensionNames(configurations []*corev3.TypedExtensionConfig) []string {
	result := make([]string, 0, len(configurations))
	for _, configuration := range configurations {
		result = append(result, configuration.GetName())
	}
	return result
}
