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
	udpatypev1 "github.com/cncf/xds/go/udpa/type/v1"
	xdscorev3 "github.com/cncf/xds/go/xds/core/v3"
	xdsmatcherv3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	dfpnetworkv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/sni_dynamic_forward_proxy/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

// These extensions are emitted only to authenticated waypoint clients while
// legacy gateways remain in service. Native gateway-agent needs no legacy bootstrap.
const (
	legacyPeerPrincipal   = "io.istio.peer_principal"
	legacyLocalPrincipal  = "io.istio.local_principal"
	sniPolicyMatcherName  = "kruise.matching.custom_matchers.sni_traffic_policy"
	sniPolicyMatcherType  = "type.googleapis.com/kruise.networking.policy_runtime.v1alpha1.SniTrafficPolicyMatcher"
	tlsActionHeaderFormat = `%CEL('x-agentio-tls' in request.headers ? ` +
		`re.extract(request.headers['x-agentio-tls'], '^action=([^;]+)(;sni=[^;]+)?$', r'\1') : '')%`
)

var (
	legacySNIDFPFilter = networkFilter(
		"envoy.filters.network.sni_dynamic_forward_proxy",
		mustPack(&dfpnetworkv3.FilterConfig{
			DnsCacheConfig: dnsCacheConfig(true),
			PortSpecifier:  &dfpnetworkv3.FilterConfig_PortValue{PortValue: 443},
		}),
	)
	legacyPeerMetadataFilter = buildDownstreamPeerMetadataFilter()
	legacyConnectAuthority   = buildConnectAuthorityFilter(
		"istio.hashable_string",
		legacyPeerPrincipal,
		legacyLocalPrincipal,
		false,
	)
	legacyConnectAuthorityWithAction = buildConnectAuthorityFilter(
		"istio.hashable_string",
		legacyPeerPrincipal,
		legacyLocalPrincipal,
		true,
	)
	legacyCaptureSNI      = buildCaptureSNIFilter("istio.hashable_string")
	legacyRelayDownstream = buildRelayDownstreamFilter(
		"istio.hashable_string",
		legacyPeerPrincipal,
		legacyLocalPrincipal,
	)
)

func buildDownstreamPeerMetadataFilter() *hcmv3.HttpFilter {
	fields, err := structpb.NewStruct(map[string]any{
		"downstream_discovery": []any{map[string]any{"workload_discovery": map[string]any{}}},
		"shared_with_upstream": true,
	})
	if err != nil {
		panic(err)
	}
	// wire-visible filter name, part of the Agentio data-plane contract pinned by testdata, never rename.
	return httpFilter("waypoint_downstream_peer_metadata", mustPack(&udpatypev1.TypedStruct{
		TypeUrl: "type.googleapis.com/io.istio.http.peer_metadata.Config",
		Value:   fields,
	}))
}

func (b *resourceBuilder) legacySNIPolicyMatcher() *xdsmatcherv3.Matcher {
	fields := b.structure(map[string]any{
		"on_tls_termination": chainActionFields(tlsTerminateChain),
		"on_passthrough":     chainActionFields(forwardTCPChain),
		"on_deny":            chainActionFields(sniDenyChain),
		"failure_mode_allow": map[string]any{
			"runtime_key":   "kruise.sni_traffic_policy.failure_mode_allow",
			"default_value": false,
		},
	})
	config := b.pack(&udpatypev1.TypedStruct{TypeUrl: sniPolicyMatcherType, Value: fields})
	return &xdsmatcherv3.Matcher{
		MatcherType: &xdsmatcherv3.Matcher_MatcherTree_{MatcherTree: &xdsmatcherv3.Matcher_MatcherTree{
			Input: serverNameInput,
			TreeType: &xdsmatcherv3.Matcher_MatcherTree_CustomMatch{CustomMatch: &xdscorev3.TypedExtensionConfig{
				Name:        sniPolicyMatcherName,
				TypedConfig: config,
			}},
		}},
		OnNoMatch: b.toChain(forwardTCPChain),
	}
}

func chainActionFields(name string) map[string]any {
	return map[string]any{"action": map[string]any{
		"name": name,
		"typed_config": map[string]any{
			"@type": "type.googleapis.com/google.protobuf.StringValue",
			"value": name,
		},
	}}
}
