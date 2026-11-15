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
	common "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	state "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/openkruise/agentio/pkg/model"
)

func (b *resourceBuilder) egressAuthorizationFilter() *hcm.HttpFilter {
	return httpFilter("agentio.egress_authorization", b.pack(&udpatypev1.TypedStruct{
		TypeUrl: "type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter",
		Value: b.structure(map[string]any{
			"dynamic_module_config": egressModuleConfig(),
			"filter_name":           "envoy_agentio_egress_authorization",
		}),
	}))
}

func egressModuleConfig() map[string]any {
	return map[string]any{
		"name":         "envoy_agentio_connection_policy",
		"do_not_close": true,
		"module": map[string]any{
			"local": map[string]any{"filename": "/usr/local/lib/libenvoy_agentio_connection_policy.so"},
		},
	}
}

// RDS supplies a fresh authorization snapshot for each request on existing connections.
func (b *resourceBuilder) egressAuthorizationRouteConfig(mode tcpDestinationMode, defaultPort uint32) *anypb.Any {
	denied := make([]any, 0)
	for _, cidr := range b.egressAuthorization.EffectiveDeniedCIDRs() {
		denied = append(denied, cidr)
	}
	return b.pack(&udpatypev1.TypedStruct{
		TypeUrl: "type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilterPerRoute",
		Value: b.structure(map[string]any{
			"dynamic_module_config": egressModuleConfig(),
			"filter_name":           "envoy_agentio_egress_authorization",
			"filter_config": map[string]any{
				"@type": "type.googleapis.com/google.protobuf.Struct",
				"value": map[string]any{
					"mode":         string(mode),
					"denied_cidrs": denied,
					"default_port": defaultPort,
					"dns":          b.rustDNSSettings(),
				},
			},
		}),
	})
}

// Empty EPE targets preserve the existing candidate; absent candidates use Host/SNI resolution.
func (b *resourceBuilder) egressTargetFilters() []*hcm.HttpFilter {
	if !b.legacyGateway {
		filter := httpFilter(
			"agentio.egress_target",
			b.pack(&state.Config{OnRequestHeaders: []*common.FilterStateValue{{
				Key: &common.FilterStateValue_ObjectKey{ObjectKey: model.FilterStateUpstreamAddress},
				Value: &common.FilterStateValue_FormatString{
					FormatString: formatString("%DYNAMIC_METADATA(agentio.route:upstream:address)%"),
				},
				SkipIfEmpty: true,
			}}}),
		)
		// CONNECT authorization concerns the tunnel target; dialing still targets the proxy.
		return []*hcm.HttpFilter{b.skipHTTPFilter(filter, b.connectMethodPredicate())}
	}
	return []*hcm.HttpFilter{
		httpFilter("agentio.egress_target", b.pack(&state.Config{OnRequestHeaders: []*common.FilterStateValue{
			{
				Key: &common.FilterStateValue_ObjectKey{ObjectKey: dynamicHostKey},
				Value: &common.FilterStateValue_FormatString{
					FormatString: formatString("%DYNAMIC_METADATA(agentio.route:upstream:ip)%"),
				},
				// Envoy requires the same mutability when replacing the route candidate.
				SkipIfEmpty: true,
			},
			{
				Key: &common.FilterStateValue_ObjectKey{ObjectKey: dynamicPortKey},
				Value: &common.FilterStateValue_FormatString{
					FormatString: formatString("%DYNAMIC_METADATA(agentio.route:upstream:port)%"),
				},
				ReadOnly:    true,
				SkipIfEmpty: true,
			},
		}})),
	}
}

// DFP accepts IP:port as its host; the embedded port takes precedence over its default.
func (b *resourceBuilder) routeUpstreamFilter() *hcm.HttpFilter {
	return httpFilter("agentio.route_upstream", b.pack(&state.Config{OnRequestHeaders: []*common.FilterStateValue{{
		Key: &common.FilterStateValue_ObjectKey{ObjectKey: dynamicHostKey},
		Value: &common.FilterStateValue_FormatString{
			FormatString: formatString("%FILTER_STATE(agentio.route.upstream:PLAIN)%"),
		},
		SkipIfEmpty: true,
	}}}))
}

func (b *resourceBuilder) rustDNSSettings() map[string]any {
	cache := b.dnsCacheConfig()
	return map[string]any{
		"max_hosts":            cache.GetMaxHosts().GetValue(),
		"max_pending_requests": cache.GetDnsCacheCircuitBreaker().GetMaxPendingRequests().GetValue(),
	}
}
