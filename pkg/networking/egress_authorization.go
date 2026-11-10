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
	common "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	state "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/openkruise/agentio/pkg/model"
)

// Empty EPE targets leave existing filter state intact, allowing normal DFP
// destination selection when no explicit upstream has been supplied.
func (b *resourceBuilder) egressTargetFilters() []*hcm.HttpFilter {
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

// Capture the selected endpoint before EPE can invalidate Envoy's route cache.
func (b *resourceBuilder) staticEndpointCandidateConfig(address string) *anypb.Any {
	return b.pack(&state.Config{OnRequestHeaders: []*common.FilterStateValue{{
		Key:        &common.FilterStateValue_ObjectKey{ObjectKey: model.FilterStateRouteUpstream},
		FactoryKey: "envoy.string",
		Value: &common.FilterStateValue_FormatString{FormatString: formatString(
			address + ":%FILTER_STATE(envoy.filters.listener.original_dst.local_ip:FIELD:port)%",
		)},
		ReadOnly: true,
	}}})
}
