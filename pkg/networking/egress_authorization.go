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
	"net/netip"

	xdsmatcherv3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	common "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	rbachttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	state "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matchinginputv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
	ipmatcherv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/input_matchers/ip/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (b *resourceBuilder) deniedIPRanges() []*corev3.CidrRange {
	var ranges []*corev3.CidrRange
	for _, cidr := range b.egressAuthorization.EffectiveDeniedCIDRs() {
		prefix := netip.MustParsePrefix(cidr)
		ranges = append(ranges, &corev3.CidrRange{
			AddressPrefix: prefix.Addr().String(),
			PrefixLen:     wrapperspb.UInt32(uint32(prefix.Bits())),
		})
		if prefix.Addr().Is4() {
			// Envoy matches CIDRs by address family; EPE and the TCP module unmap IPv4-in-IPv6.
			ranges = append(ranges, &corev3.CidrRange{
				AddressPrefix: netip.AddrFrom16(prefix.Addr().As16()).String(),
				PrefixLen:     wrapperspb.UInt32(uint32(96 + prefix.Bits())),
			})
		}
	}
	return ranges
}

// CONNECT-UDP retains its original-target admission check.
func (b *resourceBuilder) egressAuthorizationFilter() *hcm.HttpFilter {
	return httpFilter("agentio.egress_authorization", b.pack(&rbachttpv3.RBAC{
		RulesStatPrefix: "egress_authorization",
		Matcher: &xdsmatcherv3.Matcher{
			MatcherType: &xdsmatcherv3.Matcher_MatcherList_{MatcherList: &xdsmatcherv3.Matcher_MatcherList{
				Matchers: []*xdsmatcherv3.Matcher_MatcherList_FieldMatcher{{
					Predicate: &xdsmatcherv3.Matcher_MatcherList_Predicate{
						MatchType: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate_{
							SinglePredicate: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate{
								Input: typedExtension(
									"envoy.matching.inputs.filter_state",
									b.pack(&matchinginputv3.FilterStateInput{
										Key:   "envoy.filters.listener.original_dst.local_ip",
										Field: "ip",
									}),
								),
								Matcher: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate_CustomMatch{
									CustomMatch: typedExtension("envoy.matching.matchers.ip", b.pack(&ipmatcherv3.Ip{
										CidrRanges: b.deniedIPRanges(),
										StatPrefix: "egress_authorization",
									})),
								},
							},
						},
					},
					OnMatch: &xdsmatcherv3.Matcher_OnMatch{OnMatch: &xdsmatcherv3.Matcher_OnMatch_Action{
						Action: typedExtension(
							"deny",
							b.pack(&rbacv3.Action{Name: "agentio_egress_denied", Action: rbacv3.RBAC_DENY}),
						),
					}},
				}},
			}},
			OnNoMatch: &xdsmatcherv3.Matcher_OnMatch{OnMatch: &xdsmatcherv3.Matcher_OnMatch_Action{
				Action: typedExtension(
					"allow",
					b.pack(&rbacv3.Action{Name: "allowed_destination", Action: rbacv3.RBAC_ALLOW}),
				),
			}},
		},
	}))
}

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
