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
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	setstatecommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	rbachttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/openkruise/agentio/pkg/features"
)

const (
	connectUDPUpgradeType = "connect-udp"
	originalDstAddressKey = "envoy.network.transport_socket.original_dst_address"
)

var (
	// Envoy's HCM rewrites :authority from the validated MASQUE path before
	// HTTP filters run. ztunnel's UDP contract is a numeric IPv4 destination;
	// reject anything else rather than letting ORIGINAL_DST fall back to the
	// gateway's own address.
	udpTargetFilter = func() *hcmv3.HttpFilter {
		octet := `(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])`
		port := `([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])`
		return httpFilter("agentio.udp_target", mustPack(&rbachttpv3.RBAC{Rules: &rbacv3.RBAC{
			Action: rbacv3.RBAC_ALLOW,
			Policies: map[string]*rbacv3.Policy{"ipv4-target": {
				Principals: []*rbacv3.Principal{{Identifier: &rbacv3.Principal_Any{Any: true}}},
				Permissions: []*rbacv3.Permission{{Rule: &rbacv3.Permission_Header{Header: &routev3.HeaderMatcher{
					Name: ":authority",
					HeaderMatchSpecifier: &routev3.HeaderMatcher_StringMatch{StringMatch: &matcherv3.StringMatcher{
						MatchPattern: &matcherv3.StringMatcher_SafeRegex{SafeRegex: &matcherv3.RegexMatcher{
							Regex: "^" + octet + `\.` + octet + `\.` + octet + `\.` + octet + ":" + port + "$",
						}},
					}},
				}}}},
			}},
		}}))
	}()

	udpTargetStateFilter = httpFilter("agentio.udp_target_state", mustPack(&setstatehttpv3.Config{
		OnRequestHeaders: []*setstatecommonv3.FilterStateValue{{
			Key:      &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: originalDstAddressKey},
			Value:    &setstatecommonv3.FilterStateValue_FormatString{FormatString: formatString("%REQ(:AUTHORITY)%")},
			ReadOnly: true,
		}},
	}))
)

// Envoy's router selects its UDP connection pool for a terminated CONNECT-UDP
// upgrade. Keep this cluster free of HTTP protocol options.
func (b *resourceBuilder) buildUDPCluster() *clusterv3.Cluster {
	return &clusterv3.Cluster{
		Name:                 UDPPassthroughCluster,
		AltStatName:          delimitedStatsPrefix(UDPPassthroughCluster),
		ClusterDiscoveryType: &clusterv3.Cluster_Type{Type: clusterv3.Cluster_ORIGINAL_DST},
		ConnectTimeout:       durationpb.New(features.GatewayConnectTimeout),
		LbPolicy:             clusterv3.Cluster_CLUSTER_PROVIDED,
		CircuitBreakers:      defaultCircuitBreakers(),
	}
}

// connectUDPRoute must precede the TCP CONNECT route: Envoy's ConnectMatcher
// also matches extended CONNECT, which the HTTP/2 codec presents to routing
// in its upgrade form.
func connectUDPRoute() *routev3.Route {
	return &routev3.Route{
		Name: connectUDPUpgradeType,
		Match: &routev3.RouteMatch{
			PathSpecifier: &routev3.RouteMatch_ConnectMatcher_{ConnectMatcher: &routev3.RouteMatch_ConnectMatcher{}},
			Headers: []*routev3.HeaderMatcher{{
				Name:                 "upgrade",
				HeaderMatchSpecifier: &routev3.HeaderMatcher_ExactMatch{ExactMatch: connectUDPUpgradeType},
			}},
		},
		Action: &routev3.Route_Route{Route: &routev3.RouteAction{
			ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: UDPPassthroughCluster},
			Timeout:          durationpb.New(0),
			UpgradeConfigs: []*routev3.RouteAction_UpgradeConfig{{
				UpgradeType:   connectUDPUpgradeType,
				ConnectConfig: &routev3.RouteAction_UpgradeConfig_ConnectConfig{},
			}},
		}},
	}
}

// configureUDPHCM preserves CONNECT identity processing and validates the UDP
// target before opening the upstream socket. UDP skips TCP SNI policy transfer;
// datagrams are forwarded without inspection.
func configureUDPHCM(hcm *hcmv3.HttpConnectionManager) {
	router := hcm.HttpFilters[len(hcm.HttpFilters)-1]
	filters := make([]*hcmv3.HttpFilter, 0, len(hcm.HttpFilters))
	for _, filter := range hcm.HttpFilters[:len(hcm.HttpFilters)-1] {
		if filter.Name != "agentio.connect_policy" &&
			filter.Name != "agentio.connection_policy_store" &&
			filter.Name != bandwidthFilterName && filter.Name != concurrencyFilterName {
			filters = append(filters, filter)
		}
	}
	filters = append(filters, udpTargetFilter, udpTargetStateFilter, router)
	hcm.UpgradeConfigs = append(hcm.UpgradeConfigs, &hcmv3.HttpConnectionManager_UpgradeConfig{
		UpgradeType: connectUDPUpgradeType,
		Filters:     filters,
	})
}
