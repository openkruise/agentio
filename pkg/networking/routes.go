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
	"net/http"
	"strconv"
	"strings"

	"github.com/openkruise/agentio/pkg/util/protoutil"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	previoushostsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/retry/host/previous_hosts/v3"
	previousprioritiesv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/retry/priority/previous_priorities/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/features"
)

var previousHostsRetryPredicate = func() *routev3.RetryPolicy_RetryHostPredicate {
	config, err := protoutil.MarshalAny(&previoushostsv3.PreviousHostsPredicate{})
	if err != nil {
		panic(fmt.Errorf("encode previous-hosts retry predicate: %w", err))
	}
	return &routev3.RetryPolicy_RetryHostPredicate{
		Name:       "envoy.retry_host_predicates.previous_hosts",
		ConfigType: &routev3.RetryPolicy_RetryHostPredicate_TypedConfig{TypedConfig: config},
	}
}()

var remoteLocalitiesRetryPriority = func() *routev3.RetryPolicy_RetryPriority {
	config, err := protoutil.MarshalAny(&previousprioritiesv3.PreviousPrioritiesConfig{UpdateFrequency: 2})
	if err != nil {
		panic(fmt.Errorf("encode previous-priorities retry config: %w", err))
	}
	return &routev3.RetryPolicy_RetryPriority{
		Name:       "envoy.retry_priorities.previous_priorities",
		ConfigType: &routev3.RetryPolicy_RetryPriority_TypedConfig{TypedConfig: config},
	}
}()

func (b *resourceBuilder) buildRoutes(gateway *configv1.EgressGateway) ([]*routev3.RouteConfiguration, error) {
	connect := &routev3.RouteConfiguration{
		Name: ConnectTerminate,
		VirtualHosts: []*routev3.VirtualHost{{
			Name:    "default",
			Domains: []string{"*"},
			Routes: []*routev3.Route{
				{
					Match: &routev3.RouteMatch{
						PathSpecifier: &routev3.RouteMatch_ConnectMatcher_{
							ConnectMatcher: &routev3.RouteMatch_ConnectMatcher{},
						},
					},
					Action: &routev3.Route_Route{Route: &routev3.RouteAction{
						ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: MainInternal},
						Timeout:          durationpb.New(0),
						UpgradeConfigs: []*routev3.RouteAction_UpgradeConfig{{
							UpgradeType:   "CONNECT",
							ConnectConfig: &routev3.RouteAction_UpgradeConfig_ConnectConfig{},
						}},
					}},
				},
			},
		}},
	}
	// An empty, present config enables a default-disabled HTTP filter without
	// requiring filter-specific per-route configuration. Only TCP CONNECT uses it.
	tcp := connect.VirtualHosts[0].Routes[0]
	for name, enabled := range map[string]bool{
		bandwidthFilterName:   gateway.GetBandwidthLimit() != nil,
		concurrencyFilterName: gateway.GetConnectConcurrencyLimit() != nil,
	} {
		if enabled {
			if tcp.TypedPerFilterConfig == nil {
				tcp.TypedPerFilterConfig = make(map[string]*anypb.Any)
			}
			tcp.TypedPerFilterConfig[name] = b.pack(&routev3.FilterConfig{Config: &anypb.Any{}})
		}
	}
	if features.EnableUDPProxy {
		vhost := connect.VirtualHosts[0]
		vhost.Routes = append([]*routev3.Route{connectUDPRoute()}, vhost.Routes...)
	}
	http := b.buildForwardRoute(HTTPDynamicForwardProxy, gateway)
	tls := b.buildForwardRoute(TLSConnectOriginate, gateway)
	for _, route := range []*routev3.RouteConfiguration{connect, http, tls} {
		if err := route.ValidateAll(); err != nil {
			return nil, fmt.Errorf("validate route %s: %w", route.GetName(), err)
		}
	}
	return []*routev3.RouteConfiguration{connect, http, tls}, nil
}

// buildForwardRoute keeps the existing DFP cluster for static routes and
// replaces only the route-selected host and original port state.
func (b *resourceBuilder) buildForwardRoute(name string, gateway *configv1.EgressGateway) *routev3.RouteConfiguration {
	result := &routev3.RouteConfiguration{
		Name:                     name,
		ValidateClusters:         wrapperspb.Bool(false),
		IgnorePortInHostMatching: true,
	}
	settings := gateway.GetConnectionPool().GetHttp()
	defaultSettings := settings.GetDefaultRoute()
	staticDomains := make(map[string]struct{})
	for serviceIndex, service := range gateway.GetServiceEntries() {
		addresses := make([]string, 0, len(service.GetEndpoints()))
		for _, endpoint := range service.GetEndpoints() {
			addresses = append(addresses, endpoint.GetAddress())
		}
		for hostIndex, host := range service.GetHosts() {
			domains := []string{host, host + ":*"}
			for _, domain := range domains {
				staticDomains[strings.ToLower(domain)] = struct{}{}
			}
			result.VirtualHosts = append(result.VirtualHosts, &routev3.VirtualHost{
				Name:    fmt.Sprintf("sandbox|service-entry|%d|%d", serviceIndex, hostIndex),
				Domains: domains,
				Routes: []*routev3.Route{b.staticEndpointRoute(
					name,
					routeSettingsForHost(settings, host),
					addresses,
				)},
			})
		}
	}
	for index, override := range settings.GetRouteOverrides() {
		domains := make([]string, 0, len(override.GetHosts()))
		for _, domain := range override.GetHosts() {
			if domain == "*" {
				defaultSettings = override.GetSettings()
				continue
			}
			if _, found := staticDomains[strings.ToLower(domain)]; !found {
				domains = append(domains, domain)
			}
		}
		if len(domains) == 0 {
			continue
		}
		result.VirtualHosts = append(result.VirtualHosts, &routev3.VirtualHost{
			Name:    fmt.Sprintf("sandbox|override|%d", index),
			Domains: domains,
			Routes:  []*routev3.Route{forwardRoute(name, override.GetSettings())},
		})
	}
	result.VirtualHosts = append(result.VirtualHosts, &routev3.VirtualHost{
		Name:    "sandbox|default|0",
		Domains: []string{"*"},
		Routes:  []*routev3.Route{forwardRoute(name, defaultSettings)},
	})
	connectCluster := PassthroughCluster
	if name == TLSConnectOriginate {
		connectCluster = TLSProxyOriginate
	}
	for _, virtualHost := range result.VirtualHosts {
		virtualHost.Routes = append([]*routev3.Route{forwardProxyConnectRoute(connectCluster)}, virtualHost.Routes...)
	}
	return result
}

// forwardProxyConnectRoute intentionally omits ConnectConfig: the explicit
// upstream proxy, rather than this gateway, terminates the application-level
// CONNECT exchange.
func forwardProxyConnectRoute(cluster string) *routev3.Route {
	return &routev3.Route{
		Name: "sandbox-connect",
		Match: &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_ConnectMatcher_{
			ConnectMatcher: &routev3.RouteMatch_ConnectMatcher{},
		}},
		Action: &routev3.Route_Route{Route: &routev3.RouteAction{
			ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: cluster},
			Timeout:          durationpb.New(0),
			UpgradeConfigs: []*routev3.RouteAction_UpgradeConfig{{
				UpgradeType: "CONNECT",
			}},
		}},
	}
}

func (b *resourceBuilder) staticEndpointRoute(
	cluster string,
	settings *configv1.HttpRouteSettings,
	addresses []string,
) *routev3.Route {
	result := forwardRoute(cluster, settings)
	if len(addresses) == 1 {
		result.TypedPerFilterConfig = map[string]*anypb.Any{
			staticEndpointCandidateFilter: b.staticEndpointCandidateConfig(addresses[0]),
		}
		return result
	}
	weighted := make([]*routev3.WeightedCluster_ClusterWeight, 0, len(addresses))
	for _, address := range addresses {
		weighted = append(weighted, &routev3.WeightedCluster_ClusterWeight{
			Name:   cluster,
			Weight: wrapperspb.UInt32(1),
			TypedPerFilterConfig: map[string]*anypb.Any{
				staticEndpointCandidateFilter: b.staticEndpointCandidateConfig(address),
			},
		})
	}
	result.GetRoute().ClusterSpecifier = &routev3.RouteAction_WeightedClusters{
		WeightedClusters: &routev3.WeightedCluster{Clusters: weighted},
	}
	return result
}

func routeSettingsForHost(settings *configv1.ConnectionPoolHttpSettings, host string) *configv1.HttpRouteSettings {
	result := settings.GetDefaultRoute()
	bestRank, bestLength := -1, -1
	for _, override := range settings.GetRouteOverrides() {
		for _, pattern := range override.GetHosts() {
			rank, length, matched := domainMatchSpecificity(pattern, host)
			if matched && (rank > bestRank || rank == bestRank && length > bestLength) {
				result = override.GetSettings()
				bestRank, bestLength = rank, length
			}
		}
	}
	return result
}

// domainMatchSpecificity mirrors Envoy VirtualHost domain precedence: exact,
// suffix wildcard, prefix wildcard, then the catch-all wildcard.
func domainMatchSpecificity(pattern, value string) (rank int, length int, matched bool) {
	pattern = strings.ToLower(pattern)
	value = strings.ToLower(value)
	if pattern == value {
		return 3, len(pattern), true
	}
	if pattern == "*" {
		return 0, 1, value != ""
	}
	if strings.HasPrefix(pattern, "*") {
		suffix := pattern[1:]
		return 2, len(pattern), len(value) > len(suffix) && strings.HasSuffix(value, suffix)
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return 1, len(pattern), len(value) > len(prefix) && strings.HasPrefix(value, prefix)
	}
	return 0, 0, false
}

func forwardRoute(cluster string, settings *configv1.HttpRouteSettings) *routev3.Route {
	action := &routev3.RouteAction{
		ClusterSpecifier: &routev3.RouteAction_Cluster{Cluster: cluster},
		RetryPolicy: &routev3.RetryPolicy{
			RetryOn:    "reset-before-request",
			NumRetries: wrapperspb.UInt32(2),
		},
	}
	if settings != nil && settings.GetTimeout() != nil {
		// Match release-0.1 setTimeout: an explicit route timeout also caps the
		// grpc-timeout header via the deprecated max_grpc_timeout field.
		action.Timeout = durationpb.New(settings.GetTimeout().AsDuration())
		//nolint:staticcheck // MaxStreamDuration replacement has regressions; release-0.1 uses the deprecated field.
		action.MaxGrpcTimeout = durationpb.New(settings.GetTimeout().AsDuration())
	} else {
		// Match release-0.1 BuildDefaultHTTPSandboxRoute with no timeout: disable
		// the request timeout instead of falling back to Envoy's default 15s, and
		// enter the new timeout mode via zero-valued MaxStreamDuration.
		action.Timeout = durationpb.New(0)
		action.MaxStreamDuration = &routev3.RouteAction_MaxStreamDuration{
			MaxStreamDuration:    durationpb.New(0),
			GrpcTimeoutHeaderMax: durationpb.New(0),
		}
	}
	if settings != nil {
		if retries := settings.GetRetries(); retries != nil && retries.GetAttempts() <= 0 {
			action.RetryPolicy = nil
		} else if retries != nil {
			retryOn := retries.GetRetryOn()
			var statusCodes []uint32
			if retryOn == "" {
				retryOn = "connect-failure,refused-stream,unavailable,cancelled,retriable-status-codes"
			} else {
				retryOn, statusCodes = parseRetryOn(retryOn)
				if len(statusCodes) > 0 && !strings.Contains(retryOn, "retriable-status-codes") {
					if retryOn != "" {
						retryOn += ","
					}
					retryOn += "retriable-status-codes"
				}
			}
			action.RetryPolicy = &routev3.RetryPolicy{
				RetryOn:                       retryOn,
				NumRetries:                    wrapperspb.UInt32(uint32(retries.GetAttempts())),
				PerTryTimeout:                 retries.GetPerTryTimeout(),
				RetriableStatusCodes:          statusCodes,
				RetryHostPredicate:            []*routev3.RetryPolicy_RetryHostPredicate{previousHostsRetryPredicate},
				HostSelectionRetryMaxAttempts: 5,
			}
			if retries.GetRetryIgnorePreviousHosts() != nil && !retries.GetRetryIgnorePreviousHosts().GetValue() {
				action.RetryPolicy.RetryHostPredicate = nil
			}
			if retries.GetBackoff() != nil {
				action.RetryPolicy.RetryBackOff = &routev3.RetryPolicy_RetryBackOff{BaseInterval: retries.GetBackoff()}
			}
			if retries.GetRetryRemoteLocalities().GetValue() {
				action.RetryPolicy.RetryPriority = remoteLocalitiesRetryPriority
			}
		}
	}
	return &routev3.Route{
		Name:      "default",
		Decorator: &routev3.Decorator{Operation: cluster},
		Match:     &routev3.RouteMatch{PathSpecifier: &routev3.RouteMatch_Prefix{Prefix: "/"}},
		Action:    &routev3.Route_Route{Route: action},
	}
}

func parseRetryOn(value string) (string, []uint32) {
	var conditions []string
	var statusCodes []uint32
	for part := range strings.SplitSeq(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		code, err := strconv.Atoi(part)
		if err == nil && http.StatusText(code) != "" {
			statusCodes = append(statusCodes, uint32(code))
		} else {
			conditions = append(conditions, part)
		}
	}
	return strings.Join(conditions, ","), statusCodes
}
