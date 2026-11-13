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
	"net/netip"
	"strconv"
	"strings"

	"github.com/openkruise/agentio/pkg/util/protoutil"

	xdsmatcherv3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matchinginputv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
	ipmatcherv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/input_matchers/ip/v3"
	previoushostsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/retry/host/previous_hosts/v3"
	previousprioritiesv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/retry/priority/previous_priorities/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
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
	if len(gateway.GetTcpPassthrough()) > 0 {
		vhost := connect.VirtualHosts[0]
		matches := &xdsmatcherv3.Matcher_MatcherList{}
		connectMethod := &xdsmatcherv3.Matcher_MatcherList_Predicate{
			MatchType: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate_{
				SinglePredicate: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate{
					Input: typedExtension(
						"request-headers",
						b.pack(&matcherv3.HttpRequestHeaderMatchInput{HeaderName: ":method"}),
					),
					Matcher: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate_ValueMatch{
						ValueMatch: &xdsmatcherv3.StringMatcher{
							MatchPattern: &xdsmatcherv3.StringMatcher_Exact{Exact: "CONNECT"},
						},
					},
				},
			},
		}
		for index, match := range gateway.GetTcpPassthrough() {
			predicates := []*xdsmatcherv3.Matcher_MatcherList_Predicate{connectMethod}
			if len(match.GetCidrs()) > 0 {
				addresses := &ipmatcherv3.Ip{StatPrefix: TCPPassthrough}
				for _, cidr := range match.GetCidrs() {
					prefix := netip.MustParsePrefix(cidr).Masked()
					addresses.CidrRanges = append(addresses.CidrRanges, &corev3.CidrRange{
						AddressPrefix: prefix.Addr().String(),
						PrefixLen:     wrapperspb.UInt32(uint32(prefix.Bits())),
					})
				}
				predicates = append(predicates, &xdsmatcherv3.Matcher_MatcherList_Predicate{
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
								CustomMatch: typedExtension("envoy.matching.matchers.ip", b.pack(addresses)),
							},
						},
					},
				})
			}
			if len(match.GetPorts()) > 0 {
				ports := &xdsmatcherv3.Matcher_MatcherList_Predicate_PredicateList{}
				input := typedExtension("envoy.matching.inputs.filter_state", b.pack(&matchinginputv3.FilterStateInput{
					Key:   "envoy.filters.listener.original_dst.local_ip",
					Field: "port",
				}))
				for _, port := range match.GetPorts() {
					ports.Predicate = append(ports.Predicate, &xdsmatcherv3.Matcher_MatcherList_Predicate{
						MatchType: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate_{
							SinglePredicate: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate{
								Input: input,
								Matcher: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate_ValueMatch{
									ValueMatch: &xdsmatcherv3.StringMatcher{
										MatchPattern: &xdsmatcherv3.StringMatcher_Exact{
											Exact: strconv.FormatUint(uint64(port), 10),
										},
									},
								},
							},
						},
					})
				}
				portMatch := ports.Predicate[0]
				if len(ports.Predicate) > 1 {
					portMatch = &xdsmatcherv3.Matcher_MatcherList_Predicate{
						MatchType: &xdsmatcherv3.Matcher_MatcherList_Predicate_OrMatcher{OrMatcher: ports},
					}
				}
				predicates = append(predicates, portMatch)
			}
			predicate := predicates[0]
			if len(predicates) > 1 {
				predicate = &xdsmatcherv3.Matcher_MatcherList_Predicate{
					MatchType: &xdsmatcherv3.Matcher_MatcherList_Predicate_AndMatcher{
						AndMatcher: &xdsmatcherv3.Matcher_MatcherList_Predicate_PredicateList{Predicate: predicates},
					},
				}
			}
			route := proto.Clone(tcp).(*routev3.Route)
			route.Name = fmt.Sprintf("tcp-passthrough-%d", index)
			route.GetRoute().ClusterSpecifier = &routev3.RouteAction_Cluster{Cluster: TCPPassthrough}
			matches.Matchers = append(matches.Matchers, &xdsmatcherv3.Matcher_MatcherList_FieldMatcher{
				Predicate: predicate,
				OnMatch: &xdsmatcherv3.Matcher_OnMatch{OnMatch: &xdsmatcherv3.Matcher_OnMatch_Action{
					Action: typedExtension(route.Name, b.pack(route)),
				}},
			})
		}
		vhost.Matcher = &xdsmatcherv3.Matcher{
			MatcherType: &xdsmatcherv3.Matcher_MatcherList_{MatcherList: matches},
			OnNoMatch: &xdsmatcherv3.Matcher_OnMatch{OnMatch: &xdsmatcherv3.Matcher_OnMatch_Action{
				Action: typedExtension("default-connect", b.pack(&routev3.RouteList{Routes: vhost.Routes})),
			}},
		}
		vhost.Routes = nil
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

func (b *resourceBuilder) buildForwardRoute(name string, gateway *configv1.EgressGateway) *routev3.RouteConfiguration {
	result := &routev3.RouteConfiguration{
		Name:                     name,
		ValidateClusters:         wrapperspb.Bool(false),
		IgnorePortInHostMatching: true,
	}
	settings := gateway.GetHttp().GetRouting()
	defaultSettings := settings.GetFallback()
	for index, override := range settings.GetHostOverrides() {
		domains := make([]string, 0, len(override.GetHosts()))
		for _, domain := range override.GetHosts() {
			if domain == "*" {
				defaultSettings = override.GetSettings()
				continue
			}
			domains = append(domains, domain)
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
