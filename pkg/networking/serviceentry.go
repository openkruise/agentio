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
	"maps"
	"slices"
	"strconv"
	"strings"

	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	matching "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	skip "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/matcher/action/v3"
	common "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	httpstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	networkstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/set_filter_state/v3"
	snidfp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/sni_dynamic_forward_proxy/v3"
	input "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/proto"

	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

const serviceEntryDenyChain = "service-entry-deny"

func (b *resourceBuilder) internalChainMatcher(config effectiveConfig, passthrough string) *xdsmatcher.Matcher {
	if features.EnableSNITrafficPolicy {
		return b.protocolMatcher(
			toMatcher(b.sniTrafficPolicyMatcher(config.gateway.GetTlsTermination().GetExcludeHosts(), passthrough)),
		)
	}
	if termination := config.gateway.GetTlsTermination(); termination != nil {
		return b.staticSNIMatcher(termination, passthrough)
	}
	return b.protocolMatcher(b.toChain(passthrough))
}

// The SNI and HTTP filters share the DFP cache and explicit-target convention.
func (b *resourceBuilder) sniForwardFilters(config effectiveConfig, prefix []*listener.Filter) []*listener.Filter {
	state := networkFilter("agentio.route_upstream", b.pack(&networkstate.Config{
		OnNewConnection: []*common.FilterStateValue{
			{
				Key: &common.FilterStateValue_ObjectKey{ObjectKey: dynamicHostKey},
				Value: &common.FilterStateValue_FormatString{FormatString: formatString(
					"%CEL(connection.requested_server_name == '' ? destination.address : '')%",
				)},
				SkipIfEmpty: true,
			},
			{
				Key: &common.FilterStateValue_ObjectKey{ObjectKey: dynamicHostKey},
				Value: &common.FilterStateValue_FormatString{FormatString: formatString(
					"%FILTER_STATE(agentio.route.upstream:PLAIN)%",
				)},
				SkipIfEmpty: true,
			},
			{
				Key:   &common.FilterStateValue_ObjectKey{ObjectKey: dynamicPortKey},
				Value: &common.FilterStateValue_FormatString{FormatString: formatString("%DOWNSTREAM_LOCAL_PORT%")},
			},
		},
	}))
	filters := append(
		slices.Clone(prefix),
		state,
		networkFilter("envoy.filters.network.sni_dynamic_forward_proxy", b.pack(&snidfp.FilterConfig{
			DnsCacheConfig: dnsCacheConfig(b.legacyGateway),
			PortSpecifier:  &snidfp.FilterConfig_PortValue{PortValue: 443},
		})),
	)
	return b.applicationTCPFilters(config, filters, HTTPDynamicForwardProxy, config.gateway.GetTcp())
}

// Each address accepts the union of names from entries sharing that endpoint.
// Matching an address never bypasses the existing TLS policy decision.
func (b *resourceBuilder) bindServiceEntryEndpoints(
	l *listener.Listener, config effectiveConfig, manager *hcm.HttpConnectionManager, terminated bool,
) {
	hostsByIP := make(map[string][]string)
	for _, entry := range config.gateway.GetServiceEntries() {
		for _, endpoint := range entry.GetEndpoints() {
			hostsByIP[endpoint.GetAddress()] = append(hostsByIP[endpoint.GetAddress()], entry.GetHosts()...)
		}
	}
	if len(hostsByIP) == 0 {
		return
	}
	addresses := make(map[string]*xdsmatcher.Matcher_OnMatch, len(hostsByIP))
	for _, ip := range slices.Sorted(maps.Keys(hostsByIP)) {
		hosts := hostsByIP[ip]
		slices.Sort(hosts)
		name := "service-entry|" + ip
		l.FilterChains = append(l.FilterChains, &listener.FilterChain{
			Name: name + "|http",
			Filters: []*listener.Filter{
				networkFilter(
					"envoy.filters.network.http_connection_manager",
					b.pack(b.serviceEntryHCM(manager, hosts)),
				),
			},
		})
		http := exactMatcher(applicationProtocolInput, map[string]*xdsmatcher.Matcher_OnMatch{
			"'h2c'":      b.toChain(name + "|http"),
			"'http/1.0'": b.toChain(name + "|http"),
			"'http/1.1'": b.toChain(name + "|http"),
		}, b.toChain(serviceEntryDenyChain))
		if terminated {
			// Non-HTTP bytes keep the TLS identity and original destination chosen upstream.
			http.OnNoMatch = b.toChain(forwardTCPChain)
			addresses[ip] = toMatcher(http)
			continue
		}
		pin := networkFilter(
			"agentio.endpoint_upstream",
			b.pack(&networkstate.Config{OnNewConnection: []*common.FilterStateValue{
				serviceEntryTarget(),
			}}),
		)
		l.FilterChains = append(
			l.FilterChains,
			&listener.FilterChain{Name: name + "|tls", Filters: b.sniForwardFilters(config, []*listener.Filter{pin})},
		)
		domains := make([]string, 0, len(hosts)*2)
		for _, host := range hosts {
			domains = append(domains, host, host+".")
		}
		sni := &xdsmatcher.ServerNameMatcher{DomainMatchers: []*xdsmatcher.ServerNameMatcher_DomainMatcher{{
			Domains: domains,
			OnMatch: toMatcher(b.internalChainMatcher(config, name+"|tls")),
		}}}
		binding := &xdsmatcher.Matcher{
			MatcherType: &xdsmatcher.Matcher_MatcherTree_{MatcherTree: &xdsmatcher.Matcher_MatcherTree{
				Input:    serverNameInput,
				TreeType: &xdsmatcher.Matcher_MatcherTree_CustomMatch{CustomMatch: typedExtension("sni", b.pack(sni))},
			}},
			OnNoMatch: b.toChain(serviceEntryDenyChain),
		}
		addresses[ip] = toMatcher(
			exactMatcher(
				transportProtocolInput,
				map[string]*xdsmatcher.Matcher_OnMatch{"tls": toMatcher(binding)},
				toMatcher(http),
			),
		)
	}
	l.FilterChains = append(l.FilterChains, &listener.FilterChain{
		Name:    serviceEntryDenyChain,
		Filters: b.applicationTCPFilters(config, nil, BlackHoleCluster, config.gateway.GetTcp()),
	})
	l.FilterChainMatcher = exactMatcher(
		typedExtension("destination-ip", b.pack(&input.DestinationIPInput{})),
		addresses,
		toMatcher(l.FilterChainMatcher),
	)
}

func serviceEntryTarget() *common.FilterStateValue {
	return &common.FilterStateValue{
		Key:        &common.FilterStateValue_ObjectKey{ObjectKey: model.FilterStateRouteUpstream},
		FactoryKey: "envoy.string",
		ReadOnly:   true,
		Value:      &common.FilterStateValue_FormatString{FormatString: formatString("%DOWNSTREAM_LOCAL_ADDRESS%")},
	}
}

func (b *resourceBuilder) serviceEntryHCM(
	manager *hcm.HttpConnectionManager,
	hosts []string,
) *hcm.HttpConnectionManager {
	manager = proto.Clone(manager).(*hcm.HttpConnectionManager)
	names := make([]string, 0, len(hosts)*2)
	for _, host := range hosts {
		names = append(names, strconv.Quote(host), strconv.Quote(host+"."))
	}
	guard := buildHostMatchRBACFilter(mustParseCEL(fmt.Sprintf(
		"request.method != 'CONNECT' && !(request.host.split(':')[0].lowerAscii() in [%s])", strings.Join(names, ","),
	)), "deny-service-entry-host-mismatch")
	guard.Name = "agentio.service_entry_host"
	target := httpFilter(
		"agentio.endpoint_upstream",
		b.pack(&httpstate.Config{OnRequestHeaders: []*common.FilterStateValue{serviceEntryTarget()}}),
	)
	// Application CONNECT names the tunnel target, not the intercepted proxy.
	target = b.skipHTTPFilter(target, &xdsmatcher.Matcher_MatcherList_Predicate{
		MatchType: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_{
			SinglePredicate: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate{
				Input: typedExtension(
					"request-headers",
					b.pack(&matcher.HttpRequestHeaderMatchInput{HeaderName: ":method"}),
				),
				Matcher: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_ValueMatch{
					ValueMatch: &xdsmatcher.StringMatcher{
						MatchPattern: &xdsmatcher.StringMatcher_Exact{Exact: "CONNECT"},
					},
				},
			},
		},
	})
	manager.HttpFilters = append([]*hcm.HttpFilter{guard, target}, manager.HttpFilters...)
	return manager
}

func (b *resourceBuilder) skipHTTPFilter(
	f *hcm.HttpFilter,
	predicate *xdsmatcher.Matcher_MatcherList_Predicate,
) *hcm.HttpFilter {
	return httpFilter(f.Name, b.pack(&matching.ExtensionWithMatcher{
		ExtensionConfig: typedCoreExtension("envoy.filters.http.set_filter_state", f.GetTypedConfig()),
		XdsMatcher: &xdsmatcher.Matcher{
			MatcherType: &xdsmatcher.Matcher_MatcherList_{MatcherList: &xdsmatcher.Matcher_MatcherList{
				Matchers: []*xdsmatcher.Matcher_MatcherList_FieldMatcher{{
					Predicate: predicate,
					OnMatch: &xdsmatcher.Matcher_OnMatch{OnMatch: &xdsmatcher.Matcher_OnMatch_Action{
						Action: typedExtension("skip", b.pack(&skip.SkipFilter{})),
					}},
				}},
			}},
		},
	}))
}
