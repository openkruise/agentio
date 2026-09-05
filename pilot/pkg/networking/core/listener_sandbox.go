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

package core

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	xds "github.com/cncf/xds/go/xds/core/v3"
	matcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	rbacconfig "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extensionmatching "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	ratelimitv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	skipaction "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/matcher/action/v3"
	sfsvalue "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	dfphttp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	localratelimit "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	rbachttp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	sfshttp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	sfsnetwork "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/set_filter_state/v3"
	tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	rlexpr "github.com/envoyproxy/go-control-plane/envoy/extensions/rate_limit_descriptors/expr/v3"
	sniv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/cert_mappers/sni/v3"
	on_demand_secretv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/cert_selectors/on_demand_secret/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	httpmatcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	envoytypev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/google/cel-go/cel"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	istionetworking "istio.io/istio/pilot/pkg/networking"
	"istio.io/istio/pilot/pkg/networking/core/envoyfilter"
	"istio.io/istio/pilot/pkg/networking/core/match"
	istio_route "istio.io/istio/pilot/pkg/networking/core/route"
	"istio.io/istio/pilot/pkg/networking/core/route/retry"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pilot/pkg/util/protoconv"
	xdsfilters "istio.io/istio/pilot/pkg/xds/filters"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/proto"
	"istio.io/istio/pkg/wellknown"
)

const (
	forwardHttpFilterChain   = "forward-http"
	forwardTcpFilterChain    = "forward-tcp"
	tlsTerminateFilterChain  = "tls-terminate"
	httpForwardCluster       = "http_dynamic_forward_proxy"
	tlsOriginateCluster      = "tls_connect_originate"
	tlsProxyOriginateCluster = "tls_proxy_originate"
	// agentioDFPCacheName is the dynamic_forward_proxy DNS cache name shared by
	// the HTTP filter in buildWaypointInboundHTTPFilters and the upstream
	// cluster in buildDefaultTLSConnectOriginateCluster. Both ends must use the
	// same name or the HTTP forward path resolves into a different cache than
	// the cluster connects from, causing intermittent UH/503.
	agentioDFPCacheName = "agentio_dns_cache"
	// noSNISentinel is the SDS resource name envoy requests when the client
	// hello has no SNI. It must be >=1 char (proto min_len) and must not be a
	// valid DNS domain, so pilot's SDS rejects it (IsValidOnDemandDomain) and
	// the handshake fails.
	noSNISentinel = "_no_sni_"

	// outerSNIFilterStateKey carries the original ClientHello SNI from the
	// outer tls-terminate chain across the internal-listener hop into the
	// forward-http HCM. The HCM's RBAC filter compares it against the inner
	// :authority — preventing a client from passing the SNI allowlist with
	// trusted.com and then targeting untrusted.com via the inner Host header.
	// For CONNECT requests to an HTTPS proxy, the same value is copied into the
	// standard Envoy upstream TLS identity keys at request scope.
	outerSNIFilterStateKey                = "io.kruise.outer_sni"
	upstreamServerNameFilterStateKey      = "envoy.network.upstream_server_name"
	upstreamSubjectAltNamesFilterStateKey = "envoy.network.upstream_subject_alt_names"
	dynamicHostFilterStateKey             = "envoy.upstream.dynamic_host"
	dynamicPortFilterStateKey             = "envoy.upstream.dynamic_port"
	staticEndpointFilterStateFilter       = "agentio.static_endpoint_filter_state"

	// networkSetFilterStateName labels the network set_filter_state filter that
	// captures outer SNI. Envoy dispatches it by typed_config type URL, so a
	// purpose-specific name keeps config dumps readable.
	networkSetFilterStateName = "connect_sni"
	// connectProxyTLSIdentityFilterName labels the request-scoped HTTP filter
	// that copies outer SNI into Envoy's upstream TLS identity keys for CONNECT.
	connectProxyTLSIdentityFilterName = "connect-proxy-tls-identity"
	// clearDownstreamPeerFilterName is the HCM instance label for the
	// set_filter_state HTTP filter built by sandboxClearPeerMetadataObjFilter.
	// Custom (non-canonical) so the filter's purpose is obvious in config dumps.
	clearDownstreamPeerFilterName = "clear_downstream_peer"
	// connectDownstreamFilterName is the network-filter instance label for the
	// set_filter_state filter built by buildSandboxRelayFilter, which re-declares
	// the downstream peer / RBAC keys ONCE on the tls-terminate chain so they
	// reach main_forward. Custom (non-canonical) for readable config dumps.
	connectDownstreamFilterName = "connect_downstream_peer"

	sniTrafficPolicyDenyFilterChain = "sni-traffic-policy-deny"
)

func sniTrafficPolicyEnabled(metadata *model.NodeMetadata) bool {
	return features.EnableSniTrafficPolicy &&
		agentio.SupportsPolicyCapability(metadata, agentio.SniTrafficPolicyCapability)
}

// buildCaptureSNIFilter returns a network filter that captures the downstream
// ClientHello SNI into shared filter state. Placed BEFORE the TCP proxy on the
// tls-terminate chain. SharedWithUpstream=ONCE propagates the value across the
// internal-listener hop into MainForwardName. SkipIfEmpty avoids writing an
// invalid identity object when SNI is absent.
// The shared value must be Hashable so different outer SNIs cannot reuse an
// internal connection and spuriously fail the SNI/Host guard.
func buildCaptureSNIFilter() *listener.Filter {
	return &listener.Filter{
		Name: networkSetFilterStateName,
		ConfigType: &listener.Filter_TypedConfig{TypedConfig: protoconv.MessageToAny(&sfsnetwork.Config{
			OnNewConnection: []*sfsvalue.FilterStateValue{{
				Key:        &sfsvalue.FilterStateValue_ObjectKey{ObjectKey: outerSNIFilterStateKey},
				FactoryKey: "istio.hashable_string",
				Value: &sfsvalue.FilterStateValue_FormatString{
					FormatString: &core.SubstitutionFormatString{
						OmitEmptyValues: true,
						Format: &core.SubstitutionFormatString_TextFormatSource{
							TextFormatSource: &core.DataSource{
								Specifier: &core.DataSource_InlineString{InlineString: "%REQUESTED_SERVER_NAME%"},
							},
						},
					},
				},
				SharedWithUpstream: sfsvalue.FilterStateValue_ONCE,
				SkipIfEmpty:        true,
			}},
		})},
	}
}

// buildConnectProxyTLSIdentityFilter copies the outer proxy SNI into Envoy's
// standard upstream TLS identity filter-state keys only for CONNECT requests.
// ExtensionWithMatcher skips the wrapped set_filter_state filter for every
// other method, so ordinary requests retain auto_sni and auto_san_validation.
func buildConnectProxyTLSIdentityFilter() *hcm.HttpFilter {
	outerSNIFormat := &core.SubstitutionFormatString{
		OmitEmptyValues: true,
		Format: &core.SubstitutionFormatString_TextFormatSource{
			TextFormatSource: &core.DataSource{
				Specifier: &core.DataSource_InlineString{
					InlineString: fmt.Sprintf("%%FILTER_STATE(%s:PLAIN)%%", outerSNIFilterStateKey),
				},
			},
		},
	}
	setTLSIdentity := &sfshttp.Config{
		OnRequestHeaders: []*sfsvalue.FilterStateValue{
			{
				Key:         &sfsvalue.FilterStateValue_ObjectKey{ObjectKey: upstreamServerNameFilterStateKey},
				Value:       &sfsvalue.FilterStateValue_FormatString{FormatString: outerSNIFormat},
				SkipIfEmpty: true,
			},
			{
				Key:         &sfsvalue.FilterStateValue_ObjectKey{ObjectKey: upstreamSubjectAltNamesFilterStateKey},
				Value:       &sfsvalue.FilterStateValue_FormatString{FormatString: outerSNIFormat},
				SkipIfEmpty: true,
			},
		},
	}
	connectMethod := &matcher.Matcher_MatcherList_Predicate{
		MatchType: &matcher.Matcher_MatcherList_Predicate_SinglePredicate_{
			SinglePredicate: &matcher.Matcher_MatcherList_Predicate_SinglePredicate{
				Input: &xds.TypedExtensionConfig{
					Name: "request-headers",
					TypedConfig: protoconv.MessageToAny(&httpmatcher.HttpRequestHeaderMatchInput{
						HeaderName: ":method",
					}),
				},
				Matcher: &matcher.Matcher_MatcherList_Predicate_SinglePredicate_ValueMatch{
					ValueMatch: &matcher.StringMatcher{
						MatchPattern: &matcher.StringMatcher_Exact{Exact: ConnectUpgradeType},
					},
				},
			},
		},
	}
	skipFilter := &matcher.Matcher_OnMatch{
		OnMatch: &matcher.Matcher_OnMatch_Action{
			Action: &xds.TypedExtensionConfig{
				Name:        "skip",
				TypedConfig: protoconv.MessageToAny(&skipaction.SkipFilter{}),
			},
		},
	}
	wrapped := &extensionmatching.ExtensionWithMatcher{
		XdsMatcher: &matcher.Matcher{
			MatcherType: &matcher.Matcher_MatcherList_{
				MatcherList: &matcher.Matcher_MatcherList{
					Matchers: []*matcher.Matcher_MatcherList_FieldMatcher{{
						Predicate: &matcher.Matcher_MatcherList_Predicate{
							MatchType: &matcher.Matcher_MatcherList_Predicate_NotMatcher{
								NotMatcher: connectMethod,
							},
						},
						OnMatch: skipFilter,
					}},
				},
			},
		},
		ExtensionConfig: &core.TypedExtensionConfig{
			Name:        "envoy.filters.http.set_filter_state",
			TypedConfig: protoconv.MessageToAny(setTLSIdentity),
		},
	}
	return &hcm.HttpFilter{
		Name:       connectProxyTLSIdentityFilterName,
		ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: protoconv.MessageToAny(wrapped)},
	}
}

// sandboxRelayKeys are the filter-state objects that SandboxConnectAuthorityFilter
// sets ONCE on the connect_terminate HCM (see xds/filters/filters.go). ONCE means each key
// is readable on the next hop but its sharing flag is downgraded to None there, so it stops
// propagating on its own and never reaches a real upstream socket pool key. To carry them the
// extra hop into the main_forward listener (where downstream filters such as RBAC consume them)
// they are re-declared ONCE on the tls-terminate chain — the only chain that forwards to
// main_forward.
//
// factory must match the source so the value round-trips through %FILTER_STATE(...:PLAIN)%:
// local_ip and remote_ip are AddressObjects (no factory_key) so RBAC source-IP matching
// keeps working; the principals/authority are istio.hashable_string. original_dst.local_ip
// is ONCE at the source and relayed here so the ORIGINAL_DST listener filter on
// main_forward can resolve the destination; its cardinality (=#destinations) is the
// intended per-destination pool split, not bloat.
var sandboxRelayKeys = []struct {
	key     string
	factory string
}{
	{"envoy.filters.listener.original_dst.local_ip", ""},
	{"envoy.filters.listener.original_dst.remote_ip", ""},
	{"io.istio.peer_principal", "istio.hashable_string"},
	{"io.istio.local_principal", "istio.hashable_string"},
	{xdsfilters.AuthorityFilterStateKey, "istio.hashable_string"},
	// TODO(workload-discovery): once the sandbox.token/labels/id workload-discovery keys
	// are switched from TRANSITIVE to ONCE at the source (see SandboxConnectAuthorityFilter
	// in xds/filters/filters.go), add them here ({key, "envoy.string"}) so this relay carries
	// them the extra hop to whichever chain consumes them, instead of propagating to every hop.
}

// buildSandboxConnectDownstreamFilter returns a network set_filter_state filter that re-declares each
// sandboxRelayKeys entry ONCE, reading the value the previous hop left via %FILTER_STATE(k:PLAIN)%.
// It MUST run on_new_connection and BEFORE the tcp_proxy so the keys propagate to whichever
// upstream cluster the chain selects.
//
// Each value is SkipIfEmpty + OmitEmptyValues: on the plaintext catchall path the principals
// are absent, and an empty AddressObject would fail to parse — skipping avoids writing junk.
// Each value retains the source object's type so existing routing, RBAC, and connection-pool
// isolation semantics remain unchanged.
func buildSandboxConnectDownstreamFilter() *listener.Filter {
	values := make([]*sfsvalue.FilterStateValue, 0, len(sandboxRelayKeys))
	for _, k := range sandboxRelayKeys {
		values = append(values, &sfsvalue.FilterStateValue{
			Key:        &sfsvalue.FilterStateValue_ObjectKey{ObjectKey: k.key},
			FactoryKey: k.factory,
			Value: &sfsvalue.FilterStateValue_FormatString{
				FormatString: &core.SubstitutionFormatString{
					OmitEmptyValues: true,
					Format: &core.SubstitutionFormatString_TextFormatSource{
						TextFormatSource: &core.DataSource{
							Specifier: &core.DataSource_InlineString{
								InlineString: fmt.Sprintf("%%FILTER_STATE(%s:PLAIN)%%", k.key),
							},
						},
					},
				},
			},
			SharedWithUpstream: sfsvalue.FilterStateValue_ONCE,
			SkipIfEmpty:        true,
		})
	}
	return &listener.Filter{
		Name: connectDownstreamFilterName,
		ConfigType: &listener.Filter_TypedConfig{TypedConfig: protoconv.MessageToAny(&sfsnetwork.Config{
			OnNewConnection: values,
		})},
	}
}

// sniHostMismatchCondition is the CEL expression evaluated by the RBAC DENY
// policy. It denies a request when:
//  1. the request is not CONNECT (whose authority names the tunnel target), AND
//  2. the outer SNI was captured (filter state present and non-empty), AND
//  3. the inner :authority neither equals the SNI nor is "<sni>:port".
//
// `filter_state[k]` returns CEL bytes (envoy hard-codes CreateBytes regardless
// of the factory used to set the value). Comparing bytes to a string literal
// errors → policy treated as not matched → request allowed. Wrap with
// `string(...)` so we compare apples to apples; `request.host` is already
// string. If the filter state key is absent (plaintext catchall path), the
// map index itself errors → policy not matched → request passes through.
var sniHostMismatchCondition = fmt.Sprintf(`
	request.method != 'CONNECT' &&
  '%[1]s' in filter_state &&
  string(filter_state['%[1]s']) != '' &&
  request.host.split(':')[0].lowerAscii() != string(filter_state['%[1]s']).lowerAscii()
`, outerSNIFilterStateKey)

// sniHostMismatchExpr is parsed once at process start. cel.NewEnv with no
// declarations parses syntactically without type-checking, which is what we
// want — request.host and filter_state are Envoy-side attributes unknown to
// cel-go but valid in Envoy's CEL evaluator.
var sniHostMismatchExpr = mustParseCEL(sniHostMismatchCondition)

func mustParseCEL(expr string) *exprpb.Expr {
	env, err := cel.NewEnv()
	if err != nil {
		panic(fmt.Errorf("cel env: %w", err))
	}
	ast, issues := env.Parse(expr)
	if issues != nil && issues.Err() != nil {
		panic(fmt.Errorf("cel parse %q: %w", expr, issues.Err()))
	}
	parsed, err := cel.AstToParsedExpr(ast)
	if err != nil {
		panic(fmt.Errorf("cel ast->parsed %q: %w", expr, err))
	}
	return parsed.GetExpr()
}

// buildSNIHostMatchRBACFilter returns an RBAC HTTP filter that denies requests
// whose inner :authority does not match the outer ClientHello SNI captured by
// buildCaptureSNIFilter. Must run BEFORE ext_proc / DFP so policy and DNS
// never see an attacker-controlled Host. Action=DENY with any:true
// permission/principal: the policy fires whenever the CEL condition evaluates
// to true. When the filter state is absent the condition errors → policy not
// matched → request passes (preserves plaintext catchall path).
func buildSNIHostMatchRBACFilter() *hcm.HttpFilter {
	return &hcm.HttpFilter{
		Name: "envoy.filters.http.rbac",
		ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: protoconv.MessageToAny(&rbachttp.RBAC{
			Rules: &rbacconfig.RBAC{
				Action: rbacconfig.RBAC_DENY,
				Policies: map[string]*rbacconfig.Policy{
					"deny-sni-host-mismatch": {
						Permissions: []*rbacconfig.Permission{{
							Rule: &rbacconfig.Permission_Any{Any: true},
						}},
						Principals: []*rbacconfig.Principal{{
							Identifier: &rbacconfig.Principal_Any{Any: true},
						}},
						Condition: sniHostMismatchExpr,
						CelConfig: &core.CelExpressionConfig{
							EnableStringFunctions:  true,
							EnableStringConcat:     true,
							EnableStringConversion: true,
						},
					},
				},
			},
		})},
	}
}

func (lb *ListenerBuilder) buildMainForwardFilters(httpCluster, tcpCluster string, inner bool) []*listener.FilterChain {
	// The inner main_forward HCM (called with inner=true) sits one hop after the
	// tls-terminate chain. It therefore needs both: (1) :scheme rewritten back to
	// https since the inner request is plaintext; (2) downstream h2 codec enabled
	// since the outer ALPN may have negotiated h2 and the bytes arriving here
	// would be HTTP/2 frames. validateSni is independent and additionally gated
	// by the global ValidateTlsTerminatedSNI feature flag.
	schemeOverwrite := ""
	acceptHTTP2 := false
	connectProxyCluster := util.PassthroughCluster
	if inner {
		schemeOverwrite = "https"
		acceptHTTP2 = true
		connectProxyCluster = tlsProxyOriginateCluster
	}
	inner = features.ValidateTlsTerminatedSNI && inner
	catchallHTTP := &listener.FilterChain{
		Name: forwardHttpFilterChain,
		Filters: lb.buildWaypointInboundHTTPFilters(nil, inboundChainConfig{
			clusterName: httpCluster,
			port: model.ServiceInstancePort{
				ServicePort: &model.Port{
					Name:     "unknown",
					Protocol: protocol.HTTP,
				},
			},
			bind:                               "0.0.0.0",
			hbone:                              true,
			validateSni:                        inner,
			schemeOverwrite:                    schemeOverwrite,
			acceptHTTP2:                        acceptHTTP2,
			connectProxyCluster:                connectProxyCluster,
			applySandboxConnectionPoolSettings: true,
		}),
	}
	catchallTCP := &listener.FilterChain{
		Name: forwardTcpFilterChain,
		Filters: lb.buildWaypointNetworkFilters(nil, inboundChainConfig{
			clusterName: tcpCluster,
			port: model.ServiceInstancePort{
				ServicePort: &model.Port{
					Name:     "unknown",
					Protocol: protocol.TCP,
				},
			},
			bind:                               "0.0.0.0",
			hbone:                              true,
			applySandboxConnectionPoolSettings: true,
		}),
	}

	return []*listener.FilterChain{catchallHTTP, catchallTCP}
}

// buildSandboxSniTrafficPolicyDenyFilterChain builds the chain the SNI traffic policy matcher
// selects for a denied connection. It is raw rather than TLS-terminating, so the
// client is refused without first being handed a certificate, and the black hole
// cluster closes the connection instead of forwarding it anywhere.
func buildSandboxSniTrafficPolicyDenyFilterChain() *listener.FilterChain {
	return &listener.FilterChain{
		Name: sniTrafficPolicyDenyFilterChain,
		Filters: []*listener.Filter{{
			Name: wellknown.TCPProxy,
			ConfigType: &listener.Filter_TypedConfig{TypedConfig: protoconv.MessageToAny(&tcp.TcpProxy{
				StatPrefix:       sniTrafficPolicyDenyFilterChain,
				ClusterSpecifier: &tcp.TcpProxy_Cluster{Cluster: util.BlackHoleCluster},
			})},
		}},
	}
}

// buildTlsTerminateFilterChain terminates downstream TLS and forwards the
// decrypted stream to the main_forward internal listener for protocol routing.
func (lb *ListenerBuilder) buildTlsTerminateFilterChain(connPool *extensions.ConnectionPoolSettings) *listener.FilterChain {
	tcpProxy := &tcp.TcpProxy{
		StatPrefix:       MainForwardName,
		ClusterSpecifier: &tcp.TcpProxy_Cluster{Cluster: MainForwardName},
	}
	applySandboxTCPTimeouts(connPool, tcpProxy)
	return &listener.FilterChain{
		Name: tlsTerminateFilterChain,
		// Bound the on-demand SDS fetch: if the cert is not delivered within this window
		// (e.g. SDS server unresponsive), fail the handshake instead of holding the connection.
		TransportSocketConnectTimeout: durationpb.New(defaultGatewayTransportSocketConnectTimeout),
		TransportSocket: &core.TransportSocket{
			Name: wellknown.TransportSocketTLS,
			ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: protoconv.MessageToAny(&tls.DownstreamTlsContext{
				CommonTlsContext: &tls.CommonTlsContext{
					AlpnProtocols: util.ALPNHttp,
					CustomTlsCertificateSelector: &core.TypedExtensionConfig{
						Name: "envoy.tls.certificate_selectors.on_demand_secret",
						TypedConfig: protoconv.MessageToAny(&on_demand_secretv3.Config{
							ConfigSource: &core.ConfigSource{
								ResourceApiVersion: core.ApiVersion_V3,
								ConfigSourceSpecifier: &core.ConfigSource_Ads{
									Ads: &core.AggregatedConfigSource{},
								},
							},
							CertificateMapper: &core.TypedExtensionConfig{
								Name: "envoy.tls.certificate_mappers.sni",
								// DefaultValue is required (proto min_len=1). Envoy uses it as
								// the SDS resource name when SNI is empty; this sentinel is not
								// a valid DNS domain so SDS rejects it and the handshake
								// fails — the desired behavior for missing SNI.
								TypedConfig: protoconv.MessageToAny(&sniv3.SNI{DefaultValue: noSNISentinel}),
							},
						}),
					},
				},
				// Disable session resumption: on-demand certs are not integrated with it.
				SessionTicketKeysType: &tls.DownstreamTlsContext_DisableStatelessSessionResumption{
					DisableStatelessSessionResumption: true,
				},
				DisableStatefulSessionResumption: true,
			})},
		},
		Filters: []*listener.Filter{
			// Must precede TCPProxy: TCPProxy hands off to the upstream
			// internal listener; the SNI capture has to populate filter state
			// before that hand-off so it propagates with SharedWithUpstream.
			buildCaptureSNIFilter(),
			// Re-declare the RBAC keys ONCE so they survive the extra hop into
			// the main_forward listener (where RBAC consumes them). They arrive
			// there as None, so they never enter the tls_connect_originate pool
			// key. Must also precede TCPProxy for the same hand-off reason.
			buildSandboxConnectDownstreamFilter(),
			{
				Name:       wellknown.TCPProxy,
				ConfigType: &listener.Filter_TypedConfig{TypedConfig: protoconv.MessageToAny(tcpProxy)},
			},
		},
	}
}

// buildMainForwardListener builds an internal listener for sandbox catchall traffic.
// It performs protocol sniffing: HTTP traffic goes to the HTTP filter chain,
// everything else (on_no_match) goes to the TCP filter chain.
// Ordinary HTTP and TCP both use the TLS-origination DFP cluster. A CONNECT
// request on the HTTP chain instead uses the TLS original-destination proxy
// cluster so its authority cannot replace the upstream proxy address.
func (lb *ListenerBuilder) buildMainForwardListener() *listener.Listener {
	l := &listener.Listener{
		Name:              MainForwardName,
		ListenerSpecifier: &listener.Listener_InternalListener{InternalListener: &listener.Listener_InternalListenerConfig{}},
		ListenerFilters: []*listener.ListenerFilter{
			xdsfilters.OriginalDestination,
			xdsfilters.TLSInspector,
			xdsfilters.HTTPInspector,
		},
		TrafficDirection: core.TrafficDirection_INBOUND,
		FilterChains:     lb.buildMainForwardFilters(tlsOriginateCluster, tlsOriginateCluster, true),
		FilterChainMatcher: match.ToMatcher(match.NewTransportProtocol(match.TransportProtocolMatch{
			TLS: match.ToChain(forwardTcpFilterChain),
			Other: match.NewAppProtocol(match.ProtocolMatch{
				TCP:  match.ToChain(forwardTcpFilterChain),
				HTTP: match.ToChain(forwardHttpFilterChain),
			}),
		})).GetMatcher(),
	}

	accessLogBuilder.setListenerAccessLog(lb.push, lb.node, l, istionetworking.ListenerClassSidecarInbound)
	return l
}

// sandboxListeners returns sandbox-egress-specific listeners appended to the
// waypoint listener list.
func sandboxListeners(lb *ListenerBuilder) []*listener.Listener {
	return []*listener.Listener{lb.buildMainForwardListener()}
}

// connectAuthorityFilter returns the HTTP filter used on the HCM
// connect-terminate chain. Substitutes the sandbox-aware variant when this node
// is a sandbox egress; otherwise returns the standard waypoint filter.
func connectAuthorityFilter(node *model.Proxy) *hcm.HttpFilter {
	if agentio.IsSandboxEgress(node) {
		return xdsfilters.SandboxConnectAuthorityFilter
	}
	// TODO: Remove in 1.32.
	if !node.VersionGreaterOrEqual(&model.IstioVersion{Major: 1, Minor: 29, Patch: 2}) {
		return xdsfilters.ConnectAuthorityFilterPre1_29_2
	}
	return xdsfilters.ConnectAuthorityFilter
}

// sandboxOverrideHTTPInspector returns the HTTP inspector to use on the
// MainInternal listener (the unmodified inspector, since sandbox workloads
// can bind arbitrary ports and cannot opt out per-port).
func sandboxOverrideHTTPInspector() *listener.ListenerFilter {
	return xdsfilters.HTTPInspector
}

// sandboxOverrideTLSInspector returns the TLS inspector to use on the
// MainInternal listener (always enabled, no port filter).
func sandboxOverrideTLSInspector() *listener.ListenerFilter {
	return xdsfilters.TLSInspector
}

// deepestOnNoMatchTarget walks one level into the matcher tree to find the
// matcher whose OnNoMatch should be mutated. When the primary matcher is wrapped
// (e.g., multi-network hostname wrapper around the IP tree), the wrapped inner
// matcher is the correct mutation target. This preserves the exact two-level
// walk used by the original inline logic.
func deepestOnNoMatchTarget(primaryMatcher *matcher.Matcher) *matcher.Matcher {
	target := primaryMatcher
	if onNoMatch := primaryMatcher.GetOnNoMatch(); onNoMatch != nil {
		if hostnameMatcher := onNoMatch.GetMatcher(); hostnameMatcher != nil {
			target = hostnameMatcher
		}
	}
	return target
}

// buildSandboxProtocolMatcher builds the matcher used when no SNI rule matches:
// TLS → forward-tcp, HTTP → forward-http, TCP → forward-tcp.
func buildSandboxProtocolMatcher() *matcher.Matcher {
	return match.NewTransportProtocol(match.TransportProtocolMatch{
		TLS: match.ToChain(forwardTcpFilterChain),
		Other: match.NewAppProtocol(match.ProtocolMatch{
			TCP:  match.ToChain(forwardTcpFilterChain),
			HTTP: match.ToChain(forwardHttpFilterChain),
		}),
	})
}

// buildSandboxSNIMatcher builds the three-tier SNI matcher used when TLS
// termination is configured:
//  1. excludeHosts → forward-tcp (bypass TLS termination)
//  2. includeHosts → tls-terminate (TLS termination with dynamic forward proxy)
//  3. no SNI match → fallback to protocol-based detection
func buildSandboxSNIMatcher(tlsTermCfg sandboxTLSTermination, protocolFallback *matcher.Matcher_OnMatch) *matcher.Matcher_OnMatch {
	return match.ToMatcher(match.NewSNIMatcher([]match.SNIDomainMatch{
		{Domains: tlsTermCfg.GetExcludeHosts(), OnMatch: match.ToChain(forwardTcpFilterChain)},
		{Domains: tlsTermCfg.GetIncludeHosts(), OnMatch: match.ToChain(tlsTerminateFilterChain)},
	}, protocolFallback))
}

// buildSandboxSNITrafficPolicyMatcher keeps the legacy tls_termination.exclude_hosts
// bypass ahead of SNI policy evaluation. Every remaining TLS connection is routed
// by the SNI policy custom matcher, which picks between terminating TLS, passing
// through, and denying; non-TLS traffic retains protocol-based routing.
//
// The transport-protocol gate stays in front of the policy matcher: a plaintext
// connection carries no SNI, so there is nothing for the policy to evaluate and
// it must not reach the TLS-terminating chain.
func buildSandboxSNITrafficPolicyMatcher(excludeHosts []string, protocolFallback *matcher.Matcher) *matcher.Matcher_OnMatch {
	policyFallback := match.ToMatcher(match.NewTransportProtocol(match.TransportProtocolMatch{
		TLS: match.ToMatcher(match.NewSniTrafficPolicyMatcher(
			tlsTerminateFilterChain, forwardTcpFilterChain, sniTrafficPolicyDenyFilterChain)),
		Other: protocolFallback,
	}))
	if len(excludeHosts) == 0 {
		return policyFallback
	}
	return match.ToMatcher(match.NewSNIMatcher([]match.SNIDomainMatch{
		{Domains: excludeHosts, OnMatch: match.ToChain(forwardTcpFilterChain)},
	}, policyFallback))
}

// sandboxTLSTermination is the minimal interface satisfied by the sandbox
// TlsTermination config message used in buildSandboxSNIMatcher. Defined here so
// the helper does not directly import the sandbox API proto.
type sandboxTLSTermination interface {
	GetIncludeHosts() []string
	GetExcludeHosts() []string
}

// applySandboxInternalChains appends sandbox-egress catchall filter chains to the
// waypoint MainInternal listener and rewires primaryMatcher's deepest OnNoMatch
// to route into them. No-op when the node is not a sandbox egress.
func applySandboxInternalChains(
	lb *ListenerBuilder,
	chains []*listener.FilterChain,
	primaryMatcher *matcher.Matcher,
) []*listener.FilterChain {
	if !agentio.IsSandboxEgress(lb.node) {
		return chains
	}
	// catchall-main-forward: forwards unmatched traffic to the main_forward internal listener.
	chains = append(chains, lb.buildMainForwardFilters(httpForwardCluster, util.PassthroughCluster, false)...)

	target := deepestOnNoMatchTarget(primaryMatcher)
	protocolFallback := buildSandboxProtocolMatcher()

	gateway := agentio.FindEgressGatewayForProxy(lb.node, lb.push.AgentioConfig.GetEgressGateways())
	tlsTermCfg := gateway.GetTlsTermination()
	if sniTrafficPolicyEnabled(lb.node.Metadata) {
		// The policy decision is made when the filter chain is selected, so both
		// outcomes must be chains on this listener: terminating TLS is a property of
		// a chain's transport socket, which is fixed before any network filter runs.
		chains = append(chains,
			lb.buildTlsTerminateFilterChain(gateway.GetConnectionPool()),
			buildSandboxSniTrafficPolicyDenyFilterChain())
		var excludeHosts []string
		if tlsTermCfg != nil {
			excludeHosts = tlsTermCfg.GetExcludeHosts()
		}
		target.OnNoMatch = buildSandboxSNITrafficPolicyMatcher(excludeHosts, protocolFallback)
	} else if features.EnableOnDemandCerts && tlsTermCfg != nil {
		// catchall-tls: terminates TLS with on-demand certs.
		chains = append(chains, lb.buildTlsTerminateFilterChain(gateway.GetConnectionPool()))
		target.OnNoMatch = buildSandboxSNIMatcher(tlsTermCfg, match.ToMatcher(protocolFallback))
	} else {
		target.OnNoMatch = match.ToMatcher(protocolFallback)
	}
	return chains
}

// buildSandboxDFPFilter builds the dynamic-forward-proxy HCM filter that resolves
// upstream hosts via the sandbox DNS cache. Must sit between authz/ext_proc and
// the router so DNS is not leaked for forbidden destinations.
func buildSandboxDFPFilter(allowDynamicHostFromFilterState bool) *hcm.HttpFilter {
	return &hcm.HttpFilter{
		Name: "envoy.filters.http.dynamic_forward_proxy",
		ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: protoconv.MessageToAny(&dfphttp.FilterConfig{
			ImplementationSpecifier: &dfphttp.FilterConfig_DnsCacheConfig{
				DnsCacheConfig: sandboxDFPDNSCacheConfig(),
			},
			AllowDynamicHostFromFilterState: allowDynamicHostFromFilterState,
		})},
	}
}

// buildSandboxStaticEndpointFilterStateFilter installs set_filter_state in the
// decoder chain. Its listener-level configuration is intentionally empty: only
// service-entry routes supply values through typed_per_filter_config, leaving
// ordinary DFP routes untouched.
func buildSandboxStaticEndpointFilterStateFilter() *hcm.HttpFilter {
	return &hcm.HttpFilter{
		Name: staticEndpointFilterStateFilter,
		ConfigType: &hcm.HttpFilter_TypedConfig{
			TypedConfig: protoconv.MessageToAny(&sfshttp.Config{}),
		},
	}
}

// buildSandboxStaticEndpointFilterStateConfig binds one route-selected endpoint
// to DFP while retaining the request's original destination port. Keeping this
// configuration on the route (or weighted-cluster entry) avoids using a
// request header as an internal transport between filters.
func buildSandboxStaticEndpointFilterStateConfig(address string) *anypb.Any {
	return protoconv.MessageToAny(&sfshttp.Config{
		OnRequestHeaders: []*sfsvalue.FilterStateValue{
			{
				Key: &sfsvalue.FilterStateValue_ObjectKey{
					ObjectKey: dynamicHostFilterStateKey,
				},
				Value: &sfsvalue.FilterStateValue_FormatString{
					FormatString: &core.SubstitutionFormatString{
						Format: &core.SubstitutionFormatString_TextFormatSource{
							TextFormatSource: &core.DataSource{
								Specifier: &core.DataSource_InlineString{
									InlineString: address,
								},
							},
						},
					},
				},
				ReadOnly: true,
			},
			{
				Key: &sfsvalue.FilterStateValue_ObjectKey{
					ObjectKey: dynamicPortFilterStateKey,
				},
				Value: &sfsvalue.FilterStateValue_FormatString{
					FormatString: &core.SubstitutionFormatString{
						OmitEmptyValues: true,
						Format: &core.SubstitutionFormatString_TextFormatSource{
							TextFormatSource: &core.DataSource{
								Specifier: &core.DataSource_InlineString{
									InlineString: "%FILTER_STATE(" + xdsfilters.OriginalDstFilterStateKey + ":FIELD:port)%",
								},
							},
						},
					},
				},
				ReadOnly:    true,
				SkipIfEmpty: true,
			},
		},
	})
}

// appendSandboxHTTPFilters appends sandbox-egress HCM filters in the required
// order: optional SNI/host-mismatch RBAC, ext_proc, DFP. The caller is responsible
// for appending the router filter AFTER this returns. No-op when the node is not
// a sandbox egress.
func appendSandboxHTTPFilters(lb *ListenerBuilder, filters []*hcm.HttpFilter, validateSni bool) []*hcm.HttpFilter {
	if !agentio.IsSandboxEgress(lb.node) {
		return filters
	}
	if validateSni {
		// Reject requests whose inner :authority does not match the outer
		// ClientHello SNI captured by buildCaptureSNIFilter. Without this,
		// a client could SNI=trusted.com (passing tls_termination.include_hosts)
		// then send Host: untrusted.com and DFP would resolve the user-supplied
		// value, bypassing the egress allowlist. Filter state absent (plaintext
		// catchall path that did not go through tls-terminate) → CEL errors →
		// policy not matched → request passes.
		filters = append(filters, buildSNIHostMatchRBACFilter())
	}
	// ext_proc runs first so external auth/policy can reject before we pay the
	// cost of a DNS lookup and to keep authz decisions before any egress side effect.
	filters = append(filters, agentio.BuildExtProcFilter(lb.node, lb.push.AgentioConfig)...)
	gateway := sandboxEgressGateway(lb)
	staticEndpoints := len(gateway.GetServiceEntries()) > 0
	if staticEndpoints {
		filters = append(filters, buildSandboxStaticEndpointFilterStateFilter())
	}
	// DFP must sit between authz/ext_proc and the router: prepending it would let
	// it resolve the upstream host before RBAC/JWT/ext_proc had a chance to deny
	// the request, leaking DNS for forbidden destinations.
	filters = append(filters, buildSandboxDFPFilter(staticEndpoints))
	return filters
}

var (
	defaultStreamIdleTimeout = durationpb.New(30 * time.Minute)
	defaultTCPIdleTimeout    = durationpb.New(1 * time.Hour)
)

// sandboxEgressGateway returns the gateway configuration selected for this
// proxy's verified namespace and service account identity.
func sandboxEgressGateway(lb *ListenerBuilder) *extensions.EgressGateway {
	if !agentio.IsSandboxEgress(lb.node) {
		return nil
	}
	return agentio.FindEgressGatewayForProxy(lb.node, lb.push.AgentioConfig.GetEgressGateways())
}

// sandboxGatewayConnPool returns the ConnectionPoolSettings for the current
// sandbox egress gateway. Returns nil when the node is not a sandbox egress
// or no ConnectionPool is configured.
func sandboxGatewayConnPool(lb *ListenerBuilder) *extensions.ConnectionPoolSettings {
	return sandboxEgressGateway(lb).GetConnectionPool()
}

// buildSandboxHTTPRouteConfig builds the connection-pool-only form used when no
// static service entries are supplied.
func buildSandboxHTTPRouteConfig(
	lb *ListenerBuilder,
	cc inboundChainConfig,
	connPool *extensions.ConnectionPoolSettings,
) *route.RouteConfiguration {
	return buildSandboxHTTPRouteConfigForGateway(lb, cc, &extensions.EgressGateway{ConnectionPool: connPool})
}

// buildSandboxHTTPRouteConfigForGateway generates a RouteConfiguration with
// static service-entry and connection-pool override VirtualHosts, plus a
// wildcard fallback. Static routes keep the chain's DFP cluster but select a
// configured endpoint through route-local filter configuration.
func buildSandboxHTTPRouteConfigForGateway(lb *ListenerBuilder, cc inboundChainConfig, gateway *extensions.EgressGateway) *route.RouteConfiguration {
	var vhosts []*route.VirtualHost
	connPool := gateway.GetConnectionPool()
	staticDomains := make(map[string]struct{})

	for serviceIndex, service := range gateway.GetServiceEntries() {
		if service == nil {
			continue
		}
		addresses := make([]string, 0, len(service.GetEndpoints()))
		for _, endpoint := range service.GetEndpoints() {
			if endpoint != nil && endpoint.GetAddress() != "" {
				addresses = append(addresses, endpoint.GetAddress())
			}
		}
		if len(addresses) == 0 {
			continue
		}
		for hostIndex, serviceHost := range service.GetHosts() {
			if serviceHost == "" {
				continue
			}
			domains := []string{serviceHost, serviceHost + ":*"}
			for _, domain := range domains {
				staticDomains[strings.ToLower(domain)] = struct{}{}
			}
			settings := sandboxRouteSettingsForHost(connPool, serviceHost)
			vhosts = append(vhosts, &route.VirtualHost{
				Name:    fmt.Sprintf("sandbox|service-entry|%d|%d", serviceIndex, hostIndex),
				Domains: domains,
				Routes:  []*route.Route{buildSandboxStaticEndpointRoute(lb, cc, settings, addresses)},
			})
		}
	}

	for i, override := range connPool.GetHttp().GetRouteOverrides() {
		domains := make([]string, 0, len(override.GetHosts()))
		for _, domain := range override.GetHosts() {
			if _, found := staticDomains[strings.ToLower(domain)]; !found {
				domains = append(domains, domain)
			}
		}
		if len(domains) == 0 {
			continue
		}
		vhosts = append(vhosts, &route.VirtualHost{
			Name:    fmt.Sprintf("sandbox|override|%d", i),
			Domains: domains,
			Routes:  []*route.Route{buildSandboxRoute(lb, cc, override.GetSettings())},
		})
	}

	catchAllRoute := buildSandboxRoute(lb, cc, connPool.GetHttp().GetDefaultRoute())
	vhosts = append(vhosts, &route.VirtualHost{
		Name:    "sandbox|default|" + strconv.Itoa(cc.port.Port),
		Domains: []string{"*"},
		Routes:  []*route.Route{catchAllRoute},
	})

	rc := &route.RouteConfiguration{
		Name:             cc.clusterName,
		VirtualHosts:     vhosts,
		ValidateClusters: proto.BoolFalse,
	}
	prependSandboxConnectRoute(rc, cc.connectProxyCluster)
	efw := lb.envoyFilterWrapper
	if efw == nil && lb.push != nil && lb.push.Mesh != nil {
		efw = lb.push.EnvoyFilters(lb.node)
	}
	return envoyfilter.ApplyRouteConfigurationPatches(networking.EnvoyFilter_SIDECAR_INBOUND, lb.node, efw, rc)
}

func buildSandboxStaticEndpointRoute(
	lb *ListenerBuilder,
	cc inboundChainConfig,
	settings *extensions.HttpRouteSettings,
	addresses []string,
) *route.Route {
	out := buildSandboxRoute(lb, cc, settings)
	if len(addresses) == 1 {
		out.TypedPerFilterConfig = map[string]*anypb.Any{
			staticEndpointFilterStateFilter: buildSandboxStaticEndpointFilterStateConfig(addresses[0]),
		}
		return out
	}

	// Weighted cluster selection happens as part of route selection, before HTTP
	// decoder filters run. Giving each equal-weight entry its own set_filter_state
	// config therefore selects an endpoint before DFP inspects the request. All
	// entries deliberately retain the same DFP cluster: only the dynamic host
	// changes, while the request's original port is preserved.
	weightedClusters := make([]*route.WeightedCluster_ClusterWeight, 0, len(addresses))
	for _, address := range addresses {
		weightedClusters = append(weightedClusters, &route.WeightedCluster_ClusterWeight{
			Name:   cc.clusterName,
			Weight: wrapperspb.UInt32(1),
			TypedPerFilterConfig: map[string]*anypb.Any{
				staticEndpointFilterStateFilter: buildSandboxStaticEndpointFilterStateConfig(address),
			},
		})
	}
	out.GetRoute().ClusterSpecifier = &route.RouteAction_WeightedClusters{
		WeightedClusters: &route.WeightedCluster{Clusters: weightedClusters},
	}
	return out
}

func sandboxRouteSettingsForHost(connPool *extensions.ConnectionPoolSettings, serviceHost string) *extensions.HttpRouteSettings {
	settings := connPool.GetHttp().GetDefaultRoute()
	bestRank, bestLength := -1, -1
	for _, override := range connPool.GetHttp().GetRouteOverrides() {
		for _, domain := range override.GetHosts() {
			rank, length, matched := sandboxDomainMatchSpecificity(domain, serviceHost)
			if matched && (rank > bestRank || rank == bestRank && length > bestLength) {
				settings = override.GetSettings()
				bestRank, bestLength = rank, length
			}
		}
	}
	return settings
}

// sandboxDomainMatchSpecificity mirrors Envoy VirtualHost domain precedence:
// exact, suffix wildcard, prefix wildcard, then the catch-all wildcard.
func sandboxDomainMatchSpecificity(pattern, value string) (rank int, length int, matched bool) {
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

// prependSandboxConnectRoute adds the CONNECT-specific route without rebuilding
// or replacing the existing virtual hosts and ordinary routes.
func prependSandboxConnectRoute(rc *route.RouteConfiguration, clusterName string) {
	if rc == nil || clusterName == "" {
		return
	}
	for _, vhost := range rc.GetVirtualHosts() {
		vhost.Routes = append([]*route.Route{buildSandboxConnectRoute(clusterName)}, vhost.GetRoutes()...)
	}
}

// buildSandboxConnectRoute forwards an application-level CONNECT request to
// the proxy at the original destination. ConnectConfig is intentionally absent:
// the upstream proxy, rather than Agentio, terminates the CONNECT exchange.
func buildSandboxConnectRoute(clusterName string) *route.Route {
	return &route.Route{
		Name: "sandbox-connect",
		Match: &route.RouteMatch{
			PathSpecifier: &route.RouteMatch_ConnectMatcher_{
				ConnectMatcher: &route.RouteMatch_ConnectMatcher{},
			},
		},
		Action: &route.Route_Route{Route: &route.RouteAction{
			ClusterSpecifier: &route.RouteAction_Cluster{Cluster: clusterName},
			Timeout:          durationpb.New(0),
			UpgradeConfigs: []*route.RouteAction_UpgradeConfig{{
				UpgradeType: ConnectUpgradeType,
			}},
		}},
	}
}

// buildSandboxRoute builds a single inbound route with optional timeout/retry
// overrides from HttpRouteSettings. Returns the Istio default inbound route
// when settings is nil.
func buildSandboxRoute(lb *ListenerBuilder, cc inboundChainConfig, settings *extensions.HttpRouteSettings) *route.Route {
	var timeout *durationpb.Duration
	if settings != nil {
		timeout = settings.Timeout
	}
	out := istio_route.BuildDefaultHTTPSandboxRoute(lb.node, cc.clusterName, timeout)
	if settings == nil {
		return out
	}
	action := out.GetRoute()
	if settings.Retries != nil {
		action.RetryPolicy = retry.ConvertPolicy(settings.Retries, false)
	}
	return out
}

// applySandboxStreamIdleTimeout overrides the HCM StreamIdleTimeout for sandbox
// egress nodes. Uses the gateway's connection_pool.stream_idle_timeout if
// configured, otherwise defaults to 30min. No-op for non-sandbox nodes.
func applySandboxStreamIdleTimeout(lb *ListenerBuilder, h *hcm.HttpConnectionManager) {
	if !agentio.IsSandboxEgress(lb.node) {
		return
	}
	connPool := sandboxGatewayConnPool(lb)
	if t := connPool.GetHttp().GetStreamIdleTimeout(); t != nil {
		h.StreamIdleTimeout = t
	} else {
		h.StreamIdleTimeout = defaultStreamIdleTimeout
	}
}

// applySandboxTCPTimeouts sets IdleTimeout and MaxDownstreamConnectionDuration
// on a TCPProxy filter for sandbox egress. Uses gateway connection_pool values
// if configured, otherwise applies defaults (idle=1h, max_duration=nil).
func applySandboxTCPTimeouts(connPool *extensions.ConnectionPoolSettings, tcpProxy *tcp.TcpProxy) {
	if t := connPool.GetTcp().GetIdleTimeout(); t != nil {
		tcpProxy.IdleTimeout = t
	} else {
		tcpProxy.IdleTimeout = defaultTCPIdleTimeout
	}
	if t := connPool.GetTcp().GetMaxConnectionDuration(); t != nil {
		tcpProxy.MaxDownstreamConnectionDuration = t
	}
}

// buildSandboxConnectTerminateRateLimitFilter builds an envoy.filters.http.local_ratelimit
// HTTP filter from the sandbox LocalRateLimitSettings. Returns nil when rate
// limiting is not configured.
func buildSandboxConnectTerminateRateLimitFilter(lb *ListenerBuilder) *hcm.HttpFilter {
	if !agentio.IsSandboxEgress(lb.node) {
		return nil
	}
	gw := agentio.FindEgressGatewayForProxy(lb.node, lb.push.AgentioConfig.GetEgressGateways())
	rl := gw.GetConnectRateLimit()
	if rl == nil {
		return nil
	}

	cfg := &localratelimit.LocalRateLimit{
		StatPrefix: "connect_rate_limit",
		FilterEnabled: &core.RuntimeFractionalPercent{
			DefaultValue: &envoytypev3.FractionalPercent{
				Numerator:   100,
				Denominator: envoytypev3.FractionalPercent_HUNDRED,
			},
		},
		FilterEnforced: &core.RuntimeFractionalPercent{
			DefaultValue: &envoytypev3.FractionalPercent{
				Numerator:   100,
				Denominator: envoytypev3.FractionalPercent_HUNDRED,
			},
		},
		LocalRateLimitPerDownstreamConnection: rl.GetPerDownstreamConnection(),
	}

	if tb := rl.GetTokenBucket(); tb != nil {
		cfg.TokenBucket = toEnvoyTokenBucket(tb)
	}

	celActions := map[string]*route.RateLimit_Action{}
	for _, d := range rl.GetDescriptors() {
		envoyDesc := &ratelimitv3.LocalRateLimitDescriptor{
			TokenBucket: toEnvoyTokenBucket(d.GetTokenBucket()),
		}
		for _, e := range d.GetEntries() {
			envoyDesc.Entries = append(envoyDesc.Entries, &ratelimitv3.RateLimitDescriptor_Entry{
				Key:   e.GetKey(),
				Value: e.GetValue(),
			})
			if cel := e.GetCel(); cel != "" {
				if _, exists := celActions[e.GetKey()]; !exists {
					celActions[e.GetKey()] = buildCELAction(e.GetKey(), cel)
				}
			}
		}
		cfg.Descriptors = append(cfg.Descriptors, envoyDesc)
	}

	if len(celActions) > 0 {
		rlAction := &route.RateLimit{}
		for _, action := range celActions {
			rlAction.Actions = append(rlAction.Actions, action)
		}
		cfg.RateLimits = []*route.RateLimit{rlAction}
	}

	return &hcm.HttpFilter{
		Name:       "envoy.filters.http.local_ratelimit",
		ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: protoconv.MessageToAny(cfg)},
	}
}

func toEnvoyTokenBucket(tb *extensions.TokenBucket) *envoytypev3.TokenBucket {
	if tb == nil {
		return nil
	}
	out := &envoytypev3.TokenBucket{
		MaxTokens:    tb.GetMaxTokens(),
		FillInterval: tb.GetFillInterval(),
	}
	if tb.GetTokensPerFill() > 0 {
		out.TokensPerFill = &wrapperspb.UInt32Value{Value: tb.GetTokensPerFill()}
	}
	return out
}

// buildCELAction builds a rate limit action using the
// envoy.rate_limit_descriptors.expr CEL extension.
func buildCELAction(descriptorKey, celExpr string) *route.RateLimit_Action {
	return &route.RateLimit_Action{
		ActionSpecifier: &route.RateLimit_Action_Extension{
			Extension: &core.TypedExtensionConfig{
				Name: "envoy.rate_limit_descriptors.expr",
				TypedConfig: protoconv.MessageToAny(&rlexpr.Descriptor{
					DescriptorKey: descriptorKey,
					ExprSpecifier: &rlexpr.Descriptor_Text{
						Text: celExpr,
					},
					SkipIfError: true,
				}),
			},
		},
	}
}
