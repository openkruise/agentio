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
	"slices"
	"time"

	xdscorev3 "github.com/cncf/xds/go/xds/core/v3"
	xdsmatcherv3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extensionmatchingv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	ratelimitv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	skipactionv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/matcher/action/v3"
	setstatecommonv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/set_filter_state/v3"
	dfphttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	localratelimitv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	rbachttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	httpinspectorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/http_inspector/v3"
	originaldstv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/original_dst/v3"
	tlsinspectorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	setstatenetworkv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/set_filter_state/v3"
	tcpproxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	matchinginputv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
	rlexprv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/rate_limit_descriptors/expr/v3"
	snimapperv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/cert_mappers/sni/v3"
	ondemandv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/cert_selectors/on_demand_secret/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/google/cel-go/cel"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking/telemetry"
)

const (
	forwardHTTPChain              = "forward-http"
	forwardTCPChain               = "forward-tcp"
	tlsTerminateChain             = "tls-terminate"
	sniDenyChain                  = "sni-traffic-policy-deny"
	tlsActionKey                  = "agentio.tls.action"
	noSNISentinel                 = "_no_sni_"
	forwardHCMStatPrefix          = "inbound_0.0.0.0_0;"
	outerSNIKey                   = model.FilterStateOuterSNI
	upstreamServerNameKey         = "envoy.network.upstream_server_name"
	upstreamSubjectAltNamesKey    = "envoy.network.upstream_subject_alt_names"
	connectProxyTLSIdentityFilter = "agentio.connect_proxy_tls_identity"
	connectAuthorityKey           = "io.istio.connect_authority"
	dynamicHostKey                = "envoy.upstream.dynamic_host"
	dynamicPortKey                = "envoy.upstream.dynamic_port"
	staticEndpointCandidateFilter = "agentio.static_endpoint_candidate"

	sniPolicyMetadataFormat = "%DYNAMIC_METADATA(" + model.GatewayMetadataNamespace + ":sni:policy)%"
)

// Package-level filters and their encoded configurations are shared read-only.
// EnvoyFilter patches clone the enclosing listener before making any changes.
var (
	transportProtocolInput   = typedExtension("transport-protocol", mustPack(&matchinginputv3.TransportProtocolInput{}))
	applicationProtocolInput = typedExtension(
		"application-protocol",
		mustPack(&matchinginputv3.ApplicationProtocolInput{}),
	)
	serverNameInput = typedExtension("sni", mustPack(&matchinginputv3.ServerNameInput{}))

	sniHostMismatchExprText = fmt.Sprintf(`
  request.method != 'CONNECT' &&
  '%[1]s' in filter_state &&
  string(filter_state['%[1]s']) != '' &&
  request.host.split(':')[0].lowerAscii() != string(filter_state['%[1]s']).lowerAscii()
`, outerSNIKey)

	sniHostMismatchExpr = mustParseCEL(sniHostMismatchExprText)

	sniHostMatchRBACFilter = buildSNIHostMatchRBACFilter(sniHostMismatchExpr)

	connectProxyTLSIdentityHTTPFilter = buildConnectProxyTLSIdentityHTTPFilter(outerSNIKey)

	connectAuthorityHTTPFilter = buildConnectAuthorityFilter(
		"envoy.hashable_string",
		model.FilterStatePeerPrincipal,
		model.FilterStateLocalPrincipal,
		false,
	)

	relayDownstreamFilter = buildRelayDownstreamFilter(
		"envoy.hashable_string",
		model.FilterStatePeerPrincipal,
		model.FilterStateLocalPrincipal,
	)

	sniDenialReasonFilter = buildSNIDenialReasonFilter(telemetry.DenialReasonFilterStateKey)

	// Shared state must be Hashable to isolate internal connections by outer SNI.
	captureSNIFilter       = buildCaptureSNIFilter("envoy.hashable_string", outerSNIKey)
	outerTLSIdentityFilter = buildOuterTLSIdentityFilter(outerSNIKey)

	originalDstFilter  = listenerFilter("envoy.filters.listener.original_dst", mustPack(&originaldstv3.OriginalDst{}))
	tlsInspectorFilter = listenerFilter("envoy.filters.listener.tls_inspector", mustPack(&tlsinspectorv3.TlsInspector{
		InitialReadBufferSize: wrapperspb.UInt32(16 * 1024),
	}))
	httpInspectorFilter = listenerFilter(
		"envoy.filters.listener.http_inspector",
		mustPack(&httpinspectorv3.HttpInspector{}),
	)
	inspectorsHTTPFirst = []*listenerv3.ListenerFilter{originalDstFilter, httpInspectorFilter, tlsInspectorFilter}
)

func buildSNIHostMatchRBACFilter(expression *exprpb.Expr) *hcmv3.HttpFilter {
	return httpFilter("envoy.filters.http.rbac", mustPack(&rbachttpv3.RBAC{Rules: &rbacv3.RBAC{
		Action: rbacv3.RBAC_DENY,
		Policies: map[string]*rbacv3.Policy{
			"deny-sni-host-mismatch": {
				Permissions: []*rbacv3.Permission{{Rule: &rbacv3.Permission_Any{Any: true}}},
				Principals:  []*rbacv3.Principal{{Identifier: &rbacv3.Principal_Any{Any: true}}},
				Condition:   expression,
				CelConfig: &corev3.CelExpressionConfig{
					EnableStringFunctions:  true,
					EnableStringConcat:     true,
					EnableStringConversion: true,
				},
			},
		},
	}}))
}

func buildSNIDenialReasonFilter(key string) *listenerv3.Filter {
	return networkFilter(
		"envoy.filters.network.set_filter_state",
		mustPack(&setstatenetworkv3.Config{OnNewConnection: []*setstatecommonv3.FilterStateValue{
			{
				Key: &setstatecommonv3.FilterStateValue_ObjectKey{
					ObjectKey: key,
				},
				FactoryKey: "envoy.string",
				Value: &setstatecommonv3.FilterStateValue_FormatString{
					FormatString: formatString("sni_policy_denied"),
				},
				ReadOnly: true,
			},
		}}),
	)
}

// TCP payload cannot supply a new TLS identity after termination.
func buildOuterTLSIdentityFilter(key string) *listenerv3.Filter {
	return networkFilter("envoy.filters.network.set_filter_state", mustPack(&setstatenetworkv3.Config{
		OnNewConnection: []*setstatecommonv3.FilterStateValue{
			{
				Key: &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: upstreamServerNameKey},
				Value: &setstatecommonv3.FilterStateValue_FormatString{
					FormatString: formatString("%FILTER_STATE(" + key + ":PLAIN)%"),
				},
			},
			{
				Key: &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: upstreamSubjectAltNamesKey},
				Value: &setstatecommonv3.FilterStateValue_FormatString{
					FormatString: formatString("%FILTER_STATE(" + key + ":PLAIN)%"),
				},
			},
		},
	}))
}

func (b *resourceBuilder) buildListeners(config effectiveConfig, trustDomain string) ([]*listenerv3.Listener, error) {
	denialReasonFilter, tcpTLSIdentityFilter := sniDenialReasonFilter, outerTLSIdentityFilter
	if b.legacyGateway {
		denialReasonFilter, tcpTLSIdentityFilter = legacySNIDenialReasonFilter, legacyOuterTLSIdentityFilter
	}
	connectHCM, err := b.buildConnectHCM(config)
	if err != nil {
		return nil, err
	}
	if features.EnableUDPProxy {
		configureUDPHCM(connectHCM)
	}
	httpInternal, err := b.buildForwardHCM(HTTPDynamicForwardProxy, config, false)
	if err != nil {
		return nil, err
	}
	httpForward, err := b.buildForwardHCM(TLSConnectOriginate, config, true)
	if err != nil {
		return nil, err
	}

	connect := &listenerv3.Listener{
		Name:    ConnectTerminate,
		Address: socketAddress("0.0.0.0", 15008),
		ConnectionBalanceConfig: &listenerv3.Listener_ConnectionBalanceConfig{
			BalanceType: &listenerv3.Listener_ConnectionBalanceConfig_ExactBalance_{
				ExactBalance: &listenerv3.Listener_ConnectionBalanceConfig_ExactBalance{},
			},
		},
		FilterChains: []*listenerv3.FilterChain{
			{
				Name:            "default",
				TransportSocket: b.workloadDownstreamTLS(trustDomain),
				Filters: []*listenerv3.Filter{
					networkFilter("envoy.filters.network.http_connection_manager", b.pack(connectHCM)),
				},
			},
		},
	}

	connectionPool := config.gateway.GetConnectionPool()
	internalChains := []*listenerv3.FilterChain{
		{
			Name: forwardHTTPChain,
			Filters: []*listenerv3.Filter{
				networkFilter("envoy.filters.network.http_connection_manager", b.pack(httpInternal)),
			},
		},
		{Name: forwardTCPChain, Filters: b.applicationTCPFilters(config, nil, PassthroughCluster, connectionPool)},
	}
	internalChainMatcher := b.protocolMatcher(b.toChain(forwardTCPChain))
	if features.EnableSNITrafficPolicy {
		denyProxy := &tcpproxyv3.TcpProxy{
			StatPrefix:       sniDenyChain,
			ClusterSpecifier: &tcpproxyv3.TcpProxy_Cluster{Cluster: BlackHoleCluster},
		}
		// A policy denial matched a chain, so the listener's NR-only log cannot
		// record it. Honor the same providers and filters as application TCP.
		if config.telemetry != nil {
			for _, accessLog := range config.telemetry.TCPAccessLogs {
				denyProxy.AccessLog = append(denyProxy.AccessLog, proto.Clone(accessLog).(*accesslogv3.AccessLog))
			}
		}
		var denyFilters []*listenerv3.Filter
		if len(denyProxy.AccessLog) > 0 {
			// Capture the policy decision before the black-hole proxy closes the
			// connection, so logs need not expose internal cluster or chain names.
			denyFilters = append(denyFilters, denialReasonFilter)
		}
		denyFilters = append(denyFilters, networkFilter("envoy.filters.network.tcp_proxy", b.pack(denyProxy)))
		internalChains = append(internalChains,
			b.buildTLSTerminateChain(connectionPool),
			&listenerv3.FilterChain{
				Name:    sniDenyChain,
				Filters: denyFilters,
			},
		)
		internalChainMatcher = b.protocolMatcher(toMatcher(
			b.sniTrafficPolicyMatcher(config.gateway.GetTlsTermination().GetExcludeHosts()),
		))
	} else if tlsTermination := config.gateway.GetTlsTermination(); tlsTermination != nil {
		internalChains = append(internalChains, b.buildTLSTerminateChain(connectionPool))
		internalChainMatcher = b.staticSNIMatcher(tlsTermination)
	}
	mainInternal := &listenerv3.Listener{
		Name: MainInternal,
		ListenerSpecifier: &listenerv3.Listener_InternalListener{
			InternalListener: &listenerv3.Listener_InternalListenerConfig{},
		},
		TrafficDirection:   corev3.TrafficDirection_INBOUND,
		ListenerFilters:    inspectorsHTTPFirst,
		FilterChains:       internalChains,
		FilterChainMatcher: internalChainMatcher,
		// Close on timeout so delayed client bytes cannot bypass inspection.
		ListenerFiltersTimeout:           durationpb.New(time.Second),
		ContinueOnListenerFiltersTimeout: false,
	}
	if features.EnableSNITrafficPolicy && !b.legacyGateway {
		mainInternal.ListenerFilters = append(
			append([]*listenerv3.ListenerFilter{}, inspectorsHTTPFirst...),
			sniPolicyListenerFilter(),
		)
	}
	mainForward := &listenerv3.Listener{
		Name: MainForward,
		ListenerSpecifier: &listenerv3.Listener_InternalListener{
			InternalListener: &listenerv3.Listener_InternalListenerConfig{},
		},
		TrafficDirection: corev3.TrafficDirection_INBOUND,
		ListenerFilters:  []*listenerv3.ListenerFilter{originalDstFilter, httpInspectorFilter},
		FilterChains: []*listenerv3.FilterChain{
			{
				Name: forwardHTTPChain,
				Filters: []*listenerv3.Filter{
					networkFilter("envoy.filters.network.http_connection_manager", b.pack(httpForward)),
				},
			},
			{
				Name: forwardTCPChain,
				Filters: b.applicationTCPFilters(
					config,
					[]*listenerv3.Filter{tcpTLSIdentityFilter},
					TLSProxyOriginate,
					connectionPool,
				),
			},
		},
		FilterChainMatcher: b.applicationMatcher(),
		// Apply the same close-on-timeout behavior after TLS termination.
		ListenerFiltersTimeout:           durationpb.New(time.Second),
		ContinueOnListenerFiltersTimeout: false,
	}
	for _, listener := range []*listenerv3.Listener{connect, mainInternal, mainForward} {
		if config.telemetry != nil {
			for _, accessLog := range config.telemetry.ListenerAccessLogs {
				listener.AccessLog = append(listener.AccessLog, proto.Clone(accessLog).(*accesslogv3.AccessLog))
			}
		}
		if err := listener.ValidateAll(); err != nil {
			return nil, fmt.Errorf("validate listener %s: %w", listener.GetName(), err)
		}
	}
	return []*listenerv3.Listener{connect, mainInternal, mainForward}, nil
}

func (b *resourceBuilder) buildConnectHCM(config effectiveConfig) (*hcmv3.HttpConnectionManager, error) {
	gateway := config.gateway
	filters := []*hcmv3.HttpFilter{connectAuthorityHTTPFilter}
	if b.legacyGateway {
		authority := legacyConnectAuthority
		if features.EnableSNITrafficPolicy {
			authority = legacyConnectAuthorityWithAction
		}
		filters = []*hcmv3.HttpFilter{legacyPeerMetadataFilter, authority}
	}
	if !b.legacyGateway {
		filters = append(filters, b.connectExtProcFilter(), connectWorkloadFilter())
		if features.EnableSNITrafficPolicy {
			filters = append(filters, connectPolicyFilter())
		}
	}
	// Identity-based descriptors must observe the Workload resolved by Porter.
	if rateLimit := gateway.GetConnectRateLimit(); rateLimit != nil {
		filter, err := b.localRateLimitFilter(rateLimit)
		if err != nil {
			return nil, err
		}
		filters = append(filters, filter)
	}
	if concurrency := gateway.GetConnectConcurrencyLimit(); concurrency != nil {
		filter, err := b.concurrencyFilter(config.gatewayIdentity, concurrency)
		if err != nil {
			return nil, err
		}
		filters = append(filters, filter)
	}
	if bandwidth := gateway.GetBandwidthLimit(); bandwidth != nil {
		filter, err := b.bandwidthFilter(config.gatewayIdentity, bandwidth)
		if err != nil {
			return nil, err
		}
		filters = append(filters, filter)
	}
	filters = append(filters, httpFilter("envoy.filters.http.router", b.pack(&routerv3.Router{})))
	hcm := &hcmv3.HttpConnectionManager{
		StatPrefix:                   ConnectTerminate,
		NormalizePath:                wrapperspb.Bool(true),
		PathWithEscapedSlashesAction: hcmv3.HttpConnectionManager_KEEP_UNCHANGED,
		ServerName:                   "agentio-envoy",
		RouteSpecifier:               &hcmv3.HttpConnectionManager_Rds{Rds: rds(ConnectTerminate)},
		UseRemoteAddress:             wrapperspb.Bool(false),
		StreamIdleTimeout:            durationpb.New(0),
		UpgradeConfigs:               []*hcmv3.HttpConnectionManager_UpgradeConfig{{UpgradeType: "CONNECT"}},
		Http2ProtocolOptions: &corev3.Http2ProtocolOptions{
			AllowConnect:         true,
			MaxConcurrentStreams: wrapperspb.UInt32(100),
			ConnectionKeepalive: &corev3.KeepaliveSettings{
				Interval: durationpb.New(10 * time.Second),
				Timeout:  durationpb.New(20 * time.Second),
			},
		},
		HttpFilters: filters,
	}
	// Mirror release-0.1 setHboneTerminationAccessLog: CONNECT termination logs
	// only status >= 400 responses; successful tunnels are logged downstream.
	if config.telemetry != nil {
		for _, accessLog := range config.telemetry.ConnectHTTPAccessLogs {
			hcm.AccessLog = append(hcm.AccessLog, proto.Clone(accessLog).(*accesslogv3.AccessLog))
		}
	}
	return hcm, nil
}

func (b *resourceBuilder) buildForwardHCM(
	routeName string,
	config effectiveConfig,
	terminatedTLS bool,
) (*hcmv3.HttpConnectionManager, error) {
	filters := make([]*hcmv3.HttpFilter, 0, 4)
	if terminatedTLS {
		// Reject an inner authority that differs from the ClientHello SNI before
		// ext_proc or DFP can observe or resolve the attacker-controlled host.
		guard := sniHostMatchRBACFilter
		if b.legacyGateway {
			guard = legacySNIHostMatchRBACFilter
		}
		filters = append(filters, guard)
	}
	if len(config.gateway.GetServiceEntries()) > 0 {
		filters = append(filters, httpFilter(staticEndpointCandidateFilter, b.pack(&setstatehttpv3.Config{})))
	}
	if config.extProc != nil {
		filter, err := b.extProcFilter(config, config.extProc, "envoy.filters.http.ext_proc", ExtProcCluster)
		if err != nil {
			return nil, err
		}
		filters = append(filters, filter)
	}
	for _, provider := range config.additionalExtProcs {
		name := additionalExtProcName(provider)
		filter, err := b.extProcFilter(config, provider, name, name)
		if err != nil {
			return nil, err
		}
		filters = append(filters, filter)
	}
	if !b.legacyGateway || len(config.gateway.GetServiceEntries()) > 0 {
		filters = append(filters, b.routeUpstreamFilter())
	}
	if config.extProc != nil {
		filters = append(filters, b.egressTargetFilters()...)
	}
	filters = append(filters, httpFilter("envoy.filters.http.dynamic_forward_proxy", b.pack(&dfphttpv3.FilterConfig{
		ImplementationSpecifier:         &dfphttpv3.FilterConfig_DnsCacheConfig{DnsCacheConfig: dnsCacheConfig()},
		AllowDynamicHostFromFilterState: true,
	})))
	if terminatedTLS {
		identity := connectProxyTLSIdentityHTTPFilter
		if b.legacyGateway {
			identity = legacyConnectProxyTLSIdentityHTTPFilter
		}
		filters = append(filters, identity)
	}
	filters = append(filters, httpFilter("envoy.filters.http.router", b.pack(&routerv3.Router{})))
	streamIdle := durationpb.New(30 * time.Minute)
	if configured := config.gateway.GetConnectionPool().GetHttp().GetStreamIdleTimeout(); configured != nil {
		streamIdle = configured
	}
	hcm := &hcmv3.HttpConnectionManager{
		StatPrefix:                   forwardHCMStatPrefix,
		RouteSpecifier:               &hcmv3.HttpConnectionManager_Rds{Rds: rds(routeName)},
		ServerName:                   "agentio-envoy",
		Proxy_100Continue:            true,
		NormalizePath:                wrapperspb.Bool(true),
		PathWithEscapedSlashesAction: hcmv3.HttpConnectionManager_KEEP_UNCHANGED,
		UseRemoteAddress:             wrapperspb.Bool(false),
		StreamIdleTimeout:            streamIdle,
		HttpFilters:                  filters,
		UpgradeConfigs:               []*hcmv3.HttpConnectionManager_UpgradeConfig{{UpgradeType: "websocket"}},
		Http2ProtocolOptions: &corev3.Http2ProtocolOptions{
			AllowConnect: true,
		},
	}
	if config.telemetry != nil {
		if config.telemetry.HTTPMetrics != nil {
			hcm.AccessLog = append(hcm.AccessLog, proto.Clone(config.telemetry.HTTPMetrics).(*accesslogv3.AccessLog))
		}
		for _, accessLog := range config.telemetry.HTTPAccessLogs {
			hcm.AccessLog = append(hcm.AccessLog, proto.Clone(accessLog).(*accesslogv3.AccessLog))
		}
		if config.telemetry.Tracing != nil {
			hcm.Tracing = proto.Clone(config.telemetry.Tracing).(*hcmv3.HttpConnectionManager_Tracing)
		}
		if config.telemetry.RequestIDExtension != nil {
			hcm.RequestIdExtension = proto.Clone(config.telemetry.RequestIDExtension).(*hcmv3.RequestIDExtension)
		}
	}
	if terminatedTLS {
		hcm.SchemeHeaderTransformation = &corev3.SchemeHeaderTransformation{
			Transformation: &corev3.SchemeHeaderTransformation_SchemeToOverwrite{SchemeToOverwrite: "https"},
		}
	}
	return hcm, nil
}

func mustParseCEL(expression string) *exprpb.Expr {
	environment, err := cel.NewEnv()
	if err != nil {
		panic(fmt.Errorf("create CEL environment: %w", err))
	}
	ast, issues := environment.Parse(expression)
	if issues != nil && issues.Err() != nil {
		panic(fmt.Errorf("parse CEL expression %q: %w", expression, issues.Err()))
	}
	parsed, err := cel.AstToParsedExpr(ast)
	if err != nil {
		panic(fmt.Errorf("convert CEL expression %q: %w", expression, err))
	}
	return parsed.GetExpr()
}

// buildConnectProxyTLSIdentityHTTPFilter copies the outer proxy SNI into Envoy's
// upstream TLS identity keys only for CONNECT. Ordinary HTTPS requests retain
// DFP auto-SNI/SAN behavior.
func buildConnectProxyTLSIdentityHTTPFilter(key string) *hcmv3.HttpFilter {
	outerSNI := formatString(fmt.Sprintf("%%FILTER_STATE(%s:PLAIN)%%", key))
	setIdentity := &setstatehttpv3.Config{OnRequestHeaders: []*setstatecommonv3.FilterStateValue{
		{
			Key:         &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: upstreamServerNameKey},
			Value:       &setstatecommonv3.FilterStateValue_FormatString{FormatString: outerSNI},
			SkipIfEmpty: true,
		},
		{
			Key:         &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: upstreamSubjectAltNamesKey},
			Value:       &setstatecommonv3.FilterStateValue_FormatString{FormatString: outerSNI},
			SkipIfEmpty: true,
		},
	}}
	connectMethod := &xdsmatcherv3.Matcher_MatcherList_Predicate{
		MatchType: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate_{
			SinglePredicate: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate{
				Input: typedExtension(
					"request-headers",
					mustPack(&matcherv3.HttpRequestHeaderMatchInput{HeaderName: ":method"}),
				),
				Matcher: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate_ValueMatch{
					ValueMatch: &xdsmatcherv3.StringMatcher{
						MatchPattern: &xdsmatcherv3.StringMatcher_Exact{Exact: "CONNECT"},
					},
				},
			},
		},
	}
	skipConfig := mustPack(&skipactionv3.SkipFilter{})
	skip := &xdsmatcherv3.Matcher_OnMatch{
		OnMatch: &xdsmatcherv3.Matcher_OnMatch_Action{Action: &xdscorev3.TypedExtensionConfig{
			Name:        "skip",
			TypedConfig: skipConfig,
		}},
	}
	wrapper := &extensionmatchingv3.ExtensionWithMatcher{
		XdsMatcher: &xdsmatcherv3.Matcher{
			MatcherType: &xdsmatcherv3.Matcher_MatcherList_{MatcherList: &xdsmatcherv3.Matcher_MatcherList{
				Matchers: []*xdsmatcherv3.Matcher_MatcherList_FieldMatcher{
					{
						Predicate: &xdsmatcherv3.Matcher_MatcherList_Predicate{
							MatchType: &xdsmatcherv3.Matcher_MatcherList_Predicate_NotMatcher{
								NotMatcher: connectMethod,
							},
						},
						OnMatch: skip,
					},
				},
			}},
		},
		ExtensionConfig: typedCoreExtension("envoy.filters.http.set_filter_state", mustPack(setIdentity)),
	}
	name := connectProxyTLSIdentityFilter
	if key == legacyOuterSNIKey {
		name = "connect-proxy-tls-identity"
	}
	return httpFilter(name, mustPack(wrapper))
}

func (b *resourceBuilder) extProcFilter(
	config effectiveConfig,
	provider *configv1.ExtProcProvider,
	name, cluster string,
) (*hcmv3.HttpFilter, error) {
	timeout := (*durationpb.Duration)(nil)
	if provider.GetMessageTimeout() != "" {
		parsed, err := time.ParseDuration(provider.GetMessageTimeout())
		if err != nil {
			return nil, fmt.Errorf("parse ext_proc message timeout %q: %w", provider.GetMessageTimeout(), err)
		}
		timeout = durationpb.New(parsed)
	}
	requestMode := extprocv3.ProcessingMode_SEND
	responseMode := extprocv3.ProcessingMode_SKIP
	if request := provider.GetRequest(); request != nil {
		requestMode = headerMode(request.GetHeaderMode(), requestMode)
	}
	if response := provider.GetResponse(); response != nil {
		responseMode = headerMode(response.GetHeaderMode(), responseMode)
	}
	// Only the primary EPE may publish the authorized upstream target.
	var metadataOptions *extprocv3.MetadataOptions
	statPrefix := ""
	if name == "envoy.filters.http.ext_proc" {
		metadataOptions = &extprocv3.MetadataOptions{
			ReceivingNamespaces: &extprocv3.MetadataOptions_MetadataNamespaces{Untyped: []string{"agentio.route"}},
		}
	} else {
		statPrefix = name
	}
	attributes := append([]string(nil), provider.GetRequest().GetAttributes()...)
	for _, attribute := range []string{model.AttributeWorkloadName, model.AttributeWorkloadNamespace, model.AttributeWorkloadLabels, "filter_state['sandbox.labels']", "source.address", "destination.address", "destination.port"} {
		if b.legacyGateway &&
			(attribute == model.AttributeWorkloadLabels || attribute == "filter_state['sandbox.labels']") {
			continue
		}
		found := false
		for _, existing := range attributes {
			found = found || existing == attribute
		}
		if !found {
			attributes = append(attributes, attribute)
		}
	}
	if (!b.legacyGateway || len(config.gateway.GetServiceEntries()) > 0) &&
		!slices.Contains(attributes, model.AttributeRouteUpstream) {
		attributes = append(attributes, model.AttributeRouteUpstream)
	}
	return httpFilter(name, b.pack(&extprocv3.ExternalProcessor{
		GrpcService: &corev3.GrpcService{
			TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
				EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{ClusterName: cluster},
			},
		},
		FailureModeAllow:   provider.GetFailureModeAllow(),
		StatPrefix:         statPrefix,
		AllowModeOverride:  true,
		ProcessingMode:     &extprocv3.ProcessingMode{RequestHeaderMode: requestMode, ResponseHeaderMode: responseMode},
		RequestAttributes:  attributes,
		MetadataOptions:    metadataOptions,
		ResponseAttributes: provider.GetResponse().GetAttributes(),
		MessageTimeout:     timeout,
	})), nil
}

// CONNECT setup has a separate budget and cannot subscribe to tunnel bytes.
func (b *resourceBuilder) connectExtProcFilter() *hcmv3.HttpFilter {
	return httpFilter("envoy.filters.http.ext_proc", b.pack(&extprocv3.ExternalProcessor{
		GrpcService: &corev3.GrpcService{
			TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
				EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{ClusterName: PorterCluster},
			},
		},
		// CONNECT identity and policy resolution must succeed before forwarding.
		FailureModeAllow: false,
		MessageTimeout:   durationpb.New(5 * time.Second),
		ProcessingMode: &extprocv3.ProcessingMode{
			RequestHeaderMode:   extprocv3.ProcessingMode_SEND,
			ResponseHeaderMode:  extprocv3.ProcessingMode_SKIP,
			RequestBodyMode:     extprocv3.ProcessingMode_NONE,
			ResponseBodyMode:    extprocv3.ProcessingMode_NONE,
			RequestTrailerMode:  extprocv3.ProcessingMode_SKIP,
			ResponseTrailerMode: extprocv3.ProcessingMode_SKIP,
		},
		RequestAttributes: []string{
			model.AttributeSandboxID,
			model.AttributePeerIP,
			model.AttributePeerPrincipal,
			model.AttributePeerCertificate,
		},
		MetadataOptions: &extprocv3.MetadataOptions{
			ReceivingNamespaces: &extprocv3.MetadataOptions_MetadataNamespaces{
				Untyped: []string{model.GatewayMetadataNamespace},
			},
		},
	}))
}

// Publish Porter's resolved identity before creating any internal connection.
// Identity comes from the certificate or peer IP, independently of SNI policy.
func connectWorkloadFilter() *hcmv3.HttpFilter {
	config := &setstatehttpv3.Config{}
	for _, field := range []struct {
		name string
		key  string
	}{
		{"name", model.FilterStateWorkloadName},
		{"namespace", model.FilterStateWorkloadNamespace},
	} {
		config.OnRequestHeaders = append(config.OnRequestHeaders, &setstatecommonv3.FilterStateValue{
			Key:        &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: field.key},
			FactoryKey: "envoy.hashable_string",
			Value: &setstatecommonv3.FilterStateValue_FormatString{
				FormatString: formatString(
					"%DYNAMIC_METADATA(" + model.GatewayMetadataNamespace + ":workload:" + field.name + ")%",
				),
			},
			SharedWithUpstream: setstatecommonv3.FilterStateValue_ONCE,
			SkipIfEmpty:        true,
		})
	}
	for _, field := range []struct {
		key      string
		metadata string
		factory  string
	}{
		// Concurrent CONNECTs can share a pool while carrying different label snapshots.
		{model.FilterStateWorkloadLabels, "workload_labels", "envoy.hashable_string"},
		// Keep the old output while older EPE instances are still deployed.
		{"sandbox.labels", "workload_labels", "envoy.string"},
	} {
		config.OnRequestHeaders = append(config.OnRequestHeaders, &setstatecommonv3.FilterStateValue{
			Key:        &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: field.key},
			FactoryKey: field.factory,
			Value: &setstatecommonv3.FilterStateValue_FormatString{
				FormatString: formatString("%DYNAMIC_METADATA(agentio:" + field.metadata + ")%"),
			},
			SharedWithUpstream: setstatecommonv3.FilterStateValue_ONCE,
			SkipIfEmpty:        true,
		})
	}
	return httpFilter("agentio.connect_workload", mustPack(config))
}

func connectPolicyFilter() *hcmv3.HttpFilter {
	return httpFilter("agentio.connect_sni_policy", mustPack(&setstatehttpv3.Config{
		OnRequestHeaders: []*setstatecommonv3.FilterStateValue{
			{
				Key:        &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: model.FilterStateSNIPolicy},
				FactoryKey: "envoy.hashable_string",
				Value: &setstatecommonv3.FilterStateValue_FormatString{
					FormatString: formatString(sniPolicyMetadataFormat),
				},
				SharedWithUpstream: setstatecommonv3.FilterStateValue_ONCE,
				ReadOnly:           true,
				SkipIfEmpty:        true,
			},
		},
	}))
}

func headerMode(
	mode configv1.HeaderSendMode,
	fallback extprocv3.ProcessingMode_HeaderSendMode,
) extprocv3.ProcessingMode_HeaderSendMode {
	switch mode {
	case configv1.HeaderSendMode_SEND:
		return extprocv3.ProcessingMode_SEND
	case configv1.HeaderSendMode_SKIP:
		return extprocv3.ProcessingMode_SKIP
	default:
		return fallback
	}
}

func (b *resourceBuilder) workloadDownstreamTLS(trustDomain string) *corev3.TransportSocket {
	secret := func(name string) *tlsv3.SdsSecretConfig {
		return &tlsv3.SdsSecretConfig{Name: name, SdsConfig: workloadSDSConfigSource()}
	}
	config := b.pack(&tlsv3.DownstreamTlsContext{
		RequireClientCertificate: wrapperspb.Bool(true),
		CommonTlsContext: &tlsv3.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: []*tlsv3.SdsSecretConfig{secret(model.GatewayIdentitySecret)},
			ValidationContextType: &tlsv3.CommonTlsContext_CombinedValidationContext{
				CombinedValidationContext: &tlsv3.CommonTlsContext_CombinedCertificateValidationContext{
					DefaultValidationContext: &tlsv3.CertificateValidationContext{
						MatchTypedSubjectAltNames: []*tlsv3.SubjectAltNameMatcher{
							{
								SanType: tlsv3.SubjectAltNameMatcher_URI,
								Matcher: &matcherv3.StringMatcher{
									MatchPattern: &matcherv3.StringMatcher_Prefix{
										Prefix: "spiffe://" + trustDomain + "/",
									},
								},
							},
						},
					},
					ValidationContextSdsSecretConfig: secret(model.GatewayRootSecret),
				},
			},
			AlpnProtocols: []string{"h2"},
			TlsParams: &tlsv3.TlsParameters{
				TlsMinimumProtocolVersion: tlsv3.TlsParameters_TLSv1_3,
				TlsMaximumProtocolVersion: tlsv3.TlsParameters_TLSv1_3,
			},
		},
	})
	return &corev3.TransportSocket{
		Name:       "envoy.transport_sockets.tls",
		ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: config},
	}
}

func (b *resourceBuilder) buildTLSTerminateChain(pool *configv1.ConnectionPoolSettings) *listenerv3.FilterChain {
	selector := b.pack(&ondemandv3.Config{
		ConfigSource: adsConfigSource(),
		CertificateMapper: typedCoreExtension(
			"envoy.tls.certificate_mappers.sni", b.pack(&snimapperv3.SNI{DefaultValue: noSNISentinel})),
	})
	tlsConfig := b.pack(&tlsv3.DownstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{
			AlpnProtocols: []string{"h2", "http/1.1"},
			CustomTlsCertificateSelector: &corev3.TypedExtensionConfig{
				Name:        "envoy.tls.certificate_selectors.on_demand_secret",
				TypedConfig: selector,
			},
		},
		SessionTicketKeysType: &tlsv3.DownstreamTlsContext_DisableStatelessSessionResumption{
			DisableStatelessSessionResumption: true,
		},
		DisableStatefulSessionResumption: true,
	})
	capture, relay := captureSNIFilter, relayDownstreamFilter
	if b.legacyGateway {
		capture, relay = legacyCaptureSNI, legacyRelayDownstream
	}
	return &listenerv3.FilterChain{
		Name:                          tlsTerminateChain,
		TransportSocketConnectTimeout: durationpb.New(15 * time.Second),
		TransportSocket: &corev3.TransportSocket{
			Name:       "envoy.transport_sockets.tls",
			ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: tlsConfig},
		},
		Filters: []*listenerv3.Filter{
			capture,
			relay,
			b.tcpProxy(MainForward, pool, nil),
		},
	}
}

func buildConnectAuthorityFilter(factory, peerPrincipal, localPrincipal string, legacyAction bool) *hcmv3.HttpFilter {
	authorityKey := connectAuthorityKey
	if factory == "envoy.hashable_string" {
		authorityKey = model.FilterStateConnectAuthority
	}
	value := func(key, format, factory string, sharing setstatecommonv3.FilterStateValue_SharedWithUpstream) *setstatecommonv3.FilterStateValue {
		return &setstatecommonv3.FilterStateValue{
			Key:                &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: key},
			FactoryKey:         factory,
			Value:              &setstatecommonv3.FilterStateValue_FormatString{FormatString: formatString(format)},
			SharedWithUpstream: sharing,
		}
	}
	values := []*setstatecommonv3.FilterStateValue{
		value(
			"envoy.filters.listener.original_dst.local_ip",
			"%REQ(:AUTHORITY)%",
			"",
			setstatecommonv3.FilterStateValue_ONCE,
		),
		value(
			authorityKey,
			"%REQ(:AUTHORITY)%",
			factory,
			setstatecommonv3.FilterStateValue_ONCE,
		),
		value(
			"envoy.filters.listener.original_dst.remote_ip",
			"%DOWNSTREAM_REMOTE_ADDRESS%",
			"",
			setstatecommonv3.FilterStateValue_ONCE,
		),
		value(
			peerPrincipal,
			"%DOWNSTREAM_PEER_URI_SAN%",
			factory,
			setstatecommonv3.FilterStateValue_ONCE,
		),
		value(
			localPrincipal,
			"%DOWNSTREAM_LOCAL_URI_SAN%",
			factory,
			setstatecommonv3.FilterStateValue_ONCE,
		),
		value(
			"sandbox.token",
			"%REQ(X-AGENTIO-SANDBOX-TOKEN)%",
			"envoy.string",
			setstatecommonv3.FilterStateValue_TRANSITIVE,
		),
		value(
			"sandbox.labels",
			"%REQ(X-AGENTIO-SANDBOX-LABELS)%",
			"envoy.string",
			setstatecommonv3.FilterStateValue_TRANSITIVE,
		),
		value(
			model.FilterStateSandboxID,
			"%REQ(X-AGENTIO-SANDBOX-ID)%",
			"envoy.string",
			setstatecommonv3.FilterStateValue_TRANSITIVE,
		),
		// Preserve the ztunnel-attested pod across internal HTTP/TLS hops.
		// Hashable values keep different source pods out of the same upstream pool.
		value(
			model.FilterStateWorkloadName,
			"%REQ(X-AGENTIO-WORKLOAD-NAME)%",
			factory,
			setstatecommonv3.FilterStateValue_TRANSITIVE,
		),
		value(
			model.FilterStateWorkloadNamespace,
			"%REQ(X-AGENTIO-WORKLOAD-NAMESPACE)%",
			factory,
			setstatecommonv3.FilterStateValue_TRANSITIVE,
		),
	}
	if factory == "envoy.hashable_string" {
		// Native gateways resolve workload identity and labels through Porter.
		filtered := values[:0]
		for _, state := range values {
			switch state.GetObjectKey() {
			case "sandbox.labels", model.FilterStateWorkloadName, model.FilterStateWorkloadNamespace:
				continue
			case model.FilterStateSandboxID, "sandbox.token":
				// Share identity only across internal hops, not with the external pool.
				state.FactoryKey = factory
				state.SharedWithUpstream = setstatecommonv3.FilterStateValue_ONCE
			}
			filtered = append(filtered, state)
		}
		values = filtered
		// Keep legacy token capture for old ztunnels during rolling upgrades.
		metadata := value("agentio.sandbox.metadata", "%REQ(X-AGENTIO-SANDBOX-METADATA)%",
			factory, setstatecommonv3.FilterStateValue_ONCE)
		metadata.SkipIfEmpty = true
		values = append(values, metadata)
		// Read the TLS-verified peer certificate, never a CONNECT header.
		// Only Porter needs the certificate; do not propagate it to inner streams.
		values = append(values, value(model.FilterStatePeerCertificate, "%DOWNSTREAM_PEER_CERT%",
			"envoy.string", setstatecommonv3.FilterStateValue_NONE))
		// Use the physical HBONE peer, never an application-supplied forwarding header.
		values = append(values, value(model.FilterStatePeerIP, "%DOWNSTREAM_DIRECT_REMOTE_ADDRESS_WITHOUT_PORT%",
			"envoy.string", setstatecommonv3.FilterStateValue_NONE))
	}
	if legacyAction {
		// Hashable so internal upstream pools never reuse another CONNECT
		// stream's TLS decision; SkipIfEmpty so an absent header leaves no state.
		// ztunnel sends x-agentio-tls: action=<action>;sni=<name>.
		values = append(values, &setstatecommonv3.FilterStateValue{
			Key:        &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: tlsActionKey},
			FactoryKey: factory,
			Value: &setstatecommonv3.FilterStateValue_FormatString{
				FormatString: formatString(tlsActionHeaderFormat),
			},
			SharedWithUpstream: setstatecommonv3.FilterStateValue_ONCE,
			ReadOnly:           true,
			SkipIfEmpty:        true,
		})
	}
	name := "connect_authority"
	if factory == "envoy.hashable_string" {
		name = "agentio.connect_authority"
	}
	return httpFilter(name, mustPack(&setstatehttpv3.Config{OnRequestHeaders: values}))
}

func buildRelayDownstreamFilter(factory, peerPrincipal, localPrincipal string) *listenerv3.Filter {
	authorityKey := connectAuthorityKey
	if factory == "envoy.hashable_string" {
		authorityKey = model.FilterStateConnectAuthority
	}
	downstreamRelayKeys := []struct {
		key     string
		factory string
	}{
		{key: "envoy.filters.listener.original_dst.local_ip"},
		{key: "envoy.filters.listener.original_dst.remote_ip"},
		{key: peerPrincipal, factory: factory},
		{key: localPrincipal, factory: factory},
		{key: authorityKey, factory: factory},
	}
	if factory == "envoy.hashable_string" {
		// TLS termination adds one internal hop; stop sharing again at main_forward.
		for _, key := range []string{
			model.FilterStateSandboxID, "sandbox.token", "agentio.sandbox.metadata",
			model.FilterStateWorkloadName, model.FilterStateWorkloadNamespace,
			model.FilterStateWorkloadLabels, "sandbox.labels",
		} {
			stateFactory := factory
			if key == "sandbox.labels" {
				stateFactory = "envoy.string"
			}
			downstreamRelayKeys = append(downstreamRelayKeys, struct {
				key     string
				factory string
			}{key: key, factory: stateFactory})
		}
	}
	values := make([]*setstatecommonv3.FilterStateValue, 0, len(downstreamRelayKeys))
	for _, relay := range downstreamRelayKeys {
		values = append(values, &setstatecommonv3.FilterStateValue{
			Key:        &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: relay.key},
			FactoryKey: relay.factory,
			Value: &setstatecommonv3.FilterStateValue_FormatString{
				FormatString: formatString(fmt.Sprintf("%%FILTER_STATE(%s:PLAIN)%%", relay.key)),
			},
			SharedWithUpstream: setstatecommonv3.FilterStateValue_ONCE,
			SkipIfEmpty:        relay.key != model.FilterStateSandboxID && relay.key != "sandbox.token",
		})
	}
	name := "connect_downstream_peer"
	if factory == "envoy.hashable_string" {
		name = "agentio.connect_downstream_peer"
	}
	return networkFilter(name, mustPack(&setstatenetworkv3.Config{OnNewConnection: values}))
}

func (b *resourceBuilder) localRateLimitFilter(settings *configv1.LocalRateLimitSettings) (*hcmv3.HttpFilter, error) {
	config := &localratelimitv3.LocalRateLimit{
		StatPrefix:                            "connect_rate_limit",
		LocalRateLimitPerDownstreamConnection: settings.GetPerDownstreamConnection(),
		FilterEnabled:                         runtimePercent(),
		FilterEnforced:                        runtimePercent(),
	}
	if settings.GetTokenBucket() != nil {
		config.TokenBucket = tokenBucket(settings.GetTokenBucket())
	}
	for _, descriptor := range settings.GetDescriptors() {
		converted := &ratelimitv3.LocalRateLimitDescriptor{TokenBucket: tokenBucket(descriptor.GetTokenBucket())}
		rateLimit := &routev3.RateLimit{}
		for _, entry := range descriptor.GetEntries() {
			converted.Entries = append(
				converted.Entries,
				&ratelimitv3.RateLimitDescriptor_Entry{Key: entry.GetKey(), Value: entry.GetValue()},
			)
			if len(settings.GetRateLimits()) == 0 {
				if entry.GetCel() != "" {
					rateLimit.Actions = append(rateLimit.Actions, b.rateLimitCELAction(entry.GetKey(), entry.GetCel()))
				} else {
					rateLimit.Actions = append(rateLimit.Actions, &routev3.RateLimit_Action{
						ActionSpecifier: &routev3.RateLimit_Action_GenericKey_{
							GenericKey: &routev3.RateLimit_Action_GenericKey{
								DescriptorKey:   entry.GetKey(),
								DescriptorValue: entry.GetValue(),
							},
						},
					})
				}
			}
		}
		config.Descriptors = append(config.Descriptors, converted)
		if len(settings.GetRateLimits()) == 0 {
			config.RateLimits = append(config.RateLimits, rateLimit)
		}
	}
	for _, group := range settings.GetRateLimits() {
		rateLimit := &routev3.RateLimit{}
		for _, action := range group.GetActions() {
			if state := action.GetFilterState(); state != nil {
				rateLimit.Actions = append(rateLimit.Actions,
					b.rateLimitCELAction(state.GetDescriptorKey(), fmt.Sprintf("filter_state[%q]", state.GetKey())))
			} else {
				fixed := action.GetGenericKey()
				rateLimit.Actions = append(rateLimit.Actions, &routev3.RateLimit_Action{
					ActionSpecifier: &routev3.RateLimit_Action_GenericKey_{
						GenericKey: &routev3.RateLimit_Action_GenericKey{
							DescriptorKey:   fixed.GetDescriptorKey(),
							DescriptorValue: fixed.GetDescriptorValue(),
						},
					},
				})
			}
		}
		config.RateLimits = append(config.RateLimits, rateLimit)
	}
	if err := config.ValidateAll(); err != nil {
		return nil, fmt.Errorf("validate connect rate limit: %w", err)
	}
	return httpFilter("envoy.filters.http.local_ratelimit", b.pack(config)), nil
}

func (b *resourceBuilder) rateLimitCELAction(key, expression string) *routev3.RateLimit_Action {
	return &routev3.RateLimit_Action{
		ActionSpecifier: &routev3.RateLimit_Action_Extension{
			Extension: &corev3.TypedExtensionConfig{
				Name: "envoy.rate_limit_descriptors.expr",
				TypedConfig: b.pack(&rlexprv3.Descriptor{
					DescriptorKey: key,
					ExprSpecifier: &rlexprv3.Descriptor_Text{Text: expression},
					SkipIfError:   true,
				}),
			},
		},
	}
}

func tokenBucket(value *configv1.TokenBucket) *typev3.TokenBucket {
	if value == nil {
		return nil
	}
	result := &typev3.TokenBucket{MaxTokens: value.GetMaxTokens(), FillInterval: value.GetFillInterval()}
	if value.GetTokensPerFill() > 0 {
		result.TokensPerFill = wrapperspb.UInt32(value.GetTokensPerFill())
	}
	return result
}

func runtimePercent() *corev3.RuntimeFractionalPercent {
	return &corev3.RuntimeFractionalPercent{
		DefaultValue: &typev3.FractionalPercent{Numerator: 100, Denominator: typev3.FractionalPercent_HUNDRED},
	}
}

func (b *resourceBuilder) tcpProxy(
	cluster string,
	pool *configv1.ConnectionPoolSettings,
	accessLogs []*accesslogv3.AccessLog,
) *listenerv3.Filter {
	config := &tcpproxyv3.TcpProxy{
		StatPrefix:       cluster,
		ClusterSpecifier: &tcpproxyv3.TcpProxy_Cluster{Cluster: cluster},
	}
	if pool.GetTcp().GetIdleTimeout() != nil {
		config.IdleTimeout = pool.GetTcp().GetIdleTimeout()
	} else {
		config.IdleTimeout = durationpb.New(time.Hour)
	}
	config.MaxDownstreamConnectionDuration = pool.GetTcp().GetMaxConnectionDuration()
	for _, accessLog := range accessLogs {
		config.AccessLog = append(config.AccessLog, proto.Clone(accessLog).(*accesslogv3.AccessLog))
	}
	return networkFilter("envoy.filters.network.tcp_proxy", b.pack(config))
}

func (b *resourceBuilder) applicationTCPFilters(
	config effectiveConfig,
	prefix []*listenerv3.Filter,
	cluster string,
	pool *configv1.ConnectionPoolSettings,
) []*listenerv3.Filter {
	result := append([]*listenerv3.Filter{}, prefix...)
	var accessLogs []*accesslogv3.AccessLog
	if config.telemetry != nil {
		accessLogs = config.telemetry.TCPAccessLogs
	}
	return append(result, b.tcpProxy(cluster, pool, accessLogs))
}

// sniTrafficPolicyMatcher preserves gateway exclusions before consulting the
// listener module decision. Legacy proxies retain their policy-runtime fallback.
func (b *resourceBuilder) sniTrafficPolicyMatcher(excludeHosts []string) *xdsmatcherv3.Matcher {
	fallback := b.toChain(sniDenyChain)
	if b.legacyGateway {
		fallback = toMatcher(b.legacySNIPolicyMatcher())
	}
	policy := b.tlsActionMatcher(fallback)
	if len(excludeHosts) == 0 {
		return policy
	}
	domains := &xdsmatcherv3.ServerNameMatcher{DomainMatchers: []*xdsmatcherv3.ServerNameMatcher_DomainMatcher{{
		Domains: excludeHosts,
		OnMatch: b.toChain(forwardTCPChain),
	}}}
	return &xdsmatcherv3.Matcher{
		MatcherType: &xdsmatcherv3.Matcher_MatcherTree_{MatcherTree: &xdsmatcherv3.Matcher_MatcherTree{
			Input: serverNameInput,
			TreeType: &xdsmatcherv3.Matcher_MatcherTree_CustomMatch{
				CustomMatch: typedExtension("sni", b.pack(domains)),
			},
		}},
		OnNoMatch: toMatcher(policy),
	}
}

func (b *resourceBuilder) staticSNIMatcher(config *configv1.TlsTerminationConfig) *xdsmatcherv3.Matcher {
	domainMatchers := make([]*xdsmatcherv3.ServerNameMatcher_DomainMatcher, 0, 2)
	for _, match := range []struct {
		domains []string
		onMatch *xdsmatcherv3.Matcher_OnMatch
	}{
		{domains: config.GetExcludeHosts(), onMatch: b.toChain(forwardTCPChain)},
		{domains: config.GetIncludeHosts(), onMatch: b.toChain(tlsTerminateChain)},
	} {
		if len(match.domains) > 0 {
			domainMatchers = append(domainMatchers, &xdsmatcherv3.ServerNameMatcher_DomainMatcher{
				Domains: match.domains,
				OnMatch: match.onMatch,
			})
		}
	}
	domains := &xdsmatcherv3.ServerNameMatcher{DomainMatchers: domainMatchers}
	typedConfig := b.pack(domains)
	return &xdsmatcherv3.Matcher{
		MatcherType: &xdsmatcherv3.Matcher_MatcherTree_{MatcherTree: &xdsmatcherv3.Matcher_MatcherTree{
			Input: serverNameInput,
			TreeType: &xdsmatcherv3.Matcher_MatcherTree_CustomMatch{CustomMatch: &xdscorev3.TypedExtensionConfig{
				Name:        "sni",
				TypedConfig: typedConfig,
			}},
		}},
		OnNoMatch: toMatcher(b.protocolMatcher(b.toChain(forwardTCPChain))),
	}
}

func (b *resourceBuilder) protocolMatcher(tls *xdsmatcherv3.Matcher_OnMatch) *xdsmatcherv3.Matcher {
	return exactMatcher(
		transportProtocolInput,
		map[string]*xdsmatcherv3.Matcher_OnMatch{"tls": tls},
		toMatcher(b.applicationMatcher()),
	)
}

func (b *resourceBuilder) applicationMatcher() *xdsmatcherv3.Matcher {
	return exactMatcher(applicationProtocolInput, map[string]*xdsmatcherv3.Matcher_OnMatch{
		"'h2c'":      b.toChain(forwardHTTPChain),
		"'http/1.1'": b.toChain(forwardHTTPChain),
	}, b.toChain(forwardTCPChain))
}

func (b *resourceBuilder) tlsActionMatcher(gatewayDecision *xdsmatcherv3.Matcher_OnMatch) *xdsmatcherv3.Matcher {
	return exactMatcher(typedExtension("tls-action", b.pack(&matchinginputv3.FilterStateInput{Key: tlsActionKey})),
		map[string]*xdsmatcherv3.Matcher_OnMatch{
			"terminate":   b.toChain(tlsTerminateChain),
			"passthrough": b.toChain(forwardTCPChain),
			"deny":        b.toChain(sniDenyChain),
		}, gatewayDecision)
}

func exactMatcher(
	input *xdscorev3.TypedExtensionConfig,
	values map[string]*xdsmatcherv3.Matcher_OnMatch,
	fallback *xdsmatcherv3.Matcher_OnMatch,
) *xdsmatcherv3.Matcher {
	return &xdsmatcherv3.Matcher{
		MatcherType: &xdsmatcherv3.Matcher_MatcherTree_{MatcherTree: &xdsmatcherv3.Matcher_MatcherTree{
			Input: input,
			TreeType: &xdsmatcherv3.Matcher_MatcherTree_ExactMatchMap{
				ExactMatchMap: &xdsmatcherv3.Matcher_MatcherTree_MatchMap{Map: values},
			},
		}},
		OnNoMatch: fallback,
	}
}

func (b *resourceBuilder) toChain(name string) *xdsmatcherv3.Matcher_OnMatch {
	config := b.pack(wrapperspb.String(name))
	return &xdsmatcherv3.Matcher_OnMatch{
		OnMatch: &xdsmatcherv3.Matcher_OnMatch_Action{
			Action: &xdscorev3.TypedExtensionConfig{Name: name, TypedConfig: config},
		},
	}
}

func toMatcher(value *xdsmatcherv3.Matcher) *xdsmatcherv3.Matcher_OnMatch {
	return &xdsmatcherv3.Matcher_OnMatch{OnMatch: &xdsmatcherv3.Matcher_OnMatch_Matcher{Matcher: value}}
}

func typedExtension(name string, config *anypb.Any) *xdscorev3.TypedExtensionConfig {
	return &xdscorev3.TypedExtensionConfig{Name: name, TypedConfig: config}
}

func typedCoreExtension(name string, config *anypb.Any) *corev3.TypedExtensionConfig {
	return &corev3.TypedExtensionConfig{Name: name, TypedConfig: config}
}

func httpFilter(name string, config *anypb.Any) *hcmv3.HttpFilter {
	return &hcmv3.HttpFilter{Name: name, ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: config}}
}

func networkFilter(name string, config *anypb.Any) *listenerv3.Filter {
	return &listenerv3.Filter{Name: name, ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: config}}
}

func listenerFilter(name string, config *anypb.Any) *listenerv3.ListenerFilter {
	return &listenerv3.ListenerFilter{
		Name:       name,
		ConfigType: &listenerv3.ListenerFilter_TypedConfig{TypedConfig: config},
	}
}

func formatString(value string) *corev3.SubstitutionFormatString {
	return &corev3.SubstitutionFormatString{
		OmitEmptyValues: true,
		Format: &corev3.SubstitutionFormatString_TextFormatSource{TextFormatSource: &corev3.DataSource{
			Specifier: &corev3.DataSource_InlineString{InlineString: value},
		}},
	}
}

func rds(name string) *hcmv3.Rds {
	return &hcmv3.Rds{RouteConfigName: name, ConfigSource: adsConfigSource()}
}

func adsConfigSource() *corev3.ConfigSource {
	return &corev3.ConfigSource{
		ResourceApiVersion:    corev3.ApiVersion_V3,
		ConfigSourceSpecifier: &corev3.ConfigSource_Ads{Ads: &corev3.AggregatedConfigSource{}},
	}
}

func workloadSDSConfigSource() *corev3.ConfigSource {
	return &corev3.ConfigSource{
		ResourceApiVersion:  corev3.ApiVersion_V3,
		InitialFetchTimeout: durationpb.New(0),
		ConfigSourceSpecifier: &corev3.ConfigSource_ApiConfigSource{ApiConfigSource: &corev3.ApiConfigSource{
			ApiType:                   corev3.ApiConfigSource_GRPC,
			SetNodeOnFirstMessageOnly: true,
			TransportApiVersion:       corev3.ApiVersion_V3,
			GrpcServices: []*corev3.GrpcService{{TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
				EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
			}}},
		}},
	}
}

func buildCaptureSNIFilter(factory, key string) *listenerv3.Filter {
	return networkFilter(
		"envoy.filters.network.set_filter_state",
		mustPack(&setstatenetworkv3.Config{OnNewConnection: []*setstatecommonv3.FilterStateValue{
			{
				Key:        &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: key},
				FactoryKey: factory,
				Value: &setstatecommonv3.FilterStateValue_FormatString{
					FormatString: formatString("%REQUESTED_SERVER_NAME%"),
				},
				SharedWithUpstream: setstatecommonv3.FilterStateValue_ONCE,
				SkipIfEmpty:        true,
			},
		}}),
	)
}
