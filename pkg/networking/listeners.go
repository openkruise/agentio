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
	"time"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	udpatypev1 "github.com/cncf/xds/go/udpa/type/v1"
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
	dfpnetworkv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/sni_dynamic_forward_proxy/v3"
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
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/openkruise/agentio/pkg/features"
)

const (
	forwardHTTPChain                = "forward-http"
	forwardTCPChain                 = "forward-tcp"
	tlsTerminateChain               = "tls-terminate"
	sniDenyChain                    = "sni-traffic-policy-deny"
	noSNISentinel                   = "_no_sni_"
	forwardHCMStatPrefix            = "inbound_0.0.0.0_0;"
	sniPolicyMatcherName            = "kruise.matching.custom_matchers.sni_traffic_policy"
	sniPolicyMatcherType            = "type.googleapis.com/kruise.networking.policy_runtime.v1alpha1.SniTrafficPolicyMatcher"
	outerSNIKey                     = "io.kruise.outer_sni"
	upstreamServerNameKey           = "envoy.network.upstream_server_name"
	upstreamSubjectAltNamesKey      = "envoy.network.upstream_subject_alt_names"
	connectProxyTLSIdentityFilter   = "connect-proxy-tls-identity"
	connectAuthorityKey             = "io.istio.connect_authority"
	dynamicHostKey                  = "envoy.upstream.dynamic_host"
	dynamicPortKey                  = "envoy.upstream.dynamic_port"
	staticEndpointFilterStateFilter = "agentio.static_endpoint_filter_state"
)

var (
	transportProtocolInput   = typedExtension("transport-protocol", &matchinginputv3.TransportProtocolInput{})
	applicationProtocolInput = typedExtension("application-protocol", &matchinginputv3.ApplicationProtocolInput{})
	serverNameInput          = typedExtension("sni", &matchinginputv3.ServerNameInput{})
	downstreamRelayKeys      = []struct {
		key     string
		factory string
	}{
		{key: "envoy.filters.listener.original_dst.local_ip"},
		{key: "envoy.filters.listener.original_dst.remote_ip"},
		{key: "io.istio.peer_principal", factory: "istio.hashable_string"},
		{key: "io.istio.local_principal", factory: "istio.hashable_string"},
		{key: connectAuthorityKey, factory: "istio.hashable_string"},
	}
)

func buildListeners(config effectiveConfig, trustDomain string) ([]*listenerv3.Listener, error) {
	connectHCM, err := buildConnectHCM(config)
	if err != nil {
		return nil, err
	}
	httpInternal, err := buildForwardHCM(HTTPDynamicForwardProxy, config, false)
	if err != nil {
		return nil, err
	}
	httpForward, err := buildForwardHCM(TLSConnectOriginate, config, true)
	if err != nil {
		return nil, err
	}

	connect := &listenerv3.Listener{
		Name:    ConnectTerminate,
		Address: socketAddress("0.0.0.0", 15008),
		ConnectionBalanceConfig: &listenerv3.Listener_ConnectionBalanceConfig{BalanceType: &listenerv3.Listener_ConnectionBalanceConfig_ExactBalance_{
			ExactBalance: &listenerv3.Listener_ConnectionBalanceConfig_ExactBalance{},
		}},
		FilterChains: []*listenerv3.FilterChain{{
			Name:            "default",
			TransportSocket: workloadDownstreamTLS(trustDomain),
			Filters:         []*listenerv3.Filter{networkFilter("envoy.filters.network.http_connection_manager", connectHCM)},
		}},
	}

	connectionPool := config.gateway.GetConnectionPool()
	internalChains := []*listenerv3.FilterChain{
		{Name: forwardHTTPChain, Filters: []*listenerv3.Filter{networkFilter("envoy.filters.network.http_connection_manager", httpInternal)}},
		{Name: forwardTCPChain, Filters: applicationTCPFilters(config, nil, PassthroughCluster, connectionPool)},
	}
	internalChainMatcher := protocolMatcher(false)
	if features.EnableSNITrafficPolicy {
		internalChains = append(internalChains,
			buildTLSTerminateChain(connectionPool),
			&listenerv3.FilterChain{
				Name: sniDenyChain,
				Filters: []*listenerv3.Filter{networkFilter("envoy.filters.network.tcp_proxy", &tcpproxyv3.TcpProxy{
					StatPrefix:       sniDenyChain,
					ClusterSpecifier: &tcpproxyv3.TcpProxy_Cluster{Cluster: BlackHoleCluster},
				})},
			},
		)
		internalChainMatcher = sniTrafficPolicyMatcher(config.gateway.GetTlsTermination().GetExcludeHosts())
	} else if tlsTermination := config.gateway.GetTlsTermination(); tlsTermination != nil {
		internalChains = append(internalChains, buildTLSTerminateChain(connectionPool))
		internalChainMatcher = staticSNIMatcher(tlsTermination)
	}
	mainInternal := &listenerv3.Listener{
		Name:               MainInternal,
		ListenerSpecifier:  &listenerv3.Listener_InternalListener{InternalListener: &listenerv3.Listener_InternalListenerConfig{}},
		TrafficDirection:   corev3.TrafficDirection_INBOUND,
		ListenerFilters:    inspectorFilters(true),
		FilterChains:       internalChains,
		FilterChainMatcher: internalChainMatcher,
	}
	mainForward := &listenerv3.Listener{
		Name:              MainForward,
		ListenerSpecifier: &listenerv3.Listener_InternalListener{InternalListener: &listenerv3.Listener_InternalListenerConfig{}},
		TrafficDirection:  corev3.TrafficDirection_INBOUND,
		ListenerFilters:   inspectorFilters(false),
		FilterChains: []*listenerv3.FilterChain{
			{Name: forwardHTTPChain, Filters: []*listenerv3.Filter{networkFilter("envoy.filters.network.http_connection_manager", httpForward)}},
			{Name: forwardTCPChain, Filters: applicationTCPFilters(config, []*listenerv3.Filter{sniDFPFilter()}, TLSConnectOriginate, connectionPool)},
		},
		FilterChainMatcher: protocolMatcher(false),
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

func buildConnectHCM(config effectiveConfig) (*hcmv3.HttpConnectionManager, error) {
	gateway := config.gateway
	filters := []*hcmv3.HttpFilter{downstreamPeerMetadataFilter(), connectAuthorityFilter()}
	if rateLimit := gateway.GetConnectRateLimit(); rateLimit != nil {
		filter, err := localRateLimitFilter(rateLimit)
		if err != nil {
			return nil, err
		}
		filters = append(filters, filter)
	}
	filters = append(filters, httpFilter("envoy.filters.http.router", &routerv3.Router{}))
	hcm := &hcmv3.HttpConnectionManager{
		StatPrefix:        ConnectTerminate,
		ServerName:        "istio-envoy",
		RouteSpecifier:    &hcmv3.HttpConnectionManager_Rds{Rds: rds(ConnectTerminate)},
		UseRemoteAddress:  wrapperspb.Bool(false),
		StreamIdleTimeout: durationpb.New(0),
		UpgradeConfigs:    []*hcmv3.HttpConnectionManager_UpgradeConfig{{UpgradeType: "CONNECT"}},
		Http2ProtocolOptions: &corev3.Http2ProtocolOptions{
			AllowConnect:         true,
			MaxConcurrentStreams: wrapperspb.UInt32(100),
			ConnectionKeepalive:  &corev3.KeepaliveSettings{Interval: durationpb.New(10 * time.Second), Timeout: durationpb.New(20 * time.Second)},
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

func downstreamPeerMetadataFilter() *hcmv3.HttpFilter {
	fields, _ := structpb.NewStruct(map[string]any{
		"downstream_discovery": []any{map[string]any{"workload_discovery": map[string]any{}}},
		"shared_with_upstream": true,
	})
	// wire-visible filter name, part of the Agentio data-plane contract pinned by testdata, never rename.
	return httpFilter("waypoint_downstream_peer_metadata", &udpatypev1.TypedStruct{
		TypeUrl: "type.googleapis.com/io.istio.http.peer_metadata.Config",
		Value:   fields,
	})
}

func buildForwardHCM(routeName string, config effectiveConfig, terminatedTLS bool) (*hcmv3.HttpConnectionManager, error) {
	filters := make([]*hcmv3.HttpFilter, 0, 4)
	if terminatedTLS {
		// Reject an inner authority that differs from the ClientHello SNI before
		// ext_proc or DFP can observe or resolve the attacker-controlled host.
		filters = append(filters, sniHostMatchRBACFilter())
	}
	if config.extProc != nil {
		filter, err := extProcFilter(config.extProc)
		if err != nil {
			return nil, err
		}
		filters = append(filters, filter)
	}
	staticEndpoints := len(config.gateway.GetServiceEntries()) > 0
	if staticEndpoints {
		filters = append(filters, httpFilter(staticEndpointFilterStateFilter, &setstatehttpv3.Config{}))
	}
	filters = append(filters, httpFilter("envoy.filters.http.dynamic_forward_proxy", &dfphttpv3.FilterConfig{
		ImplementationSpecifier:         &dfphttpv3.FilterConfig_DnsCacheConfig{DnsCacheConfig: dnsCacheConfig()},
		AllowDynamicHostFromFilterState: staticEndpoints,
	}))
	if config.telemetry != nil {
		for _, filter := range config.telemetry.HTTPFilters {
			filters = append(filters, proto.Clone(filter).(*hcmv3.HttpFilter))
		}
	}
	if terminatedTLS {
		filters = append(filters, connectProxyTLSIdentityHTTPFilter())
	}
	filters = append(filters, httpFilter("envoy.filters.http.router", &routerv3.Router{}))
	streamIdle := durationpb.New(30 * time.Minute)
	if configured := config.gateway.GetConnectionPool().GetHttp().GetStreamIdleTimeout(); configured != nil {
		streamIdle = configured
	}
	hcm := &hcmv3.HttpConnectionManager{
		StatPrefix:        forwardHCMStatPrefix,
		RouteSpecifier:    &hcmv3.HttpConnectionManager_Rds{Rds: rds(routeName)},
		ServerName:        "istio-envoy",
		Proxy_100Continue: true,
		UseRemoteAddress:  wrapperspb.Bool(false),
		StreamIdleTimeout: streamIdle,
		HttpFilters:       filters,
		UpgradeConfigs:    []*hcmv3.HttpConnectionManager_UpgradeConfig{{UpgradeType: "websocket"}},
		Http2ProtocolOptions: &corev3.Http2ProtocolOptions{
			AllowConnect: true,
		},
	}
	if config.telemetry != nil {
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

func staticEndpointFilterStateConfig(address string) *anypb.Any {
	host := formatString(address)
	host.OmitEmptyValues = false
	config, _ := anypb.New(&setstatehttpv3.Config{OnRequestHeaders: []*setstatecommonv3.FilterStateValue{
		{
			Key:      &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: dynamicHostKey},
			Value:    &setstatecommonv3.FilterStateValue_FormatString{FormatString: host},
			ReadOnly: true,
		},
		{
			Key: &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: dynamicPortKey},
			Value: &setstatecommonv3.FilterStateValue_FormatString{FormatString: formatString(
				"%FILTER_STATE(envoy.filters.listener.original_dst.local_ip:FIELD:port)%",
			)},
			ReadOnly:    true,
			SkipIfEmpty: true,
		},
	}})
	return config
}

var sniHostMismatchExprText = fmt.Sprintf(`
  request.method != 'CONNECT' &&
  '%[1]s' in filter_state &&
  string(filter_state['%[1]s']) != '' &&
  request.host.split(':')[0].lowerAscii() != string(filter_state['%[1]s']).lowerAscii()
`, outerSNIKey)

var sniHostMismatchExpr = mustParseCEL(sniHostMismatchExprText)

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

func sniHostMatchRBACFilter() *hcmv3.HttpFilter {
	return httpFilter("envoy.filters.http.rbac", &rbachttpv3.RBAC{Rules: &rbacv3.RBAC{
		Action: rbacv3.RBAC_DENY,
		Policies: map[string]*rbacv3.Policy{
			"deny-sni-host-mismatch": {
				Permissions: []*rbacv3.Permission{{Rule: &rbacv3.Permission_Any{Any: true}}},
				Principals:  []*rbacv3.Principal{{Identifier: &rbacv3.Principal_Any{Any: true}}},
				Condition:   sniHostMismatchExpr,
				CelConfig: &corev3.CelExpressionConfig{
					EnableStringFunctions:  true,
					EnableStringConcat:     true,
					EnableStringConversion: true,
				},
			},
		},
	}})
}

// connectProxyTLSIdentityHTTPFilter copies the outer proxy SNI into Envoy's
// upstream TLS identity keys only for CONNECT. Ordinary HTTPS requests retain
// DFP auto-SNI/SAN behavior.
func connectProxyTLSIdentityHTTPFilter() *hcmv3.HttpFilter {
	outerSNI := formatString(fmt.Sprintf("%%FILTER_STATE(%s:PLAIN)%%", outerSNIKey))
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
				Input: typedExtension("request-headers", &matcherv3.HttpRequestHeaderMatchInput{HeaderName: ":method"}),
				Matcher: &xdsmatcherv3.Matcher_MatcherList_Predicate_SinglePredicate_ValueMatch{
					ValueMatch: &xdsmatcherv3.StringMatcher{MatchPattern: &xdsmatcherv3.StringMatcher_Exact{Exact: "CONNECT"}},
				},
			},
		},
	}
	skipConfig, _ := anypb.New(&skipactionv3.SkipFilter{})
	skip := &xdsmatcherv3.Matcher_OnMatch{OnMatch: &xdsmatcherv3.Matcher_OnMatch_Action{Action: &xdscorev3.TypedExtensionConfig{
		Name: "skip", TypedConfig: skipConfig,
	}}}
	wrapper := &extensionmatchingv3.ExtensionWithMatcher{
		XdsMatcher: &xdsmatcherv3.Matcher{MatcherType: &xdsmatcherv3.Matcher_MatcherList_{MatcherList: &xdsmatcherv3.Matcher_MatcherList{
			Matchers: []*xdsmatcherv3.Matcher_MatcherList_FieldMatcher{{
				Predicate: &xdsmatcherv3.Matcher_MatcherList_Predicate{MatchType: &xdsmatcherv3.Matcher_MatcherList_Predicate_NotMatcher{
					NotMatcher: connectMethod,
				}},
				OnMatch: skip,
			}},
		}}},
		ExtensionConfig: typedCoreExtension("envoy.filters.http.set_filter_state", setIdentity),
	}
	return httpFilter(connectProxyTLSIdentityFilter, wrapper)
}

func extProcFilter(provider *configv1.ExtProcProvider) (*hcmv3.HttpFilter, error) {
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
	return httpFilter("envoy.filters.http.ext_proc", &extprocv3.ExternalProcessor{
		GrpcService:        &corev3.GrpcService{TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{ClusterName: ExtProcCluster}}},
		FailureModeAllow:   provider.GetFailureModeAllow(),
		AllowModeOverride:  true,
		ProcessingMode:     &extprocv3.ProcessingMode{RequestHeaderMode: requestMode, ResponseHeaderMode: responseMode},
		RequestAttributes:  provider.GetRequest().GetAttributes(),
		ResponseAttributes: provider.GetResponse().GetAttributes(),
		MessageTimeout:     timeout,
	}), nil
}

func headerMode(mode configv1.HeaderSendMode, fallback extprocv3.ProcessingMode_HeaderSendMode) extprocv3.ProcessingMode_HeaderSendMode {
	switch mode {
	case configv1.HeaderSendMode_SEND:
		return extprocv3.ProcessingMode_SEND
	case configv1.HeaderSendMode_SKIP:
		return extprocv3.ProcessingMode_SKIP
	default:
		return fallback
	}
}

func workloadDownstreamTLS(trustDomain string) *corev3.TransportSocket {
	secret := func(name string) *tlsv3.SdsSecretConfig {
		return &tlsv3.SdsSecretConfig{Name: name, SdsConfig: workloadSDSConfigSource()}
	}
	config, _ := anypb.New(&tlsv3.DownstreamTlsContext{
		RequireClientCertificate: wrapperspb.Bool(true),
		CommonTlsContext: &tlsv3.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: []*tlsv3.SdsSecretConfig{secret("default")},
			ValidationContextType: &tlsv3.CommonTlsContext_CombinedValidationContext{CombinedValidationContext: &tlsv3.CommonTlsContext_CombinedCertificateValidationContext{
				DefaultValidationContext: &tlsv3.CertificateValidationContext{MatchTypedSubjectAltNames: []*tlsv3.SubjectAltNameMatcher{{
					SanType: tlsv3.SubjectAltNameMatcher_URI,
					Matcher: &matcherv3.StringMatcher{MatchPattern: &matcherv3.StringMatcher_Prefix{Prefix: "spiffe://" + trustDomain + "/"}},
				}}},
				ValidationContextSdsSecretConfig: secret("ROOTCA"),
			}},
			AlpnProtocols: []string{"h2"},
			TlsParams: &tlsv3.TlsParameters{
				TlsMinimumProtocolVersion: tlsv3.TlsParameters_TLSv1_3,
				TlsMaximumProtocolVersion: tlsv3.TlsParameters_TLSv1_3,
			},
		},
	})
	return &corev3.TransportSocket{Name: "envoy.transport_sockets.tls", ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: config}}
}

func buildTLSTerminateChain(pool *configv1.ConnectionPoolSettings) *listenerv3.FilterChain {
	selector, _ := anypb.New(&ondemandv3.Config{
		ConfigSource: adsConfigSource(),
		CertificateMapper: typedCoreExtension(
			"envoy.tls.certificate_mappers.sni", &snimapperv3.SNI{DefaultValue: noSNISentinel}),
	})
	tlsConfig, _ := anypb.New(&tlsv3.DownstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{
			AlpnProtocols:                []string{"h2", "http/1.1"},
			CustomTlsCertificateSelector: &corev3.TypedExtensionConfig{Name: "envoy.tls.certificate_selectors.on_demand_secret", TypedConfig: selector},
		},
		SessionTicketKeysType:            &tlsv3.DownstreamTlsContext_DisableStatelessSessionResumption{DisableStatelessSessionResumption: true},
		DisableStatefulSessionResumption: true,
	})
	return &listenerv3.FilterChain{
		Name:                          tlsTerminateChain,
		TransportSocketConnectTimeout: durationpb.New(15 * time.Second),
		TransportSocket:               &corev3.TransportSocket{Name: "envoy.transport_sockets.tls", ConfigType: &corev3.TransportSocket_TypedConfig{TypedConfig: tlsConfig}},
		Filters:                       []*listenerv3.Filter{captureSNIFilter(), relayDownstreamFilter(), tcpProxy(MainForward, pool, nil)},
	}
}

func connectAuthorityFilter() *hcmv3.HttpFilter {
	value := func(key, format, factory string, sharing setstatecommonv3.FilterStateValue_SharedWithUpstream) *setstatecommonv3.FilterStateValue {
		return &setstatecommonv3.FilterStateValue{
			Key:                &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: key},
			FactoryKey:         factory,
			Value:              &setstatecommonv3.FilterStateValue_FormatString{FormatString: formatString(format)},
			SharedWithUpstream: sharing,
		}
	}
	return httpFilter("connect_authority", &setstatehttpv3.Config{OnRequestHeaders: []*setstatecommonv3.FilterStateValue{
		value("envoy.filters.listener.original_dst.local_ip", "%REQ(:AUTHORITY)%", "", setstatecommonv3.FilterStateValue_ONCE),
		value(connectAuthorityKey, "%REQ(:AUTHORITY)%", "istio.hashable_string", setstatecommonv3.FilterStateValue_ONCE),
		value("envoy.filters.listener.original_dst.remote_ip", "%DOWNSTREAM_REMOTE_ADDRESS%", "", setstatecommonv3.FilterStateValue_ONCE),
		value("io.istio.peer_principal", "%DOWNSTREAM_PEER_URI_SAN%", "istio.hashable_string", setstatecommonv3.FilterStateValue_ONCE),
		value("io.istio.local_principal", "%DOWNSTREAM_LOCAL_URI_SAN%", "istio.hashable_string", setstatecommonv3.FilterStateValue_ONCE),
		value("sandbox.token", "%REQ(X-AGENTIO-SANDBOX-TOKEN)%", "envoy.string", setstatecommonv3.FilterStateValue_TRANSITIVE),
		value("sandbox.labels", "%REQ(X-AGENTIO-SANDBOX-LABELS)%", "envoy.string", setstatecommonv3.FilterStateValue_TRANSITIVE),
		value("sandbox.id", "%REQ(X-AGENTIO-SANDBOX-ID)%", "envoy.string", setstatecommonv3.FilterStateValue_TRANSITIVE),
	}})
}

func relayDownstreamFilter() *listenerv3.Filter {
	values := make([]*setstatecommonv3.FilterStateValue, 0, len(downstreamRelayKeys))
	for _, relay := range downstreamRelayKeys {
		values = append(values, &setstatecommonv3.FilterStateValue{
			Key:        &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: relay.key},
			FactoryKey: relay.factory,
			Value: &setstatecommonv3.FilterStateValue_FormatString{
				FormatString: formatString(fmt.Sprintf("%%FILTER_STATE(%s:PLAIN)%%", relay.key)),
			},
			SharedWithUpstream: setstatecommonv3.FilterStateValue_ONCE,
			SkipIfEmpty:        true,
		})
	}
	return networkFilter("connect_downstream_peer", &setstatenetworkv3.Config{OnNewConnection: values})
}

func captureSNIFilter() *listenerv3.Filter {
	// Shared state must be Hashable so internal connections cannot be reused
	// across different outer SNIs and spuriously fail the SNI/Host guard.
	return networkFilter("envoy.filters.network.set_filter_state", &setstatenetworkv3.Config{OnNewConnection: []*setstatecommonv3.FilterStateValue{{
		Key:                &setstatecommonv3.FilterStateValue_ObjectKey{ObjectKey: outerSNIKey},
		FactoryKey:         "istio.hashable_string",
		Value:              &setstatecommonv3.FilterStateValue_FormatString{FormatString: formatString("%REQUESTED_SERVER_NAME%")},
		SharedWithUpstream: setstatecommonv3.FilterStateValue_ONCE,
		SkipIfEmpty:        true,
	}}})
}

func localRateLimitFilter(settings *configv1.LocalRateLimitSettings) (*hcmv3.HttpFilter, error) {
	config := &localratelimitv3.LocalRateLimit{
		StatPrefix:                            "connect_rate_limit",
		LocalRateLimitPerDownstreamConnection: settings.GetPerDownstreamConnection(),
		FilterEnabled:                         runtimePercent(),
		FilterEnforced:                        runtimePercent(),
	}
	if settings.GetTokenBucket() != nil {
		config.TokenBucket = tokenBucket(settings.GetTokenBucket())
	}
	actions := map[string]*routev3.RateLimit_Action{}
	for _, descriptor := range settings.GetDescriptors() {
		converted := &ratelimitv3.LocalRateLimitDescriptor{TokenBucket: tokenBucket(descriptor.GetTokenBucket())}
		for _, entry := range descriptor.GetEntries() {
			converted.Entries = append(converted.Entries, &ratelimitv3.RateLimitDescriptor_Entry{Key: entry.GetKey(), Value: entry.GetValue()})
			if entry.GetCel() != "" {
				configAny, _ := anypb.New(&rlexprv3.Descriptor{
					DescriptorKey: entry.GetKey(),
					ExprSpecifier: &rlexprv3.Descriptor_Text{Text: entry.GetCel()},
					SkipIfError:   true,
				})
				actions[entry.GetKey()] = &routev3.RateLimit_Action{ActionSpecifier: &routev3.RateLimit_Action_Extension{
					Extension: &corev3.TypedExtensionConfig{Name: "envoy.rate_limit_descriptors.expr", TypedConfig: configAny},
				}}
			}
		}
		config.Descriptors = append(config.Descriptors, converted)
	}
	if len(actions) > 0 {
		rateLimit := &routev3.RateLimit{}
		for _, descriptor := range settings.GetDescriptors() {
			for _, entry := range descriptor.GetEntries() {
				if action := actions[entry.GetKey()]; action != nil {
					rateLimit.Actions = append(rateLimit.Actions, action)
					delete(actions, entry.GetKey())
				}
			}
		}
		config.RateLimits = []*routev3.RateLimit{rateLimit}
	}
	if err := config.ValidateAll(); err != nil {
		return nil, fmt.Errorf("validate connect rate limit: %w", err)
	}
	return httpFilter("envoy.filters.http.local_ratelimit", config), nil
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
	return &corev3.RuntimeFractionalPercent{DefaultValue: &typev3.FractionalPercent{Numerator: 100, Denominator: typev3.FractionalPercent_HUNDRED}}
}

func tcpProxy(cluster string, pool *configv1.ConnectionPoolSettings, accessLogs []*accesslogv3.AccessLog) *listenerv3.Filter {
	config := &tcpproxyv3.TcpProxy{StatPrefix: cluster, ClusterSpecifier: &tcpproxyv3.TcpProxy_Cluster{Cluster: cluster}}
	if pool.GetTcp().GetIdleTimeout() != nil {
		config.IdleTimeout = pool.GetTcp().GetIdleTimeout()
	} else {
		config.IdleTimeout = durationpb.New(time.Hour)
	}
	config.MaxDownstreamConnectionDuration = pool.GetTcp().GetMaxConnectionDuration()
	for _, accessLog := range accessLogs {
		config.AccessLog = append(config.AccessLog, proto.Clone(accessLog).(*accesslogv3.AccessLog))
	}
	return networkFilter("envoy.filters.network.tcp_proxy", config)
}

func applicationTCPFilters(config effectiveConfig, prefix []*listenerv3.Filter, cluster string, pool *configv1.ConnectionPoolSettings) []*listenerv3.Filter {
	result := append([]*listenerv3.Filter{}, prefix...)
	var accessLogs []*accesslogv3.AccessLog
	if config.telemetry != nil {
		for _, filter := range config.telemetry.TCPFilters {
			result = append(result, proto.Clone(filter).(*listenerv3.Filter))
		}
		accessLogs = config.telemetry.TCPAccessLogs
	}
	return append(result, tcpProxy(cluster, pool, accessLogs))
}

func sniDFPFilter() *listenerv3.Filter {
	return networkFilter("envoy.filters.network.sni_dynamic_forward_proxy", &dfpnetworkv3.FilterConfig{
		DnsCacheConfig: dnsCacheConfig(),
		PortSpecifier:  &dfpnetworkv3.FilterConfig_PortValue{PortValue: 443},
	})
}

func inspectorFilters(httpFirst bool) []*listenerv3.ListenerFilter {
	originalDst := listenerFilter("envoy.filters.listener.original_dst", &originaldstv3.OriginalDst{})
	tlsInspector := listenerFilter("envoy.filters.listener.tls_inspector", &tlsinspectorv3.TlsInspector{
		InitialReadBufferSize: wrapperspb.UInt32(16 * 1024),
	})
	httpInspector := listenerFilter("envoy.filters.listener.http_inspector", &httpinspectorv3.HttpInspector{})
	if httpFirst {
		return []*listenerv3.ListenerFilter{originalDst, httpInspector, tlsInspector}
	}
	return []*listenerv3.ListenerFilter{originalDst, tlsInspector, httpInspector}
}

func sniTrafficPolicyMatcher(excludeHosts []string) *xdsmatcherv3.Matcher {
	policy := sniPolicyMatcher()
	tlsMatch := toMatcher(policy)
	if len(excludeHosts) > 0 {
		domains := &xdsmatcherv3.ServerNameMatcher{DomainMatchers: []*xdsmatcherv3.ServerNameMatcher_DomainMatcher{{
			Domains: excludeHosts,
			OnMatch: toChain(forwardTCPChain),
		}}}
		config, _ := anypb.New(domains)
		tlsMatch = toMatcher(&xdsmatcherv3.Matcher{
			MatcherType: &xdsmatcherv3.Matcher_MatcherTree_{MatcherTree: &xdsmatcherv3.Matcher_MatcherTree{
				Input:    serverNameInput,
				TreeType: &xdsmatcherv3.Matcher_MatcherTree_CustomMatch{CustomMatch: &xdscorev3.TypedExtensionConfig{Name: "sni", TypedConfig: config}},
			}},
			OnNoMatch: tlsMatch,
		})
	}
	app := applicationMatcher()
	return exactMatcher(transportProtocolInput, map[string]*xdsmatcherv3.Matcher_OnMatch{"tls": tlsMatch}, toMatcher(app))
}

func staticSNIMatcher(config *configv1.TlsTerminationConfig) *xdsmatcherv3.Matcher {
	domainMatchers := make([]*xdsmatcherv3.ServerNameMatcher_DomainMatcher, 0, 2)
	for _, match := range []struct {
		domains []string
		onMatch *xdsmatcherv3.Matcher_OnMatch
	}{
		{domains: config.GetExcludeHosts(), onMatch: toChain(forwardTCPChain)},
		{domains: config.GetIncludeHosts(), onMatch: toChain(tlsTerminateChain)},
	} {
		if len(match.domains) > 0 {
			domainMatchers = append(domainMatchers, &xdsmatcherv3.ServerNameMatcher_DomainMatcher{
				Domains: match.domains,
				OnMatch: match.onMatch,
			})
		}
	}
	domains := &xdsmatcherv3.ServerNameMatcher{DomainMatchers: domainMatchers}
	typedConfig, _ := anypb.New(domains)
	return &xdsmatcherv3.Matcher{
		MatcherType: &xdsmatcherv3.Matcher_MatcherTree_{MatcherTree: &xdsmatcherv3.Matcher_MatcherTree{
			Input: serverNameInput,
			TreeType: &xdsmatcherv3.Matcher_MatcherTree_CustomMatch{CustomMatch: &xdscorev3.TypedExtensionConfig{
				Name:        "sni",
				TypedConfig: typedConfig,
			}},
		}},
		OnNoMatch: toMatcher(protocolMatcher(false)),
	}
}

func protocolMatcher(tlsToPolicy bool) *xdsmatcherv3.Matcher {
	var tls *xdsmatcherv3.Matcher_OnMatch
	if tlsToPolicy {
		tls = toMatcher(sniPolicyMatcher())
	} else {
		tls = toChain(forwardTCPChain)
	}
	return exactMatcher(transportProtocolInput, map[string]*xdsmatcherv3.Matcher_OnMatch{"tls": tls}, toMatcher(applicationMatcher()))
}

func applicationMatcher() *xdsmatcherv3.Matcher {
	return exactMatcher(applicationProtocolInput, map[string]*xdsmatcherv3.Matcher_OnMatch{
		"'h2c'":      toChain(forwardHTTPChain),
		"'http/1.1'": toChain(forwardHTTPChain),
	}, toChain(forwardTCPChain))
}

func sniPolicyMatcher() *xdsmatcherv3.Matcher {
	fields, _ := structpb.NewStruct(map[string]any{
		"on_tls_termination": chainActionFields(tlsTerminateChain),
		"on_passthrough":     chainActionFields(forwardTCPChain),
		"on_deny":            chainActionFields(sniDenyChain),
		"failure_mode_allow": map[string]any{"runtime_key": "kruise.sni_traffic_policy.failure_mode_allow", "default_value": false},
	})
	config, _ := anypb.New(&udpatypev1.TypedStruct{TypeUrl: sniPolicyMatcherType, Value: fields})
	return &xdsmatcherv3.Matcher{
		MatcherType: &xdsmatcherv3.Matcher_MatcherTree_{MatcherTree: &xdsmatcherv3.Matcher_MatcherTree{
			Input: serverNameInput,
			TreeType: &xdsmatcherv3.Matcher_MatcherTree_CustomMatch{CustomMatch: &xdscorev3.TypedExtensionConfig{
				Name:        sniPolicyMatcherName,
				TypedConfig: config,
			}},
		}},
		OnNoMatch: toChain(forwardTCPChain),
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

func exactMatcher(input *xdscorev3.TypedExtensionConfig, values map[string]*xdsmatcherv3.Matcher_OnMatch, fallback *xdsmatcherv3.Matcher_OnMatch) *xdsmatcherv3.Matcher {
	return &xdsmatcherv3.Matcher{
		MatcherType: &xdsmatcherv3.Matcher_MatcherTree_{MatcherTree: &xdsmatcherv3.Matcher_MatcherTree{
			Input:    input,
			TreeType: &xdsmatcherv3.Matcher_MatcherTree_ExactMatchMap{ExactMatchMap: &xdsmatcherv3.Matcher_MatcherTree_MatchMap{Map: values}},
		}},
		OnNoMatch: fallback,
	}
}

func toChain(name string) *xdsmatcherv3.Matcher_OnMatch {
	config, _ := anypb.New(wrapperspb.String(name))
	return &xdsmatcherv3.Matcher_OnMatch{OnMatch: &xdsmatcherv3.Matcher_OnMatch_Action{Action: &xdscorev3.TypedExtensionConfig{Name: name, TypedConfig: config}}}
}

func toMatcher(value *xdsmatcherv3.Matcher) *xdsmatcherv3.Matcher_OnMatch {
	return &xdsmatcherv3.Matcher_OnMatch{OnMatch: &xdsmatcherv3.Matcher_OnMatch_Matcher{Matcher: value}}
}

func typedExtension(name string, message proto.Message) *xdscorev3.TypedExtensionConfig {
	config, _ := anypb.New(message)
	return &xdscorev3.TypedExtensionConfig{Name: name, TypedConfig: config}
}

func typedCoreExtension(name string, message proto.Message) *corev3.TypedExtensionConfig {
	config, _ := anypb.New(message)
	return &corev3.TypedExtensionConfig{Name: name, TypedConfig: config}
}

func httpFilter(name string, message proto.Message) *hcmv3.HttpFilter {
	config, _ := anypb.New(message)
	return &hcmv3.HttpFilter{Name: name, ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: config}}
}

func networkFilter(name string, message proto.Message) *listenerv3.Filter {
	config, _ := anypb.New(message)
	return &listenerv3.Filter{Name: name, ConfigType: &listenerv3.Filter_TypedConfig{TypedConfig: config}}
}

func listenerFilter(name string, message proto.Message) *listenerv3.ListenerFilter {
	config, _ := anypb.New(message)
	return &listenerv3.ListenerFilter{Name: name, ConfigType: &listenerv3.ListenerFilter_TypedConfig{TypedConfig: config}}
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
