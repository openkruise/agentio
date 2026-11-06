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

package gatewaydeployer

import (
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	networking "istio.io/api/networking/v1alpha3"
	corev1 "k8s.io/api/core/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
)

const agentgatewayOriginalTarget = `(string(destination.address).contains(":") ? "[" + string(destination.address) + "]" : string(destination.address)) + ":" + string(destination.port)`

const agentgatewaySourceAddress = `(string(source.address).contains(":") ? "[" + string(source.address) + "]" : string(source.address)) + ":" + string(source.port)`

var agentgatewayWorkloadAttributes = map[string]string{
	model.AttributeWorkloadUID:       "extproc.agentio.workload.resource_name",
	model.AttributeWorkloadName:      "extproc.agentio.workload.name",
	model.AttributeWorkloadNamespace: "extproc.agentio.workload.namespace",
}

func agentgatewayWorkloadIdentity(provider *configv1.ExtProcProvider) bool {
	for _, attribute := range provider.GetRequest().GetAttributes() {
		if _, found := agentgatewayWorkloadAttributes[attribute]; found {
			return true
		}
	}
	return false
}

// Keep the intercepted port even when Host contains a different explicit port.
const agentgatewayHostTarget = `(request.host.startsWith("[") ? request.host.split("]")[0] + "]" : request.host.split(":")[0]) + ":" + string(destination.port)`

type agentgatewayConfigInputs struct {
	Global      *configv1.AgentioConfig
	Services    []model.Service
	Endpoints   []model.Endpoint
	TrustBundle string
	MITM        bool
}

func agentgatewayEgressConfig(
	gateway *configv1.EgressGateway,
	ports []corev1.ServicePort,
	inputs agentgatewayConfigInputs,
) (string, error) {
	if err := agentgatewaySupportedFields(
		gateway.ProtoReflect(),
		"",
		"http",
		"ext_proc",
		"service_entries",
		"tls_termination",
		"upstream_trust_bundle",
		"tls",
		"tcp",
	); err != nil {
		return "", err
	}
	normalized, err := model.NormalizeEgressGatewayServiceEntries(gateway)
	if err != nil {
		return "", err
	}
	if err := (model.Gateway{Namespace: "generated", Name: "agentgateway", Config: normalized}).ValidateForUse(); err != nil {
		return "", err
	}
	if err := agentgatewayTransportSettings(normalized); err != nil {
		return "", err
	}
	if normalized.ExtProc == nil {
		normalized.ExtProc = inputs.Global.GetSandboxExtProc()
	}
	providers := []*configv1.ExtProcProvider{normalized.ExtProc}
	if model.ExtProcEnabled(normalized.ExtProc) {
		providers = append(providers, inputs.Global.GetAdditionalExtProcs()...)
	}
	if len(providers) > 2 {
		return "", fmt.Errorf("agentgateway supports at most one additionalExtProc after the primary processor")
	}
	if len(providers) > 1 &&
		(agentgatewayWorkloadIdentity(providers[0]) || agentgatewayWorkloadIdentity(providers[1])) {
		return "", fmt.Errorf(
			"agentgateway workload identity uses the first processor phase; additionalExtProcs are unavailable",
		)
	}
	if len(gateway.GetTlsTermination().GetIncludeHosts()) > 0 && !inputs.MITM {
		return "", fmt.Errorf(
			"tlsTermination requires gateway.agentio.kruise.io/agentgateway-certs with ca.crt and ca.key",
		)
	}
	listener, err := agentgatewayHTTPListener(normalized, providers)
	if err != nil {
		return "", err
	}
	tlsListeners, err := agentgatewayTLSListeners(normalized, listener, inputs)
	if err != nil {
		return "", err
	}
	listeners := append([]any{listener}, tlsListeners...)
	listeners = append(listeners, map[string]any{
		"protocol":  "TCP",
		"tcpRoutes": []any{map[string]any{"backends": agentgatewayBackends(nil)}},
	})
	binds, err := agentgatewayBinds(listeners, ports)
	if err != nil {
		return "", err
	}
	config := map[string]any{
		"config": map[string]any{
			"adminAddr": "127.0.0.1:15000",
			"dns":       map[string]any{"lookupFamily": "V4Only"},
		},
		"binds": binds,
		"frontendPolicies": map[string]any{
			"connect": map[string]any{"mode": "deny"},
		},
	}
	services, workloads := agentgatewayProcessorServices(providers, inputs)
	if len(services) > 0 {
		config["services"], config["workloads"] = services, workloads
	}
	content, err := json.Marshal(config)
	return string(content), err
}

func agentgatewayBinds(listeners []any, ports []corev1.ServicePort) ([]any, error) {
	// Native HBONE requires an internal bind for each destination port.
	destinations := []int{80, 443}
	hbonePort := 0
	for _, port := range ports {
		if port.Name == "status-port" {
			continue
		}
		if port.AppProtocol != nil && *port.AppProtocol == "hbone" {
			if hbonePort != 0 {
				return nil, fmt.Errorf("generated agentgateway configuration requires exactly one HBONE listener")
			}
			hbonePort = int(port.Port)
		} else {
			destinations = append(destinations, int(port.Port))
		}
	}
	if hbonePort == 0 {
		return nil, fmt.Errorf("generated agentgateway configuration requires an HBONE listener")
	}
	slices.Sort(destinations)
	destinations = slices.Compact(destinations)
	binds := []any{map[string]any{
		"port":           hbonePort,
		"tunnelProtocol": "hboneGateway",
		"listeners":      []any{map[string]any{"protocol": "HBONE"}},
	}}
	for _, port := range destinations {
		if port == hbonePort {
			return nil, fmt.Errorf("HBONE port %d conflicts with an internal destination port", port)
		}
		binds = append(binds, map[string]any{
			"port":      port,
			"mode":      "internal",
			"protocol":  "AUTO",
			"listeners": listeners,
		})
	}
	return binds, nil
}

func agentgatewayTransportSettings(gateway *configv1.EgressGateway) error {
	tls := gateway.GetTls().GetOrigination()
	if tls.GetMinProtocolVersion() == configv1.UpstreamTlsSettings_TLSV1_3 ||
		tls.GetMaxProtocolVersion() == configv1.UpstreamTlsSettings_TLSV1_2 || len(tls.GetCipherSuites()) != 0 {
		return fmt.Errorf("native backendTLS cannot restrict TLS versions or cipher suites")
	}
	if gateway.GetTcp().GetMaxConnectionDuration() != nil {
		return fmt.Errorf("agentgateway cannot translate tcp.maxConnectionDuration")
	}
	for name, duration := range map[string]*durationpb.Duration{
		"http.streamIdleTimeout": gateway.GetHttp().GetStreamIdleTimeout(),
		"tcp.idleTimeout":        gateway.GetTcp().GetIdleTimeout(),
	} {
		if duration == nil {
			continue
		}
		if err := duration.CheckValid(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if duration.AsDuration() != 0 {
			return fmt.Errorf("agentgateway cannot translate non-zero %s", name)
		}
	}
	return nil
}

func agentgatewayHTTPListener(
	gateway *configv1.EgressGateway,
	providers []*configv1.ExtProcProvider,
) (map[string]any, error) {
	primary, err := agentgatewayExtProc(gateway.GetExtProc())
	if err != nil {
		return nil, err
	}
	routes, err := agentgatewayHTTPRoutes(gateway, primary)
	if err != nil {
		return nil, err
	}
	processor := primary
	policies := map[string]any{}
	if agentgatewayWorkloadIdentity(gateway.GetExtProc()) {
		// Resolve authenticated connection identity before the HTTP policy processor runs.
		maps.Copy(primary["requestAttributes"].(map[string]string), agentgatewayWorkloadAttributes)
		policies["extProc"] = map[string]any{
			"host":        "127.0.0.1:9002",
			"failureMode": "failClosed",
			"requestAttributes": map[string]string{
				"destination.address":          "string(destination.address)",
				"destination.port":             "destination.port",
				model.AttributePeerCertificate: `has(source.certificate) ? source.certificate : ""`,
				model.AttributePeerIP:          "string(source.rawAddress)",
				model.AttributePeerPrincipal:   `has(source.spiffeId) ? source.spiffeId : ""`,
			},
			"processingOptions": map[string]any{
				"requestHeaderMode":   "send",
				"responseHeaderMode":  "skip",
				"requestBodyMode":     "none",
				"responseBodyMode":    "none",
				"requestTrailerMode":  "skip",
				"responseTrailerMode": "skip",
			},
		}
	}
	if len(providers) == 2 {
		processor, err = agentgatewayExtProc(providers[1])
		if err != nil {
			return nil, fmt.Errorf("additionalExtProcs: %w", err)
		}
		// Native gateway and route phases provide ordered request / reverse response processing.
		policies["extProc"] = primary
	}
	for _, value := range routes {
		route := value.(map[string]any)
		if processor != nil {
			route["policies"].(map[string]any)["extProc"] = processor
		}
	}
	if http := gateway.GetHttp(); http != nil && http.AcceptHttp_10 != nil && !http.GetAcceptHttp_10() {
		policies["authorization"] = map[string]any{
			"rules": []any{map[string]any{"deny": `request.version == "HTTP/1.0"`}},
		}
	}
	listener := map[string]any{"protocol": "HTTP", "routes": routes}
	if len(policies) != 0 {
		listener["policies"] = policies
	}
	return listener, nil
}

func agentgatewayTLSListeners(
	gateway *configv1.EgressGateway,
	http map[string]any,
	inputs agentgatewayConfigInputs,
) ([]any, error) {
	termination := map[string]bool{"*": false}
	for _, host := range gateway.GetTlsTermination().GetIncludeHosts() {
		termination[strings.ToLower(host)] = true
	}
	for _, host := range gateway.GetTlsTermination().GetExcludeHosts() {
		termination[strings.ToLower(host)] = false
	}
	hosts := slices.Sorted(maps.Keys(termination))
	listeners := make([]any, 0, len(hosts))
	for _, host := range hosts {
		if host == "" || host != "*" && strings.Contains(strings.TrimPrefix(host, "*."), "*") {
			return nil, fmt.Errorf("agentgateway only supports exact, *.suffix and * TLS hosts, got %q", host)
		}
		if !termination[host] {
			listeners = append(listeners, map[string]any{
				"protocol": "TLS",
				"hostname": host,
				"tcpRoutes": []any{map[string]any{"backends": []any{
					map[string]any{
						"dynamic": map[string]any{
							"target": `has(destination.hostname) ? destination.hostname + ":" + string(destination.port) : ` + agentgatewayOriginalTarget,
						},
					},
				}}},
			})
			continue
		}
		listeners = append(listeners, agentgatewayHTTPSListener(http, host, inputs))
	}
	return listeners, nil
}

func agentgatewayHTTPSListener(http map[string]any, host string, inputs agentgatewayConfigInputs) map[string]any {
	listener := maps.Clone(http)
	listener["protocol"], listener["hostname"] = "HTTPS", host
	listener["tls"] = map[string]any{
		"mode": "dynamicCa",
		"cert": "/etc/agentgateway/certs/ca.crt",
		"key":  "/etc/agentgateway/certs/ca.key",
	}
	routes := []any{}
	for _, value := range http["routes"].([]any) {
		route := maps.Clone(value.(map[string]any))
		backends := []any{}
		for _, value := range route["backends"].([]any) {
			backend := maps.Clone(value.(map[string]any))
			tls := map[string]any{}
			if backend["dynamic"].(map[string]any)["target"] != agentgatewayHostTarget {
				// Static endpoints are dialed by IP while TLS verifies the service hostname.
				tls["hostname"] = route["hostnames"].([]string)[0]
			}
			if inputs.TrustBundle != "" {
				tls["root"] = "/etc/agentgateway/upstream-root.pem"
			}
			backend["policies"] = map[string]any{"backendTLS": tls}
			backends = append(backends, backend)
		}
		route["backends"] = backends
		routes = append(routes, route)
	}
	listener["routes"] = routes
	return listener
}

// Unsupported settings must not silently lose enforcement when changing data planes.
func agentgatewaySupportedFields(message protoreflect.Message, prefix string, allowed ...protoreflect.Name) error {
	var unsupported []string
	message.Range(func(field protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		if !slices.Contains(allowed, field.Name()) {
			unsupported = append(unsupported, prefix+field.JSONName())
		}
		return true
	})
	if len(unsupported) != 0 {
		slices.Sort(unsupported)
		return fmt.Errorf(
			"agentgateway egress translation does not support %s; use native config.yaml or agentio-egress",
			strings.Join(unsupported, ", "),
		)
	}
	return nil
}

func agentgatewayHTTPRoutes(gateway *configv1.EgressGateway, extProc map[string]any) ([]any, error) {
	http := gateway.GetHttp()
	if err := agentgatewaySupportedFields(
		http.ProtoReflect(),
		"http.",
		"accept_http_10",
		"routing",
		"stream_idle_timeout",
	); err != nil {
		return nil, err
	}
	routing := http.GetRouting()
	fallbackSettings := routing.GetFallback()
	for _, override := range routing.GetHostOverrides() {
		if len(override.GetHosts()) == 0 {
			return nil, fmt.Errorf("http.routing.hostOverrides requires at least one host")
		}
		for _, host := range override.GetHosts() {
			if host == "" || host != "*" && strings.Contains(strings.TrimPrefix(host, "*."), "*") {
				return nil, fmt.Errorf("agentgateway only supports exact, *.suffix and * host overrides, got %q", host)
			}
		}
		if slices.Contains(override.GetHosts(), "*") {
			fallbackSettings = override.GetSettings()
		}
	}
	routes := make([]any, 0, len(gateway.GetServiceEntries())+len(routing.GetHostOverrides())+1)
	for _, entry := range gateway.GetServiceEntries() {
		for _, host := range entry.GetHosts() {
			settings := agentgatewaySettingsForHost(routing, host)
			route, err := agentgatewayHTTPRoute([]string{host}, settings, entry.GetEndpoints(), extProc)
			if err != nil {
				return nil, err
			}
			routes = append(routes, route)
		}
	}
	for _, override := range routing.GetHostOverrides() {
		if slices.Contains(override.GetHosts(), "*") {
			continue
		}
		route, err := agentgatewayHTTPRoute(override.GetHosts(), override.GetSettings(), nil, extProc)
		if err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	fallback, err := agentgatewayHTTPRoute(nil, fallbackSettings, nil, extProc)
	if err != nil {
		return nil, err
	}
	return append(routes, fallback), nil
}

func agentgatewaySettingsForHost(routing *configv1.HttpRoutingSettings, host string) *configv1.HttpRouteSettings {
	settings := routing.GetFallback()
	best := 0
	for _, override := range routing.GetHostOverrides() {
		for _, pattern := range override.GetHosts() {
			pattern = strings.ToLower(pattern)
			if pattern == host {
				return override.GetSettings()
			}
			if (pattern == "*" || strings.HasPrefix(pattern, "*.") && strings.HasSuffix(host, pattern[1:])) &&
				len(pattern) > best {
				settings, best = override.GetSettings(), len(pattern)
			}
		}
	}
	return settings
}

func agentgatewayHTTPRoute(
	hosts []string,
	settings *configv1.HttpRouteSettings,
	endpoints []*configv1.EgressServiceEntryEndpoint,
	extProc map[string]any,
) (map[string]any, error) {
	policies, err := agentgatewayRoutePolicies(settings)
	if err != nil {
		return nil, err
	}
	policies["urlRewrite"] = map[string]any{"authority": "none"}
	if extProc != nil {
		policies["extProc"] = extProc
	}
	backends := agentgatewayBackends(endpoints)
	if len(endpoints) == 0 {
		backends = []any{map[string]any{"dynamic": map[string]any{"target": agentgatewayHostTarget}}}
	}
	route := map[string]any{"policies": policies, "backends": backends}
	canonicalHosts := make([]string, 0, len(hosts))
	for _, host := range hosts {
		canonicalHosts = append(canonicalHosts, strings.ToLower(host))
	}
	if len(hosts) > 0 {
		route["hostnames"] = canonicalHosts
	}
	return route, nil
}

func agentgatewayRoutePolicies(settings *configv1.HttpRouteSettings) (map[string]any, error) {
	policies := map[string]any{}
	timeouts := map[string]any{}
	if settings.GetRetries().GetAttempts() < 0 {
		return nil, fmt.Errorf("HTTP retry attempts must not be negative")
	}
	if timeout := settings.GetTimeout(); timeout != nil {
		if err := timeout.CheckValid(); err != nil || timeout.AsDuration() < 0 {
			return nil, fmt.Errorf("invalid HTTP route timeout: %v", timeout)
		}
		if timeout.AsDuration() > 0 {
			timeouts["requestTimeout"] = timeout.AsDuration().String()
		}
	}
	if retry := settings.GetRetries(); retry != nil && retry.GetAttempts() > 0 {
		native, err := agentgatewayRetryPolicy(retry)
		if err != nil {
			return nil, err
		}
		policies["retry"] = native
		if timeout := retry.GetPerTryTimeout(); timeout != nil {
			if err := timeout.CheckValid(); err != nil || timeout.AsDuration() <= 0 {
				return nil, fmt.Errorf("invalid per-try timeout: %v", timeout)
			}
			timeouts["backendRequestTimeout"] = timeout.AsDuration().String()
		}
	}
	if len(timeouts) > 0 {
		policies["timeout"] = timeouts
	}
	return policies, nil
}

func agentgatewayRetryPolicy(retry *networking.HTTPRetry) (map[string]any, error) {
	if retry.GetAttempts() > 255 || retry.RetryIgnorePreviousHosts != nil || retry.RetryRemoteLocalities != nil {
		return nil, fmt.Errorf(
			"agentgateway retries support at most 255 retries and no previous-host/locality settings",
		)
	}
	codes := []int{}
	var grpcConditions []string
	for condition := range strings.SplitSeq(retry.GetRetryOn(), ",") {
		switch strings.TrimSpace(condition) {
		case "", "connect-failure", "refused-stream":
		case "5xx":
			for code := 500; code < 600; code++ {
				codes = append(codes, code)
			}
		case "gateway-error":
			codes = append(codes, 502, 503, 504)
		case "unavailable":
			grpcConditions = append(grpcConditions, "response.grpcStatus == 14")
		case "cancelled":
			grpcConditions = append(grpcConditions, "response.grpcStatus == 1")
		default:
			code, err := strconv.Atoi(strings.TrimSpace(condition))
			if err != nil || code < 100 || code > 599 {
				return nil, fmt.Errorf("agentgateway does not translate retryOn condition %q", condition)
			}
			codes = append(codes, code)
		}
	}
	native := map[string]any{"attempts": retry.GetAttempts(), "codes": codes}
	if strings.TrimSpace(retry.GetRetryOn()) == "" {
		grpcConditions = []string{"response.grpcStatus in [1, 14]"}
	}
	if len(grpcConditions) > 0 {
		native["condition"] = "has(response.grpcStatus) && (" + strings.Join(grpcConditions, " || ") + ")"
	}
	if backoff := retry.GetBackoff(); backoff != nil {
		if err := backoff.CheckValid(); err != nil || backoff.AsDuration() <= 0 {
			return nil, fmt.Errorf("invalid retry backoff: %v", backoff)
		}
		native["backoff"] = backoff.AsDuration().String()
	}
	return native, nil
}

func agentgatewayBackends(endpoints []*configv1.EgressServiceEntryEndpoint) []any {
	if len(endpoints) == 0 {
		return []any{map[string]any{"dynamic": map[string]any{"target": agentgatewayOriginalTarget}}}
	}
	backends := make([]any, 0, len(endpoints))
	for _, endpoint := range endpoints {
		backends = append(backends, map[string]any{"dynamic": map[string]any{
			"target": strconv.Quote(endpoint.GetAddress()+":") + " + string(destination.port)",
		}})
	}
	return backends
}

func agentgatewayExtProc(provider *configv1.ExtProcProvider) (map[string]any, error) {
	if !model.ExtProcEnabled(provider) {
		return nil, nil
	}
	if err := agentgatewaySupportedFields(
		provider.ProtoReflect(),
		"extProc.",
		"service",
		"service_ref",
		"port",
		"failure_mode_allow",
		"request",
		"response",
		"name",
		"tls",
		"cluster_settings",
	); err != nil {
		return nil, err
	}
	if err := model.ValidateExtProcServiceRef(provider); err != nil {
		return nil, err
	}
	if err := model.ValidateExtProcTLS(provider.GetTls()); err != nil {
		return nil, err
	}
	for _, mode := range []*configv1.ProcessingModeOptions{provider.GetRequest(), provider.GetResponse()} {
		if _, known := configv1.HeaderSendMode_name[int32(mode.GetHeaderMode())]; !known {
			return nil, fmt.Errorf("invalid extProc header mode %d", mode.GetHeaderMode())
		}
	}
	if provider.GetTls().GetMode() == configv1.ExtProcTLSSettings_MUTUAL {
		return nil, fmt.Errorf(
			"extProc MUTUAL requires a fail-closed native Agentiod CA backend TLS policy, which is unavailable",
		)
	}
	http := provider.GetClusterSettings().GetHttp()
	if http.GetMaxConcurrentStreams() != 0 || http.GetMaxRequestsPerConnection() != 0 {
		return nil, fmt.Errorf("agentgateway cannot translate extProc HTTP/2 stream or request-per-connection limits")
	}
	port := provider.GetPort()
	if port == 0 {
		port = 9002
	}
	if port > 65535 {
		return nil, fmt.Errorf("extProc.port must be between 1 and 65535")
	}
	attributes := map[string]string{
		"source.address":      agentgatewaySourceAddress,
		"destination.address": "string(destination.address)",
		"destination.port":    "destination.port",
	}
	for _, attribute := range provider.GetRequest().GetAttributes() {
		expression, err := agentgatewayExtProcAttribute(attribute, false)
		if err != nil {
			return nil, err
		}
		attributes[attribute] = expression
	}
	responseAttributes := map[string]string{}
	for _, attribute := range provider.GetResponse().GetAttributes() {
		expression, err := agentgatewayExtProcAttribute(attribute, true)
		if err != nil {
			return nil, err
		}
		responseAttributes[attribute] = expression
	}
	failureMode := "failClosed"
	if provider.GetFailureModeAllow() {
		failureMode = "failOpen"
	}
	requestHeaders := "send"
	if provider.GetRequest().GetHeaderMode() == configv1.HeaderSendMode_SKIP {
		requestHeaders = "skip"
	}
	responseHeaders := "skip"
	if provider.GetResponse().GetHeaderMode() == configv1.HeaderSendMode_SEND {
		responseHeaders = "send"
	}
	processor := map[string]any{
		"failureMode":        failureMode,
		"requestAttributes":  attributes,
		"responseAttributes": responseAttributes,
		"processingOptions": map[string]any{
			"requestHeaderMode":   requestHeaders,
			"responseHeaderMode":  responseHeaders,
			"requestBodyMode":     "none",
			"responseBodyMode":    "none",
			"requestTrailerMode":  "skip",
			"responseTrailerMode": "skip",
			"allowModeOverride":   true,
		},
	}
	if ref := provider.GetServiceRef(); ref != nil {
		processor["name"] = ref.GetNamespace() + "/" + agentgatewayProcessorHostname(provider)
		processor["port"] = port
	} else {
		processor["host"] = net.JoinHostPort(provider.GetService(), strconv.Itoa(int(port)))
	}
	return processor, nil
}

func agentgatewayExtProcAttribute(attribute string, response bool) (string, error) {
	if expression, found := agentgatewayWorkloadAttributes[attribute]; found && !response {
		return expression, nil
	}
	switch attribute {
	case "source.address":
		return agentgatewaySourceAddress, nil
	case "destination.address":
		return "string(" + attribute + ")", nil
	case "source.port",
		"destination.port",
		"request.method",
		"request.host",
		"request.path",
		"request.scheme",
		"request.headers":
		return attribute, nil
	case "request.protocol":
		return "request.version", nil
	case "response.code", "response.headers":
		if response {
			return attribute, nil
		}
	}
	return "", fmt.Errorf("agentgateway cannot supply extProc attribute %q", attribute)
}
