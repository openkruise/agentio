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

package telemetry

import (
	"fmt"
	"sort"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

type Inputs struct {
	LegacyGateway     bool
	Gateway           model.Gateway
	RootNamespace     string
	ClusterID         string
	Telemetry         []model.Telemetry
	ProviderOverrides *model.TelemetryProviderOverrides
}

type Output struct {
	HTTPMetrics    *hcmv3.HttpFilter
	HTTPAccessLogs []*accesslogv3.AccessLog
	// ConnectHTTPAccessLogs mirror release-0.1 HBONE termination access logs:
	// attached to the CONNECT termination HCM, filtered to status >= 400.
	ConnectHTTPAccessLogs []*accesslogv3.AccessLog
	// ListenerAccessLogs cover filter-chain misses and direct TCP denials
	// without duplicating application access logs.
	ListenerAccessLogs []*accesslogv3.AccessLog
	TCPAccessLogs      []*accesslogv3.AccessLog
	Tracing            *hcmv3.HttpConnectionManager_Tracing
	RequestIDExtension *hcmv3.RequestIDExtension
	Clusters           []*clusterv3.Cluster
}

func Build(inputs Inputs) (*Output, error) {
	if err := inputs.Gateway.ValidateForUse(); err != nil {
		return nil, err
	}
	providers, err := resolveTelemetryProviders(
		inputs.ProviderOverrides,
		inputs.Gateway.Config.GetAccessLogFormat(),
		inputs.LegacyGateway,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve Telemetry providers: %w", err)
	}
	selected, err := selectTelemetry(inputs.Gateway, inputs.RootNamespace, inputs.Telemetry)
	if err != nil {
		return nil, err
	}
	result := &Output{}
	usedProviders := map[string]model.TelemetryProvider{}

	metrics := mergeMetrics(selected, providers.DefaultMetrics)
	for _, name := range sortedKeys(metrics) {
		provider, err := requireProvider(providers, name)
		if err != nil {
			return nil, err
		}
		if !provider.Prometheus {
			return nil, fmt.Errorf("Telemetry provider %q does not support metrics", name)
		}
		filter, err := buildMetricsFilter(metrics[name], inputs.LegacyGateway)
		if err != nil {
			return nil, fmt.Errorf("build metrics provider %q: %w", name, err)
		}
		if filter != nil {
			if result.HTTPMetrics != nil {
				return nil, fmt.Errorf("multiple Prometheus providers would duplicate gateway metrics")
			}
			result.HTTPMetrics = filter
			usedProviders[name] = provider.Clone()
		}
	}
	logs := mergeLogs(selected, providers.DefaultAccessLogging)
	for _, name := range sortedKeys(logs) {
		provider, err := requireProvider(providers, name)
		if err != nil {
			return nil, err
		}
		configuration := logs[name]
		if configuration.Disabled {
			continue
		}
		if provider.HTTPAccessLog == nil || provider.TCPAccessLog == nil {
			return nil, fmt.Errorf("Telemetry provider %q does not support HTTP and TCP access logging", name)
		}
		httpLog, err := buildAccessLog(provider.HTTPAccessLog, configuration.Filter)
		if err != nil {
			return nil, fmt.Errorf("build HTTP access-log provider %q: %w", name, err)
		}
		connectLog, err := buildConnectAccessLog(provider.HTTPAccessLog, configuration.Filter)
		if err != nil {
			return nil, fmt.Errorf("build CONNECT access-log provider %q: %w", name, err)
		}
		listenerLog, err := buildListenerAccessLog(provider.TCPAccessLog, configuration.Filter)
		if err != nil {
			return nil, fmt.Errorf("build listener access-log provider %q: %w", name, err)
		}
		tcpLog, err := buildAccessLog(provider.TCPAccessLog, configuration.Filter)
		if err != nil {
			return nil, fmt.Errorf("build TCP access-log provider %q: %w", name, err)
		}
		result.HTTPAccessLogs = append(result.HTTPAccessLogs, httpLog)
		result.ConnectHTTPAccessLogs = append(result.ConnectHTTPAccessLogs, connectLog)
		result.ListenerAccessLogs = append(result.ListenerAccessLogs, listenerLog)
		result.TCPAccessLogs = append(result.TCPAccessLogs, tcpLog)
		usedProviders[name] = provider.Clone()
	}

	tracing := mergeTracing(selected, providers.DefaultTracing)
	if tracing.Provider != "" {
		provider, err := requireProvider(providers, tracing.Provider)
		if err != nil {
			return nil, err
		}
		if provider.Tracing == nil {
			return nil, fmt.Errorf("Telemetry provider %q does not support tracing", tracing.Provider)
		}
		result.Tracing, result.RequestIDExtension, err = buildTracing(
			tracing,
			provider.Tracing,
			inputs.Gateway,
			inputs.ClusterID,
		)
		if err != nil {
			return nil, fmt.Errorf("build tracing provider %q: %w", tracing.Provider, err)
		}
		if result.Tracing != nil {
			usedProviders[tracing.Provider] = provider.Clone()
		}
	}

	clusterNames := sets.New[string]()
	for _, name := range sortedKeys(usedProviders) {
		for _, cluster := range usedProviders[name].Clusters {
			if clusterNames.Contains(cluster.Name) {
				return nil, fmt.Errorf("Telemetry cluster %q is duplicated", cluster.Name)
			}
			clusterNames.Insert(cluster.Name)
			result.Clusters = append(result.Clusters, proto.Clone(cluster).(*clusterv3.Cluster))
		}
	}
	if err := validateTelemetryOutput(result); err != nil {
		return nil, err
	}
	return result, nil
}

func requireProvider(providers model.TelemetryProviders, name string) (model.TelemetryProvider, error) {
	provider := providers.Provider(name)
	if provider == nil {
		return model.TelemetryProvider{}, fmt.Errorf("Telemetry provider %q does not exist", name)
	}
	return provider.Clone(), nil
}

func sortedKeys[V any](values map[string]V) []string {
	result := make([]string, 0, len(values))
	for name := range values {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func validateTelemetryOutput(output *Output) error {
	accessLogs := make(
		[]*accesslogv3.AccessLog,
		0,
		len(
			output.HTTPAccessLogs,
		)+len(
			output.ConnectHTTPAccessLogs,
		)+len(
			output.ListenerAccessLogs,
		)+len(
			output.TCPAccessLogs,
		),
	)
	if output.HTTPMetrics != nil {
		if err := output.HTTPMetrics.ValidateAll(); err != nil {
			return fmt.Errorf("Telemetry metrics filter: %w", err)
		}
	}
	accessLogs = append(accessLogs, output.HTTPAccessLogs...)
	accessLogs = append(accessLogs, output.ConnectHTTPAccessLogs...)
	accessLogs = append(accessLogs, output.ListenerAccessLogs...)
	accessLogs = append(accessLogs, output.TCPAccessLogs...)
	for _, accessLog := range accessLogs {
		if err := accessLog.ValidateAll(); err != nil {
			return fmt.Errorf("Telemetry access log %q: %w", accessLog.Name, err)
		}
	}
	if output.Tracing != nil {
		if err := output.Tracing.ValidateAll(); err != nil {
			return fmt.Errorf("Telemetry tracing: %w", err)
		}
	}
	if output.RequestIDExtension != nil {
		if err := output.RequestIDExtension.ValidateAll(); err != nil {
			return fmt.Errorf("Telemetry request-ID extension: %w", err)
		}
	}
	for _, cluster := range output.Clusters {
		if err := cluster.ValidateAll(); err != nil {
			return fmt.Errorf("Telemetry cluster %q: %w", cluster.Name, err)
		}
	}
	return nil
}
