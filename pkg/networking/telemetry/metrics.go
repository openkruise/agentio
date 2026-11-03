// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	dynamicmodulesv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/dynamic_modules/v3"
	dynamicfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_modules/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"istio.io/api/envoy/extensions/stats"

	"github.com/openkruise/agentio/pkg/util/protoutil"
)

func buildMetricsFilter(configuration metricsConfig, legacy bool) (*hcmv3.HttpFilter, error) {
	if configuration.ServerMetrics.Disabled {
		return nil, nil
	}
	requests, duration := true, true
	for _, override := range configuration.ServerMetrics.Overrides {
		switch override.Name {
		case "REQUEST_COUNT":
			requests = !override.Disabled
		case "REQUEST_DURATION":
			duration = !override.Disabled
		default:
			continue
		}
		if override.Disabled {
			continue
		}
		for _, tag := range override.Tags {
			if !tag.Remove || tag.Name == "response_code" || tag.Name == "response_flags" {
				return nil, fmt.Errorf("metric %s does not support overriding dimension %s", override.Name, tag.Name)
			}
		}
	}
	if !requests && !duration {
		return nil, nil
	}
	if legacy {
		return buildLegacyMetricsFilter(requests, duration)
	}
	selection := ""
	if !duration {
		selection = "requests"
	} else if !requests {
		selection = "duration"
	}
	config, err := protoutil.MarshalAny(wrapperspb.String(selection))
	if err != nil {
		return nil, err
	}
	typed, err := protoutil.MarshalAny(&dynamicfilterv3.DynamicModuleFilter{
		DynamicModuleConfig: &dynamicmodulesv3.DynamicModuleConfig{
			Name:             "agentio_gateway_metrics",
			MetricsNamespace: "agentio_gateway",
			Module: &corev3.AsyncDataSource{Specifier: &corev3.AsyncDataSource_Local{
				Local: &corev3.DataSource{Specifier: &corev3.DataSource_Filename{
					Filename: "/usr/local/lib/libagentio_gateway_metrics.so",
				}},
			}},
		},
		FilterName:   "agentio_gateway_metrics",
		FilterConfig: config,
	})
	if err != nil {
		return nil, err
	}
	return &hcmv3.HttpFilter{
		Name:       "envoy.filters.http.dynamic_modules",
		ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: typed},
	}, nil
}

// Keep the legacy Istio extension on the same two-metric, two-dimension contract.
func buildLegacyMetricsFilter(requests, duration bool) (*hcmv3.HttpFilter, error) {
	config := &stats.PluginConfig{
		DisableHostHeaderFallback: true,
		Reporter:                  stats.Reporter_SERVER_GATEWAY,
		Metrics: []*stats.MetricConfig{
			{TagsToRemove: []string{
				"reporter",
				"source_principal",
				"source_app",
				"source_workload",
				"source_workload_namespace",
				"source_version",
				"source_cluster",
				"source_canonical_service",
				"source_canonical_revision",
				"destination_workload",
				"destination_workload_namespace",
				"destination_principal",
				"destination_app",
				"destination_version",
				"destination_service",
				"destination_service_name",
				"destination_service_namespace",
				"destination_namespace",
				"destination_port",
				"destination_cluster",
				"destination_canonical_service",
				"destination_canonical_revision",
				"connection_security_policy",
				"request_operation",
				"request_protocol",
				"grpc_response_status",
			}},
			{Name: "requests_total", Drop: !requests},
			{Name: "request_duration_milliseconds", Drop: !duration},
		},
	}
	for _, name := range []string{
		"request_bytes", "response_bytes", "request_messages_total", "response_messages_total",
		"tcp_connections_opened_total", "tcp_connections_closed_total", "tcp_received_bytes_total", "tcp_sent_bytes_total",
	} {
		config.Metrics = append(config.Metrics, &stats.MetricConfig{Name: name, Drop: true})
	}
	typed, err := protoutil.MarshalAny(config)
	if err != nil {
		return nil, err
	}
	return &hcmv3.HttpFilter{Name: "istio.stats", ConfigType: &hcmv3.HttpFilter_TypedConfig{TypedConfig: typed}}, nil
}
