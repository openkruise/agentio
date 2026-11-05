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
	"slices"
	"testing"
	"time"

	"istio.io/api/envoy/extensions/stats"

	dynamicfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_modules/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestMetricsFilterSelection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		config    metricConfig
		selection string
		disabled  bool
		invalid   bool
	}{
		{name: "defaults"},
		{name: "disabled", config: metricConfig{Disabled: true}, disabled: true},
		{name: "requests", config: metricConfig{Overrides: []metricsOverride{{Name: "REQUEST_DURATION", Disabled: true}}}, selection: "requests"},
		{name: "duration", config: metricConfig{Overrides: []metricsOverride{{Name: "REQUEST_COUNT", Disabled: true}}}, selection: "duration"},
		{name: "both disabled", config: metricConfig{Overrides: []metricsOverride{{Name: "REQUEST_COUNT", Disabled: true}, {Name: "REQUEST_DURATION", Disabled: true}}}, disabled: true},
		{name: "unsupported metrics ignored", config: metricConfig{Overrides: []metricsOverride{{Name: "REQUEST_SIZE"}, {Name: "TCP_RECEIVED_BYTES", Disabled: true}}}},
		{name: "legacy tag removals", config: metricConfig{Overrides: []metricsOverride{{Name: "REQUEST_COUNT", Tags: []tagOverride{{Name: "source_workload", Remove: true}, {Name: "request_protocol", Remove: true}, {Name: "grpc_response_status", Remove: true}}}}}},
		{name: "unsupported tag", config: metricConfig{Overrides: []metricsOverride{{Name: "REQUEST_COUNT", Tags: []tagOverride{{Name: "tenant", Value: "x"}}}}}, invalid: true},
		{name: "required response flags", config: metricConfig{Overrides: []metricsOverride{{Name: "REQUEST_DURATION", Tags: []tagOverride{{Name: "response_flags", Remove: true}}}}}, invalid: true},
		{name: "required response code", config: metricConfig{Overrides: []metricsOverride{{Name: "REQUEST_COUNT", Tags: []tagOverride{{Name: "response_code", Remove: true}}}}}, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// reportingInterval is TCP-specific; it does not schedule HTTP observations.
			interval := time.Microsecond
			filter, err := buildMetricsFilter(
				metricsConfig{ServerMetrics: tc.config, ReportingInterval: &interval},
				false,
			)
			if (err != nil) != tc.invalid {
				t.Fatalf("error = %v", err)
			}
			if tc.invalid {
				return
			}
			if (filter == nil) != tc.disabled {
				t.Fatalf("filter = %v", filter)
			}
			if filter == nil {
				return
			}
			config := &dynamicfilterv3.DynamicModuleFilter{}
			if err := filter.GetTypedConfig().UnmarshalTo(config); err != nil {
				t.Fatal(err)
			}
			if err := config.ValidateAll(); err != nil {
				t.Fatal(err)
			}
			selection := &wrapperspb.StringValue{}
			if err := config.FilterConfig.UnmarshalTo(selection); err != nil {
				t.Fatal(err)
			}
			modulePath := config.DynamicModuleConfig.GetModule().GetLocal().GetFilename()
			if filter.Name != "envoy.filters.http.dynamic_modules" ||
				config.DynamicModuleConfig.Name != "agentio_gateway_metrics" ||
				config.DynamicModuleConfig.MetricsNamespace != "agentio_gateway" ||
				modulePath != "/usr/local/lib/libagentio_gateway_metrics.so" ||
				config.FilterName != "agentio_gateway_metrics" ||
				selection.Value != tc.selection {
				t.Fatal(config)
			}
		})
	}
}

func TestLegacyMetricsSelection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		overrides []metricsOverride
		requests  bool
		duration  bool
	}{
		{name: "both", requests: true, duration: true},
		{name: "requests", overrides: []metricsOverride{{Name: "REQUEST_DURATION", Disabled: true}}, requests: true},
		{name: "duration", overrides: []metricsOverride{{Name: "REQUEST_COUNT", Disabled: true}}, duration: true},
		{name: "none", overrides: []metricsOverride{{Name: "REQUEST_COUNT", Disabled: true}, {Name: "REQUEST_DURATION", Disabled: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := buildMetricsFilter(metricsConfig{ServerMetrics: metricConfig{Overrides: tc.overrides}}, true)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.requests && !tc.duration {
				if filter != nil {
					t.Fatal("disabled metrics have a filter")
				}
				return
			}
			cfg := &stats.PluginConfig{}
			if filter.Name != "istio.stats" {
				t.Fatal(filter.Name)
			}
			if err := filter.GetTypedConfig().UnmarshalTo(cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.Reporter != stats.Reporter_SERVER_GATEWAY || !cfg.DisableHostHeaderFallback {
				t.Fatal(cfg)
			}
			enabled := map[string]bool{}
			for _, m := range cfg.Metrics {
				if m.Name != "" {
					enabled[m.Name] = !m.Drop
				}
			}
			if enabled["requests_total"] != tc.requests || enabled["request_duration_milliseconds"] != tc.duration {
				t.Fatal(enabled)
			}
			for name, on := range enabled {
				if on && name != "requests_total" && name != "request_duration_milliseconds" {
					t.Fatalf("unexpected metric %s", name)
				}
			}
			removed := cfg.Metrics[0].TagsToRemove
			for _, name := range []string{"reporter", "source_workload", "destination_service", "request_protocol", "grpc_response_status"} {
				if !slices.Contains(removed, name) {
					t.Fatalf("unexpected dimension %s", name)
				}
			}
			for _, name := range []string{"response_code", "response_flags"} {
				if slices.Contains(removed, name) {
					t.Fatalf("required dimension removed: %s", name)
				}
			}
		})
	}
	output, err := Build(Inputs{Gateway: testTelemetryGateway(), RootNamespace: "agentio-system", LegacyGateway: true})
	if err != nil {
		t.Fatal(err)
	}
	if output.HTTPMetrics.GetName() != "istio.stats" || len(output.HTTPAccessLogs) != 1 {
		t.Fatal("legacy metrics and access logs must both be present")
	}
}
