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
	"reflect"
	"testing"

	"github.com/openkruise/agentio/pkg/model"
)

// These vectors cover only the egress Gateway server view. Selector, sidecar,
// and service-attachment cases are outside this package's contract.

func TestAgentioMetricsMergeVectors(t *testing.T) {
	disabled := true
	enabled := false
	allServerDisabled := model.TelemetryMetricOverride{
		Match:    model.TelemetryMetricSelector{Kind: model.TelemetryMetricAll, Mode: model.TelemetryModeServer},
		Disabled: &disabled,
	}
	requestCountEnabled := model.TelemetryMetricOverride{
		Match:    model.TelemetryMetricSelector{Kind: model.TelemetryMetricStandard, Name: "REQUEST_COUNT", Mode: model.TelemetryModeServer},
		Disabled: &enabled,
	}

	tests := []struct {
		name     string
		policies []model.Telemetry
		defaults []string
		want     map[string]metricsConfig
	}{
		{
			name: "no metrics provider",
			want: map[string]metricsConfig{},
		},
		{
			name:     "default provider",
			defaults: []string{"prometheus"},
			want:     map[string]metricsConfig{"prometheus": {}},
		},
		{
			name: "explicit provider without defaults",
			policies: []model.Telemetry{{Metrics: []model.TelemetryMetrics{{
				Providers: []string{"prometheus"},
			}}}},
			want: map[string]metricsConfig{"prometheus": {
				ClientMetrics: metricConfig{},
				ServerMetrics: metricConfig{},
			}},
		},
		{
			name: "server disable does not affect client",
			policies: []model.Telemetry{{Metrics: []model.TelemetryMetrics{{
				Providers: []string{"prometheus"},
				Overrides: []model.TelemetryMetricOverride{allServerDisabled},
			}}}},
			defaults: []string{"prometheus"},
			want: map[string]metricsConfig{"prometheus": {
				ClientMetrics: metricConfig{},
				ServerMetrics: metricConfig{Disabled: true},
			}},
		},
		{
			name: "later specific override re-enables a disabled mode",
			policies: []model.Telemetry{
				{Metrics: []model.TelemetryMetrics{{Providers: []string{"prometheus"}, Overrides: []model.TelemetryMetricOverride{allServerDisabled}}}},
				{Metrics: []model.TelemetryMetrics{{Overrides: []model.TelemetryMetricOverride{requestCountEnabled}}}},
			},
			defaults: []string{"prometheus"},
			want: map[string]metricsConfig{"prometheus": {
				ClientMetrics: metricConfig{},
				ServerMetrics: metricConfig{Overrides: []metricsOverride{{Name: "REQUEST_COUNT", Tags: []tagOverride{}}}},
			}},
		},
		{
			name: "empty child inherits provider",
			policies: []model.Telemetry{
				{Metrics: []model.TelemetryMetrics{{Providers: []string{"root"}}}},
				{Metrics: []model.TelemetryMetrics{{}}},
			},
			defaults: []string{"default"},
			want: map[string]metricsConfig{"root": {
				ClientMetrics: metricConfig{},
				ServerMetrics: metricConfig{},
			}},
		},
		{
			name: "child provider replaces parent provider set",
			policies: []model.Telemetry{
				{Metrics: []model.TelemetryMetrics{{Providers: []string{"root"}, Overrides: []model.TelemetryMetricOverride{allServerDisabled}}}},
				{Metrics: []model.TelemetryMetrics{{Providers: []string{"child"}}}},
			},
			defaults: []string{"default"},
			want: map[string]metricsConfig{"child": {
				ClientMetrics: metricConfig{},
				ServerMetrics: metricConfig{},
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mergeMetrics(tc.policies, tc.defaults); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("mergeMetrics() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestAgentioAccessLoggingMergeVectors(t *testing.T) {
	disabled := true
	enabled := false
	serverError := "response.code >= 500"
	serverFailure := "response.code >= 400"

	tests := []struct {
		name     string
		policies []model.Telemetry
		defaults []string
		want     map[string]loggingSpec
	}{
		{
			name:     "default provider",
			defaults: []string{"envoy"},
			want:     map[string]loggingSpec{"envoy": {}},
		},
		{
			name: "explicit provider replaces default",
			policies: []model.Telemetry{{AccessLogging: []model.TelemetryAccessLogging{{
				Mode:      model.TelemetryModeServer,
				Providers: []string{"json"},
			}}}},
			defaults: []string{"envoy"},
			want:     map[string]loggingSpec{"json": {}},
		},
		{
			name: "empty child inherits provider",
			policies: []model.Telemetry{
				{AccessLogging: []model.TelemetryAccessLogging{{Mode: model.TelemetryModeServer, Providers: []string{"json"}}}},
				{AccessLogging: []model.TelemetryAccessLogging{{Mode: model.TelemetryModeServer}}},
			},
			defaults: []string{"envoy"},
			want:     map[string]loggingSpec{"json": {}},
		},
		{
			name: "disable then enable",
			policies: []model.Telemetry{
				{AccessLogging: []model.TelemetryAccessLogging{{Mode: model.TelemetryModeServer, Disabled: &disabled}}},
				{AccessLogging: []model.TelemetryAccessLogging{{Mode: model.TelemetryModeServer, Disabled: &enabled}}},
			},
			defaults: []string{"envoy"},
			want:     map[string]loggingSpec{"envoy": {}},
		},
		{
			name: "multiple providers retain independent disabled state",
			policies: []model.Telemetry{{AccessLogging: []model.TelemetryAccessLogging{
				{Mode: model.TelemetryModeServer, Providers: []string{"envoy"}},
				{Mode: model.TelemetryModeServer, Providers: []string{"json"}, Disabled: &disabled},
			}}},
			want: map[string]loggingSpec{"envoy": {}, "json": {Disabled: true}},
		},
		{
			name: "last filter wins",
			policies: []model.Telemetry{{AccessLogging: []model.TelemetryAccessLogging{
				{Mode: model.TelemetryModeServer, Providers: []string{"envoy"}, Filter: &serverError},
				{Mode: model.TelemetryModeServer, Providers: []string{"envoy"}, Filter: &serverFailure},
			}}},
			want: map[string]loggingSpec{"envoy": {Filter: &serverFailure}},
		},
		{
			name: "last nil filter clears parent filter",
			policies: []model.Telemetry{
				{AccessLogging: []model.TelemetryAccessLogging{{Mode: model.TelemetryModeServer, Providers: []string{"envoy"}, Filter: &serverError}}},
				{AccessLogging: []model.TelemetryAccessLogging{{Mode: model.TelemetryModeServer}}},
			},
			want: map[string]loggingSpec{"envoy": {}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mergeLogs(tc.policies, tc.defaults); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("mergeLogs() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestAgentioTracingMergeVectors(t *testing.T) {
	disabled := true
	enabled := false
	sampling := 80.0
	clientSampling := 99.9
	requestID := false

	tests := []struct {
		name     string
		policies []model.Telemetry
		defaults []string
		want     tracingSpec
	}{
		{
			name:     "default provider",
			defaults: []string{"zipkin"},
			want: tracingSpec{
				Provider:                     "zipkin",
				UseRequestIDForTraceSampling: true,
				EnableIstioTags:              true,
			},
		},
		{
			name: "first explicit provider replaces default",
			policies: []model.Telemetry{{Tracing: []model.TelemetryTracing{{
				Mode:      model.TelemetryModeServer,
				Providers: []string{"otel", "ignored"},
			}}}},
			defaults: []string{"zipkin"},
			want: tracingSpec{
				Provider:                     "otel",
				UseRequestIDForTraceSampling: true,
				EnableIstioTags:              true,
			},
		},
		{
			name: "empty child inherits provider",
			policies: []model.Telemetry{
				{Tracing: []model.TelemetryTracing{{Mode: model.TelemetryModeServer, Providers: []string{"otel"}}}},
				{Tracing: []model.TelemetryTracing{{Mode: model.TelemetryModeServer}}},
			},
			want: tracingSpec{
				Provider:                     "otel",
				UseRequestIDForTraceSampling: true,
				EnableIstioTags:              true,
			},
		},
		{
			name: "disable then enable",
			policies: []model.Telemetry{
				{Tracing: []model.TelemetryTracing{{Mode: model.TelemetryModeServer, DisableSpanReporting: &disabled}}},
				{Tracing: []model.TelemetryTracing{{Mode: model.TelemetryModeServer, DisableSpanReporting: &enabled}}},
			},
			defaults: []string{"zipkin"},
			want: tracingSpec{
				Provider:                     "zipkin",
				UseRequestIDForTraceSampling: true,
				EnableIstioTags:              true,
			},
		},
		{
			name: "later custom tags replace rather than merge",
			policies: []model.Telemetry{
				{Tracing: []model.TelemetryTracing{{
					Mode: model.TelemetryModeServer,
					CustomTags: map[string]model.TelemetryTracingTag{
						"root": {Kind: model.TelemetryTracingTagLiteral, Value: "root"},
					},
				}}},
				{Tracing: []model.TelemetryTracing{{
					Mode:                         model.TelemetryModeServer,
					RandomSamplingPercentage:     &sampling,
					UseRequestIDForTraceSampling: &requestID,
					CustomTags: map[string]model.TelemetryTracingTag{
						"child": {Kind: model.TelemetryTracingTagLiteral, Value: "child"},
					},
				}}},
			},
			defaults: []string{"zipkin"},
			want: tracingSpec{
				Provider:                 "zipkin",
				RandomSamplingPercentage: &sampling,
				CustomTags: map[string]model.TelemetryTracingTag{
					"child": {Kind: model.TelemetryTracingTagLiteral, Value: "child"},
				},
				UseRequestIDForTraceSampling: false,
				EnableIstioTags:              true,
			},
		},
		{
			name: "client-only override does not alter server",
			policies: []model.Telemetry{{Tracing: []model.TelemetryTracing{{
				Mode:                     model.TelemetryModeClient,
				Providers:                []string{"client"},
				RandomSamplingPercentage: &clientSampling,
			}}}},
			defaults: []string{"zipkin"},
			want: tracingSpec{
				Provider:                     "zipkin",
				UseRequestIDForTraceSampling: true,
				EnableIstioTags:              true,
			},
		},
		{
			name:     "missing provider disables tracing",
			policies: []model.Telemetry{{Tracing: []model.TelemetryTracing{{Mode: model.TelemetryModeServer}}}},
			want: tracingSpec{
				Disabled:                     true,
				UseRequestIDForTraceSampling: true,
				EnableIstioTags:              true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mergeTracing(tc.policies, tc.defaults); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("mergeTracing() = %#v, want %#v", got, tc.want)
			}
		})
	}
}
