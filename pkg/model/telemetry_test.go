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

package model

import (
	"slices"
	"testing"
	"time"
)

func TestNewTelemetryNormalizesExactGatewayTargets(t *testing.T) {
	metadata := TelemetryMetadata{
		Namespace: "demo",
		Name:      "gateway",
		Source:    "agentio-system/source-one",
	}
	if policy, err := NewTelemetry(metadata, []string{"demo/z", "demo/a", "demo/z"}, nil, nil, nil); err == nil {
		t.Fatalf("duplicate targets produced policy %+v, want rejection", policy)
	}

	targets := []string{"demo/z", "demo/a"}
	policy, err := NewTelemetry(metadata, targets, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	targets[0] = "mutated/value"
	if got, want := policy.TargetGateways, []string{"demo/a", "demo/z"}; !slices.Equal(got, want) {
		t.Fatalf("TargetGateways = %v, want %v", got, want)
	}
	if got, want := policy.ResourceName(), "agentio-system/source-one|demo/gateway"; got != want {
		t.Fatalf("ResourceName() = %q, want %q", got, want)
	}
	if got, want := policy.LogicalName(), "demo/gateway"; got != want {
		t.Fatalf("LogicalName() = %q, want %q", got, want)
	}
}

func TestNewTelemetryRejectsInvalidNestedConfiguration(t *testing.T) {
	metadata := TelemetryMetadata{Namespace: "demo", Name: "gateway", Source: "agentio-system/source"}
	trueValue := true
	interval := -time.Second
	tests := []struct {
		name    string
		metrics []TelemetryMetrics
		tracing []TelemetryTracing
		logging []TelemetryAccessLogging
	}{
		{
			name: "invalid mode",
			metrics: []TelemetryMetrics{{Overrides: []TelemetryMetricOverride{{
				Match: TelemetryMetricSelector{Kind: TelemetryMetricAll, Mode: TelemetryMode(99)},
			}}}},
		},
		{
			name:    "negative reporting interval",
			metrics: []TelemetryMetrics{{ReportingInterval: &interval}},
		},
		{
			name: "upsert without value",
			metrics: []TelemetryMetrics{{Overrides: []TelemetryMetricOverride{{
				Match: TelemetryMetricSelector{Kind: TelemetryMetricAll, Mode: TelemetryModeClientAndServer},
				TagOverrides: map[string]TelemetryMetricTagOverride{
					"destination": {Operation: TelemetryTagUpsert},
				},
			}}}},
		},
		{
			name: "custom metric without name",
			metrics: []TelemetryMetrics{{Overrides: []TelemetryMetricOverride{{
				Match:    TelemetryMetricSelector{Kind: TelemetryMetricCustom, Mode: TelemetryModeServer},
				Disabled: &trueValue,
			}}}},
		},
		{
			name: "invalid tracing tag",
			tracing: []TelemetryTracing{{
				Mode: TelemetryModeServer,
				CustomTags: map[string]TelemetryTracingTag{
					"broken": {Kind: TelemetryTracingTagEnvironment},
				},
			}},
		},
		{
			name:    "empty access log filter",
			logging: []TelemetryAccessLogging{{Mode: TelemetryModeServer, Filter: stringPointer("")}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if policy, err := NewTelemetry(metadata, nil, tc.metrics, tc.tracing, tc.logging); err == nil {
				t.Fatalf("invalid configuration produced policy %+v", policy)
			}
		})
	}
}

func TestTelemetryOwnsNestedMutableValues(t *testing.T) {
	metadata := TelemetryMetadata{Namespace: "demo", Name: "gateway", Source: "agentio-system/source"}
	remove := TelemetryMetricTagOverride{Operation: TelemetryTagRemove}
	metrics := []TelemetryMetrics{{
		Providers: []string{"prometheus"},
		Overrides: []TelemetryMetricOverride{{
			Match:        TelemetryMetricSelector{Kind: TelemetryMetricAll, Mode: TelemetryModeClientAndServer},
			TagOverrides: map[string]TelemetryMetricTagOverride{"source": remove},
		}},
	}}
	tracing := []TelemetryTracing{{
		Mode: TelemetryModeServer,
		CustomTags: map[string]TelemetryTracingTag{
			"literal": {Kind: TelemetryTracingTagLiteral, Value: "original"},
		},
	}}
	policy, err := NewTelemetry(metadata, nil, metrics, tracing, nil)
	if err != nil {
		t.Fatal(err)
	}

	metrics[0].Providers[0] = "changed"
	metrics[0].Overrides[0].TagOverrides["source"] = TelemetryMetricTagOverride{Operation: TelemetryTagUpsert, Value: "changed"}
	tracing[0].CustomTags["literal"] = TelemetryTracingTag{Kind: TelemetryTracingTagLiteral, Value: "changed"}

	if got := policy.Metrics[0].Providers[0]; got != "prometheus" {
		t.Fatalf("provider alias mutated to %q", got)
	}
	if got := policy.Metrics[0].Overrides[0].TagOverrides["source"]; got != remove {
		t.Fatalf("tag override alias mutated to %+v", got)
	}
	if got := policy.Tracing[0].CustomTags["literal"].Value; got != "original" {
		t.Fatalf("tracing tag alias mutated to %q", got)
	}

	clone := policy.Clone()
	clone.Metrics[0].Providers[0] = "clone-change"
	if policy.Metrics[0].Providers[0] != "prometheus" {
		t.Fatal("Clone shares provider storage")
	}
	if !policy.Equals(policy.Clone()) {
		t.Fatal("policy does not equal an independent clone")
	}
}

func stringPointer(value string) *string { return &value }
