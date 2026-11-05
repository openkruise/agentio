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
	"strings"
	"testing"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	tracev3 "github.com/envoyproxy/go-control-plane/envoy/config/trace/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/openkruise/agentio/pkg/model"
)

func TestResolveProvidersAppliesPresenceAwareOverrides(t *testing.T) {
	override := &model.TelemetryProviderOverrides{
		Metrics:       model.OptionalProviderNames{Set: true, Names: []string{}},
		Tracing:       model.OptionalProviderNames{Set: true, Names: []string{"trace"}},
		AccessLogging: model.OptionalProviderNames{Set: true, Names: []string{"REMOTE"}},
		Providers: []model.TelemetryProvider{
			{
				Name:          "remote",
				HTTPAccessLog: &accesslogv3.AccessLog{Name: "replacement"},
				TCPAccessLog:  &accesslogv3.AccessLog{Name: "replacement"},
			},
			{Name: "trace", Tracing: testTracingProvider(t)},
		},
		RemoveProviders: []string{"envoy"},
	}
	got, err := resolveTelemetryProviders(override, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.DefaultMetrics == nil || len(got.DefaultMetrics) != 0 {
		t.Fatalf("explicit empty metrics = %#v", got.DefaultMetrics)
	}
	if !slices.Equal(got.DefaultTracing, []string{"trace"}) ||
		!slices.Equal(got.DefaultAccessLogging, []string{"REMOTE"}) {
		t.Fatalf(
			"resolved defaults = metrics:%v tracing:%v logging:%v",
			got.DefaultMetrics,
			got.DefaultTracing,
			got.DefaultAccessLogging,
		)
	}
	if got.Provider("envoy") != nil || got.Provider("ReMoTe") == nil ||
		got.Provider("remote").HTTPAccessLog.GetName() != "replacement" {
		t.Fatalf("resolved providers = %+v", got.Providers)
	}
	if override.Providers[0].HTTPAccessLog.GetName() != "replacement" {
		t.Fatal("ResolveProviders mutated override")
	}
}

func testTracingProvider(t *testing.T) *model.TelemetryTracingProvider {
	t.Helper()
	typed, err := anypb.New(&emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	return &model.TelemetryTracingProvider{Provider: &tracev3.Tracing_Http{
		Name:       "envoy.tracers.test",
		ConfigType: &tracev3.Tracing_Http_TypedConfig{TypedConfig: typed},
	}}
}

func TestResolveProvidersRejectsInvalidOverrides(t *testing.T) {
	tests := []struct {
		name     string
		override model.TelemetryProviderOverrides
		want     string
	}{
		{
			name: "case duplicate",
			override: model.TelemetryProviderOverrides{Providers: []model.TelemetryProvider{
				{Name: "remote", Prometheus: true}, {Name: "REMOTE", Prometheus: true},
			}},
			want: "duplicate",
		},
		{
			name: "unknown default",
			override: model.TelemetryProviderOverrides{
				Tracing: model.OptionalProviderNames{Set: true, Names: []string{"missing"}},
			},
			want: "missing",
		},
		{
			name:     "removed default",
			override: model.TelemetryProviderOverrides{RemoveProviders: []string{"prometheus"}},
			want:     "prometheus",
		},
		{
			name: "duplicate cluster",
			override: model.TelemetryProviderOverrides{Providers: []model.TelemetryProvider{{
				Name:          "remote",
				HTTPAccessLog: &accesslogv3.AccessLog{Name: "remote"},
				Clusters:      []*clusterv3.Cluster{{Name: "same"}, {Name: "same"}},
			}}},
			want: "cluster",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolveTelemetryProviders(
				&tc.override,
				nil,
				false,
			); err == nil ||
				!strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("ResolveProviders error = %v, want containing %q", err, tc.want)
			}
		})
	}
}
