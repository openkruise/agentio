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

package kubernetes

import (
	"slices"
	"strings"
	"testing"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
)

func TestDecodeTelemetryConvertsAllSignalsAndGatewayTargets(t *testing.T) {
	configMap := telemetryConfigMap("custom-source", `
apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  namespace: demo
  name: gateway-signals
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: z-gateway
  - group: gateway.networking.k8s.io
    kind: Gateway
    namespace: demo
    name: a-gateway
  metrics:
  - providers:
    - name: prometheus
    reportingInterval: 15s
    overrides:
    - match:
        customMetric: request.queue
        mode: SERVER
      disabled: false
      tagOverrides:
        removed:
          operation: REMOVE
        added:
          operation: UPSERT
          value: request.host
  tracing:
  - match:
      mode: SERVER
    providers:
    - name: otel
    randomSamplingPercentage: 12.5
    disableSpanReporting: false
    useRequestIdForTraceSampling: false
    enableIstioTags: true
    customTags:
      literal:
        literal:
          value: fixed
      environment:
        environment:
          name: POD_NAME
          defaultValue: unknown
      header:
        header:
          name: x-request-kind
          defaultValue: missing
      formatter:
        formatter:
          value: '%REQ(:METHOD)%'
  accessLogging:
  - match:
      mode: CLIENT_AND_SERVER
    providers:
    - name: envoy
    disabled: false
    filter:
      expression: response.code >= 500
`)

	got, err := decodeTelemetries(configMap)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("decoded policies = %d, want 1", len(got))
	}
	policy := got[0]
	if got, want := policy.ResourceName(), "agentio-system/custom-source|demo/gateway-signals"; got != want {
		t.Fatalf("ResourceName() = %q, want %q", got, want)
	}
	if want := []string{"demo/a-gateway", "demo/z-gateway"}; !slices.Equal(policy.TargetGateways, want) {
		t.Fatalf("TargetGateways = %v, want %v", policy.TargetGateways, want)
	}
	metric := policy.Metrics[0]
	if metric.ReportingInterval == nil || metric.ReportingInterval.String() != "15s" || len(metric.Overrides) != 1 {
		t.Fatalf("metrics = %+v", metric)
	}
	if match := metric.Overrides[0].Match; match.Kind != model.TelemetryMetricCustom || match.Name != "request.queue" ||
		match.Mode != model.TelemetryModeServer {
		t.Fatalf("metric match = %+v", match)
	}
	if got := metric.Overrides[0].TagOverrides["removed"]; got.Operation != model.TelemetryTagRemove {
		t.Fatalf("removed tag = %+v", got)
	}
	if got := metric.Overrides[0].TagOverrides["added"]; got.Operation != model.TelemetryTagUpsert ||
		got.Value != "request.host" {
		t.Fatalf("added tag = %+v", got)
	}
	trace := policy.Tracing[0]
	if trace.RandomSamplingPercentage == nil || *trace.RandomSamplingPercentage != 12.5 ||
		trace.DisableSpanReporting == nil || *trace.DisableSpanReporting ||
		trace.UseRequestIDForTraceSampling == nil || *trace.UseRequestIDForTraceSampling ||
		trace.EnableIstioTags == nil || !*trace.EnableIstioTags {
		t.Fatalf("tracing presence = %+v", trace)
	}
	for name, kind := range map[string]model.TelemetryTracingTagKind{
		"literal": model.TelemetryTracingTagLiteral, "environment": model.TelemetryTracingTagEnvironment,
		"header": model.TelemetryTracingTagHeader, "formatter": model.TelemetryTracingTagFormatter,
	} {
		if got := trace.CustomTags[name].Kind; got != kind {
			t.Errorf("custom tag %s kind = %v, want %v", name, got, kind)
		}
	}
	logging := policy.AccessLogging[0]
	if logging.Mode != model.TelemetryModeClientAndServer || logging.Filter == nil ||
		*logging.Filter != "response.code >= 500" {
		t.Fatalf("access logging = %+v", logging)
	}
}

func TestDecodeTelemetryChartMetricsOverridesRemovesAllDimensions(t *testing.T) {
	configMap := telemetryConfigMap("chart-source", chartMetricsTelemetryYAML)
	got, err := decodeTelemetries(configMap)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Metrics) != 1 || len(got[0].Metrics[0].Overrides) != 1 {
		t.Fatalf("decoded chart policy = %+v", got)
	}
	override := got[0].Metrics[0].Overrides[0]
	if override.Match.Kind != model.TelemetryMetricAll || override.Match.Mode != model.TelemetryModeClientAndServer {
		t.Fatalf("chart metric match = %+v", override.Match)
	}
	want := []string{
		"connection_security_policy",
		"destination_app",
		"destination_canonical_revision",
		"destination_canonical_service",
		"destination_cluster",
		"destination_namespace",
		"destination_port",
		"destination_principal",
		"destination_service",
		"destination_service_name",
		"destination_service_namespace",
		"destination_version",
		"destination_workload",
		"destination_workload_namespace",
		"reporter",
		"request_operation",
		"source_app",
		"source_canonical_revision",
		"source_canonical_service",
		"source_cluster",
		"source_principal",
		"source_version",
		"source_workload",
		"source_workload_namespace",
	}
	gotNames := make([]string, 0, len(override.TagOverrides))
	for name, operation := range override.TagOverrides {
		gotNames = append(gotNames, name)
		if operation.Operation != model.TelemetryTagRemove || operation.Value != "" {
			t.Errorf("tag %s = %+v, want REMOVE", name, operation)
		}
	}
	slices.Sort(gotNames)
	if !slices.Equal(gotNames, want) {
		t.Fatalf("removed tags = %v, want %v", gotNames, want)
	}
	if len(got[0].TargetGateways) != 0 {
		t.Fatalf("chart targetless policy targets = %v", got[0].TargetGateways)
	}
}

func TestAgentioChartTelemetryCompatibility(t *testing.T) {
	policies, err := decodeTelemetries(telemetryConfigMap("chart-source", chartMetricsTelemetryYAML))
	if err != nil {
		t.Fatal(err)
	}
	resources, err := networking.Build(networking.Inputs{
		Gateway: model.Gateway{
			Namespace: "demo",
			Name:      "egress",
			Source:    model.GatewaySourceAgentioConfig,
			Config:    &configv1.EgressGateway{},
		},
		TelemetryRootNamespace: "agentio-system",
		Telemetry:              policies,
		DiscoveryAddress:       "agentiod.agentio-system.svc:15012",
		TrustDomain:            "cluster.local",
	})
	if err != nil {
		t.Fatal(err)
	}
	listener := new(listenerv3.Listener)
	for _, resource := range resources {
		if resource.Key.TypeURL == model.ListenerType && resource.XDSName == networking.MainForward {
			if err := resource.Value.UnmarshalTo(listener); err != nil {
				t.Fatal(err)
			}
		}
	}
	if listener.Name == "" {
		t.Fatal("MainForward listener not found")
	}
	var connectionManager *hcmv3.HttpConnectionManager
	hasTCPStats := false
	for _, chain := range listener.FilterChains {
		for _, filter := range chain.Filters {
			if filter.Name == "istio.stats" {
				hasTCPStats = true
			}
			if filter.Name == "envoy.filters.network.http_connection_manager" {
				connectionManager = new(hcmv3.HttpConnectionManager)
				if err := filter.GetTypedConfig().UnmarshalTo(connectionManager); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if connectionManager == nil || hasTCPStats {
		t.Fatalf("chart application Telemetry = HCM %v TCP stats %v", connectionManager != nil, hasTCPStats)
	}
	for _, filter := range connectionManager.HttpFilters {
		if filter.Name == "istio.stats" {
			t.Fatal("Istio stats filter remains")
		}
	}
	if connectionManager.HttpFilters[0].Name != "envoy.filters.http.dynamic_modules" ||
		len(connectionManager.AccessLog) != 1 || connectionManager.AccessLog[0].Name != "envoy.access_loggers.file" {
		t.Fatalf(
			"chart native metrics/access logs = %v / %v",
			connectionManager.HttpFilters,
			connectionManager.AccessLog,
		)
	}

}

func TestDecodeTelemetryPreservesOptionalFieldAbsence(t *testing.T) {
	configMap := telemetryConfigMap("optional", `
apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  namespace: demo
  name: optional
spec:
  metrics:
  - overrides:
    - match:
        metric: REQUEST_COUNT
  tracing:
  - providers:
    - name: otel
  accessLogging:
  - providers:
    - name: envoy
`)
	got, err := decodeTelemetries(configMap)
	if err != nil {
		t.Fatal(err)
	}
	metric := got[0].Metrics[0].Overrides[0]
	trace := got[0].Tracing[0]
	logging := got[0].AccessLogging[0]
	if metric.Disabled != nil || trace.RandomSamplingPercentage != nil || trace.DisableSpanReporting != nil ||
		trace.UseRequestIDForTraceSampling != nil || trace.EnableIstioTags != nil || logging.Disabled != nil {
		t.Fatalf("absent wrappers became present: metric=%+v tracing=%+v logging=%+v", metric, trace, logging)
	}
}

func TestDecodeTelemetryReadsMultipleDocumentsAndTargetRefShapes(t *testing.T) {
	configMap := telemetryConfigMap("document-shapes", `
apiVersion: telemetry.istio.io/v1alpha1
kind: Telemetry
metadata:
  namespace: demo
  name: singular
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: egress
  metrics:
  - overrides:
    - disabled: true
---
apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  namespace: demo
  name: plural
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: egress
  tracing:
  - providers:
    - name: trace
  accessLogging:
  - providers:
    - name: envoy
`)

	got, err := decodeTelemetries(configMap)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("decoded Telemetry = %d, want 2: %+v", len(got), got)
	}
	byName := map[string]model.Telemetry{}
	for _, policy := range got {
		byName[policy.Name] = policy
	}
	singular := byName["singular"]
	if !slices.Equal(singular.TargetGateways, []string{"demo/egress"}) ||
		len(singular.Metrics) != 1 || len(singular.Metrics[0].Overrides) != 1 {
		t.Fatalf("singular targetRef Telemetry = %+v", singular)
	}
	metric := singular.Metrics[0].Overrides[0]
	if metric.Match.Kind != model.TelemetryMetricAll || metric.Match.Mode != model.TelemetryModeClientAndServer ||
		metric.Disabled == nil || !*metric.Disabled {
		t.Fatalf("default metric selector = %+v", metric)
	}
	plural := byName["plural"]
	if !slices.Equal(plural.TargetGateways, []string{"demo/egress"}) ||
		len(plural.Tracing) != 1 || plural.Tracing[0].Mode != model.TelemetryModeClientAndServer ||
		len(plural.AccessLogging) != 1 || plural.AccessLogging[0].Mode != model.TelemetryModeClientAndServer {
		t.Fatalf("plural targetRefs Telemetry = %+v", plural)
	}
}

func TestDecodeTelemetryRejectsUnsupportedAttachmentsAndMalformedCEL(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want string
	}{
		{name: "selector", spec: "selector: {}", want: "selector"},
		{
			name: "cross namespace",
			spec: `targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    namespace: other
    name: egress`,
			want: "crosses namespace",
		},
		{
			name: "wrong kind",
			spec: `targetRefs:
  - group: gateway.networking.k8s.io
    kind: GatewayClass
    name: egress`,
			want: "unsupported targetRef",
		},
		{
			name: "both target forms",
			spec: `targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: one
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: two`,
			want: "targetRef and targetRefs",
		},
		{
			name: "invalid CEL",
			spec: `accessLogging:
  - filter:
      expression: 'response.code >'`,
			want: "CEL",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configMap := telemetryConfigMap("invalid", `
apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  namespace: demo
  name: invalid
spec:
  `+tc.spec)
			if _, err := decodeTelemetries(configMap); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("decode error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestTelemetryCollectionUsesAllLabelledConfigMapsAndRetainsPerSourceLastKnownGood(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	configMaps := krt.NewMutableCollection[*corev1.ConfigMap](nil, nil, options...)
	policies := newTelemetriesCollection(configMaps.AsCollection(), "agentio-system", options...)

	first := telemetryConfigMap("first-arbitrary-name", targetlessMetricsTelemetry("demo", "first"))
	first.ResourceVersion = "1"
	second := telemetryConfigMap("second-arbitrary-name", targetlessMetricsTelemetry("other", "second"))
	second.Labels[KubeSourceConfigMapLabel] = "any-value"
	configMaps.ConditionalUpdateObject(first)
	configMaps.ConditionalUpdateObject(second)
	if !policies.WaitUntilSynced(stop) {
		t.Fatal("Telemetry collection did not sync")
	}
	testutil.Eventually(
		t,
		func() bool { return len(policies.List()) == 2 },
		"both labelled ConfigMaps publish Telemetry",
	)

	broken := first.DeepCopy()
	broken.ResourceVersion = "2"
	broken.Data[KubeSourceDataKey] = `
apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  namespace: demo
  name: broken
spec:
  selector: {}`
	configMaps.ConditionalUpdateObject(broken)
	testutil.Eventually(t, func() bool {
		items := policies.List()
		if len(items) != 2 {
			return false
		}
		for _, item := range items {
			if item.Source == "agentio-system/first-arbitrary-name" {
				return item.Name == "first" && item.ResourceVersion == "1"
			}
		}
		return false
	}, "malformed replacement retains only that source's previous Telemetry")

	configMaps.DeleteObject("agentio-system/first-arbitrary-name")
	testutil.Eventually(t, func() bool {
		items := policies.List()
		return len(items) == 1 && items[0].Name == "second"
	}, "deleting one source removes only its Telemetry")
}

func TestTelemetrySemanticErrorDoesNotBlockEnvoyFilterDecoder(t *testing.T) {
	configMap := telemetryConfigMap("mixed", `
apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  namespace: demo
  name: invalid
spec:
  selector: {}
---
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  namespace: demo
  name: valid
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: egress
  configPatches:
  - applyTo: CLUSTER
    patch:
      operation: ADD
      value:
        name: added
`)
	if _, err := decodeTelemetries(configMap); err == nil {
		t.Fatal("invalid Telemetry was accepted")
	}
	filters, err := decodeEnvoyFilters(configMap)
	if err != nil || len(filters) != 1 || filters[0].Name != "valid" {
		t.Fatalf("EnvoyFilter decode = %+v, %v", filters, err)
	}
}

func telemetryConfigMap(name, sources string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      name,
			Labels:    map[string]string{KubeSourceConfigMapLabel: ""},
		},
		Data: map[string]string{KubeSourceDataKey: sources},
	}
}

func targetlessMetricsTelemetry(namespace, name string) string {
	return `
apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  namespace: ` + namespace + `
  name: ` + name + `
spec:
  metrics:
  - providers:
    - name: prometheus
`
}

const chartMetricsTelemetryYAML = `
apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  name: metrics-overrides
  namespace: agentio-system
spec:
  metrics:
  - providers:
    - name: prometheus
    overrides:
    - match:
        metric: ALL_METRICS
      mode: CLIENT_AND_SERVER
      tagOverrides:
        reporter: {operation: REMOVE}
        source_principal: {operation: REMOVE}
        source_app: {operation: REMOVE}
        source_workload: {operation: REMOVE}
        source_workload_namespace: {operation: REMOVE}
        source_version: {operation: REMOVE}
        source_cluster: {operation: REMOVE}
        source_canonical_service: {operation: REMOVE}
        source_canonical_revision: {operation: REMOVE}
        destination_workload: {operation: REMOVE}
        destination_workload_namespace: {operation: REMOVE}
        destination_principal: {operation: REMOVE}
        destination_app: {operation: REMOVE}
        destination_version: {operation: REMOVE}
        destination_service: {operation: REMOVE}
        destination_service_name: {operation: REMOVE}
        destination_service_namespace: {operation: REMOVE}
        destination_namespace: {operation: REMOVE}
        destination_port: {operation: REMOVE}
        destination_cluster: {operation: REMOVE}
        destination_canonical_service: {operation: REMOVE}
        destination_canonical_revision: {operation: REMOVE}
        connection_security_policy: {operation: REMOVE}
        request_operation: {operation: REMOVE}
`
