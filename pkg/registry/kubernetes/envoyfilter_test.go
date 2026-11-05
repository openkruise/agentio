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
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	dfpclusterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	dfphttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestDecodeConfigMapEnvoyFiltersTargetsGatewayAndSkipsUnknownKinds(t *testing.T) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "istio-system",
			Name:            "config-sources",
			ResourceVersion: "17",
			Labels:          map[string]string{KubeSourceConfigMapLabel: "true"},
		},
		Data: map[string]string{KubeSourceDataKey: `
apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  name: ignored
  namespace: istio-system
spec: {}
---
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: gateway-patch
  namespace: demo
spec:
  priority: -10
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: egress
  configPatches:
  - applyTo: CLUSTER
    match:
      context: GATEWAY
      cluster:
        name: main_forward
    patch:
      operation: MERGE
      value:
        altStatName: patched
`},
	}

	got, err := decodeEnvoyFilters(configMap)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("decoded filters = %d, want 1", len(got))
	}
	filter := got[0]
	if filter.LogicalName() != "demo/gateway-patch" || filter.ResourceVersion != "17" || filter.Priority != -10 {
		t.Fatalf("decoded filter = %+v", filter)
	}
	if !slices.Equal(filter.TargetGateways, []string{"demo/egress"}) {
		t.Fatalf("targets = %v", filter.TargetGateways)
	}
	patch := filter.Patches[0]
	cluster, ok := patch.Target.(model.ClusterPatch)
	if !ok || patch.Operation != model.PatchMerge || cluster.Value.GetAltStatName() != "patched" {
		t.Fatalf("patch = %+v", patch)
	}
}

func TestDecodeConfigMapEnvoyFiltersReadsMultipleDocuments(t *testing.T) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "istio-system",
			Name:      "config-sources",
			Labels:    map[string]string{KubeSourceConfigMapLabel: ""},
		},
		Data: map[string]string{KubeSourceDataKey: `
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: first
  namespace: demo
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
        name: first
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: ignored
---
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: second
  namespace: demo
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
        name: second
`},
	}

	got, err := decodeEnvoyFilters(configMap)
	if err != nil || len(got) != 2 || got[0].Name != "first" || got[1].Name != "second" {
		t.Fatalf("decode = %+v, %v", got, err)
	}
}

func TestDecodeConfigMapEnvoyFiltersRejectsMalformedRecognizedDocument(t *testing.T) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "istio-system",
			Name:      "config-sources",
			Labels:    map[string]string{KubeSourceConfigMapLabel: "true"},
		},
		Data: map[string]string{KubeSourceDataKey: `
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: broken
  namespace: demo
spec:
  priority: not-an-integer
`},
	}

	if _, err := decodeEnvoyFilters(configMap); err == nil {
		t.Fatal("malformed EnvoyFilter accepted")
	}
}

func TestDecodeConfigMapEnvoyFiltersReturnsValidDocumentsWithPartialError(t *testing.T) {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "istio-system",
			Name:      "config-sources",
			Labels:    map[string]string{KubeSourceConfigMapLabel: "true"},
		},
		Data: map[string]string{KubeSourceDataKey: `
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: valid
  namespace: demo
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
        name: valid
---
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: broken
  namespace: demo
spec:
  priority: not-an-integer
`},
	}

	got, err := decodeEnvoyFilters(configMap)
	if err == nil {
		t.Fatal("partial parse did not report the malformed EnvoyFilter")
	}
	if len(got) != 1 || got[0].Name != "valid" {
		t.Fatalf("partial decode = %+v, want valid document", got)
	}
}

func TestEnvoyFilterCollectionUsesRootNamespaceAndRetainsLastKnownGood(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	configMaps := krt.NewMutableCollection[*corev1.ConfigMap](nil, nil, options...)
	filters := newGatewayPatchesCollection(configMaps.AsCollection(), "agentio-system", options...)
	waitForUpdates := patchUpdateBarrier(t, configMaps, filters)

	valid := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "agentio-system",
			Name:            "config-sources",
			ResourceVersion: "1",
			Labels:          map[string]string{KubeSourceConfigMapLabel: ""},
		},
		Data: map[string]string{KubeSourceDataKey: `
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  namespace: demo
  name: egress-patch
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
        name: egress-patch
`},
	}
	configMaps.ConditionalUpdateObject(valid)
	if !filters.WaitUntilSynced(stop) {
		t.Fatal("EnvoyFilter collection did not sync")
	}
	testutil.Eventually(t, func() bool {
		items := filters.List()
		return len(items) == 1 && items[0].ResourceVersion == "1"
	}, "valid EnvoyFilter is published")

	outside := valid.DeepCopy()
	outside.Namespace = "other-system"
	outside.Name = "ignored"
	configMaps.ConditionalUpdateObject(outside)
	broken := valid.DeepCopy()
	broken.ResourceVersion = "2"
	broken.Data[KubeSourceDataKey] = `
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  namespace: demo
  name: new-valid-document
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
        name: new-valid-document
---
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  namespace: demo
  name: broken-document
spec:
  priority: not-an-integer
`
	configMaps.ConditionalUpdateObject(broken)
	waitForUpdates()
	if items := patchesFromSource(
		filters,
		"agentio-system/config-sources",
	); len(items) != 1 ||
		items[0].ResourceVersion != "1" {
		t.Fatalf("partially malformed replacement changed last-known-good patches: %#v", items)
	}
	if items := patchesFromSource(filters, "other-system/ignored"); len(items) != 0 {
		t.Fatalf("non-root patches were selected: %#v", items)
	}

	configMaps.DeleteObject("agentio-system/config-sources")
	waitForUpdates()
	if items := patchesFromSource(filters, "agentio-system/config-sources"); len(items) != 0 {
		t.Fatalf("deleting the source retained its EnvoyFilters: %#v", items)
	}
}

func TestDecodeDeployedIPv4DynamicForwardProxyEnvoyFilter(t *testing.T) {
	configMap := deployedEnvoyFilterConfigMap(`
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: egress-gateway-dfp-ipv4-only
  namespace: sandbox-traffic-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: egress-gateway
  configPatches:
  - applyTo: CLUSTER
    match:
      context: SIDECAR_INBOUND
      cluster:
        name: tls_connect_originate
    patch:
      operation: MERGE
      value:
        cluster_type:
          name: envoy.clusters.dynamic_forward_proxy
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
            dns_cache_config:
              name: agentio_dns_cache
              dns_lookup_family: V4_ONLY
  - applyTo: HTTP_FILTER
    match:
      context: SIDECAR_INBOUND
      listener:
        filterChain:
          filter:
            name: envoy.filters.network.http_connection_manager
            subFilter:
              name: envoy.filters.http.dynamic_forward_proxy
    patch:
      operation: MERGE
      value:
        name: envoy.filters.http.dynamic_forward_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
          dns_cache_config:
            name: agentio_dns_cache
            dns_lookup_family: V4_ONLY
`)

	got, err := decodeEnvoyFilters(configMap)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Patches) != 2 {
		t.Fatalf("decoded policies = %+v", got)
	}
	if !slices.Equal(got[0].TargetGateways, []string{"sandbox-traffic-system/egress-gateway"}) {
		t.Fatalf("targets = %v", got[0].TargetGateways)
	}
	clusterPatch, ok := got[0].Patches[0].Target.(model.ClusterPatch)
	if !ok || got[0].Patches[0].Operation != model.PatchMerge || clusterPatch.Match.Name != "tls_connect_originate" {
		t.Fatalf("cluster patch = %+v", got[0].Patches[0])
	}
	clusterConfig := &dfpclusterv3.ClusterConfig{}
	if err := clusterPatch.Value.GetClusterType().GetTypedConfig().UnmarshalTo(clusterConfig); err != nil {
		t.Fatal(err)
	}
	if cache := clusterConfig.GetDnsCacheConfig(); cache.GetName() != "agentio_dns_cache" ||
		cache.GetDnsLookupFamily() != clusterv3.Cluster_V4_ONLY {
		t.Fatalf("cluster DNS cache = %+v", cache)
	}

	httpPatch, ok := got[0].Patches[1].Target.(model.HTTPFilterPatch)
	if !ok || got[0].Patches[1].Operation != model.PatchMerge ||
		httpPatch.Match.FilterChain.Filter.SubFilter.Name != "envoy.filters.http.dynamic_forward_proxy" {
		t.Fatalf("HTTP patch = %+v", got[0].Patches[1])
	}
	httpConfig := &dfphttpv3.FilterConfig{}
	if err := httpPatch.Value.GetTypedConfig().UnmarshalTo(httpConfig); err != nil {
		t.Fatal(err)
	}
	if cache := httpConfig.GetDnsCacheConfig(); cache.GetName() != "agentio_dns_cache" ||
		cache.GetDnsLookupFamily() != clusterv3.Cluster_V4_ONLY {
		t.Fatalf("HTTP DNS cache = %+v", cache)
	}
}

func TestDecodeDeployedSandboxConnectEnvoyFilter(t *testing.T) {
	configMap := deployedEnvoyFilterConfigMap(`
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: enable-sandbox-connect
  namespace: sandbox-traffic-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: egress-gateway
  configPatches:
  - applyTo: HTTP_ROUTE
    match:
      context: SIDECAR_INBOUND
      routeConfiguration:
        name: PassthroughCluster
        vhost:
          route:
            name: default
    patch:
      operation: INSERT_BEFORE
      value:
        name: sandbox-connect
        match:
          connect_matcher: {}
        route:
          cluster: PassthroughCluster
          timeout: 0s
          upgrade_configs:
          - upgrade_type: CONNECT
            connect_config: {}
`)

	got, err := decodeEnvoyFilters(configMap)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Patches) != 1 {
		t.Fatalf("decoded policies = %+v", got)
	}
	patch := got[0].Patches[0]
	routePatch, ok := patch.Target.(model.HTTPRoutePatch)
	if !ok || patch.Operation != model.PatchInsertBefore {
		t.Fatalf("route patch = %+v", patch)
	}
	if routePatch.Match.Name != "http_dynamic_forward_proxy" || routePatch.Match.VirtualHost.Route.Name != "default" {
		t.Fatalf("route match = %+v", routePatch.Match)
	}
	route := routePatch.Value
	if route.GetName() != "sandbox-connect" || route.GetMatch().GetConnectMatcher() == nil ||
		route.GetRoute().GetCluster() != "PassthroughCluster" || route.GetRoute().GetTimeout().AsDuration() != 0 ||
		len(
			route.GetRoute().GetUpgradeConfigs(),
		) != 1 || route.GetRoute().GetUpgradeConfigs()[0].GetUpgradeType() != "CONNECT" ||
		route.GetRoute().GetUpgradeConfigs()[0].GetConnectConfig() == nil {
		t.Fatalf("inserted route = %+v", route)
	}
}

func TestDecodeEnvoyFilterAcceptsExplicitSameNamespaceTargetAndInboundContext(t *testing.T) {
	configMap := deployedEnvoyFilterConfigMap(`
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: explicit-namespace
  namespace: sandbox-traffic-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: egress-gateway
    namespace: sandbox-traffic-system
  configPatches:
  - applyTo: CLUSTER
    match:
      context: SIDECAR_INBOUND
      cluster:
        name: tls_connect_originate
    patch:
      operation: MERGE
      value:
        alt_stat_name: patched
`)
	got, err := decodeEnvoyFilters(configMap)
	if err != nil || len(got) != 1 ||
		!slices.Equal(got[0].TargetGateways, []string{"sandbox-traffic-system/egress-gateway"}) {
		t.Fatalf("decode = %+v, %v", got, err)
	}
}

func TestDecodeEnvoyFilterRejectsInvalidTargetOrApplyToMatch(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "CLUSTER with listener match",
			yaml: `
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: mismatch
  namespace: sandbox-traffic-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: egress-gateway
  configPatches:
  - applyTo: CLUSTER
    match:
      context: SIDECAR_INBOUND
      listener:
        name: main_forward
    patch:
      operation: MERGE
      value:
        alt_stat_name: must-not-match-all
`,
		},
		{
			name: "cross namespace target",
			yaml: `
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: cross-namespace
  namespace: sandbox-traffic-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: egress-gateway
    namespace: other-system
  configPatches:
  - applyTo: CLUSTER
    patch:
      operation: ADD
      value:
        name: must-not-attach
`,
		},
		{
			name: "EXTENSION_CONFIG with cluster match",
			yaml: `
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: extension-mismatch
  namespace: sandbox-traffic-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: egress-gateway
  configPatches:
  - applyTo: EXTENSION_CONFIG
    match:
      context: SIDECAR_INBOUND
      cluster:
        name: must-not-be-discarded
    patch:
      operation: ADD
      value:
        name: must-not-be-added
        typed_config:
          "@type": type.googleapis.com/google.protobuf.Empty
`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeEnvoyFilters(deployedEnvoyFilterConfigMap(tc.yaml)); err == nil {
				t.Fatal("invalid EnvoyFilter accepted")
			}
		})
	}
}

func TestDecodeEnvoyFilterIgnoresSidecarOutboundContext(t *testing.T) {
	configMap := deployedEnvoyFilterConfigMap(`
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: outbound
  namespace: sandbox-traffic-system
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: egress-gateway
  configPatches:
  - applyTo: CLUSTER
    match:
      context: SIDECAR_OUTBOUND
    patch:
      operation: ADD
      value:
        name: must-not-apply
`)
	got, err := decodeEnvoyFilters(configMap)
	if err != nil || len(got) != 0 {
		t.Fatalf("decode = %+v, %v", got, err)
	}
}

func deployedEnvoyFilterConfigMap(sources string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       "sandbox-traffic-system",
			Name:            "deployed-envoy-filter",
			ResourceVersion: "1",
			Labels:          map[string]string{KubeSourceConfigMapLabel: "true"},
		},
		Data: map[string]string{KubeSourceDataKey: sources},
	}
}
