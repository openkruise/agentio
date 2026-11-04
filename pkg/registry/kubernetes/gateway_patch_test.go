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
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/compiler"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
)

const envoyFilterClusterPatch = `apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  namespace: demo
  name: legacy-patch
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: egress
  configPatches:
  - applyTo: CLUSTER
    match:
      cluster: {name: http_dynamic_forward_proxy}
    patch:
      operation: MERGE
      value: {connect_timeout: 3s}
`

func TestGatewayPatchConfigMapTypeSelection(t *testing.T) {
	patchLabels := map[string]string{ManifestTypeConfigMapLabel: GatewayPatchManifestType}
	sourceLabels := map[string]string{KubeSourceConfigMapLabel: "true"}
	bothLabels := map[string]string{
		ManifestTypeConfigMapLabel: GatewayPatchManifestType,
		KubeSourceConfigMapLabel:   "true",
	}
	for _, tt := range []struct {
		name      string
		labels    map[string]string
		data      map[string]string
		wantCount int
		wantName  string
		wantError string
	}{
		{name: "no labels or keys"},
		{name: "data keys alone do not select", data: map[string]string{KubePatchDataKey: validPatchConfig, KubeSourceDataKey: envoyFilterClusterPatch}},
		{name: "unknown type ignored", labels: map[string]string{ManifestTypeConfigMapLabel: "unknown"}, data: map[string]string{KubePatchDataKey: "[broken"}},
		{name: "type is case sensitive", labels: map[string]string{ManifestTypeConfigMapLabel: "GatewayPatch"}, data: map[string]string{KubePatchDataKey: validPatchConfig}},
		{name: "empty type ignored", labels: map[string]string{ManifestTypeConfigMapLabel: ""}, data: map[string]string{KubePatchDataKey: validPatchConfig}},
		{name: "sources only", labels: sourceLabels, data: map[string]string{KubeSourceDataKey: envoyFilterClusterPatch}, wantCount: 1, wantName: "legacy-patch"},
		{name: "legacy label does not select patch", labels: sourceLabels, data: map[string]string{KubePatchDataKey: validPatchConfig}},
		{name: "legacy ignores patch data", labels: sourceLabels, data: map[string]string{KubePatchDataKey: "[broken", KubeSourceDataKey: envoyFilterClusterPatch}, wantCount: 1, wantName: "legacy-patch"},
		{name: "patch only", labels: patchLabels, data: map[string]string{KubePatchDataKey: validPatchConfig}, wantCount: 1, wantName: "patches"},
		{name: "patch label does not select sources", labels: patchLabels, data: map[string]string{KubeSourceDataKey: envoyFilterClusterPatch}},
		{name: "patch wins", labels: bothLabels, data: map[string]string{KubePatchDataKey: validPatchConfig, KubeSourceDataKey: strings.ReplaceAll(envoyFilterClusterPatch, "3s", "9s")}, wantCount: 1, wantName: "patches"},
		{name: "invalid sources ignored", labels: bothLabels, data: map[string]string{KubePatchDataKey: validPatchConfig, KubeSourceDataKey: "[broken"}, wantCount: 1, wantName: "patches"},
		{name: "same identity ignored", labels: bothLabels, data: map[string]string{
			KubePatchDataKey:  validPatchConfig,
			KubeSourceDataKey: strings.Replace(envoyFilterClusterPatch, "namespace: demo\n  name: legacy-patch", "namespace: agentio-system\n  name: patches", 1),
		}, wantCount: 1, wantName: "patches"},
		{name: "missing patch masks sources", labels: bothLabels, data: map[string]string{KubeSourceDataKey: envoyFilterClusterPatch}},
		{name: "empty patch masks sources", labels: bothLabels, data: map[string]string{KubePatchDataKey: "", KubeSourceDataKey: envoyFilterClusterPatch}},
		{name: "blank patch masks sources", labels: bothLabels, data: map[string]string{KubePatchDataKey: " \n", KubeSourceDataKey: envoyFilterClusterPatch}},
		{name: "empty patch ignores invalid sources", labels: bothLabels, data: map[string]string{KubePatchDataKey: "", KubeSourceDataKey: "[broken"}},
		{name: "invalid patch has no fallback", labels: bothLabels, data: map[string]string{KubePatchDataKey: "[broken", KubeSourceDataKey: envoyFilterClusterPatch}, wantError: "data.patches"},
		{name: "invalid sources without patch", labels: sourceLabels, data: map[string]string{KubeSourceDataKey: "[broken"}, wantError: "data.sources"},
		{name: "partial legacy update rejected", labels: sourceLabels, data: map[string]string{KubeSourceDataKey: envoyFilterClusterPatch + "---\n[broken"}, wantError: "data.sources"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cm := patchConfigMap("")
			cm.Labels = tt.labels
			cm.Data = tt.data
			patches, err := decodeGatewayPatches(cm)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) || len(patches) != 0 {
					t.Fatalf("patches = %#v, error = %v; want no patches and %s error", patches, err, tt.wantError)
				}
				return
			}
			if err != nil || len(patches) != tt.wantCount {
				t.Fatalf("patches = %#v, error = %v; want %d patches", patches, err, tt.wantCount)
			}
			if len(patches) > 0 && patches[0].Name != tt.wantName {
				t.Fatalf("name = %q; want %q", patches[0].Name, tt.wantName)
			}
			if len(patches) > 0 {
				if !slices.Equal(patches[0].TargetGateways, []string{"demo/egress"}) {
					t.Fatalf("unexpected target gateways: %v", patches[0].TargetGateways)
				}
				cluster := patches[0].Patches[0].Target.(model.ClusterPatch)
				if cluster.Value.GetConnectTimeout().AsDuration() != 3*time.Second {
					t.Fatalf("unexpected cluster timeout: %v", cluster.Value.GetConnectTimeout())
				}
			}
		})
	}
}

func TestGatewayPatchFormatSwitchesRetainLastGood(t *testing.T) {
	stop := t.Context().Done()
	options := []krt.CollectionOption{krt.WithStop(stop)}
	configMaps := krt.NewMutableCollection[*corev1.ConfigMap](nil, nil, options...)
	patches := newGatewayPatchesCollection(configMaps.AsCollection(), "agentio-system", options...)
	waitForUpdates := patchUpdateBarrier(t, configMaps, patches)
	var mu sync.Mutex
	seen := map[string]bool{}
	patches.Register(func(event krt.Event[model.GatewayPatch]) {
		if event.New != nil && event.New.Source == "agentio-system/patches" {
			mu.Lock()
			seen[event.New.ResourceVersion] = true
			mu.Unlock()
		}
	})
	if !patches.WaitUntilSynced(stop) {
		t.Fatal("patch collection did not sync")
	}
	cm := patchConfigMap(validPatchConfig)
	cm.Labels[KubeSourceConfigMapLabel] = "true"
	cm.Data[KubeSourceDataKey] = envoyFilterClusterPatch
	for _, step := range []struct {
		name       string
		version    string
		mutate     func(*corev1.ConfigMap)
		wantCount  int
		wantName   string
		acceptedRV string
	}{
		{name: "patch masks legacy", version: "1", wantCount: 1, wantName: "patches", acceptedRV: "1"},
		{name: "invalid configuration retains accepted patches", version: "2", mutate: func(cm *corev1.ConfigMap) { cm.Data[KubePatchDataKey] = "[broken" }, wantCount: 1, wantName: "patches", acceptedRV: "1"},
		{name: "patch recovers despite invalid legacy", version: "3", mutate: func(cm *corev1.ConfigMap) { cm.Data[KubeSourceDataKey] = "[broken" }, wantCount: 1, wantName: "patches", acceptedRV: "3"},
		{name: "invalid second patch rejects complete update", version: "partial-patches", mutate: func(cm *corev1.ConfigMap) {
			cm.Data[KubePatchDataKey] = strings.ReplaceAll(validPatchConfig, "3s", "5s") + "- target: cluster\n  operation: invalid\n"
		}, wantCount: 1, wantName: "patches", acceptedRV: "3"},
		{name: "removing patch label activates legacy", version: "4", mutate: func(cm *corev1.ConfigMap) { delete(cm.Labels, ManifestTypeConfigMapLabel) }, wantCount: 1, wantName: "legacy-patch", acceptedRV: "4"},
		{name: "invalid legacy retains legacy", version: "5", mutate: func(cm *corev1.ConfigMap) {
			delete(cm.Labels, ManifestTypeConfigMapLabel)
			cm.Data[KubeSourceDataKey] = "[broken"
		}, wantCount: 1, wantName: "legacy-patch", acceptedRV: "4"},
		{name: "invalid second document rejects complete update", version: "partial-sources", mutate: func(cm *corev1.ConfigMap) {
			delete(cm.Labels, ManifestTypeConfigMapLabel)
			cm.Data[KubeSourceDataKey] = strings.ReplaceAll(envoyFilterClusterPatch, "3s", "5s") + "---\n[broken"
		}, wantCount: 1, wantName: "legacy-patch", acceptedRV: "4"},
		{name: "invalid patch cannot switch format", version: "6", mutate: func(cm *corev1.ConfigMap) { cm.Data[KubePatchDataKey] = "[broken" }, wantCount: 1, wantName: "legacy-patch", acceptedRV: "4"},
		{name: "patch replaces legacy", version: "7", wantCount: 1, wantName: "patches", acceptedRV: "7"},
		{name: "clearing patch masks legacy", version: "8", mutate: func(cm *corev1.ConfigMap) { cm.Data[KubePatchDataKey] = " \n" }},
		{name: "missing key still masks legacy", version: "9", mutate: func(cm *corev1.ConfigMap) { delete(cm.Data, KubePatchDataKey) }},
		{name: "restoring patch after withdrawal", version: "10", wantCount: 1, wantName: "patches", acceptedRV: "10"},
	} {
		changed := cm.DeepCopy()
		changed.ResourceVersion = step.version
		if step.mutate != nil {
			step.mutate(changed)
		}
		configMaps.ConditionalUpdateObject(changed)
		waitForUpdates()
		list := patchesFromSource(patches, "agentio-system/patches")
		if len(list) != step.wantCount ||
			(len(list) > 0 && (list[0].ResourceVersion != step.acceptedRV || list[0].Name != step.wantName)) {
			t.Fatalf(
				"%s: patches = %#v; want count=%d name=%s version=%s",
				step.name,
				list,
				step.wantCount,
				step.wantName,
				step.acceptedRV,
			)
		}
	}
	eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return seen["10"]
	}, "patch event delivery")
	mu.Lock()
	invalidPublished := seen["2"] || seen["5"] || seen["6"] || seen["partial-patches"] || seen["partial-sources"]
	mu.Unlock()
	if invalidPublished {
		t.Fatal("a rejected source revision was published")
	}

	outside := cm.DeepCopy()
	outside.Namespace = "outside"
	configMaps.ConditionalUpdateObject(outside)
	waitForUpdates()
	for _, patch := range patches.List() {
		if patch.Source == "outside/patches" {
			t.Fatal("non-root source selected")
		}
	}
	for _, remove := range []struct {
		name   string
		mutate func(*corev1.ConfigMap)
	}{
		{"delete keys", func(cm *corev1.ConfigMap) { cm.Data = nil }},
		{"clear key", func(cm *corev1.ConfigMap) { cm.Data[KubePatchDataKey] = " \n" }},
		{"remove label", func(cm *corev1.ConfigMap) { cm.Labels = nil }},
		{"change type", func(cm *corev1.ConfigMap) {
			delete(cm.Labels, KubeSourceConfigMapLabel)
			cm.Labels[ManifestTypeConfigMapLabel] = "unknown"
		}},
	} {
		changed := cm.DeepCopy()
		remove.mutate(changed)
		changed.ResourceVersion = remove.name
		configMaps.ConditionalUpdateObject(changed)
		waitForUpdates()
		if list := patchesFromSource(patches, "agentio-system/patches"); len(list) != 0 {
			t.Fatalf("%s did not withdraw patches: %#v", remove.name, list)
		}
		configMaps.ConditionalUpdateObject(cm.DeepCopy())
		waitForUpdates()
		if list := patchesFromSource(
			patches,
			"agentio-system/patches",
		); len(list) != 1 ||
			list[0].ResourceVersion != "1" {
			t.Fatalf("restored patches = %#v", list)
		}
	}
	broken := cm.DeepCopy()
	broken.Data[KubePatchDataKey] = "invalid"
	configMaps.ConditionalUpdateObject(broken)
	waitForUpdates()
	if list := patchesFromSource(patches, "agentio-system/patches"); len(list) != 1 || list[0].ResourceVersion != "1" {
		t.Fatalf("last-known-good patches before deletion = %#v", list)
	}
	configMaps.DeleteObject("agentio-system/patches")
	waitForUpdates()
	if list := patchesFromSource(patches, "agentio-system/patches"); len(list) != 0 {
		t.Fatalf("deleted source retained patches: %#v", list)
	}
}

// A separate ConfigMap update travels through the same ordered handler queue.
// Waiting for its output ensures rejected updates have finished processing before
// asserting that another source retained its last-known-good state.
func patchUpdateBarrier(
	t *testing.T,
	configMaps krt.StaticCollection[*corev1.ConfigMap],
	patches krt.Collection[model.GatewayPatch],
) func() {
	t.Helper()
	revision := 0
	return func() {
		t.Helper()
		revision++
		marker := patchConfigMap(validPatchConfig)
		marker.Name = "test-progress"
		marker.ResourceVersion = strconv.Itoa(revision)
		configMaps.ConditionalUpdateObject(marker)
		eventually(t, func() bool {
			list := patchesFromSource(patches, "agentio-system/test-progress")
			return len(list) == 1 && list[0].ResourceVersion == marker.ResourceVersion
		}, "patch update queue processed earlier events")
	}
}

func patchesFromSource(patches krt.Collection[model.GatewayPatch], source string) []model.GatewayPatch {
	var result []model.GatewayPatch
	for _, patch := range patches.List() {
		if patch.Source == source {
			result = append(result, patch)
		}
	}
	return result
}

func TestGatewayPatchInitialFailureDoesNotActivateSources(t *testing.T) {
	cm := patchConfigMap("[broken")
	cm.Labels[KubeSourceConfigMapLabel] = "true"
	cm.Data[KubeSourceDataKey] = envoyFilterClusterPatch
	options := []krt.CollectionOption{krt.WithStop(t.Context().Done())}
	configMaps := krt.NewStaticCollection[*corev1.ConfigMap](nil, []*corev1.ConfigMap{cm}, options...)
	patches := newGatewayPatchesCollection(configMaps, "agentio-system", options...)
	if !patches.WaitUntilSynced(t.Context().Done()) {
		t.Fatal("initial invalid source did not sync")
	}
	if len(patches.List()) != 0 {
		t.Fatal("initial invalid source published a partial patch")
	}
}

func TestPatchSelectionPreservesTelemetry(t *testing.T) {
	stop := t.Context().Done()
	options := []krt.CollectionOption{krt.WithStop(stop)}
	cm := patchConfigMap(validPatchConfig)
	cm.Labels[KubeSourceConfigMapLabel] = "true"
	cm.Data[KubeSourceDataKey] = envoyFilterClusterPatch + "---\n" + targetlessMetricsTelemetry("demo", "first")
	configMaps := krt.NewMutableCollection[*corev1.ConfigMap](nil, []*corev1.ConfigMap{cm}, options...)
	patches := newGatewayPatchesCollection(configMaps.AsCollection(), "agentio-system", options...)
	telemetries := newTelemetriesCollection(configMaps.AsCollection(), "agentio-system", options...)
	waitForUpdates := patchUpdateBarrier(t, configMaps, patches)
	if !patches.WaitUntilSynced(stop) || !telemetries.WaitUntilSynced(stop) {
		t.Fatal("collections did not sync")
	}
	if list := patches.List(); len(list) != 1 || list[0].Name != "patches" {
		t.Fatalf("patches = %#v", list)
	}
	if list := telemetries.List(); len(list) != 1 || list[0].Name != "first" {
		t.Fatalf("telemetries = %#v", list)
	}
	changed := cm.DeepCopy()
	changed.ResourceVersion = "2"
	changed.Data[KubePatchDataKey] = "[broken"
	changed.Data[KubeSourceDataKey] = envoyFilterClusterPatch + "---\n" + targetlessMetricsTelemetry("demo", "second")
	configMaps.ConditionalUpdateObject(changed)
	waitForUpdates()
	eventually(t, func() bool {
		list := telemetries.List()
		return len(list) == 1 && list[0].Name == "second" && list[0].ResourceVersion == "2"
	}, "Telemetry updates independently of invalid patches")
	if list := patchesFromSource(patches, "agentio-system/patches"); len(list) != 1 || list[0].ResourceVersion != "1" {
		t.Fatalf("last-known-good patches = %#v", list)
	}
	changed = changed.DeepCopy()
	changed.ResourceVersion = "3"
	changed.Data[KubePatchDataKey] = validPatchConfig
	delete(changed.Labels, KubeSourceConfigMapLabel)
	configMaps.ConditionalUpdateObject(changed)
	eventually(t, func() bool {
		list := patchesFromSource(patches, "agentio-system/patches")
		return len(telemetries.List()) == 0 && len(list) == 1 && list[0].ResourceVersion == "3"
	}, "patch label alone does not select legacy Telemetry")
}

func TestPatchConfigAndEnvoyFilterProduceEquivalentGatewayResources(t *testing.T) {
	patch, err := decodeGatewayPatches(patchConfigMap(validPatchConfig))
	if err != nil {
		t.Fatal(err)
	}
	cm := patchConfigMap("")
	cm.Labels = map[string]string{KubeSourceConfigMapLabel: "true"}
	cm.Data[KubeSourceDataKey] = envoyFilterClusterPatch
	legacy, err := decodeGatewayPatches(cm)
	if err != nil {
		t.Fatal(err)
	}
	gateway := model.Gateway{Namespace: "demo", Name: "egress", Config: &configv1.EgressGateway{}}
	build := func(patches []model.GatewayPatch) model.ResourceSet {
		t.Helper()
		resources, err := networking.Build(networking.Inputs{
			Gateway:          gateway,
			GatewayPatches:   patches,
			DiscoveryAddress: "agentiod.agentio-system.svc:15012",
			TrustDomain:      "cluster.local",
		})
		if err != nil {
			t.Fatal(err)
		}
		set, err := model.NewResourceSet(resources)
		if err != nil {
			t.Fatal(err)
		}
		return set
	}
	a, b := build(patch), build(legacy)
	if a.Version() != b.Version() {
		t.Fatalf("patch and legacy xDS differ: %v", a.Diff(b))
	}
}

func TestConfigMapPatchOrderingAcrossSources(t *testing.T) {
	for _, tt := range []struct {
		name           string
		firstPriority  int
		secondPriority int
		includeSource  bool
		wantTimeout    time.Duration
	}{
		{name: "priority precedes name", firstPriority: 10, secondPriority: -10, wantTimeout: 3 * time.Second},
		{name: "equal priority uses name", wantTimeout: 5 * time.Second},
		{name: "sources in another ConfigMap still participate", includeSource: true, wantTimeout: 9 * time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			first := patchConfigMap(validPatchConfig + "priority: " + strconv.Itoa(tt.firstPriority) + "\n")
			first.Name = "a-patches"
			first.CreationTimestamp = metav1.NewTime(time.Unix(200, 0))
			second := patchConfigMap(
				strings.ReplaceAll(
					validPatchConfig,
					"3s",
					"5s",
				) + "priority: " + strconv.Itoa(
					tt.secondPriority,
				) + "\n",
			)
			second.Name = "b-patches"
			second.CreationTimestamp = metav1.NewTime(time.Unix(100, 0))
			// Reverse input order to ensure application order comes from metadata.
			inputs := []*corev1.ConfigMap{second, first}
			if tt.includeSource {
				source := patchConfigMap("")
				source.Name = "c-sources"
				source.Labels = map[string]string{KubeSourceConfigMapLabel: "true"}
				source.Data[KubeSourceDataKey] = strings.ReplaceAll(
					envoyFilterClusterPatch,
					"3s",
					"9s",
				) + "  priority: 20\n"
				inputs = append(inputs, source)
			}
			var patches []model.GatewayPatch
			for _, cm := range inputs {
				decoded, err := decodeGatewayPatches(cm)
				if err != nil {
					t.Fatal(err)
				}
				patches = append(patches, decoded...)
			}
			resources, err := networking.Build(networking.Inputs{
				Gateway:          model.Gateway{Namespace: "demo", Name: "egress", Config: &configv1.EgressGateway{}},
				GatewayPatches:   patches,
				DiscoveryAddress: "agentiod.agentio-system.svc:15012",
				TrustDomain:      "cluster.local",
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, resource := range resources {
				if resource.Key.TypeURL != model.ClusterType || resource.XDSName != networking.HTTPDynamicForwardProxy {
					continue
				}
				cluster := &clusterv3.Cluster{}
				if err := resource.Value.UnmarshalTo(cluster); err != nil {
					t.Fatal(err)
				}
				if got := cluster.GetConnectTimeout().AsDuration(); got != tt.wantTimeout {
					t.Fatalf("connect timeout = %s, want %s", got, tt.wantTimeout)
				}
				return
			}
			t.Fatal("patched cluster was not generated")
		})
	}
}

func TestConfigMapPatchesReachCompilerAndRetainLastGoodResources(t *testing.T) {
	ctx := t.Context()
	base := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
		Data: map[string]string{
			"config": "egressGateways:\n- {namespace: demo, name: egress}\n- {namespace: other, name: egress}\n",
		},
	}
	client := &fakeKubeClient{Client: kube.NewFakeClient(base), watcher: newFakeGatewayCRDWatcher()}
	registry, err := New(
		client,
		Options{ClusterID: "test", TrustDomain: "cluster.local", RootNamespace: "agentio-system"},
		ctx.Done(),
	)
	if err != nil {
		t.Fatal(err)
	}
	c, err := compiler.New(compiler.Inputs{
		ClusterID:                  "test",
		RootNamespace:              "agentio-system",
		TrustDomain:                "cluster.local",
		DiscoveryAddress:           "agentiod.agentio-system.svc:15012",
		Pods:                       registry.Pods,
		KubernetesServices:         registry.KubernetesServices,
		EndpointSlices:             registry.EndpointSlices,
		ConfigMaps:                 registry.ConfigMaps,
		Secrets:                    registry.Secrets,
		Sandboxes:                  registry.Sandboxes.Collection,
		Workloads:                  registry.Workloads,
		Services:                   registry.Services,
		Endpoints:                  registry.Endpoints,
		Gateways:                   registry.Gateways,
		TrafficPolicies:            registry.TrafficPolicies,
		SecurityProfiles:           registry.SecurityProfiles,
		GatewayPatches:             registry.GatewayPatches,
		Telemetry:                  registry.Telemetry,
		TelemetryProviderOverrides: registry.TelemetryProviderOverrides,
		AgentioConfig:              registry.AgentioConfig,
	}, krt.NewOptionsBuilder(ctx.Done(), "patch-test", nil))
	if err != nil {
		t.Fatal(err)
	}
	client.Run(ctx.Done())
	eventually(t, func() bool {
		return registry.HasSynced() && c.HasSynced() && len(patchGatewayHashes(t, c, "demo/egress")) > 0
	}, "baseline Gateway compilation")
	baseline := patchGatewayHashes(t, c, "demo/egress")
	other := patchGatewayHashes(t, c, "other/egress")
	cm, err := client.Kube().
		CoreV1().
		ConfigMaps("agentio-system").
		Create(ctx, patchConfigMap(strings.Replace(validPatchConfig, "[demo/egress]", "[demo/egress, late/egress]", 1)), metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	eventually(
		t,
		func() bool { return patchGatewayTimeout(t, c, "demo/egress") == 3*time.Second },
		"ConfigMap watch -> compiler -> xDS",
	)
	lastGood := patchGatewayHashes(t, c, "demo/egress")
	if !maps.Equal(patchGatewayHashes(t, c, "other/egress"), other) {
		t.Fatal("non-target Gateway changed")
	}

	cm = cm.DeepCopy()
	cm.ResourceVersion = "2"
	// Parseable patch, invalid final resource: use a name collision between existing clusters.
	cm.Data[KubePatchDataKey] = strings.Replace(validPatchConfig, "connect_timeout: 3s", "name: main_forward", 1)
	if _, err := client.Kube().CoreV1().ConfigMaps(cm.Namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return c.Failures()["Gateway/demo/egress"] != "" }, "invalid final resources recorded")
	if !maps.Equal(patchGatewayHashes(t, c, "demo/egress"), lastGood) {
		t.Fatal("invalid resources replaced last-known-good graph")
	}
	if !maps.Equal(patchGatewayHashes(t, c, "other/egress"), other) {
		t.Fatal("failure changed non-target Gateway")
	}

	cm = cm.DeepCopy()
	cm.ResourceVersion = "3"
	cm.Data[KubePatchDataKey] = strings.Replace(
		strings.Replace(validPatchConfig, "3s", "4s", 1),
		"[demo/egress]",
		"[demo/egress, late/egress]",
		1,
	)
	if _, err := client.Kube().CoreV1().ConfigMaps(cm.Namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		return c.Failures()["Gateway/demo/egress"] == "" && patchGatewayTimeout(t, c, "demo/egress") == 4*time.Second
	}, "valid update recovers graph")

	if len(patchGatewayHashes(t, c, "late/egress")) != 0 {
		t.Fatal("patch created an undeclared gateway")
	}
	base = base.DeepCopy()
	base.ResourceVersion = "2"
	base.Data["config"] += "- {namespace: late, name: egress}\n"
	if _, err := client.Kube().
		CoreV1().
		ConfigMaps(base.Namespace).
		Update(ctx, base, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(
		t,
		func() bool { return patchGatewayTimeout(t, c, "late/egress") == 4*time.Second },
		"previously missing target picks up patches",
	)

	if err := client.Kube().CoreV1().ConfigMaps(cm.Namespace).Delete(ctx, cm.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(
		t,
		func() bool { return maps.Equal(patchGatewayHashes(t, c, "demo/egress"), baseline) },
		"delete restores generated baseline",
	)
}

func patchGatewayHashes(t *testing.T, c *compiler.Compiler, gateway string) map[string]string {
	t.Helper()
	set, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for _, kind := range set.Types() {
		for _, resource := range set.ListResourcesOwnedByGateway(kind, gateway) {
			result[resource.ResourceName()] = resource.Hash
		}
	}
	return result
}

func patchGatewayTimeout(t *testing.T, c *compiler.Compiler, gateway string) time.Duration {
	t.Helper()
	set, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range set.ListResourcesOwnedByGateway(model.ClusterType, gateway) {
		cluster := &clusterv3.Cluster{}
		if err := resource.Value.UnmarshalTo(cluster); err != nil {
			t.Fatal(err)
		}
		if cluster.Name == networking.HTTPDynamicForwardProxy {
			return cluster.GetConnectTimeout().AsDuration()
		}
	}
	return 0
}

func TestPatchExampleBuildsTypedGatewayResources(t *testing.T) {
	manifest, err := os.ReadFile("../../../manifests/examples/gateway-patches.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cm corev1.ConfigMap
	if err := yaml.UnmarshalStrict(manifest, &cm); err != nil {
		t.Fatal(err)
	}
	patches, err := decodeGatewayPatches(&cm)
	if err != nil {
		t.Fatal(err)
	}
	resources, err := networking.Build(networking.Inputs{
		Gateway:        model.Gateway{Namespace: "demo", Name: "egress", Config: &configv1.EgressGateway{}},
		GatewayPatches: patches, TrustDomain: "cluster.local", DiscoveryAddress: "agentiod.agentio-system.svc:15012",
	})
	if err != nil {
		t.Fatal(err)
	}
	foundCluster, foundHCM := false, false
	for _, resource := range resources {
		switch resource.Key.TypeURL {
		case model.ClusterType:
			cluster := &clusterv3.Cluster{}
			if err := resource.Value.UnmarshalTo(cluster); err != nil {
				t.Fatal(err)
			}
			if cluster.Name == networking.HTTPDynamicForwardProxy {
				foundCluster = cluster.GetConnectTimeout().AsDuration() == 3*time.Second
			}
		case model.ListenerType:
			listener := &listenerv3.Listener{}
			if err := resource.Value.UnmarshalTo(listener); err != nil {
				t.Fatal(err)
			}
			if listener.Name != networking.MainInternal {
				continue
			}
			for _, chain := range listener.FilterChains {
				for _, filter := range chain.Filters {
					if filter.Name != "envoy.filters.network.http_connection_manager" {
						continue
					}
					hcm := &hcmv3.HttpConnectionManager{}
					if err := filter.GetTypedConfig().UnmarshalTo(hcm); err != nil {
						t.Fatal(err)
					}
					foundHCM = hcm.GetStreamIdleTimeout().AsDuration() == 5*time.Minute
				}
			}
		}
	}
	if !foundCluster || !foundHCM {
		t.Fatalf("example effects: cluster=%v hcm=%v", foundCluster, foundHCM)
	}
}
