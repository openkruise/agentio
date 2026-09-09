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

package compiler

import (
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/pkg/util/sets"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	resolverdns "github.com/openkruise/agentio/pkg/dns/controller"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
	"github.com/openkruise/agentio/pkg/policy"
)

// recorder collects the resources krt reports as changed, so a test can assert
// what a given input edit did and — more importantly — did not invalidate.
type recorder struct {
	mu      sync.Mutex
	changed sets.Set[string]
}

func newRecorder(collection krt.EventStream[model.Resource]) *recorder {
	r := &recorder{changed: sets.New[string]()}
	collection.RegisterBatch(func(events []krt.Event[model.Resource]) {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, event := range events {
			r.changed.Insert(event.Latest().ResourceName())
		}
	}, false)
	return r
}

func (r *recorder) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]string, 0, len(r.changed))
	for name := range r.changed {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func (r *recorder) has(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.changed.Contains(name)
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.changed = sets.New[string]()
}

// settle waits for krt propagation to quiet before a negative assertion.
func settle() {
	time.Sleep(200 * time.Millisecond)
}

// eventually polls until condition holds, which is how krt's asynchronous
// propagation has to be observed.
func eventually(t testing.TB, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition never held: %s", message)
}

// awaitSteadyState waits until every named resource exists and the graph has gone
// quiet; must run before registering an event recorder to avoid recording initial Adds.
func awaitSteadyState(t testing.TB, compiler *Compiler, names ...string) {
	t.Helper()
	eventually(t, func() bool {
		for _, name := range names {
			if compiler.graph.resources.GetKey(name) == nil {
				return false
			}
		}
		return true
	}, "all expected resources present")
	settle()
}

type incrementalFixture struct {
	compiler           *Compiler
	sandboxes          krt.StaticCollection[model.Sandbox]
	workloads          krt.StaticCollection[model.Workload]
	services           krt.StaticCollection[model.Service]
	endpoints          krt.StaticCollection[model.Endpoint]
	trafficPolicies    krt.StaticCollection[model.TrafficPolicy]
	securityProfiles   krt.StaticCollection[model.SecurityProfile]
	gatewayPatches     krt.StaticCollection[model.GatewayPatch]
	telemetry          krt.StaticCollection[model.Telemetry]
	telemetryProviders krt.StaticSingleton[model.TelemetryProviderOverrides]
	agentioConfig      krt.StaticCollection[model.AgentioConfiguration]
	gateways           krt.Collection[model.Gateway]
	dnsResults         krt.StaticCollection[resolverdns.Result]
	resolveCalls       map[string]int
	resolveMu          sync.Mutex
}

func newIncrementalFixture(t testing.TB) *incrementalFixture {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}

	fixture := &incrementalFixture{
		sandboxes:          krt.NewStaticCollection[model.Sandbox](nil, nil, options...),
		workloads:          krt.NewStaticCollection[model.Workload](nil, nil, options...),
		services:           krt.NewStaticCollection[model.Service](nil, nil, options...),
		endpoints:          krt.NewStaticCollection[model.Endpoint](nil, nil, options...),
		trafficPolicies:    krt.NewStaticCollection[model.TrafficPolicy](nil, nil, options...),
		securityProfiles:   krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...),
		gatewayPatches:     krt.NewStaticCollection[model.GatewayPatch](nil, nil, options...),
		telemetry:          krt.NewStaticCollection[model.Telemetry](nil, nil, options...),
		telemetryProviders: krt.NewStatic[model.TelemetryProviderOverrides](nil, true, options...),
		agentioConfig:      krt.NewStaticCollection[model.AgentioConfiguration](nil, nil, options...),
		dnsResults:         krt.NewStaticCollection[resolverdns.Result](nil, nil, options...),
		resolveCalls:       map[string]int{},
	}
	fixture.gateways = testGatewaySource(fixture.agentioConfig, options...)

	inputs := validCompilerInputs(stop)
	inputs.Sandboxes = fixture.sandboxes
	inputs.Workloads = fixture.workloads
	inputs.Services = fixture.services
	inputs.Endpoints = fixture.endpoints
	inputs.Gateways = fixture.gateways
	inputs.TrafficPolicies = fixture.trafficPolicies
	inputs.SecurityProfiles = fixture.securityProfiles
	inputs.GatewayPatches = fixture.gatewayPatches
	inputs.Telemetry = fixture.telemetry
	inputs.TelemetryProviderOverrides = fixture.telemetryProviders
	inputs.AgentioConfig = fixture.agentioConfig
	inputs.Resolve = fixture.resolve
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	fixture.compiler = compiler
	return fixture
}

func TestWorkloadMetadataConfigurationLifecycle(t *testing.T) {
	fixture := newIncrementalFixture(t)
	workload := testWorkload("demo", "client", "10.0.0.2")
	workload.Labels = map[string]string{
		"keep":   "yes",
		"drop-a": "a",
		"drop-b": "b",
	}
	fixture.workloads.ConditionalUpdateObject(workload)
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, addressResourceName("demo", "client"))

	if labels, found := compiledWorkloadMetadataLabels(t, fixture.compiler, workload.UID); found {
		t.Fatalf("metadata labels without AgentioConfig = %v, want no metadata extension", labels)
	}

	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "empty",
		Value:           &configv1.AgentioConfig{},
	})
	eventually(t, func() bool {
		labels, found := compiledWorkloadMetadataLabels(t, fixture.compiler, workload.UID)
		return found && maps.Equal(labels, workload.Labels)
	}, "non-nil empty configuration publishes unfiltered metadata")

	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "ignore-a",
		Value: &configv1.AgentioConfig{
			SandboxIgnoredLabels: []string{"drop-a"},
		},
	})
	wantIgnoreA := map[string]string{"keep": "yes", "drop-b": "b"}
	eventually(t, func() bool {
		labels, found := compiledWorkloadMetadataLabels(t, fixture.compiler, workload.UID)
		return found && maps.Equal(labels, wantIgnoreA)
	}, "ignored-label update republishes filtered workload metadata")

	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "invalid",
		Value: &configv1.AgentioConfig{
			SandboxIgnoredLabels: []string{"drop-b"},
			EgressPolicies: []*extensionsv1.EgressPolicy{{
				MatchCidrs: []string{"not-a-cidr"},
				Policy:     extensionsv1.EgressPolicyAction_DENY,
			}},
		},
	})
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["AgentioConfig/configuration"]
		current := fixture.compiler.graph.configuration.Get()
		return failed && current != nil && current.ResourceVersion == "ignore-a"
	}, "invalid configuration retains the accepted configuration")
	if labels, found := compiledWorkloadMetadataLabels(t, fixture.compiler, workload.UID); !found || !maps.Equal(labels, wantIgnoreA) {
		t.Fatalf("metadata labels after rejected configuration = %v, found %v, want %v", labels, found, wantIgnoreA)
	}

	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "recovered",
		Value: &configv1.AgentioConfig{
			SandboxIgnoredLabels: []string{"drop-b"},
		},
	})
	wantRecovered := map[string]string{"keep": "yes", "drop-a": "a"}
	eventually(t, func() bool {
		labels, found := compiledWorkloadMetadataLabels(t, fixture.compiler, workload.UID)
		return found && maps.Equal(labels, wantRecovered)
	}, "valid recovery republishes workload metadata")
}

func compiledWorkloadMetadataLabels(
	t testing.TB,
	compiler *Compiler,
	workloadUID string,
) (map[string]string, bool) {
	t.Helper()
	resource, found := currentSnapshot(t, compiler).Get(model.ResourceKey{
		TypeURL: model.AddressType,
		Name:    workloadUID,
	})
	if !found {
		t.Fatalf("workload Address %q not found", workloadUID)
	}
	address := &workloadv1.Address{}
	if err := resource.Value.UnmarshalTo(address); err != nil {
		t.Fatalf("unmarshal workload Address %q: %v", workloadUID, err)
	}
	for _, extension := range address.GetWorkload().GetExtensions() {
		if extension.GetName() != "workload-metadata" {
			continue
		}
		metadata := &extensionsv1.WorkloadMetadata{}
		if err := extension.GetConfig().UnmarshalTo(metadata); err != nil {
			t.Fatalf("unmarshal workload metadata %q: %v", workloadUID, err)
		}
		return maps.Clone(metadata.GetLabels()), true
	}
	return nil, false
}

func TestGatewayTelemetryChangeAffectsOnlyTargetGateway(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "gateways", Value: &configv1.AgentioConfig{
		EgressGateways: []*configv1.EgressGateway{{Namespace: "demo", Name: "egress-a"}, {Namespace: "demo", Name: "egress-b"}},
	}})
	wantA := gatewayResourceName(model.ListenerType, "demo/egress-a", networking.MainForward)
	wantB := gatewayResourceName(model.ListenerType, "demo/egress-b", networking.MainForward)
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, wantA, wantB)
	beforeB := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b")
	recorder := newRecorder(fixture.compiler.Resources())

	policy, err := model.NewTelemetry(model.TelemetryMetadata{
		Namespace: "demo", Name: "metrics-a", Source: "agentio-system/custom-source",
	}, []string{"demo/egress-a"}, []model.TelemetryMetrics{{
		Overrides: []model.TelemetryMetricOverride{{
			Match:        model.TelemetryMetricSelector{Kind: model.TelemetryMetricStandard, Name: "REQUEST_COUNT", Mode: model.TelemetryModeServer},
			TagOverrides: map[string]model.TelemetryMetricTagOverride{"remove-me": {Operation: model.TelemetryTagRemove}},
		}},
	}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.telemetry.ConditionalUpdateObject(policy)
	eventually(t, func() bool { return recorder.has(wantA) }, "target Gateway Telemetry listener update")
	settle()
	for _, changed := range recorder.names() {
		if strings.Contains(changed, "|demo/egress-b|") {
			t.Fatalf("Telemetry for egress-a invalidated egress-b: %v", recorder.names())
		}
	}
	if afterB := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b"); !maps.Equal(beforeB, afterB) {
		t.Fatalf("non-target Gateway changed:\nbefore=%v\nafter=%v", beforeB, afterB)
	}
}

func TestConflictingTelemetryRetainsTargetGatewayLastKnownGood(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "gateway", Value: &configv1.AgentioConfig{
		EgressGateways: []*configv1.EgressGateway{{Namespace: "demo", Name: "egress"}},
	}})
	wantListener := gatewayResourceName(model.ListenerType, "demo/egress", networking.MainForward)
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, wantListener)

	first, err := model.NewTelemetry(model.TelemetryMetadata{
		Namespace: "demo", Name: "first", Source: "agentio-system/source-a",
	}, []string{"demo/egress"}, []model.TelemetryMetrics{{Overrides: []model.TelemetryMetricOverride{{
		Match:        model.TelemetryMetricSelector{Kind: model.TelemetryMetricStandard, Name: "REQUEST_COUNT", Mode: model.TelemetryModeServer},
		TagOverrides: map[string]model.TelemetryMetricTagOverride{"first": {Operation: model.TelemetryTagRemove}},
	}}}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.telemetry.ConditionalUpdateObject(first)
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Gateway/demo/egress"]
		return !failed
	}, "first Telemetry accepted")
	settle()
	lastGood := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress")

	second, err := model.NewTelemetry(model.TelemetryMetadata{
		Namespace: "demo", Name: "second", Source: "agentio-system/source-b",
	}, []string{"demo/egress"}, nil, nil, []model.TelemetryAccessLogging{{Mode: model.TelemetryModeServer}})
	if err != nil {
		t.Fatal(err)
	}
	fixture.telemetry.ConditionalUpdateObject(second)
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Gateway/demo/egress"]
		return failed
	}, "same-layer Telemetry conflict recorded")
	settle()
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress"); !maps.Equal(got, lastGood) {
		t.Fatalf("Telemetry conflict replaced last-known-good graph:\nlast-good=%v\ngot=%v", lastGood, got)
	}

	fixture.telemetry.DeleteObject(second.ResourceName())
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Gateway/demo/egress"]
		return !failed
	}, "Telemetry conflict recovery")
}

func TestSandboxSelectorMetadataUpdateRecomputesBindings(t *testing.T) {
	fixture := newIncrementalFixture(t)
	workload := testWorkload("workload-namespace", "client", "10.1.0.1")
	sandbox := model.Sandbox{
		UID:       workload.SandboxBindings[0].SandboxUID,
		Namespace: "sandbox-namespace",
		Labels:    map[string]string{"app": "sandbox"},
	}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	fixture.workloads.ConditionalUpdateObject(workload)
	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name: "allow", Namespace: sandbox.Namespace,
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "sandbox"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	})
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		binding := fixture.compiler.SandboxPolicyBindings().GetKey(sandbox.UID)
		return binding != nil && reflect.DeepEqual(
			binding.PolicyNames(policy.PolicyKindAuthorization),
			[]string{"sandbox-namespace/allow-egress"},
		)
	}, "explicit Sandbox namespace and labels select policy")

	sandbox.Labels = map[string]string{"app": "other"}
	fixture.sandboxes.ConditionalUpdateObject(sandbox)
	eventually(t, func() bool {
		return fixture.compiler.SandboxPolicyBindings().GetKey(sandbox.UID) == nil
	}, "Sandbox label update removes selector-derived binding")
}

func TestEnvoyFilterChangeAffectsOnlyTargetGateway(t *testing.T) {
	fixture := newIncrementalFixture(t)
	a := &configv1.EgressGateway{Namespace: "demo", Name: "egress-a"}
	b := &configv1.EgressGateway{Namespace: "demo", Name: "egress-b"}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "gateways", Value: &configv1.AgentioConfig{
		EgressGateways: []*configv1.EgressGateway{a, b},
	}})
	waitSynced(t, fixture.compiler)
	aCluster := gatewayResourceName(model.ClusterType, "demo/egress-a", networking.MainForward)
	bCluster := gatewayResourceName(model.ClusterType, "demo/egress-b", networking.MainForward)
	awaitSteadyState(t, fixture.compiler, aCluster, bCluster)
	before := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b")
	recorder := newRecorder(fixture.compiler.Resources())

	fixture.gatewayPatches.ConditionalUpdateObject(testClusterGatewayPatch(t,
		"patch-a", "agentio-system/config-sources", "1", "demo/egress-a", "patched-a"))

	eventually(t, func() bool { return recorder.has(aCluster) }, "target Gateway cluster patched")
	settle()
	for _, changed := range recorder.names() {
		if strings.Contains(changed, "|demo/egress-b|") {
			t.Fatalf("EnvoyFilter for egress-a invalidated egress-b: %v", recorder.names())
		}
	}
	after := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b")
	if !maps.Equal(before, after) {
		t.Fatalf("non-target Gateway graph changed:\nbefore=%v\nafter=%v", before, after)
	}
}

func TestDuplicateEnvoyFilterIdentityRetainsTargetGatewayLastKnownGood(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "gateway", Value: &configv1.AgentioConfig{
		EgressGateways: []*configv1.EgressGateway{{Namespace: "demo", Name: "egress"}},
	}})
	wantCluster := gatewayResourceName(model.ClusterType, "demo/egress", networking.MainForward)
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, wantCluster)
	baseline := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress")

	filter := testClusterGatewayPatch(t, "shared", "agentio-system/source-a", "1", "demo/egress", "last-good")
	fixture.gatewayPatches.ConditionalUpdateObject(filter)
	eventually(t, func() bool {
		return !maps.Equal(gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress"), baseline)
	}, "first EnvoyFilter applied")
	settle()
	lastGood := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress")

	duplicate := filter
	duplicate.Source = "agentio-system/source-b"
	duplicate.ResourceVersion = "2"
	fixture.gatewayPatches.ConditionalUpdateObject(duplicate)
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["Gateway/demo/egress"]
		return found
	}, "duplicate EnvoyFilter records target Gateway failure")
	settle()
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress"); !maps.Equal(got, lastGood) {
		t.Fatalf("duplicate EnvoyFilter replaced last-known-good gateway graph:\nlast-good=%v\ngot=%v", lastGood, got)
	}
}

func TestDuplicateEnvoyFilterIdentityAcrossTargetsFailsTargetUnionClosed(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "gateways", Value: &configv1.AgentioConfig{
		EgressGateways: []*configv1.EgressGateway{
			{Namespace: "demo", Name: "egress-a"},
			{Namespace: "demo", Name: "egress-b"},
		},
	}})
	wantA := gatewayResourceName(model.ClusterType, "demo/egress-a", networking.MainForward)
	wantB := gatewayResourceName(model.ClusterType, "demo/egress-b", networking.MainForward)
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, wantA, wantB)
	baselineA := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a")
	baselineB := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b")

	first := testClusterGatewayPatch(t, "shared", "agentio-system/source-a", "1", "demo/egress-a", "patched-a")
	fixture.gatewayPatches.ConditionalUpdateObject(first)
	eventually(t, func() bool {
		return !maps.Equal(gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a"), baselineA)
	}, "first source establishes gateway A last-known-good graph")
	lastGoodA := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a")

	duplicate := testClusterGatewayPatch(t, "shared", "agentio-system/source-b", "2", "demo/egress-b", "patched-b")
	fixture.gatewayPatches.ConditionalUpdateObject(duplicate)
	eventually(t, func() bool {
		failures := fixture.compiler.Failures()
		_, failedA := failures["Gateway/demo/egress-a"]
		_, failedB := failures["Gateway/demo/egress-b"]
		return failedA && failedB
	}, "duplicate logical identity fails the union of disjoint target Gateways")
	settle()
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a"); !maps.Equal(got, lastGoodA) {
		t.Fatalf("gateway A did not retain last-known-good graph:\nwant=%v\ngot=%v", lastGoodA, got)
	}
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b"); !maps.Equal(got, baselineB) {
		t.Fatalf("gateway B did not retain baseline graph:\nwant=%v\ngot=%v", baselineB, got)
	}

	fixture.gatewayPatches.DeleteObject(duplicate.ResourceName())
	eventually(t, func() bool {
		return len(fixture.compiler.Failures()) == 0
	}, "removing one source resolves both target Gateway conflicts")
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a")[wantA]; got != lastGoodA[wantA] {
		t.Fatalf("gateway A patched cluster hash after recovery = %s, want %s", got, lastGoodA[wantA])
	}
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b")[wantB]; got != baselineB[wantB] {
		t.Fatalf("gateway B baseline cluster hash after recovery = %s, want %s", got, baselineB[wantB])
	}
}

func testClusterGatewayPatch(
	t *testing.T,
	name, source, resourceVersion, target, altStatName string,
) model.GatewayPatch {
	t.Helper()
	policy, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace: "demo", Name: name, Source: source, ResourceVersion: resourceVersion,
	}, 0, []string{target}, []model.EnvoyPatch{{
		Operation: model.PatchMerge,
		Target: model.ClusterPatch{
			Match: &model.ClusterMatch{Name: networking.MainForward},
			Value: &clusterv3.Cluster{AltStatName: altStatName},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func (f *incrementalFixture) resolve(ctx krt.HandlerContext, host string) []netip.Addr {
	f.resolveMu.Lock()
	f.resolveCalls[host]++
	f.resolveMu.Unlock()
	resolved := krt.FetchOne(ctx, f.dnsResults, krt.FilterKey(host))
	if resolved == nil {
		return nil
	}
	return resolved.Addresses
}

func (f *incrementalFixture) resolutionCount(host string) int {
	f.resolveMu.Lock()
	defer f.resolveMu.Unlock()
	return f.resolveCalls[host]
}

func (f *incrementalFixture) setResolved(host string, addresses ...netip.Addr) {
	f.dnsResults.ConditionalUpdateObject(resolverdns.Result{Hostname: host, Addresses: addresses})
}

func testWorkload(namespace, name, address string) model.Workload {
	uid := "cluster//Pod/" + namespace + "/" + name
	return model.Workload{
		UID: uid,
		SandboxBindings: []model.SandboxBinding{
			{
				SandboxUID: uid,
			},
		},
		Namespace: namespace,
		Name:      name,
		Addresses: []string{address},
		Labels:    map[string]string{"app": name},
		Ready:     true,
		Principal: model.Principal{
			Kind:        model.PrincipalServiceAccount,
			TrustDomain: "cluster.local",
			ServiceAccount: model.ServiceAccountRef{
				Namespace:      namespace,
				ServiceAccount: "default",
			},
		},
	}
}

func addressResourceName(namespace, name string) string {
	return model.AddressType + "|cluster//Pod/" + namespace + "/" + name
}

func gatewayResourceName(typeURL, gateway, xdsName string) string {
	return typeURL + "|" + gateway + "|" + xdsName
}

func gatewayGraphHashes(snapshot model.ResourceSet, gatewayKey string) map[string]string {
	result := map[string]string{}
	for _, typeURL := range []string{model.ClusterType, model.ListenerType, model.RouteType, model.ExtensionConfigurationType, model.ProxyConfigType} {
		for _, resource := range snapshot.ListResourcesOwnedByGateway(typeURL, gatewayKey) {
			result[resource.ResourceName()] = resource.Hash
		}
	}
	return result
}

func resourceReferencesGateway(resource model.Resource, gatewayKey string) bool {
	return resource.Facts.Workload != nil &&
		slices.Contains(resource.Facts.Workload.GatewayReferences, gatewayKey)
}

// The semantic configuration is projected into keyed gateways before resource
// generation, so a valid add, update, or delete publishes only that identity.
func TestGatewayConfigChangesAffectOnlyConfiguredGateway(t *testing.T) {
	fixture := newIncrementalFixture(t)
	a := &configv1.EgressGateway{Namespace: "demo", Name: "egress-a"}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "initial", Value: &configv1.AgentioConfig{
		EgressGateways: []*configv1.EgressGateway{a},
	}})
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		gatewayResourceName(model.ProxyConfigType, "demo/egress-a", "agentio-proxy"))
	recorder := newRecorder(fixture.compiler.Resources())

	b := &configv1.EgressGateway{Namespace: "demo", Name: "egress-b"}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "add", Value: &configv1.AgentioConfig{
		EgressGateways: []*configv1.EgressGateway{a, b},
	}})
	bProxy := gatewayResourceName(model.ProxyConfigType, "demo/egress-b", "agentio-proxy")
	eventually(t, func() bool { return recorder.has(bProxy) }, "configured gateway add")
	settle()
	for _, changed := range recorder.names() {
		if strings.Contains(changed, "|demo/egress-a|") {
			t.Fatalf("adding egress-b invalidated egress-a; changed=%v", recorder.names())
		}
	}

	recorder.reset()
	b = &configv1.EgressGateway{
		Namespace: "demo", Name: "egress-b",
		ExtProc:        &configv1.ExtProcProvider{Service: "epe.demo.svc.cluster.local", Port: 9002},
		TlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"new.example.com"}},
	}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "update", Value: &configv1.AgentioConfig{
		EgressGateways: []*configv1.EgressGateway{a, b},
	}})
	bExtProc := gatewayResourceName(model.ClusterType, "demo/egress-b", networking.ExtProcCluster)
	eventually(t, func() bool { return recorder.has(bExtProc) }, "configured gateway update")
	settle()
	for _, changed := range recorder.names() {
		if strings.Contains(changed, "|demo/egress-a|") {
			t.Fatalf("updating egress-b invalidated egress-a; changed=%v", recorder.names())
		}
	}

	recorder.reset()
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "delete", Value: &configv1.AgentioConfig{
		EgressGateways: []*configv1.EgressGateway{a},
	}})
	eventually(t, func() bool { return recorder.has(bProxy) }, "configured gateway delete")
	settle()
	for _, changed := range recorder.names() {
		if strings.Contains(changed, "|demo/egress-a|") {
			t.Fatalf("deleting egress-b invalidated egress-a; changed=%v", recorder.names())
		}
	}
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b"); len(got) != 0 {
		t.Fatalf("deleted gateway retained resources: %v", got)
	}
}

// The registry preserves duplicate selected entries in one Gateway.Config; the
// compiler must therefore report the existing fail-closed error and publish no
// resources for that identity.
func TestDuplicateGatewayConfigPublishesNoGraphAndRecordsFailure(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "duplicate", Value: &configv1.AgentioConfig{
		EgressGateways: []*configv1.EgressGateway{
			{Namespace: "demo", Name: "egress"},
			{Namespace: "demo", Name: "egress"},
		},
	}})
	waitSynced(t, fixture.compiler)

	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["Gateway/demo/egress"]
		return found
	}, "duplicate gateway configuration failure")
	snapshot := currentSnapshot(t, fixture.compiler)
	for _, typeURL := range []string{model.ClusterType, model.ListenerType, model.RouteType, model.ProxyConfigType} {
		if resources := snapshot.ListResourcesOwnedByGateway(typeURL, "demo/egress"); len(resources) != 0 {
			t.Fatalf("duplicate gateway published %s resources: %v", typeURL, resources)
		}
	}

	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "removed", Value: &configv1.AgentioConfig{},
	})
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Gateway/demo/egress"]
		return !failed
	}, "removed initially invalid gateway clears failure")
}

func TestInvalidSemanticConfigurationRetainsGatewayGraphUntilRecovery(t *testing.T) {
	fixture := newIncrementalFixture(t)
	valid := &configv1.AgentioConfig{
		SandboxExtProc: &configv1.ExtProcProvider{Service: "epe-old.demo.svc.cluster.local", Port: 9002},
		EgressPolicies: []*extensionsv1.EgressPolicy{{
			MatchCidrs: []string{"10.0.0.0/24"}, Policy: extensionsv1.EgressPolicyAction_DENY,
		}},
		EgressGateways: []*configv1.EgressGateway{{
			Namespace: "demo", Name: "egress",
			TlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"old.example.com"}},
		}},
	}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "valid", Value: valid})
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		gatewayResourceName(model.ClusterType, "demo/egress", networking.ExtProcCluster),
		gatewayResourceName(model.ListenerType, "demo/egress", networking.MainInternal))
	baseline := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress")
	if len(baseline) == 0 {
		t.Fatal("valid configuration published no gateway graph")
	}

	invalid := &configv1.AgentioConfig{
		SandboxExtProc: &configv1.ExtProcProvider{
			Service: "epe-new.demo.svc.cluster.local", Port: 9002, FailureModeAllow: true,
		},
		EgressPolicies: []*extensionsv1.EgressPolicy{{
			MatchCidrs: []string{"not-a-cidr"}, Policy: extensionsv1.EgressPolicyAction_DENY,
		}},
		EgressGateways: []*configv1.EgressGateway{{
			Namespace: "demo", Name: "egress",
			TlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"new.example.com"}},
		}},
	}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "invalid", Value: invalid})
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["AgentioConfig/configuration"]
		return found
	}, "invalid semantic configuration failure")
	settle()

	effective := fixture.compiler.graph.configuration.Get()
	if effective == nil || effective.ResourceVersion != "valid" ||
		len(effective.Egress.GetEgressPolicies()) != 1 ||
		effective.Egress.GetEgressPolicies()[0].GetMatchCidrs()[0] != "10.0.0.0/24" {
		t.Fatalf("effective policy advanced past last known good: %+v", effective)
	}
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress"); !maps.Equal(got, baseline) {
		t.Fatalf("gateway graph advanced with rejected configuration:\nold=%v\nnew=%v", baseline, got)
	}
	semanticGateway := fixture.compiler.Gateways().GetKey("demo/egress")
	if semanticGateway == nil ||
		!slices.Equal(semanticGateway.Config.GetTlsTermination().GetIncludeHosts(), []string{"old.example.com"}) {
		t.Fatalf("semantic gateway advanced with rejected configuration: %+v", semanticGateway)
	}

	recovered := &configv1.AgentioConfig{
		SandboxExtProc: invalid.SandboxExtProc,
		EgressPolicies: []*extensionsv1.EgressPolicy{{
			MatchCidrs: []string{"203.0.113.0/24"}, Policy: extensionsv1.EgressPolicyAction_DENY,
		}},
		EgressGateways: invalid.EgressGateways,
	}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "recovered", Value: recovered})
	eventually(t, func() bool {
		current := fixture.compiler.graph.configuration.Get()
		if current == nil || current.ResourceVersion != "recovered" {
			return false
		}
		_, failed := fixture.compiler.Failures()["AgentioConfig/configuration"]
		return !failed && !maps.Equal(gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress"), baseline)
	}, "valid recovery applies policy and gateway changes")
}

func TestEgressPolicyIncrementalAttachmentAndLastKnownGood(t *testing.T) {
	fixture := newIncrementalFixture(t)
	client := testWorkload("demo", "client", "10.0.0.2")
	other := testWorkload("other", "client", "10.0.1.2")
	fixture.workloads.ConditionalUpdateObject(client)
	fixture.workloads.ConditionalUpdateObject(other)
	valid := func(resourceVersion, cidr, service string) model.AgentioConfiguration {
		return model.AgentioConfiguration{
			ResourceVersion: resourceVersion,
			Value: &configv1.AgentioConfig{EgressPolicies: []*extensionsv1.EgressPolicy{
				{
					Namespaces: []string{"demo"}, MatchCidrs: []string{cidr}, Policy: extensionsv1.EgressPolicyAction_GATEWAY,
					Gateway: &extensionsv1.GatewayAddress{Service: service, Port: 15008},
				},
			}},
		}
	}
	fixture.agentioConfig.ConditionalUpdateObject(valid("valid", "203.0.113.1/32", "egress-a.agentio-system.svc.cluster.local"))
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, addressResourceName("demo", "client"), addressResourceName("other", "client"))
	baseline, _ := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: client.UID})
	otherBaseline, _ := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: other.UID})
	if !resourceReferencesGateway(baseline, "agentio-system/egress-a") {
		t.Fatalf("valid facts = %+v", baseline.Facts)
	}

	var bindingEvents atomic.Int64
	fixture.compiler.graph.policies.sandboxBindings.RegisterBatch(func(events []krt.Event[policy.SandboxPolicyBindings]) {
		bindingEvents.Add(int64(len(events)))
	}, false)
	fixture.agentioConfig.ConditionalUpdateObject(valid("rules", "203.0.113.2/32", "egress-a.agentio-system.svc.cluster.local"))
	eventually(t, func() bool {
		resource, found := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: client.UID})
		return found && resource.Hash != baseline.Hash
	}, "rules-only egress update changes matching workload")
	settle()
	if got := bindingEvents.Load(); got != 0 {
		t.Fatalf("rules-only egress update emitted %d workload binding events, want 0", got)
	}
	if current, _ := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: other.UID}); current.Hash != otherBaseline.Hash {
		t.Fatal("rules-only demo egress update changed unrelated namespace")
	}

	fixture.agentioConfig.ConditionalUpdateObject(valid("gateway", "203.0.113.2/32", "egress-b.agentio-system.svc.cluster.local"))
	eventually(t, func() bool {
		resource, found := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: client.UID})
		return found && resourceReferencesGateway(resource, "agentio-system/egress-b")
	}, "gateway reference changes")
	lastGood, _ := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: client.UID})
	if resourceReferencesGateway(lastGood, "agentio-system/egress-a") {
		t.Fatalf("old gateway reference remains: %+v", lastGood.Facts)
	}

	fixture.agentioConfig.ConditionalUpdateObject(valid("invalid", "203.0.113.3/32", "egress..svc.cluster.local"))
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["AgentioConfig/configuration"]
		return found
	}, "malformed gateway records configuration failure")
	settle()
	retained, _ := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: client.UID})
	if retained.Hash != lastGood.Hash {
		t.Fatalf("malformed gateway replaced last-known-good workload: %s != %s", retained.Hash, lastGood.Hash)
	}
}

func TestInitialInvalidEgressAndTLSGatewayDoNotCreateSandboxReference(t *testing.T) {
	for _, test := range []struct {
		name   string
		config *configv1.AgentioConfig
	}{
		{
			name: "invalid egress",
			config: &configv1.AgentioConfig{EgressPolicies: []*extensionsv1.EgressPolicy{
				{
					Policy:  extensionsv1.EgressPolicyAction_GATEWAY,
					Gateway: &extensionsv1.GatewayAddress{Service: "egress..svc.cluster.local", Port: 15008},
				},
			}},
		},
		{
			name: "TLS include hosts only",
			config: &configv1.AgentioConfig{EgressGateways: []*configv1.EgressGateway{
				{
					Namespace: "agentio-system", Name: "egress",
					TlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"api.example.com"}},
				},
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newIncrementalFixture(t)
			client := testWorkload("demo", "client", "10.0.0.2")
			fixture.workloads.ConditionalUpdateObject(client)
			fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "initial", Value: test.config})
			waitSynced(t, fixture.compiler)
			awaitSteadyState(t, fixture.compiler, addressResourceName("demo", "client"))
			resource, _ := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{TypeURL: model.AddressType, Name: client.UID})
			if resource.Facts.Workload != nil && len(resource.Facts.Workload.GatewayReferences) != 0 {
				t.Fatalf("facts = %+v, unexpected gateway reference", resource.Facts)
			}
			address := &workloadv1.Address{}
			if err := resource.Value.UnmarshalTo(address); err != nil {
				t.Fatal(err)
			}
			names := extensionNames(address.GetWorkload().GetExtensions())
			for _, name := range names {
				if name == "egress-policies" {
					t.Fatalf("extensions = %v, unexpected egress policy", names)
				}
			}
		})
	}
}

func TestGatewayWDSOwnershipLifecycle(t *testing.T) {
	fixture := newIncrementalFixture(t)
	gatewaySandbox := testWorkload("demo", "egress-pod", "10.0.0.10")
	gatewaySandbox.Principal.ServiceAccount.ServiceAccount = "egress"
	unrelatedSandbox := testWorkload("other", "client", "10.0.1.10")
	gatewayService := model.Service{
		Namespace: "demo", Name: "egress", Hostname: "egress.demo.svc.cluster.local", Addresses: []string{"10.96.0.10"},
	}
	unrelatedService := model.Service{
		Namespace: "other", Name: "backend", Hostname: "backend.other.svc.cluster.local", Addresses: []string{"10.96.1.10"},
	}
	fixture.workloads.ConditionalUpdateObject(gatewaySandbox)
	fixture.workloads.ConditionalUpdateObject(unrelatedSandbox)
	fixture.services.ConditionalUpdateObject(gatewayService)
	fixture.services.ConditionalUpdateObject(unrelatedService)
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "empty", Value: &configv1.AgentioConfig{},
	})
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		addressResourceName("demo", "egress-pod"), addressResourceName("other", "client"),
		model.AddressType+"|"+gatewayService.ResourceName(), model.AddressType+"|"+unrelatedService.ResourceName())
	baseline := currentSnapshot(t, fixture.compiler)
	unrelatedWorkload, _ := baseline.Get(model.ResourceKey{TypeURL: model.AddressType, Name: unrelatedSandbox.UID})
	unrelatedServiceResource, _ := baseline.Get(model.ResourceKey{TypeURL: model.AddressType, Name: unrelatedService.ResourceName()})
	owned := "demo/egress"
	for _, key := range []model.ResourceKey{
		{TypeURL: model.AddressType, Name: gatewaySandbox.UID},
		{TypeURL: model.AddressType, Name: gatewayService.ResourceName()},
	} {
		resource, _ := baseline.Get(key)
		if resource.Facts.GatewayOwner == owned {
			t.Fatalf("resource %v owned before Gateway configuration", key)
		}
	}

	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "add", Value: &configv1.AgentioConfig{EgressGateways: []*configv1.EgressGateway{{
			Namespace: "demo", Name: "egress",
		}}},
	})
	eventually(t, func() bool {
		snapshot := currentSnapshot(t, fixture.compiler)
		workload, workloadFound := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: gatewaySandbox.UID})
		service, serviceFound := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: gatewayService.ResourceName()})
		return workloadFound && serviceFound && workload.Facts.GatewayOwner == owned && service.Facts.GatewayOwner == owned
	}, "Gateway workload and service gain ownership")
	settle()
	afterAdd := currentSnapshot(t, fixture.compiler)
	if current, _ := afterAdd.Get(model.ResourceKey{TypeURL: model.AddressType, Name: unrelatedSandbox.UID}); current.Hash != unrelatedWorkload.Hash {
		t.Fatal("Gateway configuration changed unrelated workload")
	}
	if current, _ := afterAdd.Get(model.ResourceKey{TypeURL: model.AddressType, Name: unrelatedService.ResourceName()}); current.Hash != unrelatedServiceResource.Hash {
		t.Fatal("Gateway configuration changed unrelated service")
	}

	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "remove", Value: &configv1.AgentioConfig{},
	})
	eventually(t, func() bool {
		snapshot := currentSnapshot(t, fixture.compiler)
		workload, workloadFound := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: gatewaySandbox.UID})
		service, serviceFound := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: gatewayService.ResourceName()})
		return workloadFound && serviceFound && workload.Facts.GatewayOwner == "" && service.Facts.GatewayOwner == ""
	}, "Gateway workload and service lose ownership")
}

func TestInvalidGatewayUpdateRetainsLastKnownGoodGraph(t *testing.T) {
	fixture := newIncrementalFixture(t)
	valid := &configv1.AgentioConfig{EgressGateways: []*configv1.EgressGateway{{
		Namespace: "demo", Name: "egress",
	}}}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "valid", Value: valid})
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		gatewayResourceName(model.ProxyConfigType, "demo/egress", "agentio-proxy"))
	baseline := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress")

	duplicate := &configv1.AgentioConfig{EgressGateways: []*configv1.EgressGateway{
		{Namespace: "demo", Name: "egress"},
		{Namespace: "demo", Name: "egress", TlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"new.example.com"}}},
	}}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "duplicate", Value: duplicate})
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["Gateway/demo/egress"]
		return found
	}, "duplicate gateway update failure")
	settle()
	if got := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress"); !maps.Equal(got, baseline) {
		t.Fatalf("invalid gateway update replaced last known good graph:\nold=%v\nnew=%v", baseline, got)
	}

	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "removed", Value: &configv1.AgentioConfig{},
	})
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Gateway/demo/egress"]
		return !failed && len(gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress")) == 0
	}, "removed invalid gateway clears failure and last-known-good graph")

	recovered := &configv1.AgentioConfig{EgressGateways: []*configv1.EgressGateway{{
		Namespace: "demo", Name: "egress",
		TlsTermination: &configv1.TlsTerminationConfig{IncludeHosts: []string{"new.example.com"}},
	}}}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "recovered", Value: recovered})
	eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["Gateway/demo/egress"]
		return !failed && !maps.Equal(gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress"), baseline)
	}, "valid gateway recovery replaces last known good graph")
}

// A namespaced policy edit must invalidate only the workloads of that namespace.
func TestPolicyEditInvalidatesOnlyItsNamespace(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.workloads.ConditionalUpdateObject(testWorkload("alpha", "client", "10.1.0.1"))
	fixture.workloads.ConditionalUpdateObject(testWorkload("beta", "client", "10.2.0.1"))
	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name: "allow", Namespace: "alpha",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	})
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		addressResourceName("alpha", "client"),
		addressResourceName("beta", "client"),
		model.WorkloadAuthorizationType+"|alpha/allow-egress")

	recorder := newRecorder(fixture.compiler.Resources())

	// Widen the alpha policy. Only alpha's workload and the alpha Authorization
	// depend on it.
	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name: "allow", Namespace: "alpha",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/8"}},
			}}},
		},
	})

	eventually(t, func() bool {
		return recorder.has(model.WorkloadAuthorizationType + "|alpha/allow-egress")
	}, "alpha authorization recompiled")
	settle()

	if recorder.has(addressResourceName("beta", "client")) {
		t.Fatalf("editing an alpha policy invalidated a beta workload; changed=%v", recorder.names())
	}
}

func TestExactSandboxPolicyLifecycleAffectsOnlyTarget(t *testing.T) {
	fixture := newIncrementalFixture(t)
	first := testWorkload("demo", "first", "10.1.0.1")
	second := testWorkload("demo", "second", "10.1.0.2")
	firstUID := "sandbox-first"
	secondUID := "sandbox-second"
	first.SandboxBindings[0].SandboxUID = firstUID
	second.SandboxBindings[0].SandboxUID = secondUID
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{
		UID: firstUID, Namespace: "demo",
		Labels: map[string]string{agentsv1alpha1.LabelSandboxID: firstUID},
	})
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{
		UID: secondUID, Namespace: "demo",
		Labels: map[string]string{agentsv1alpha1.LabelSandboxID: secondUID},
	})
	fixture.workloads.ConditionalUpdateObject(first)
	fixture.workloads.ConditionalUpdateObject(second)
	waitSynced(t, fixture.compiler)
	firstAddress := addressResourceName("demo", "first")
	secondAddress := addressResourceName("demo", "second")
	awaitSteadyState(t, fixture.compiler, firstAddress, secondAddress)

	policyInput := model.TrafficPolicy{
		Name: "exact", Namespace: "demo", SandboxUID: firstUID,
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				agentsv1alpha1.LabelSandboxID: firstUID,
			}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	}
	authorization := model.WorkloadAuthorizationType + "|demo/exact-egress"
	recorder := newRecorder(fixture.compiler.Resources())
	fixture.trafficPolicies.ConditionalUpdateObject(policyInput)
	eventually(t, func() bool {
		return recorder.has(authorization) && recorder.has(firstAddress)
	}, "exact policy attached to its Sandbox")
	settle()
	if got, want := recorder.names(), []string{authorization, firstAddress}; !reflect.DeepEqual(got, want) {
		t.Fatalf("exact policy add changed %v, want %v", got, want)
	}
	if recorder.has(secondAddress) {
		t.Fatalf("exact policy add invalidated unrelated Sandbox; changed=%v", recorder.names())
	}

	recorder.reset()
	fixture.trafficPolicies.DeleteObject(policyInput.ResourceName())
	eventually(t, func() bool {
		return recorder.has(authorization) && recorder.has(firstAddress)
	}, "exact policy detached from its Sandbox")
	settle()
	if got, want := recorder.names(), []string{authorization, firstAddress}; !reflect.DeepEqual(got, want) {
		t.Fatalf("exact policy delete changed %v, want %v", got, want)
	}
	if recorder.has(secondAddress) {
		t.Fatalf("exact policy delete invalidated unrelated Sandbox; changed=%v", recorder.names())
	}
}

// Rule payload changes update the independently stored Authorization without
// invalidating canonical Workload Addresses.
func TestTrafficRulesOnlyUpdateDoesNotInvalidateWorkloads(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.workloads.ConditionalUpdateObject(testWorkload("demo", "client", "10.1.0.1"))
	policyInput := model.TrafficPolicy{
		Name: "allow", Namespace: "demo",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	}
	fixture.trafficPolicies.ConditionalUpdateObject(policyInput)
	waitSynced(t, fixture.compiler)
	authorizationKey := model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: "demo/allow-egress"}
	eventually(t, func() bool {
		_, found := currentSnapshot(t, fixture.compiler).Get(authorizationKey)
		return found
	}, "initial authorization resource")
	settle()
	recorder := newRecorder(fixture.compiler.Resources())
	oldAuthorization, _ := currentSnapshot(t, fixture.compiler).Get(authorizationKey)

	updated := policyInput
	updated.Spec.Egress = policyInput.Spec.Egress.DeepCopy()
	updated.Spec.Egress.Rules[0].To[0].CIDR = "10.0.0.0/8"
	fixture.trafficPolicies.ConditionalUpdateObject(updated)
	eventually(t, func() bool {
		current, found := currentSnapshot(t, fixture.compiler).Get(authorizationKey)
		return found && current.Hash != oldAuthorization.Hash
	}, "authorization rules update")
	settle()

	if recorder.has(addressResourceName("demo", "client")) {
		t.Fatalf("rules-only TrafficPolicy update invalidated workload; changed=%v", recorder.names())
	}
}

// A global policy legitimately attaches everywhere, so it must invalidate
// workloads in every namespace.
func TestGlobalPolicyInvalidatesEveryNamespace(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.workloads.ConditionalUpdateObject(testWorkload("alpha", "client", "10.1.0.1"))
	fixture.workloads.ConditionalUpdateObject(testWorkload("beta", "client", "10.2.0.1"))
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		addressResourceName("alpha", "client"),
		addressResourceName("beta", "client"))

	recorder := newRecorder(fixture.compiler.Resources())

	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name: "deny-all", Global: true,
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	})

	for _, namespace := range []string{"alpha", "beta"} {
		expected := addressResourceName(namespace, "client")
		eventually(t, func() bool { return recorder.has(expected) },
			"global policy invalidated "+namespace)
	}
}

// An endpoint edit must reach the workload that owns the endpoint address, and
// only that workload.
func TestEndpointEditReachesOnlyItsWorkload(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.workloads.ConditionalUpdateObject(testWorkload("alpha", "client", "10.1.0.1"))
	fixture.workloads.ConditionalUpdateObject(testWorkload("alpha", "other", "10.1.0.2"))
	fixture.services.ConditionalUpdateObject(model.Service{
		Namespace: "alpha", Name: "backend", Hostname: "backend.alpha.svc.cluster.local",
		Ports: []model.ServicePort{{Name: "http", Port: 80, TargetPort: 8080, Protocol: "TCP"}},
	})
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		addressResourceName("alpha", "client"),
		addressResourceName("alpha", "other"))

	recorder := newRecorder(fixture.compiler.Resources())

	fixture.endpoints.ConditionalUpdateObject(model.Endpoint{
		ServiceKey: "alpha/backend.alpha.svc.cluster.local", SourceKey: "alpha/backend-abc",
		Address: "10.1.0.1", PortName: "http", Port: 8080, Protocol: "TCP", Ready: true,
	})

	eventually(t, func() bool {
		return recorder.has(addressResourceName("alpha", "client"))
	}, "endpoint reached its own workload")
	settle()

	if recorder.has(addressResourceName("alpha", "other")) {
		t.Fatalf("an endpoint for 10.1.0.1 invalidated the workload at 10.1.0.2; changed=%v", recorder.names())
	}
}

func TestEndpointTargetUIDMovementAndStalePodReplacementKeepDependencies(t *testing.T) {
	fixture := newIncrementalFixture(t)
	podA := workloadWithSourceUID("alpha", "pod-a", "10.1.0.1", "uid-a")
	podB := workloadWithSourceUID("alpha", "pod-b", "10.1.0.1", "uid-b")
	podC := workloadWithSourceUID("alpha", "pod-c", "10.1.0.1", "uid-c")
	for _, workload := range []model.Workload{podA, podB, podC} {
		fixture.workloads.ConditionalUpdateObject(workload)
	}
	fixture.services.ConditionalUpdateObject(incrementalService("backend", "backend.alpha.svc.cluster.local", 8080))
	endpointA := incrementalTargetEndpoint("backend.alpha.svc.cluster.local", "uid-a", "pod-a")
	fixture.endpoints.ConditionalUpdateObject(endpointA)
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		addressResourceName("alpha", "pod-a"), addressResourceName("alpha", "pod-b"), addressResourceName("alpha", "pod-c"))
	eventually(t, func() bool {
		return workloadHasTargetPort(t, fixture.compiler, podA, 8080)
	}, "UID-targeted endpoint attached to pod-a")
	settle()

	recorder := newRecorder(fixture.compiler.Resources())
	endpointB := incrementalTargetEndpoint("backend.alpha.svc.cluster.local", "uid-b", "pod-b")
	fixture.endpoints.DeleteObject(endpointA.ResourceName())
	fixture.endpoints.ConditionalUpdateObject(endpointB)
	assertWorkloadEvents(t, recorder, []model.Workload{podA, podB}, []model.Workload{podC})
	if workloadHasService(t, fixture.compiler, podA, "backend.alpha.svc.cluster.local") {
		t.Fatal("pod-a retained service after target UID moved")
	}
	if !workloadHasTargetPort(t, fixture.compiler, podB, 8080) {
		t.Fatal("pod-b did not gain service after target UID moved")
	}

	recorder.reset()
	replacementB := podB
	replacementB.SourceUID = "uid-b-replacement"
	fixture.workloads.ConditionalUpdateObject(replacementB)
	assertWorkloadEvents(t, recorder, []model.Workload{replacementB}, []model.Workload{podA, podC})
	if workloadHasService(t, fixture.compiler, replacementB, "backend.alpha.svc.cluster.local") {
		t.Fatal("same-name replacement Pod attached endpoint for stale Kubernetes UID")
	}
}

func TestEndpointTargetNameMovementKeepsUIDLessDependencies(t *testing.T) {
	fixture := newIncrementalFixture(t)
	podA := testWorkload("alpha", "pod-a", "10.1.0.1")
	podB := testWorkload("alpha", "pod-b", "10.1.0.1")
	podC := testWorkload("alpha", "pod-c", "10.1.0.1")
	for _, workload := range []model.Workload{podA, podB, podC} {
		fixture.workloads.ConditionalUpdateObject(workload)
	}
	fixture.services.ConditionalUpdateObject(incrementalService("backend", "backend.alpha.svc.cluster.local", 8080))
	endpointA := incrementalTargetEndpoint("backend.alpha.svc.cluster.local", "", "pod-a")
	fixture.endpoints.ConditionalUpdateObject(endpointA)
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		addressResourceName("alpha", "pod-a"), addressResourceName("alpha", "pod-b"), addressResourceName("alpha", "pod-c"))
	eventually(t, func() bool {
		return workloadHasTargetPort(t, fixture.compiler, podA, 8080)
	}, "UID-less endpoint attached to pod-a by namespace/name")
	settle()

	recorder := newRecorder(fixture.compiler.Resources())
	endpointB := incrementalTargetEndpoint("backend.alpha.svc.cluster.local", "", "pod-b")
	fixture.endpoints.DeleteObject(endpointA.ResourceName())
	fixture.endpoints.ConditionalUpdateObject(endpointB)
	assertWorkloadEvents(t, recorder, []model.Workload{podA, podB}, []model.Workload{podC})
	if workloadHasService(t, fixture.compiler, podA, "backend.alpha.svc.cluster.local") {
		t.Fatal("pod-a retained service after UID-less target name moved")
	}
	if !workloadHasTargetPort(t, fixture.compiler, podB, 8080) {
		t.Fatal("pod-b did not gain service after UID-less target name moved")
	}
}

func TestServicePortAddUpdateDeleteKeepsWorkloadDependency(t *testing.T) {
	fixture := newIncrementalFixture(t)
	podA := testWorkload("alpha", "pod-a", "10.1.0.1")
	podB := testWorkload("alpha", "pod-b", "10.1.0.2")
	fixture.workloads.ConditionalUpdateObject(podA)
	fixture.workloads.ConditionalUpdateObject(podB)
	fixture.endpoints.ConditionalUpdateObject(incrementalAddressEndpoint("backend.alpha.svc.cluster.local", "10.1.0.1", 8080))
	fixture.endpoints.ConditionalUpdateObject(incrementalAddressEndpoint("other.alpha.svc.cluster.local", "10.1.0.2", 7070))
	valid := incrementalService("backend", "backend.alpha.svc.cluster.local", 8080)
	fixture.services.ConditionalUpdateObject(valid)
	fixture.services.ConditionalUpdateObject(incrementalService("other", "other.alpha.svc.cluster.local", 7070))
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, addressResourceName("alpha", "pod-a"), addressResourceName("alpha", "pod-b"))
	eventually(t, func() bool {
		return workloadHasTargetPort(t, fixture.compiler, podA, 8080)
	}, "initial Service mapping compiled")
	settle()

	// A delete leaves a missing-key Fetch dependency behind. The following add
	// must still reach pod-a, proving the edge was not lost.
	recorder := newRecorder(fixture.compiler.Resources())
	fixture.services.DeleteObject(valid.ResourceName())
	assertWorkloadEvents(t, recorder, []model.Workload{podA}, []model.Workload{podB})
	if workloadHasService(t, fixture.compiler, podA, "backend.alpha.svc.cluster.local") {
		t.Fatal("Service delete left workload service mapping")
	}

	recorder.reset()
	fixture.services.ConditionalUpdateObject(valid)
	assertWorkloadEvents(t, recorder, []model.Workload{podA}, []model.Workload{podB})
	if !workloadHasTargetPort(t, fixture.compiler, podA, 8080) {
		t.Fatal("Service add did not publish 80->8080 mapping")
	}

	recorder.reset()
	contradictory := incrementalService("backend", "backend.alpha.svc.cluster.local", 9090)
	fixture.services.ConditionalUpdateObject(contradictory)
	assertWorkloadEvents(t, recorder, []model.Workload{podA}, []model.Workload{podB})
	if ports := workloadServicePorts(t, fixture.compiler, podA, "backend.alpha.svc.cluster.local"); len(ports) != 0 {
		t.Fatalf("contradictory Service update ports = %+v, want omitted mapping", ports)
	}

	recorder.reset()
	fixture.services.DeleteObject(contradictory.ResourceName())
	assertWorkloadEvents(t, recorder, []model.Workload{podA}, []model.Workload{podB})
	if workloadHasService(t, fixture.compiler, podA, "backend.alpha.svc.cluster.local") {
		t.Fatal("Service delete left workload service mapping")
	}

	// Re-add once more after the update/delete cycle so all three mutation types
	// prove their dependency edge remains live.
	recorder.reset()
	fixture.services.ConditionalUpdateObject(valid)
	assertWorkloadEvents(t, recorder, []model.Workload{podA}, []model.Workload{podB})
	if !workloadHasTargetPort(t, fixture.compiler, podA, 8080) {
		t.Fatal("Service re-add did not trigger workload after missing-key fetch")
	}
}

func workloadWithSourceUID(namespace, name, address, uid string) model.Workload {
	result := testWorkload(namespace, name, address)
	result.SourceUID = uid
	return result
}

func incrementalService(name, hostname string, targetPort uint32) model.Service {
	return model.Service{
		Namespace: "alpha", Name: name, Hostname: hostname,
		Ports: []model.ServicePort{{Name: "http", Port: 80, TargetPort: targetPort, Protocol: "TCP"}},
	}
}

func incrementalTargetEndpoint(hostname, targetUID, targetName string) model.Endpoint {
	return model.Endpoint{
		ServiceKey: "alpha/" + hostname, SourceKey: "alpha/" + targetName + "-slice",
		Address: "10.1.0.1", PortName: "http", Port: 8080, Protocol: "TCP", Ready: true,
		HasTargetRef: true, TargetKind: "Pod", TargetUID: targetUID,
		TargetNamespace: "alpha", TargetName: targetName,
	}
}

func incrementalAddressEndpoint(hostname, address string, port uint32) model.Endpoint {
	return model.Endpoint{
		ServiceKey: "alpha/" + hostname, SourceKey: "alpha/" + hostname + "-slice",
		Address: address, PortName: "http", Port: port, Protocol: "TCP", Ready: true,
	}
}

func assertWorkloadEvents(t testing.TB, recorder *recorder, affected, unaffected []model.Workload) {
	t.Helper()
	eventually(t, func() bool {
		for _, workload := range affected {
			if !recorder.has(model.AddressType + "|" + workload.UID) {
				return false
			}
		}
		return true
	}, "affected workload resources changed")
	settle()
	for _, workload := range affected {
		if !recorder.has(model.AddressType + "|" + workload.UID) {
			t.Fatalf("affected workload %s did not change canonical Address; events=%v", workload.UID, recorder.names())
		}
	}
	for _, workload := range unaffected {
		if recorder.has(model.AddressType + "|" + workload.UID) {
			t.Fatalf("unaffected workload %s changed; events=%v", workload.UID, recorder.names())
		}
	}
}

func workloadHasTargetPort(t testing.TB, compiler *Compiler, workloadInput model.Workload, targetPort uint32) bool {
	t.Helper()
	ports := workloadServicePorts(t, compiler, workloadInput, "backend.alpha.svc.cluster.local")
	return len(ports) == 1 && ports[0].GetServicePort() == 80 && ports[0].GetTargetPort() == targetPort
}

func workloadHasService(t testing.TB, compiler *Compiler, workloadInput model.Workload, hostname string) bool {
	t.Helper()
	workload := compiledWorkload(t, compiler, workloadInput)
	_, found := workload.GetServices()[workloadInput.Namespace+"/"+hostname]
	return found
}

func workloadServicePorts(t testing.TB, compiler *Compiler, workloadInput model.Workload, hostname string) []*workloadv1.Port {
	t.Helper()
	workload := compiledWorkload(t, compiler, workloadInput)
	return workload.GetServices()[workloadInput.Namespace+"/"+hostname].GetPorts()
}

func compiledWorkload(t testing.TB, compiler *Compiler, workloadInput model.Workload) *workloadv1.Workload {
	t.Helper()
	resource, found := currentSnapshot(t, compiler).Get(model.ResourceKey{
		TypeURL: model.AddressType,
		Name:    workloadInput.UID,
	})
	if !found {
		t.Fatalf("workload resource %s missing", workloadInput.UID)
	}
	address := &workloadv1.Address{}
	if err := resource.Value.UnmarshalTo(address); err != nil {
		t.Fatalf("unmarshal workload %s: %v", workloadInput.UID, err)
	}
	return address.GetWorkload()
}

// DNS results are keyed krt objects, so changing an address propagates to the
// policies that fetched that hostname.
func TestDNSChangePropagatesThroughCollection(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.workloads.ConditionalUpdateObject(testWorkload("alpha", "client", "10.1.0.1"))
	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name: "fqdn", Namespace: "alpha",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "api.example.com"}},
			}}},
		},
	})
	waitSynced(t, fixture.compiler)

	authorizationKey := model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: "alpha/fqdn-egress"}
	var unresolvedHash string
	eventually(t, func() bool {
		resource, found := currentSnapshot(t, fixture.compiler).Get(authorizationKey)
		if found {
			unresolvedHash = resource.Hash
		}
		return found
	}, "authorization published before resolution")

	fixture.setResolved("api.example.com", netip.MustParseAddr("203.0.113.7"))

	eventually(t, func() bool {
		resource, found := currentSnapshot(t, fixture.compiler).Get(authorizationKey)
		return found && resource.Hash != unresolvedHash
	}, "DNS resolution recompiled the authorization")
}

func TestDNSChangeOnlyRecompilesPoliciesForThatHostname(t *testing.T) {
	fixture := newIncrementalFixture(t)
	for _, policy := range []struct {
		name string
		host string
	}{
		{name: "api", host: "api.example.com"},
		{name: "database", host: "database.example.com"},
	} {
		fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
			Name: policy.name, Namespace: "alpha",
			Spec: agentsv1alpha1.TrafficPolicySpec{
				Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
					Action: agentsv1alpha1.RuleActionAllow,
					To:     []agentsv1alpha1.TrafficPolicyPeer{{FQDN: policy.host}},
				}}},
			},
		})
	}
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		return fixture.resolutionCount("api.example.com") > 0 && fixture.resolutionCount("database.example.com") > 0
	}, "both policies compiled")

	authorizationKey := model.ResourceKey{TypeURL: model.WorkloadAuthorizationType, Name: "alpha/api-egress"}
	var unresolvedHash string
	eventually(t, func() bool {
		resource, found := currentSnapshot(t, fixture.compiler).Get(authorizationKey)
		if found {
			unresolvedHash = resource.Hash
		}
		return found
	}, "API authorization published before resolution")
	databaseCalls := fixture.resolutionCount("database.example.com")

	fixture.setResolved("api.example.com", netip.MustParseAddr("203.0.113.7"))
	eventually(t, func() bool {
		resource, found := currentSnapshot(t, fixture.compiler).Get(authorizationKey)
		return found && resource.Hash != unresolvedHash
	}, "API DNS resolution recompiled its authorization")
	settle()

	if got := fixture.resolutionCount("database.example.com"); got != databaseCalls {
		t.Fatalf("unrelated DNS policy recompiled: database resolution calls = %d, want %d", got, databaseCalls)
	}
}

// One malformed object must not stop the rest of the configuration from publishing.
func TestMalformedPolicyIsOmittedWhileRestPublishes(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.workloads.ConditionalUpdateObject(testWorkload("alpha", "client", "10.1.0.1"))
	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name: "broken", Namespace: "alpha", SandboxUID: "sandbox-a",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				"app": "client", agentsv1alpha1.LabelSandboxID: "sandbox-b",
			}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	})
	waitSynced(t, fixture.compiler)

	eventually(t, func() bool {
		_, found := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{
			TypeURL: model.AddressType, Name: "cluster//Pod/alpha/client"})
		return found
	}, "workload published despite the broken policy")

	snapshot := currentSnapshot(t, fixture.compiler)
	if _, found := snapshot.Get(model.ResourceKey{
		TypeURL: model.WorkloadAuthorizationType, Name: "alpha/broken-egress"}); found {
		t.Fatal("a policy with conflicting Sandbox UIDs produced an Authorization")
	}
	eventually(t, func() bool { return len(fixture.compiler.Failures()) == 1 }, "failure is reported")

	failures := fixture.compiler.Failures()
	if _, found := failures["TrafficPolicy/namespaced/alpha/broken"]; !found {
		t.Fatalf("failure not attributed to the policy: %v", failures)
	}

	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name: "broken", Namespace: "alpha",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
			}}},
		},
	})
	eventually(t, func() bool {
		_, found := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{
			TypeURL: model.WorkloadAuthorizationType, Name: "alpha/broken-egress"})
		return found && len(fixture.compiler.Failures()) == 0
	}, "fixed policy publishes and clears the failure")
}

func TestDeletingMalformedTrafficPolicyClearsFailure(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name:       "broken",
		Namespace:  "alpha",
		SandboxUID: "sandbox-a",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				agentsv1alpha1.LabelSandboxID: "sandbox-b",
			}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{
				Rules: []agentsv1alpha1.TrafficPolicyRule{
					{
						Action: agentsv1alpha1.RuleActionAllow,
						To: []agentsv1alpha1.TrafficPolicyPeer{
							{
								CIDR: "10.0.0.0/24",
							},
						},
					},
				},
			},
		},
	})
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["TrafficPolicy/namespaced/alpha/broken"]
		return found
	}, "malformed policy failure")

	fixture.trafficPolicies.DeleteObject("namespaced/alpha/broken")
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["TrafficPolicy/namespaced/alpha/broken"]
		return !found
	}, "deleted malformed policy clears failure")
}

func TestDeletingMalformedSecurityProfileClearsFailure(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.securityProfiles.ConditionalUpdateObject(model.SecurityProfile{
		Name:      "broken",
		Namespace: "alpha",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{},
			Rules: []agentsv1alpha1.SecurityRule{
				{
					Name: "api",
					Match: []agentsv1alpha1.RuleMatch{
						{
							Domains: []string{"*foo.example.com"},
						},
					},
				},
			},
		},
	})
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["SecurityProfile/namespaced/alpha/broken"]
		return found
	}, "malformed profile failure")

	fixture.securityProfiles.DeleteObject("namespaced/alpha/broken")
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["SecurityProfile/namespaced/alpha/broken"]
		return !found
	}, "deleted malformed profile clears failure")
}

func TestDeletingInvalidWorkloadClearsDomainAndWDSFailures(t *testing.T) {
	t.Run("domain validation", func(t *testing.T) {
		fixture := newIncrementalFixture(t)
		workload := testWorkload("alpha", "client", "10.1.0.1")
		workload.Principal.Kind = "unsupported"
		fixture.workloads.ConditionalUpdateObject(workload)
		waitSynced(t, fixture.compiler)
		eventually(t, func() bool {
			_, found := fixture.compiler.Failures()["Workload/"+workload.UID]
			return found
		}, "invalid Workload failure")

		fixture.workloads.DeleteObject(workload.UID)
		eventually(t, func() bool {
			_, found := fixture.compiler.Failures()["Workload/"+workload.UID]
			return !found
		}, "deleted invalid Workload clears failure")
	})

	t.Run("wire projection", func(t *testing.T) {
		fixture := newIncrementalFixture(t)
		workload := testWorkload("alpha", "client", "10.1.0.1")
		workload.SandboxBindings = append(workload.SandboxBindings, model.SandboxBinding{
			SandboxUID: "sandbox-b",
		})
		fixture.workloads.ConditionalUpdateObject(workload)
		waitSynced(t, fixture.compiler)
		eventually(t, func() bool {
			_, found := fixture.compiler.Failures()["WDSWorkload/"+workload.UID]
			return found
		}, "invalid WDS projection failure")

		fixture.workloads.DeleteObject(workload.UID)
		eventually(t, func() bool {
			_, found := fixture.compiler.Failures()["WDSWorkload/"+workload.UID]
			return !found
		}, "deleted WDS input clears failure")
	})
}

func TestMalformedTrafficPolicyUpdatePreservesLastKnownGood(t *testing.T) {
	fixture := newIncrementalFixture(t)
	valid := model.TrafficPolicy{
		Name:      "allow",
		Namespace: "alpha",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "client",
				},
			},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{
				Rules: []agentsv1alpha1.TrafficPolicyRule{
					{
						Action: agentsv1alpha1.RuleActionAllow,
						To: []agentsv1alpha1.TrafficPolicyPeer{
							{
								CIDR: "10.0.0.0/24",
							},
						},
					},
				},
			},
		},
	}
	fixture.trafficPolicies.ConditionalUpdateObject(valid)
	waitSynced(t, fixture.compiler)

	key := model.ResourceKey{
		TypeURL: model.WorkloadAuthorizationType,
		Name:    "alpha/allow-egress",
	}
	eventually(t, func() bool {
		_, found := currentSnapshot(t, fixture.compiler).Get(key)
		return found
	}, "initial authorization resource")
	baseline, _ := currentSnapshot(t, fixture.compiler).Get(key)

	invalid := valid
	invalid.SandboxUID = "sandbox-a"
	invalid.Spec = *valid.Spec.DeepCopy()
	invalid.Spec.Selector.MatchLabels[agentsv1alpha1.LabelSandboxID] = "sandbox-b"
	fixture.trafficPolicies.ConditionalUpdateObject(invalid)
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["TrafficPolicy/namespaced/alpha/allow"]
		return found
	}, "invalid update failure")
	settle()

	retained, found := currentSnapshot(t, fixture.compiler).Get(key)
	if !found {
		t.Fatal("invalid update removed the last-known-good Authorization")
	}
	if retained.Hash != baseline.Hash {
		t.Fatalf("invalid update replaced the last-known-good Authorization: %s != %s", retained.Hash, baseline.Hash)
	}
}

func TestMalformedSecurityProfileUpdatePreservesLastKnownGood(t *testing.T) {
	fixture := newIncrementalFixture(t)
	valid := model.SecurityProfile{
		Name:      "terminate",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "client",
				},
			},
			Rules: []agentsv1alpha1.SecurityRule{
				{
					Name: "api",
					Match: []agentsv1alpha1.RuleMatch{
						{
							Domains: []string{"api.example.com"},
						},
					},
				},
			},
		},
	}
	fixture.securityProfiles.ConditionalUpdateObject(valid)
	waitSynced(t, fixture.compiler)

	key := "demo/terminate"
	eventually(t, func() bool {
		return fixture.compiler.graph.policies.sniPolicies.GetKey(key) != nil
	}, "initial SNI policy")
	baseline := fixture.compiler.graph.policies.sniPolicies.GetKey(key)

	invalid := valid
	invalid.Spec.Rules = append([]agentsv1alpha1.SecurityRule(nil), valid.Spec.Rules...)
	invalid.Spec.Rules[0].Match = append([]agentsv1alpha1.RuleMatch(nil), valid.Spec.Rules[0].Match...)
	invalid.Spec.Rules[0].Match[0].Domains = []string{"*foo.example.com"}
	fixture.securityProfiles.ConditionalUpdateObject(invalid)
	eventually(t, func() bool {
		_, found := fixture.compiler.Failures()["SecurityProfile/namespaced/demo/terminate"]
		return found
	}, "invalid update failure")
	settle()

	retained := fixture.compiler.graph.policies.sniPolicies.GetKey(key)
	if retained == nil || !retained.Equals(*baseline) {
		t.Fatal("invalid update replaced the last-known-good SNI policy")
	}
}

// Deleting an input must remove its resources rather than leave them stranded in
// the snapshot.
func TestWorkloadDeletionRemovesItsResources(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.workloads.ConditionalUpdateObject(testWorkload("alpha", "client", "10.1.0.1"))
	waitSynced(t, fixture.compiler)
	eventually(t, func() bool {
		_, found := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{
			TypeURL: model.AddressType, Name: "cluster//Pod/alpha/client"})
		return found
	}, "workload published")

	fixture.workloads.DeleteObject("cluster//Pod/alpha/client")

	eventually(t, func() bool {
		snapshot := currentSnapshot(t, fixture.compiler)
		_, address := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: "cluster//Pod/alpha/client"})
		return !address
	}, "canonical Address removed")
}

func currentSnapshot(t testing.TB, compiler *Compiler) model.ResourceSet {
	t.Helper()
	snapshot, err := compiler.Snapshot()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return snapshot
}
