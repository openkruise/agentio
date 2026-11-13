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
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/pkg/util/sets"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/internal/testutil"
	resolverdns "github.com/openkruise/agentio/pkg/dns/controller"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
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

// awaitSteadyState waits until every named resource exists and the graph has gone
// quiet; must run before registering an event recorder to avoid recording initial Adds.
func awaitSteadyState(t testing.TB, compiler *Compiler, names ...string) {
	t.Helper()
	testutil.Eventually(t, func() bool {
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

func newIncrementalFixture(t testing.TB, configure ...func(*Inputs)) *incrementalFixture {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}

	fixture := &incrementalFixture{
		sandboxes:          krt.NewMutableCollection[model.Sandbox](nil, nil, options...),
		workloads:          krt.NewMutableCollection[model.Workload](nil, nil, options...),
		services:           krt.NewMutableCollection[model.Service](nil, nil, options...),
		endpoints:          krt.NewMutableCollection[model.Endpoint](nil, nil, options...),
		trafficPolicies:    krt.NewMutableCollection[model.TrafficPolicy](nil, nil, options...),
		securityProfiles:   krt.NewMutableCollection[model.SecurityProfile](nil, nil, options...),
		gatewayPatches:     krt.NewMutableCollection[model.GatewayPatch](nil, nil, options...),
		telemetry:          krt.NewMutableCollection[model.Telemetry](nil, nil, options...),
		telemetryProviders: krt.NewStatic[model.TelemetryProviderOverrides](nil, true, options...),
		agentioConfig:      krt.NewMutableCollection[model.AgentioConfiguration](nil, nil, options...),
		dnsResults:         krt.NewMutableCollection[resolverdns.Result](nil, nil, options...),
		resolveCalls:       map[string]int{},
	}
	fixture.gateways = testGatewaySource(fixture.agentioConfig.AsCollection(), options...)

	inputs := validCompilerInputs(stop)
	inputs.Sandboxes = fixture.sandboxes.AsCollection()
	inputs.Workloads = fixture.workloads.AsCollection()
	inputs.Services = fixture.services.AsCollection()
	inputs.Endpoints = fixture.endpoints.AsCollection()
	inputs.Gateways = fixture.gateways
	inputs.TrafficPolicies = fixture.trafficPolicies.AsCollection()
	inputs.SecurityProfiles = fixture.securityProfiles.AsCollection()
	inputs.GatewayPatches = fixture.gatewayPatches.AsCollection()
	inputs.Telemetry = fixture.telemetry.AsCollection()
	inputs.TelemetryProviderOverrides = fixture.telemetryProviders
	inputs.AgentioConfig = fixture.agentioConfig.AsCollection()
	inputs.Resolve = fixture.resolve
	for _, apply := range configure {
		apply(&inputs)
	}
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	fixture.compiler = compiler
	return fixture
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
	if err := resourceValue(t, resource).UnmarshalTo(address); err != nil {
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

func testClusterGatewayPatch(
	t *testing.T,
	name, source, resourceVersion, target, altStatName string,
) model.GatewayPatch {
	t.Helper()
	policy, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace:       "demo",
		Name:            name,
		Source:          source,
		ResourceVersion: resourceVersion,
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
	resolved := krt.FetchOne(ctx, f.dnsResults.AsCollection(), krt.FilterKey(host))
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
		UID:       uid,
		Namespace: namespace,
		Name:      name,
		Addresses: []string{address},
		Labels:    map[string]string{"app": name},
		Ready:     true,
		Principal: model.MustServiceAccountPrincipal(namespace, "default"),
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

func workloadWithSourceUID(namespace, name, address, uid string) model.Workload {
	result := testWorkload(namespace, name, address)
	result.Source = model.SourceRef{Registry: "kubernetes/cluster", Key: uid}
	return result
}

func incrementalService(name, hostname string, targetPort uint32) model.Service {
	return model.Service{
		Namespace: "alpha",
		Name:      name,
		Hostname:  hostname,
		Ports:     []model.ServicePort{{Name: "http", Port: 80, TargetPort: targetPort, Protocol: "TCP"}},
	}
}

func incrementalTargetEndpoint(hostname, targetUID, targetName string) model.Endpoint {
	return model.Endpoint{
		ServiceKey:      "alpha/" + hostname,
		SourceKey:       "alpha/" + targetName + "-slice",
		Address:         "10.1.0.1",
		PortName:        "http",
		Port:            8080,
		Protocol:        "TCP",
		Ready:           true,
		HasTargetRef:    true,
		TargetKind:      "Pod",
		TargetUID:       targetUID,
		TargetNamespace: "alpha",
		TargetName:      targetName,
	}
}

func incrementalAddressEndpoint(hostname, address string, port uint32) model.Endpoint {
	return model.Endpoint{
		ServiceKey: "alpha/" + hostname,
		SourceKey:  "alpha/" + hostname + "-slice",
		Address:    address,
		PortName:   "http",
		Port:       port,
		Protocol:   "TCP",
		Ready:      true,
	}
}

func assertWorkloadEvents(t testing.TB, recorder *recorder, affected, unaffected []model.Workload) {
	t.Helper()
	testutil.Eventually(t, func() bool {
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

func workloadServicePorts(
	t testing.TB,
	compiler *Compiler,
	workloadInput model.Workload,
	hostname string,
) []*workloadv1.Port {
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
	if err := resourceValue(t, resource).UnmarshalTo(address); err != nil {
		t.Fatalf("unmarshal workload %s: %v", workloadInput.UID, err)
	}
	return address.GetWorkload()
}

func currentSnapshot(t testing.TB, compiler *Compiler) model.ResourceSet {
	t.Helper()
	snapshot, err := compiler.Snapshot()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return snapshot
}

const testServiceKey = "demo/backend.demo.svc.cluster.local"

func extensionNames(extensions []*workloadv1.Extension) []string {
	result := make([]string, 0, len(extensions))
	for _, extension := range extensions {
		result = append(result, extension.GetName())
	}
	return result
}

func testWDSWorkload(name, sourceUID, address string) model.Workload {
	uid := "cluster//Pod/demo/" + name
	return model.Workload{
		UID:       uid,
		Source:    model.SourceRef{Registry: "kubernetes/cluster", Key: sourceUID},
		Namespace: "demo",
		Name:      name,
		Addresses: []string{address},
		Ready:     true,
		Principal: model.MustServiceAccountPrincipal("demo", "default"),
	}
}

func compileWorkloadServices(
	t testing.TB,
	ports []model.ServicePort,
	endpoints []model.Endpoint,
	workloadInputs []model.Workload,
) (*workloadv1.Workload, string) {
	t.Helper()
	workloads, hashes := compileWorkloadsAndHashes(t, ports, endpoints, workloadInputs)
	return workloads[workloadInputs[0].Name], hashes[workloadInputs[0].Name]
}

func compileWorkloads(
	t testing.TB,
	ports []model.ServicePort,
	endpoints []model.Endpoint,
	workloadInputs []model.Workload,
) map[string]*workloadv1.Workload {
	t.Helper()
	workloads, _ := compileWorkloadsAndHashes(t, ports, endpoints, workloadInputs)
	return workloads
}

func compileWorkloadsAndHashes(
	t testing.TB,
	ports []model.ServicePort,
	endpoints []model.Endpoint,
	workloadInputs []model.Workload,
) (map[string]*workloadv1.Workload, map[string]string) {
	t.Helper()
	return compileWorkloadsAndHashesForService(t, model.Service{
		Namespace: "demo",
		Name:      "backend",
		Hostname:  "backend.demo.svc.cluster.local",
		Ports:     ports,
	}, endpoints, workloadInputs)
}

func compileWorkloadsAndHashesForService(
	t testing.TB,
	service model.Service,
	endpoints []model.Endpoint,
	workloadInputs []model.Workload,
) (map[string]*workloadv1.Workload, map[string]string) {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	inputs := validCompilerInputs(stop)
	inputs.Services = krt.NewStaticCollection(nil, []model.Service{service}, options...)
	inputs.Endpoints = krt.NewStaticCollection(nil, endpoints, options...)
	inputs.Workloads = krt.NewStaticCollection(nil, workloadInputs, options...)
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	snapshot := compileSynced(t, compiler)
	workloads := make(map[string]*workloadv1.Workload, len(workloadInputs))
	hashes := make(map[string]string, len(workloadInputs))
	for _, workloadInput := range workloadInputs {
		resource, found := snapshot.Get(model.ResourceKey{
			TypeURL: model.AddressType,
			Name:    workloadInput.UID,
		})
		if !found {
			t.Fatalf("workload %q missing", workloadInput.UID)
		}
		address := &workloadv1.Address{}
		if err := resourceValue(t, resource).UnmarshalTo(address); err != nil {
			t.Fatalf("unmarshal workload %q: %v", workloadInput.UID, err)
		}
		workloads[workloadInput.Name] = address.GetWorkload()
		hashes[workloadInput.Name] = resource.Hash
	}
	return workloads, hashes
}

func validCompilerInputs(stop <-chan struct{}) Inputs {
	options := []krt.CollectionOption{krt.WithStop(stop)}
	return Inputs{
		SandboxMode:                true,
		ClusterID:                  "cluster",
		RootNamespace:              "agentio-system",
		DiscoveryAddress:           "agentiod.agentio-system.svc:15012",
		TrustDomain:                "cluster.local",
		Sandboxes:                  krt.NewStaticCollection[model.Sandbox](nil, nil, options...),
		Workloads:                  krt.NewStaticCollection[model.Workload](nil, nil, options...),
		Pods:                       krt.NewStaticCollection[*corev1.Pod](nil, nil, options...),
		KubernetesServices:         krt.NewStaticCollection[*corev1.Service](nil, nil, options...),
		EndpointSlices:             krt.NewStaticCollection[*discoveryv1.EndpointSlice](nil, nil, options...),
		ConfigMaps:                 krt.NewStaticCollection[*corev1.ConfigMap](nil, nil, options...),
		Secrets:                    krt.NewStaticCollection[*corev1.Secret](nil, nil, options...),
		Services:                   krt.NewStaticCollection[model.Service](nil, nil, options...),
		Endpoints:                  krt.NewStaticCollection[model.Endpoint](nil, nil, options...),
		Gateways:                   krt.NewStaticCollection[model.Gateway](nil, nil, options...),
		TrafficPolicies:            krt.NewStaticCollection[model.TrafficPolicy](nil, nil, options...),
		SecurityProfiles:           krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...),
		GatewayPatches:             krt.NewStaticCollection[model.GatewayPatch](nil, nil, options...),
		Telemetry:                  krt.NewStaticCollection[model.Telemetry](nil, nil, options...),
		TelemetryProviderOverrides: krt.NewStatic[model.TelemetryProviderOverrides](nil, true, options...),
		AgentioConfig:              krt.NewStaticCollection[model.AgentioConfiguration](nil, nil, options...),
	}
}

// testGatewaySource models the Registry boundary for compiler-only tests. The
// production compiler receives a source-merged Gateway collection directly.
func testGatewaySource(
	configurations krt.Collection[model.AgentioConfiguration],
	options ...krt.CollectionOption,
) krt.Collection[model.Gateway] {
	return krt.NewManyCollection(configurations,
		func(_ krt.HandlerContext, configuration model.AgentioConfiguration) []model.Gateway {
			return model.GatewaysFromAgentioConfig(configuration.Value)
		}, options...)
}

// testSandboxForWorkload explicitly declares a Sandbox for a bound test fixture.
func testSandboxForWorkload(workload model.Workload) model.Sandbox {
	return model.Sandbox{
		Attester:  &model.Attester{WorkloadUID: workload.UID},
		UID:       workload.UID,
		Namespace: workload.Namespace,
	}
}

func waitForAddressUpdates(t testing.TB, updates *atomic.Uint64, target uint64) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for updates.Load() < target {
		if time.Now().After(deadline) {
			t.Fatalf("Address update wave did not complete: %d < %d", updates.Load(), target)
		}
		time.Sleep(500 * time.Microsecond)
	}
}

type dnsBenchmarkResult struct {
	host    string
	address netip.Addr
}

func (r dnsBenchmarkResult) ResourceName() string { return r.host }

func dnsScaleCompiler(t testing.TB, count int, dnsResults krt.Collection[dnsBenchmarkResult],
	stop <-chan struct{}, options []krt.CollectionOption, debugger *krt.DebugHandler,
) *Compiler {
	t.Helper()
	workloads := krt.NewMutableCollection[model.Workload](nil, nil, options...)
	sandboxes := krt.NewMutableCollection[model.Sandbox](nil, nil, options...)
	for index := range count {
		workload := testWDSWorkload(
			fmt.Sprintf("workload-%d", index),
			"",
			fmt.Sprintf("10.%d.%d.%d", (index/65536)%256, (index/256)%256, index%256),
		)
		workload.Labels = map[string]string{"app": "workload"}
		workloads.ConditionalUpdateObject(workload)
		sandboxes.ConditionalUpdateObject(testSandboxForWorkload(workload))
	}
	services := krt.NewStaticCollection[model.Service](nil, nil, options...)
	endpoints := krt.NewStaticCollection[model.Endpoint](nil, nil, options...)
	trafficPolicies := krt.NewStaticCollection[model.TrafficPolicy](nil, []model.TrafficPolicy{{
		Name:      "egress-default",
		Namespace: "demo",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "workload"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/8"}},
			}}},
		},
	}}, options...)
	securityProfiles := krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...)
	// The egress policy's match hostname is what pins the configuration
	// singleton to the DNS results collection.
	agentioConfig := krt.NewStaticCollection[model.AgentioConfiguration](nil, []model.AgentioConfiguration{{
		Value: &configv1.AgentioConfig{
			EgressGateways: []*configv1.EgressGateway{{Namespace: "demo", Name: "egress-0"}},
			EgressPolicies: []*extensionsv1.EgressPolicy{{MatchHosts: []string{"api.example.com"}}},
		},
	}}, options...)

	inputs := validCompilerInputs(stop)
	inputs.SandboxMode = false
	inputs.Sandboxes = sandboxes.AsCollection()
	inputs.Workloads = workloads.AsCollection()
	inputs.Services = services
	inputs.Endpoints = endpoints
	inputs.Gateways = testGatewaySource(agentioConfig, options...)
	inputs.TrafficPolicies = trafficPolicies
	inputs.SecurityProfiles = securityProfiles
	inputs.AgentioConfig = agentioConfig
	inputs.Resolve = func(ctx krt.HandlerContext, host string) []netip.Addr {
		if result := krt.FetchOne(ctx, dnsResults, krt.FilterKey(host)); result != nil {
			return []netip.Addr{result.address}
		}
		return nil
	}
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", debugger))
	if err != nil {
		t.Fatal(err)
	}
	return compiler
}

// waitSynced blocks until the compiler's derived collections are populated.
func waitSynced(t testing.TB, compiler *Compiler) {
	t.Helper()
	waitSyncedWithin(t, compiler, 30*time.Second)
}

func waitSyncedWithin(t testing.TB, compiler *Compiler, timeout time.Duration) {
	t.Helper()
	stop := make(chan struct{})
	timer := time.AfterFunc(timeout, func() { close(stop) })
	defer timer.Stop()
	if !compiler.WaitUntilSynced(stop) {
		t.Fatalf("compiler did not sync within %s", timeout)
	}
}

// compileSynced waits for the graph and then compiles, failing the test on error.
func compileSynced(t testing.TB, compiler *Compiler) model.ResourceSet {
	t.Helper()
	waitSynced(t, compiler)
	snapshot, err := compiler.Snapshot()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if failures := compiler.Failures(); len(failures) > 0 {
		t.Fatalf("objects failed to compile: %v", failures)
	}
	return snapshot
}

func resourceValue(t testing.TB, resource model.Resource) *anypb.Any {
	t.Helper()
	if resource.Value != nil {
		return resource.Value
	}
	encoded, err := resource.Generate(model.ClientScope{Class: model.ClientEgressGateway}, resource.Key.TypeURL)
	if err != nil {
		t.Fatal(err)
	}
	return encoded.Value
}
