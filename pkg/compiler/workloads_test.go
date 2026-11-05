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
	"reflect"
	"sync/atomic"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// An endpoint edit must reach the workload that owns the endpoint address, and
// only that workload.
func TestEndpointEditReachesOnlyItsWorkload(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.workloads.ConditionalUpdateObject(testWorkload("alpha", "client", "10.1.0.1"))
	fixture.workloads.ConditionalUpdateObject(testWorkload("alpha", "other", "10.1.0.2"))
	fixture.services.ConditionalUpdateObject(model.Service{
		Namespace: "alpha",
		Name:      "backend",
		Hostname:  "backend.alpha.svc.cluster.local",
		Ports:     []model.ServicePort{{Name: "http", Port: 80, TargetPort: 8080, Protocol: "TCP"}},
	})
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler,
		addressResourceName("alpha", "client"),
		addressResourceName("alpha", "other"))

	recorder := newRecorder(fixture.compiler.Resources())

	fixture.endpoints.ConditionalUpdateObject(model.Endpoint{
		ServiceKey: "alpha/backend.alpha.svc.cluster.local",
		SourceKey:  "alpha/backend-abc",
		Address:    "10.1.0.1",
		PortName:   "http",
		Port:       8080,
		Protocol:   "TCP",
		Ready:      true,
	})

	testutil.Eventually(t, func() bool {
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
	awaitSteadyState(
		t,
		fixture.compiler,
		addressResourceName(
			"alpha",
			"pod-a",
		),
		addressResourceName("alpha", "pod-b"),
		addressResourceName("alpha", "pod-c"),
	)
	testutil.Eventually(t, func() bool {
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
	replacementB.Source.Key = "uid-b-replacement"
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
	awaitSteadyState(
		t,
		fixture.compiler,
		addressResourceName(
			"alpha",
			"pod-a",
		),
		addressResourceName("alpha", "pod-b"),
		addressResourceName("alpha", "pod-c"),
	)
	testutil.Eventually(t, func() bool {
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
	fixture.endpoints.ConditionalUpdateObject(
		incrementalAddressEndpoint("backend.alpha.svc.cluster.local", "10.1.0.1", 8080),
	)
	fixture.endpoints.ConditionalUpdateObject(
		incrementalAddressEndpoint("other.alpha.svc.cluster.local", "10.1.0.2", 7070),
	)
	valid := incrementalService("backend", "backend.alpha.svc.cluster.local", 8080)
	fixture.services.ConditionalUpdateObject(valid)
	fixture.services.ConditionalUpdateObject(incrementalService("other", "other.alpha.svc.cluster.local", 7070))
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, addressResourceName("alpha", "pod-a"), addressResourceName("alpha", "pod-b"))
	testutil.Eventually(t, func() bool {
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

func TestDeletingInvalidWorkloadClearsDomainAndWDSFailures(t *testing.T) {
	t.Run("domain validation", func(t *testing.T) {
		fixture := newIncrementalFixture(t)
		workload := testWorkload("alpha", "client", "10.1.0.1")
		workload.TunnelProtocol = "unsupported"
		fixture.workloads.ConditionalUpdateObject(workload)
		waitSynced(t, fixture.compiler)
		testutil.Eventually(t, func() bool {
			_, found := fixture.compiler.Failures()["Workload/"+workload.UID]
			return found
		}, "invalid Workload failure")

		fixture.workloads.DeleteObject(workload.UID)
		testutil.Eventually(t, func() bool {
			_, found := fixture.compiler.Failures()["Workload/"+workload.UID]
			return !found
		}, "deleted invalid Workload clears failure")
	})

	t.Run("wire projection", func(t *testing.T) {
		fixture := newIncrementalFixture(t)
		workload := testWorkload("alpha", "client", "10.1.0.1")
		workload.Addresses = []string{"not-an-ip"}
		fixture.workloads.ConditionalUpdateObject(workload)
		waitSynced(t, fixture.compiler)
		testutil.Eventually(t, func() bool {
			_, found := fixture.compiler.Failures()["WDSWorkload/"+workload.UID]
			return found
		}, "invalid WDS projection failure")

		fixture.workloads.DeleteObject(workload.UID)
		testutil.Eventually(t, func() bool {
			_, found := fixture.compiler.Failures()["WDSWorkload/"+workload.UID]
			return !found
		}, "deleted WDS input clears failure")
	})
}

// Deleting an input must remove its resources rather than leave them stranded in
// the snapshot.
func TestWorkloadDeletionRemovesItsResources(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.workloads.ConditionalUpdateObject(testWorkload("alpha", "client", "10.1.0.1"))
	waitSynced(t, fixture.compiler)
	testutil.Eventually(t, func() bool {
		_, found := currentSnapshot(t, fixture.compiler).Get(model.ResourceKey{
			TypeURL: model.AddressType,
			Name:    "cluster//Pod/alpha/client",
		})
		return found
	}, "workload published")

	fixture.workloads.DeleteObject("cluster//Pod/alpha/client")

	testutil.Eventually(t, func() bool {
		snapshot := currentSnapshot(t, fixture.compiler)
		_, address := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: "cluster//Pod/alpha/client"})
		return !address
	}, "canonical Address removed")
}

func TestCompilerPublishesDiscoveryOnlyWorkload(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workload := testWDSWorkload("opaque-endpoint", "", "10.0.0.9")
	workload.Principal = model.Principal{}

	workload.HostNetwork = true

	inputs := validCompilerInputs(stop)
	inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{workload}, options...)
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := compileSynced(t, compiler)
	resource, found := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: workload.UID})
	if !found {
		t.Fatalf("discovery-only WDS Address %q is missing; failures: %v", workload.UID, compiler.Failures())
	}
	address := &workloadv1.Address{}
	if err := resource.Value.UnmarshalTo(address); err != nil {
		t.Fatal(err)
	}
	if got := address.GetWorkload().GetNetworkMode(); got != workloadv1.NetworkMode_HOST_NETWORK {
		t.Fatalf("network mode = %v, want HOST_NETWORK", got)
	}
	if got := address.GetWorkload().GetAuthorizationPolicies(); len(got) != 0 {
		t.Fatalf("authorization policies = %v, want none", got)
	}
}

func TestWorkloadServicePortsPreserveServiceAndTargetPorts(t *testing.T) {
	tests := []struct {
		name      string
		service   model.ServicePort
		endpoint  model.Endpoint
		wantPorts []*workloadv1.Port
	}{
		{
			name: "numeric target port",
			service: model.ServicePort{
				Name:       "http",
				Port:       80,
				TargetPort: 8080,
				Protocol:   "TCP",
			},
			endpoint: model.Endpoint{
				ServiceKey: testServiceKey,
				SourceKey:  "demo/backend-a",
				Address:    "10.0.0.1",
				PortName:   "http",
				Port:       8080,
				Protocol:   "TCP",
				Ready:      true,
			},
			wantPorts: []*workloadv1.Port{{ServicePort: 80, TargetPort: 8080}},
		},
		{
			name: "numeric target port contradicting EndpointSlice is omitted",
			service: model.ServicePort{
				Name:       "http",
				Port:       80,
				TargetPort: 8080,
				Protocol:   "TCP",
			},
			endpoint: model.Endpoint{
				ServiceKey: testServiceKey,
				SourceKey:  "demo/backend-a",
				Address:    "10.0.0.1",
				PortName:   "http",
				Port:       9090,
				Protocol:   "TCP",
				Ready:      true,
			},
			wantPorts: nil,
		},
		{
			name: "named target port retained while service port name is EndpointSlice join key",
			service: model.ServicePort{
				Name:           "web",
				Port:           81,
				TargetPortName: "http-backend",
				Protocol:       "TCP",
			},
			endpoint: model.Endpoint{
				ServiceKey: testServiceKey,
				SourceKey:  "demo/backend-a",
				Address:    "10.0.0.1",
				PortName:   "web",
				Port:       9090,
				Protocol:   "TCP",
				Ready:      true,
			},
			wantPorts: []*workloadv1.Port{{ServicePort: 81, TargetPort: 9090}},
		},
		{
			name: "named target port with mismatched service port name is omitted",
			service: model.ServicePort{
				Name:           "web",
				Port:           81,
				TargetPortName: "http-backend",
				Protocol:       "TCP",
			},
			endpoint: model.Endpoint{
				ServiceKey: testServiceKey,
				SourceKey:  "demo/backend-a",
				Address:    "10.0.0.1",
				PortName:   "metrics",
				Port:       9090,
				Protocol:   "TCP",
				Ready:      true,
			},
			wantPorts: nil,
		},
		{
			name: "protocol mismatch is omitted",
			service: model.ServicePort{
				Name:       "dns",
				Port:       53,
				TargetPort: 5353,
				Protocol:   "UDP",
			},
			endpoint: model.Endpoint{
				ServiceKey: testServiceKey,
				SourceKey:  "demo/backend-a",
				Address:    "10.0.0.1",
				PortName:   "dns",
				Port:       5353,
				Protocol:   "TCP",
				Ready:      true,
			},
			wantPorts: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			workload, _ := compileWorkloadServices(t,
				[]model.ServicePort{tc.service}, []model.Endpoint{tc.endpoint},
				[]model.Workload{testWDSWorkload("pod-a", "pod-a-uid", "10.0.0.1")},
			)
			got := workload.GetServices()[testServiceKey]
			if got == nil {
				t.Fatalf("service %q missing", testServiceKey)
			}
			if !reflect.DeepEqual(got.GetPorts(), tc.wantPorts) {
				t.Fatalf("ports = %+v, want %+v", got.GetPorts(), tc.wantPorts)
			}
		})
	}
}

func TestPublishNotReadyServiceIncludesUnhealthyEndpoint(t *testing.T) {
	service := model.Service{
		Namespace:                "demo",
		Name:                     "backend",
		Hostname:                 "backend.demo.svc.cluster.local",
		PublishNotReadyAddresses: true,
		Ports: []model.ServicePort{
			{
				Name:       "http",
				Port:       80,
				TargetPort: 8080,
				Protocol:   "TCP",
			},
		},
	}
	workloads, _ := compileWorkloadsAndHashesForService(t, service, []model.Endpoint{
		{
			ServiceKey: testServiceKey,
			SourceKey:  "demo/backend-a",
			Address:    "10.0.0.1",
			PortName:   "http",
			Port:       8080,
			Protocol:   "TCP",
			Ready:      false,
		},
	}, []model.Workload{
		testWDSWorkload("pod-a", "pod-a-uid", "10.0.0.1"),
	})

	ports := workloads["pod-a"].GetServices()[testServiceKey].GetPorts()
	want := []*workloadv1.Port{
		{
			ServicePort: 80,
			TargetPort:  8080,
		},
	}
	if !reflect.DeepEqual(ports, want) {
		t.Fatalf("publish-not-ready ports = %+v, want %+v", ports, want)
	}
}

func TestWorkloadServicePortsAreStableAcrossEndpointOrder(t *testing.T) {
	ports := []model.ServicePort{
		{Name: "http", Port: 80, TargetPort: 8080, Protocol: "TCP"},
		{Name: "metrics", Port: 15020, TargetPortName: "metrics-backend", Protocol: "TCP"},
	}
	firstEndpoints := []model.Endpoint{
		{
			ServiceKey: testServiceKey,
			SourceKey:  "demo/backend-b",
			Address:    "10.0.0.1",
			PortName:   "metrics",
			Port:       15021,
			Protocol:   "TCP",
			Ready:      true,
		},
		{
			ServiceKey: testServiceKey,
			SourceKey:  "demo/backend-a",
			Address:    "10.0.0.1",
			PortName:   "http",
			Port:       8080,
			Protocol:   "TCP",
			Ready:      true,
		},
	}
	secondEndpoints := []model.Endpoint{firstEndpoints[1], firstEndpoints[0]}
	first, firstHash := compileWorkloadServices(
		t,
		ports,
		firstEndpoints,
		[]model.Workload{testWDSWorkload("pod-a", "pod-a-uid", "10.0.0.1")},
	)
	second, secondHash := compileWorkloadServices(
		t,
		[]model.ServicePort{ports[1], ports[0]},
		secondEndpoints,
		[]model.Workload{testWDSWorkload("pod-a", "pod-a-uid", "10.0.0.1")},
	)
	if !reflect.DeepEqual(first.GetServices(), second.GetServices()) {
		t.Fatalf(
			"service mappings differ by input order: first=%+v second=%+v",
			first.GetServices(),
			second.GetServices(),
		)
	}
	if firstHash != secondHash {
		t.Fatalf("workload hashes differ by input order: %s != %s", firstHash, secondHash)
	}
}

func TestEndpointTargetRefPreventsHostNetworkCrossAttachment(t *testing.T) {
	endpoint := model.Endpoint{
		ServiceKey:      testServiceKey,
		SourceKey:       "demo/backend-a",
		Address:         "10.0.0.1",
		PortName:        "http",
		Port:            8080,
		Protocol:        "TCP",
		Ready:           true,
		HasTargetRef:    true,
		TargetKind:      "Pod",
		TargetUID:       "pod-a-uid",
		TargetName:      "pod-a",
		TargetNamespace: "demo",
	}
	workloadInputs := []model.Workload{
		testWDSWorkload("pod-a", "pod-a-uid", "10.0.0.1"),
		testWDSWorkload("pod-b", "pod-b-uid", "10.0.0.1"),
	}
	workloads := compileWorkloads(t, []model.ServicePort{{
		Name:       "http",
		Port:       80,
		TargetPort: 8080,
		Protocol:   "TCP",
	}}, []model.Endpoint{endpoint}, workloadInputs)
	if _, found := workloads["pod-a"].GetServices()[testServiceKey]; !found {
		t.Fatalf("pod-a services = %+v, want %q", workloads["pod-a"].GetServices(), testServiceKey)
	}
	if _, found := workloads["pod-b"].GetServices()[testServiceKey]; found {
		t.Fatalf("pod-b cross-attached targetRef service: %+v", workloads["pod-b"].GetServices())
	}

	stale := endpoint
	stale.TargetUID = "stale-pod-a-uid"
	workloads = compileWorkloads(t, []model.ServicePort{{
		Name:       "http",
		Port:       80,
		TargetPort: 8080,
		Protocol:   "TCP",
	}}, []model.Endpoint{stale}, workloadInputs[:1])
	if _, found := workloads["pod-a"].GetServices()[testServiceKey]; found {
		t.Fatalf("stale UID attached by matching name or IP: %+v", workloads["pod-a"].GetServices())
	}
}

func TestEndpointTargetRefUsesNameOnlyWithoutUIDAndIPOnlyWithoutRef(t *testing.T) {
	base := model.Endpoint{
		ServiceKey: testServiceKey,
		SourceKey:  "demo/backend-a",
		Address:    "10.0.0.1",
		PortName:   "http",
		Port:       8080,
		Protocol:   "TCP",
		Ready:      true,
	}
	workloadInputs := []model.Workload{
		testWDSWorkload("pod-a", "pod-a-uid", "10.0.0.1"),
		testWDSWorkload("pod-b", "pod-b-uid", "10.0.0.1"),
	}
	servicePorts := []model.ServicePort{{
		Name:       "http",
		Port:       80,
		TargetPort: 8080,
		Protocol:   "TCP",
	}}

	byName := base
	byName.HasTargetRef = true
	byName.TargetKind = "Pod"
	byName.TargetName = "pod-a"
	byName.TargetNamespace = "demo"
	workloads := compileWorkloads(t, servicePorts, []model.Endpoint{byName}, workloadInputs)
	if _, found := workloads["pod-a"].GetServices()[testServiceKey]; !found {
		t.Fatalf("UID-less targetRef did not attach by name: %+v", workloads["pod-a"].GetServices())
	}
	if _, found := workloads["pod-b"].GetServices()[testServiceKey]; found {
		t.Fatalf("UID-less targetRef fell back to shared IP: %+v", workloads["pod-b"].GetServices())
	}

	workloads = compileWorkloads(t, servicePorts, []model.Endpoint{base}, workloadInputs)
	for _, name := range []string{"pod-a", "pod-b"} {
		if _, found := workloads[name].GetServices()[testServiceKey]; !found {
			t.Fatalf(
				"targetRef-absent endpoint did not use IP fallback for %s: %+v",
				name,
				workloads[name].GetServices(),
			)
		}
	}
}

func TestWorkloadInlineSNIPolicyLifecycle(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	builder := krt.NewOptionsBuilder(stop, "inline-test", nil)
	options := func(name string) []krt.CollectionOption { return builder.WithName(name) }
	bindings := krt.NewMutableCollection[policy.Bindings](nil, nil, options("bindings")...)
	payloads := krt.NewMutableCollection[policy.CompiledSecurityProfile](nil, nil, options("payloads")...)
	workload := testWDSWorkload("client", "", "10.1.0.2")

	workloads := krt.NewMutableCollection(nil, []model.Workload{workload}, options("workloads")...)
	inputs := validCompilerInputs(stop)
	inputs.Workloads = workloads.AsCollection()
	inputs.SandboxMode = false
	inputs.Sandboxes = krt.NewStaticCollection(
		nil,
		[]model.Sandbox{{UID: workload.UID, Attester: &model.Attester{WorkloadUID: workload.UID}}},
		options("sandboxes")...)
	failures := newFailureRecorder()
	policies := policyCollections{
		policyBindings:   bindings.AsCollection(),
		securityProfiles: payloads.AsCollection(),
		trafficPolicies:  krt.NewStaticCollection[policy.CompiledTrafficPolicy](nil, nil, options("traffic")...),
	}
	compatibility := newWorkloadPolicies(
		inputs,
		policies,
		krt.NewStaticCollection[compiledSandbox](nil, nil, options("compiled-sandboxes")...),
		failures,
		options,
	)
	metadata := krt.NewStatic[workloadMetadataConfiguration](nil, true, options("metadata")...)
	resolved := newWorkloadResources(inputs, newBaseIndexes(inputs), metadata,
		compatibility, failures, options)
	getPolicy := func() *extensionsv1.SniTrafficPolicy {
		resources := resolved.List()
		if len(resources) == 0 {
			return nil
		}
		address := &workloadv1.Address{}
		if err := resources[0].Value.UnmarshalTo(address); err != nil {
			t.Fatal(err)
		}
		for _, extension := range address.GetWorkload().Extensions {
			if extension.Name == "sni-traffic-policy" {
				payload := &extensionsv1.SniTrafficPolicy{}
				if err := extension.Config.UnmarshalTo(payload); err != nil {
					t.Fatal(err)
				}
				return payload
			}
		}
		return nil
	}
	var changes, withdrawals atomic.Int64
	resolved.RegisterBatch(func(events []krt.Event[model.Resource]) {
		changes.Add(int64(len(events)))
		for _, event := range events {
			if event.New == nil {
				withdrawals.Add(1)
			}
		}
	}, false)
	binding := func(names ...string) policy.Bindings {
		return policy.Bindings{
			TargetUID: workload.UID,
			Groups:    []policy.BindingGroup{{Kind: policy.PolicyKindSecurityProfile, Names: names}},
		}
	}
	payload := func(name, host string) policy.CompiledSecurityProfile {
		return policy.CompiledSecurityProfile{
			Name: name,
			SNIPolicy: &extensionsv1.SniTrafficPolicy{
				Rules: []*extensionsv1.SniRule{{Match: &extensionsv1.SniMatch{Sni: []string{host}}}},
			},
		}
	}
	expect := func(hosts ...string) {
		t.Helper()
		testutil.Eventually(t, func() bool {
			got := getPolicy()
			if got == nil || len(got.Rules) != len(hosts) {
				return false
			}
			for i, host := range hosts {
				if got.Rules[i].Match.Sni[0] != host {
					return false
				}
			}
			return true
		}, "complete ordered inline policy")
	}
	bindings.UpdateObject(binding("second", "first"))
	if !resolved.WaitUntilSynced(stop) {
		t.Fatal("sync failed")
	}
	if getPolicy() != nil || len(resolved.List()) != 1 {
		t.Fatal("missing policies must not suppress the Workload")
	}
	payloads.UpdateObject(payload("first", "first.example"))
	expect("first.example")
	payloads.UpdateObject(payload("second", "second.example"))
	expect("second.example", "first.example")
	// Rules-only edits must propagate without a binding event.
	payloads.UpdateObject(payload("first", "updated.example"))
	expect("second.example", "updated.example")
	// Unrelated policy changes must not invalidate this Workload.
	settle()
	before := changes.Load()
	payloads.UpdateObject(payload("unrelated", "other.example"))
	settle()
	if changes.Load() != before {
		t.Fatal("unrelated payload invalidated inline policy")
	}
	// A missing replacement is omitted while unrelated policies keep enforcing.
	bindings.UpdateObject(binding("second", "replacement"))
	testutil.Eventually(
		t,
		func() bool { return failures.snapshot()["WorkloadPolicies/"+workload.UID] != "" },
		"missing replacement records a failure",
	)
	expect("second.example")
	payloads.UpdateObject(payload("replacement", "replacement.example"))
	expect("second.example", "replacement.example")
	// Removing the attachment removes the extension instead of retaining old rules.
	bindings.UpdateObject(binding())
	testutil.Eventually(t, func() bool { return getPolicy() == nil }, "policy removal")
	bindings.UpdateObject(binding("first"))
	expect("updated.example")
	bindings.DeleteObject(workload.UID)
	testutil.Eventually(
		t,
		func() bool { return getPolicy() == nil && len(resolved.List()) == 1 },
		"binding removal preserves Workload networking",
	)
	settle()
	if withdrawals.Load() != 0 {
		t.Fatal("policy changes withdrew the Workload")
	}
	workloads.DeleteObject(workload.UID)
	testutil.Eventually(t, func() bool { return len(resolved.List()) == 0 }, "Workload deletion")
}

func TestSNIRulesOnlyUpdateDoesNotRecomputeWorkloadBindings(t *testing.T) {
	const workloadCount = 250
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	builder := krt.NewOptionsBuilder(stop, "", nil)

	workloads := krt.NewMutableCollection[model.Workload](nil, nil, options...)
	for index := range workloadCount {
		workloads.ConditionalUpdateObject(model.Workload{
			UID:       fmt.Sprintf("cluster//Pod/demo/workload-%d", index),
			Namespace: "demo",
			Labels:    map[string]string{"app": "workload"},
		})
	}
	profiles := krt.NewMutableCollection[model.SecurityProfile](nil, nil, options...)
	profile := model.SecurityProfile{
		Name:      "security-profile",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "workload"}},
			Rules: []agentsv1alpha1.SecurityRule{{
				Name:  "api",
				Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}},
			}},
		},
	}
	profiles.ConditionalUpdateObject(profile)

	var profileCompiles atomic.Int64
	compiled := krt.NewCollection(profiles.AsCollection(),
		func(_ krt.HandlerContext, profile model.SecurityProfile) *policy.CompiledSecurityProfile {
			profileCompiles.Add(1)
			result, err := policy.CompileSecurityProfile(profile)
			if err != nil {
				t.Errorf("compile SNI profile: %v", err)
			}
			return result
		}, append(options, krt.WithName("test-sni-policies"))...)
	projected := policy.NewPolicyAttachmentsCollection(compiled, builder, "security-profile-attachments")
	bindings := policy.NewWorkloadPolicyBindingsCollection(workloads.AsCollection(), projected, builder)

	var bindingRecomputes atomic.Int64
	observedBindings := krt.NewCollection(bindings,
		func(_ krt.HandlerContext, binding policy.Bindings) *policy.Bindings {
			bindingRecomputes.Add(1)
			return &binding
		}, append(options, krt.WithName("test-workload-bindings"))...)
	var inlineUpdates atomic.Int64
	inputs := validCompilerInputs(stop)
	inputs.SandboxMode = false
	inputs.Workloads = workloads.AsCollection()
	resources := newWorkloadPolicies(inputs, policyCollections{
		policyBindings:   bindings,
		securityProfiles: compiled,
		trafficPolicies:  krt.NewStaticCollection[policy.CompiledTrafficPolicy](nil, nil, options...),
	}, krt.NewStaticCollection[compiledSandbox](nil, nil, options...), newFailureRecorder(), builder.WithName)
	if !observedBindings.WaitUntilSynced(stop) || !resources.WaitUntilSynced(stop) {
		t.Fatal("test policy graph did not sync")
	}
	settle()
	resources.RegisterBatch(func(events []krt.Event[workloadPolicies]) {
		inlineUpdates.Add(int64(len(events)))
	}, false)
	bindingRecomputes.Store(0)
	profileCompiles.Store(0)

	updated := profile
	updated.Spec = agentsv1alpha1.SecurityProfileSpec{
		Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "workload"}},
		Rules: []agentsv1alpha1.SecurityRule{{
			Name:  "api",
			Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"changed.example.com"}}},
		}},
	}
	profiles.ConditionalUpdateObject(updated)
	testutil.Eventually(t, func() bool { return inlineUpdates.Load() == workloadCount }, "inline SNI payloads updated")
	settle()

	if got := profileCompiles.Load(); got != 1 {
		t.Fatalf("profile compiles = %d, want 1 for %d Workloads", got, workloadCount)
	}
	// Changes outside binding metadata and SNI produce no downstream work.
	updated.Spec = *updated.Spec.DeepCopy()
	updated.Spec.Rules[0].Name = "renamed-rule"
	profiles.ConditionalUpdateObject(updated)
	testutil.Eventually(t, func() bool { return profileCompiles.Load() == 2 }, "body change compiled once")
	settle()

	if got := bindingRecomputes.Load(); got != 0 {
		t.Fatalf("Workload binding recomputes = %d, want 0", got)
	}
	if got := inlineUpdates.Load(); got != workloadCount {
		t.Fatalf("inline policy updates = %d, want %d", got, workloadCount)
	}
}
