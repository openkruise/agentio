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
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// The scale test compiles a cluster with every input populated, not sandboxes alone.
func TestCompileFiveThousandSandboxes(t *testing.T) {
	compiler := scaleCompiler(t, 5_000)
	waitSynced(t, compiler)
	snapshot, err := compiler.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if failures := compiler.Failures(); len(failures) > 0 {
		t.Fatalf("objects failed to compile at scale: %v", failures)
	}
	// The retained graph has one canonical Address representation per workload.
	// Direct Workload resources are projected only for subscribed gateways and
	// must not double the steady-state snapshot.
	if got := len(snapshot.List(model.WorkloadType)); got != 0 {
		t.Fatalf("retained Workload resources = %d, want 0", got)
	}
	if got := len(snapshot.List(model.AddressType)); got != 5_000+scaleServices {
		t.Fatalf("Address resources = %d, want %d", got, 5_000+scaleServices)
	}
	if got := len(snapshot.List(model.WorkloadAuthorizationType)); got != scalePolicies {
		t.Fatalf("Authorization resources = %d, want %d", got, scalePolicies)
	}
	if got := len(snapshot.List(model.SniTrafficPolicyType)); got != 0 {
		t.Fatalf("independent SNI policy resources = %d, want 0", got)
	}
	for _, resource := range snapshot.List(model.AddressType) {
		if resource.Facts.Authorization != nil {
			t.Fatalf("Address %s carries Authorization-family facts", resource.Key.Name)
		}
	}
}

func BenchmarkCompileTenThousandSandboxes(b *testing.B) {
	compiler := scaleCompiler(b, 10_000)
	waitSynced(b, compiler)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := compiler.Snapshot(); err != nil {
			b.Fatal(err)
		}
	}
}

// Shape of the cluster the scale test and benchmark compile. The policy count
// is what makes attachment matching visible; the endpoints-per-service count is
// what makes the service-to-endpoint join visible.
const (
	scaleServices            = 500
	scalePolicies            = 100
	scaleEndpointsPerService = 4
	scaleGateways            = 5
)

func scaleCompiler(t testing.TB, count int) *Compiler {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workloads := krt.NewStaticCollection[model.Workload](nil, nil, options...)
	for index := range count {
		workload := testWDSWorkload(fmt.Sprintf("sandbox-%d", index), "", fmt.Sprintf("10.%d.%d.%d", (index/65536)%256, (index/256)%256, index%256))
		workload.Labels = map[string]string{"app": "sandbox"}
		workloads.ConditionalUpdateObject(workload)
	}

	services := krt.NewStaticCollection[model.Service](nil, nil, options...)
	endpoints := krt.NewStaticCollection[model.Endpoint](nil, nil, options...)
	for index := range scaleServices {
		name := fmt.Sprintf("service-%d", index)
		hostname := name + ".demo.svc.cluster.local"
		services.ConditionalUpdateObject(model.Service{
			Namespace: "demo", Name: name, Hostname: hostname,
			Addresses: []string{fmt.Sprintf("10.96.%d.%d", (index/256)%256, index%256)},
			Ports:     []model.ServicePort{{Name: "http", Port: 8080, Protocol: "TCP"}},
		})
		for replica := range scaleEndpointsPerService {
			endpoints.ConditionalUpdateObject(model.Endpoint{
				ServiceKey: "demo/" + hostname, SourceKey: "demo/" + name + "-slice",
				Address: fmt.Sprintf("10.%d.%d.%d", (index/256)%256, index%256, replica), Port: 8080, Ready: true,
			})
		}
	}

	trafficPolicies := krt.NewStaticCollection[model.TrafficPolicy](nil, nil, options...)
	securityProfiles := krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...)
	for index := range scalePolicies {
		selector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "sandbox"}}
		trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
			Name: fmt.Sprintf("policy-%d", index), Namespace: "demo",
			Spec: agentsv1alpha1.TrafficPolicySpec{
				Selector: selector,
				Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
					Action: agentsv1alpha1.RuleActionAllow,
					To: []agentsv1alpha1.TrafficPolicyPeer{
						{CIDR: fmt.Sprintf("10.%d.0.0/16", index%256)},
						// A Service peer exercises the service-to-endpoint join.
						{Service: &agentsv1alpha1.TrafficPolicyServiceRef{Namespace: "demo", Name: fmt.Sprintf("service-%d", index%scaleServices)}},
					},
				}}},
			},
		})
		securityProfiles.ConditionalUpdateObject(model.SecurityProfile{
			Name: fmt.Sprintf("profile-%d", index), Namespace: "demo",
			Spec: agentsv1alpha1.SecurityProfileSpec{
				Selector: selector,
				Rules: []agentsv1alpha1.SecurityRule{{
					Name:  "api",
					Match: []agentsv1alpha1.RuleMatch{{Domains: []string{fmt.Sprintf("api-%d.example.com", index)}}},
				}},
			},
		})
	}

	gateways := make([]*configv1.EgressGateway, 0, scaleGateways)
	for index := range scaleGateways {
		name := fmt.Sprintf("egress-%d", index)
		gateways = append(gateways, &configv1.EgressGateway{Namespace: "demo", Name: name})
	}
	agentioConfig := krt.NewStaticCollection[model.AgentioConfiguration](nil, []model.AgentioConfiguration{{
		Value: &configv1.AgentioConfig{EgressGateways: gateways},
	}}, options...)

	inputs := validCompilerInputs(stop)
	inputs.Workloads = workloads
	inputs.Services = services
	inputs.Endpoints = endpoints
	inputs.Gateways = testGatewaySource(agentioConfig, options...)
	inputs.TrafficPolicies = trafficPolicies
	inputs.SecurityProfiles = securityProfiles
	inputs.AgentioConfig = agentioConfig
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	return compiler
}
