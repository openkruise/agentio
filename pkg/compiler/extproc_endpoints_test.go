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
	"reflect"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
)

func TestExtProcEndpointsFollowServiceAndReadiness(t *testing.T) {
	fixture := newIncrementalFixture(t)
	config := &configv1.AgentioConfig{
		SandboxExtProc: &configv1.ExtProcProvider{
			Service:    "legacy.invalid",
			ServiceRef: &configv1.ServiceReference{Namespace: "system", Name: "epe"},
		},
		AdditionalExtProcs: []*configv1.ExtProcProvider{
			{Name: "scanner", ServiceRef: &configv1.ServiceReference{Namespace: "system", Name: "scanner"}},
		},
		EgressGateways: []*configv1.EgressGateway{
			{Namespace: "demo", Name: "egress-a"},
			{Namespace: "demo", Name: "egress-b", ExtProc: &configv1.ExtProcProvider{Service: "other.invalid"}},
			{Namespace: "demo", Name: "disabled", ExtProc: &configv1.ExtProcProvider{}},
		},
	}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "initial", Value: config})
	waitSynced(t, fixture.compiler)
	expectEndpoints := func(owner, name string, want []string) {
		t.Helper()
		eventually(t, func() bool {
			count := 0
			for _, resource := range currentSnapshot(t, fixture.compiler).ListResourcesOwnedByGateway(model.EndpointType, owner) {
				if resource.XDSName != name {
					continue
				}
				assignment := &endpointv3.ClusterLoadAssignment{}
				if err := resource.Value.UnmarshalTo(assignment); err != nil {
					t.Fatal(err)
				}
				var addresses []string
				for _, locality := range assignment.Endpoints {
					for _, ep := range locality.LbEndpoints {
						addresses = append(addresses, ep.GetEndpoint().GetAddress().GetSocketAddress().GetAddress())
					}
				}
				if !reflect.DeepEqual(addresses, want) {
					return false
				}
				count++
			}
			return count == 2
		}, "legacy and native EDS assignments for "+owner+"/"+name)
	}
	expectEndpoints("demo/egress-a", networking.ExtProcCluster, nil)
	expectEndpoints("demo/egress-a", "agentio.additional-ext-proc.scanner", nil)
	expectEndpoints("demo/egress-b", "agentio.additional-ext-proc.scanner", nil)
	if got := currentSnapshot(
		t,
		fixture.compiler,
	).ListResourcesOwnedByGateway(model.EndpointType, "demo/disabled"); len(
		got,
	) != 0 {
		t.Fatalf("disabled processor received endpoints: %v", got)
	}
	beforeA := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a")
	beforeB := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b")
	service := model.Service{
		Namespace: "system",
		Name:      "epe",
		Hostname:  "epe.system.svc.custom",
		Ports:     []model.ServicePort{{Name: "grpc", Port: 9002, TargetPort: 19002}},
	}
	ep := model.Endpoint{
		ServiceKey: service.ResourceName(),
		Address:    "10.0.0.1",
		Port:       19002,
		PortName:   "grpc",
		Ready:      true,
	}
	fixture.endpoints.ConditionalUpdateObject(ep)
	fixture.services.ConditionalUpdateObject(service)
	expectEndpoints("demo/egress-a", networking.ExtProcCluster, []string{ep.Address})
	for _, state := range []struct {
		ready       bool
		terminating bool
	}{{false, false}, {true, false}, {true, true}, {true, false}} {
		ep.Ready, ep.Terminating = state.ready, state.terminating
		fixture.endpoints.ConditionalUpdateObject(ep)
		var want []string
		if ep.Ready && !ep.Terminating {
			want = []string{ep.Address}
		}
		expectEndpoints("demo/egress-a", networking.ExtProcCluster, want)
	}
	fixture.services.DeleteObject(service.ResourceName())
	expectEndpoints("demo/egress-a", networking.ExtProcCluster, nil)
	fixture.services.ConditionalUpdateObject(service)
	expectEndpoints("demo/egress-a", networking.ExtProcCluster, []string{ep.Address})
	fixture.endpoints.DeleteObject(ep.ResourceName())
	expectEndpoints("demo/egress-a", networking.ExtProcCluster, nil)
	if !maps.Equal(beforeA, gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-a")) ||
		!maps.Equal(beforeB, gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress-b")) {
		t.Fatal("endpoint changes rebuilt CDS/LDS/RDS or changed another gateway")
	}
	scanner := service
	scanner.Name, scanner.Hostname = "scanner", "scanner.system.svc.custom"
	scannerEP := ep
	scannerEP.ServiceKey, scannerEP.Address = scanner.ResourceName(), "10.0.0.2"
	fixture.services.ConditionalUpdateObject(scanner)
	fixture.endpoints.ConditionalUpdateObject(scannerEP)
	expectEndpoints("demo/egress-a", "agentio.additional-ext-proc.scanner", []string{scannerEP.Address})
	expectEndpoints("demo/egress-b", "agentio.additional-ext-proc.scanner", []string{scannerEP.Address})
	next := proto.Clone(config).(*configv1.AgentioConfig)
	next.SandboxExtProc.ServiceRef = nil
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "DNS", Value: next})
	eventually(t, func() bool {
		for _, resource := range currentSnapshot(t, fixture.compiler).ListResourcesOwnedByGateway(model.EndpointType, "demo/egress-a") {
			if resource.XDSName == networking.ExtProcCluster {
				return false
			}
		}
		for _, resource := range currentSnapshot(t, fixture.compiler).ListResourcesOwnedByGateway(model.ClusterType, "demo/egress-a") {
			if resource.XDSName != networking.ExtProcCluster {
				continue
			}
			cluster := &clusterv3.Cluster{}
			if err := resource.Value.UnmarshalTo(cluster); err != nil {
				t.Fatal(err)
			}
			return cluster.GetType() == clusterv3.Cluster_STRICT_DNS
		}
		return false
	}, "switching to DNS removes EDS resources")
	if failures := fixture.compiler.Failures(); len(failures) != 0 {
		t.Fatalf("compiler failures: %v", failures)
	}
}

func TestExtProcEndpointsUpdateDuringGatewayFailure(t *testing.T) {
	fixture := newIncrementalFixture(t)
	config := &configv1.AgentioConfig{
		SandboxExtProc: &configv1.ExtProcProvider{
			ServiceRef: &configv1.ServiceReference{Namespace: "system", Name: "epe"},
		},
		EgressGateways: []*configv1.EgressGateway{{Namespace: "demo", Name: "egress"}},
	}
	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{ResourceVersion: "initial", Value: config})
	service := model.Service{
		Namespace: "system",
		Name:      "epe",
		Hostname:  "epe.system.svc",
		Ports:     []model.ServicePort{{Name: "grpc", Port: 9002, TargetPort: 9002}},
	}
	ep := model.Endpoint{
		ServiceKey: service.ResourceName(),
		Address:    "10.0.0.1",
		PortName:   "grpc",
		Port:       9002,
		Ready:      true,
	}
	fixture.services.ConditionalUpdateObject(service)
	fixture.endpoints.ConditionalUpdateObject(ep)
	waitSynced(t, fixture.compiler)
	expectEndpoints := func(want []string) {
		t.Helper()
		eventually(t, func() bool {
			count := 0
			for _, resource := range currentSnapshot(t, fixture.compiler).ListResourcesOwnedByGateway(model.EndpointType, "demo/egress") {
				assignment := &endpointv3.ClusterLoadAssignment{}
				if err := resource.Value.UnmarshalTo(assignment); err != nil {
					t.Fatal(err)
				}
				var addresses []string
				for _, locality := range assignment.Endpoints {
					for _, endpoint := range locality.LbEndpoints {
						addresses = append(
							addresses,
							endpoint.GetEndpoint().GetAddress().GetSocketAddress().GetAddress(),
						)
					}
				}
				if !reflect.DeepEqual(addresses, want) {
					return false
				}
				count++
			}
			return count == 2
		}, "last accepted target's endpoints for legacy and native gateways")
	}
	expectEndpoints([]string{ep.Address})
	before := gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress")
	patch, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace:       "demo",
		Name:            "bad",
		Source:          "system/patch",
		ResourceVersion: "1",
	}, 0, []string{"demo/egress"}, []model.EnvoyPatch{{
		Operation: model.PatchAdd,
		Target:    model.ClusterPatch{Value: &clusterv3.Cluster{Name: networking.MainForward}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	fixture.gatewayPatches.ConditionalUpdateObject(patch)
	eventually(t, func() bool { return len(fixture.compiler.Failures()) > 0 }, "patch rejects gateway compilation")
	fixture.endpoints.DeleteObject(ep.ResourceName())
	expectEndpoints(nil)
	fixture.endpoints.ConditionalUpdateObject(ep)
	expectEndpoints([]string{ep.Address})
	fixture.services.DeleteObject(service.ResourceName())
	expectEndpoints(nil)
	fixture.services.ConditionalUpdateObject(service)
	expectEndpoints([]string{ep.Address})

	// A rejected target change must not redirect the retained cluster's EDS.
	next := proto.Clone(config).(*configv1.AgentioConfig)
	next.SandboxExtProc.ServiceRef.Name = "replacement"
	replacement := service
	replacement.Name, replacement.Hostname = "replacement", "replacement.system.svc"
	replacementEP := ep
	replacementEP.ServiceKey, replacementEP.Address = replacement.ResourceName(), "10.0.0.2"
	fixture.services.ConditionalUpdateObject(replacement)
	fixture.endpoints.ConditionalUpdateObject(replacementEP)
	fixture.agentioConfig.ConditionalUpdateObject(
		model.AgentioConfiguration{ResourceVersion: "replacement", Value: next},
	)
	settle()
	ep.Terminating = true
	fixture.endpoints.ConditionalUpdateObject(ep)
	expectEndpoints(nil)
	if !maps.Equal(before, gatewayGraphHashes(currentSnapshot(t, fixture.compiler), "demo/egress")) {
		t.Fatal("failed gateway compilation replaced CDS/LDS/RDS")
	}
	fixture.gatewayPatches.DeleteObject(patch.ResourceName())
	expectEndpoints([]string{replacementEP.Address})
	eventually(t, func() bool { return len(fixture.compiler.Failures()) == 0 }, "patch recovery commits the new target")
	fixture.agentioConfig.ConditionalUpdateObject(
		model.AgentioConfiguration{ResourceVersion: "deleted", Value: &configv1.AgentioConfig{}},
	)
	eventually(t, func() bool {
		return len(
			currentSnapshot(t, fixture.compiler).ListResourcesOwnedByGateway(model.EndpointType, "demo/egress"),
		) == 0
	}, "gateway deletion withdraws endpoint resources")
}
