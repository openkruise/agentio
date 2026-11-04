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

package xds

import (
	"context"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
)

func TestAgentioEgressReceivesExtProcEDSAndEmptyUpdate(t *testing.T) {
	service := model.Service{
		Namespace: "system",
		Name:      "epe",
		Hostname:  "epe.system.svc",
		Ports:     []model.ServicePort{{Name: "grpc", Port: 9002, TargetPort: 19002}},
	}
	inputs := networking.Inputs{
		Gateway: model.Gateway{Namespace: "demo", Name: "egress", Config: &configv1.EgressGateway{}},
		GlobalExtProc: &configv1.ExtProcProvider{
			ServiceRef: &configv1.ServiceReference{Namespace: "system", Name: "epe"},
		},
		ExtProcServices: []model.Service{service},
		ExtProcEndpoints: []model.Endpoint{
			{ServiceKey: service.ResourceName(), PortName: "grpc", Port: 19002, Address: "10.0.0.1", Ready: true},
		},
		DiscoveryAddress: "agentiod:15012",
		TrustDomain:      "cluster.local",
	}
	resources, err := networking.Build(inputs)
	if err != nil {
		t.Fatal(err)
	}
	scope := gatewayScope()
	scope.Class = model.ClientAgentioEgress
	server := newTestServer(t, scope, resources, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stream := newFakeStream(ctx, 8)
	done := server.start(stream)
	t.Cleanup(func() {
		if err := server.finish(t, stream, done); err != nil {
			t.Error(err)
		}
	})
	stream.send(nodeRequest(model.ClusterType))
	cds := stream.awaitResponses(t, model.ClusterType, 1)[0]
	found := false
	for _, resource := range cds.Resources {
		if resource.Name != networking.ExtProcCluster {
			continue
		}
		cluster := &clusterv3.Cluster{}
		if err := resource.Resource.UnmarshalTo(cluster); err != nil {
			t.Fatal(err)
		}
		if cluster.GetType() != clusterv3.Cluster_EDS {
			t.Fatalf("cluster=%v", cluster)
		}
		found = true
	}
	if !found {
		t.Fatal("ext-proc EDS cluster not sent")
	}
	stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.ClusterType, ResponseNonce: cds.Nonce})
	stream.send(
		&discoveryv3.DeltaDiscoveryRequest{
			TypeUrl:                model.EndpointType,
			ResourceNamesSubscribe: []string{networking.ExtProcCluster},
		},
	)
	eds := stream.awaitResponses(t, model.EndpointType, 1)[0]
	if len(eds.Resources) != 1 || eds.Resources[0].Name != networking.ExtProcCluster {
		t.Fatalf("EDS=%v", eds)
	}
	assignment := &endpointv3.ClusterLoadAssignment{}
	if err := eds.Resources[0].Resource.UnmarshalTo(assignment); err != nil {
		t.Fatal(err)
	}
	if len(assignment.Endpoints) != 1 || len(assignment.Endpoints[0].LbEndpoints) != 1 ||
		assignment.Endpoints[0].LbEndpoints[0].GetEndpoint().GetAddress().GetSocketAddress().GetPortValue() != 19002 {
		t.Fatalf("EDS assignment=%v", assignment)
	}
	stream.send(&discoveryv3.DeltaDiscoveryRequest{TypeUrl: model.EndpointType, ResponseNonce: eds.Nonce})
	inputs.ExtProcEndpoints = nil
	resources, err = networking.Build(inputs)
	if err != nil {
		t.Fatal(err)
	}
	server.resources.publish(selectionSnapshot(t, resources))
	updated := stream.awaitResponses(t, model.EndpointType, 2)[1]
	if len(updated.Resources) != 1 || len(updated.RemovedResources) != 0 {
		t.Fatalf("empty EDS must be an update: %v", updated)
	}
	assignment.Reset()
	if err := updated.Resources[0].Resource.UnmarshalTo(assignment); err != nil {
		t.Fatal(err)
	}
	if assignment.ClusterName != networking.ExtProcCluster || len(assignment.Endpoints) != 0 {
		t.Fatalf("stale endpoints retained: %v", assignment)
	}
	if len(stream.responsesFor(model.ClusterType)) != 1 {
		t.Fatal("endpoint withdrawal changed CDS")
	}
}
