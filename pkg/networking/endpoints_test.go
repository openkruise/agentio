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

package networking

import (
	"reflect"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestExtProcEDS(t *testing.T) {
	service := model.Service{
		Namespace: "system",
		Name:      "epe",
		Hostname:  "epe.system.svc.custom",
		Ports:     []model.ServicePort{{Name: "extproc", Port: 9002, TargetPort: 19002, Protocol: "TCP"}},
	}
	endpoint := model.Endpoint{
		ServiceKey: service.ResourceName(),
		Address:    "10.0.0.1",
		Port:       19002,
		PortName:   "extproc",
		Protocol:   "TCP",
		Ready:      true,
		Serving:    true,
	}
	endpoints := []model.Endpoint{endpoint}
	for _, change := range []func(*model.Endpoint){
		func(e *model.Endpoint) { e.SourceKey = "overlapping-slice" },
		func(e *model.Endpoint) { e.Address = "2001:db8::1" },
		func(e *model.Endpoint) { e.Ready = false },
		func(e *model.Endpoint) { e.Serving = false },
		func(e *model.Endpoint) { e.Terminating = true },
		func(e *model.Endpoint) { e.PortName = "health" },
		func(e *model.Endpoint) { e.Port = 0 },
		func(e *model.Endpoint) { e.Protocol = "UDP" },
		func(e *model.Endpoint) { e.ServiceKey = "other/service" },
	} {
		e := endpoint
		change(&e)
		endpoints = append(endpoints, e)
	}
	provider := &configv1.ExtProcProvider{
		Service:    "ignored.invalid",
		ServiceRef: &configv1.ServiceReference{Namespace: "system", Name: "epe"},
		Tls: &configv1.ExtProcTLSSettings{
			Mode:          configv1.ExtProcTLSSettings_MUTUAL,
			PeerSpiffeIds: []string{"spiffe://cluster.local/ns/system/sa/epe"},
		},
	}
	for _, legacy := range []bool{false, true} {
		inputs := Inputs{
			LegacyGateway:      legacy,
			Gateway:            testGateway(nil),
			GlobalExtProc:      provider,
			AdditionalExtProcs: []*configv1.ExtProcProvider{{Name: "second", ServiceRef: provider.ServiceRef}},
			Services:           []model.Service{service},
			Endpoints:          endpoints,
			DiscoveryAddress:   "agentiod:15012",
			TrustDomain:        "cluster.local",
		}
		compiled, err := BuildGateway(inputs)
		if err != nil {
			t.Fatal(err)
		}
		for _, resource := range compiled.StaticResources {
			if resource.Key.TypeURL == model.EndpointType {
				t.Fatal("gateway compilation contains a placeholder EDS resource")
			}
		}
		resources, err := Build(inputs)
		if err != nil {
			t.Fatal(err)
		}
		for _, resource := range resources {
			if resource.Key.TypeURL != model.EndpointType {
				continue
			}
			prefix := inputs.Gateway.ResourceName() + "|"
			if !legacy {
				prefix += "agentio-egress|"
			}
			if resource.Key.Name != prefix+resource.XDSName ||
				resource.Facts.GatewayOwner != inputs.Gateway.ResourceName() ||
				resource.Facts.AgentioEgress != !legacy {
				t.Fatalf("legacy=%v incorrect EDS publication identity: %+v", legacy, resource)
			}
		}
		clusters := messagesOf(
			t,
			resources,
			model.ClusterType,
			func() *clusterv3.Cluster { return &clusterv3.Cluster{} },
		)
		assignments := messagesOf(
			t,
			resources,
			model.EndpointType,
			func() *endpointv3.ClusterLoadAssignment { return &endpointv3.ClusterLoadAssignment{} },
		)
		if len(assignments) != 2 {
			t.Fatalf("EDS assignments=%v", assignments)
		}
		for _, name := range []string{ExtProcCluster, "agentio.additional-ext-proc.second"} {
			cluster := clusters[name]
			if cluster.GetType() != clusterv3.Cluster_EDS || cluster.LoadAssignment != nil ||
				cluster.GetEdsClusterConfig().
					GetServiceName() !=
					name || cluster.GetEdsClusterConfig().GetEdsConfig().GetAds() == nil {
				t.Fatalf("legacy=%v invalid EDS cluster: %v", legacy, cluster)
			}
			if err := cluster.ValidateAll(); err != nil {
				t.Fatal(err)
			}
			assignment := assignments[name]
			if err := assignment.ValidateAll(); err != nil {
				t.Fatal(err)
			}
			var addresses []string
			for _, locality := range assignment.Endpoints {
				for _, ep := range locality.LbEndpoints {
					address := ep.GetEndpoint().GetAddress().GetSocketAddress()
					if address.GetPortValue() != 19002 {
						t.Fatalf("Service port was not mapped: %v", address)
					}
					addresses = append(addresses, address.GetAddress())
				}
			}
			if !reflect.DeepEqual(addresses, []string{"10.0.0.1", "2001:db8::1"}) {
				t.Fatalf("eligible addresses=%v", addresses)
			}
		}
		dnsProvider := proto.Clone(provider).(*configv1.ExtProcProvider)
		dnsProvider.ServiceRef = nil
		inputs.GlobalExtProc = dnsProvider
		inputs.AdditionalExtProcs = nil
		dns, err := Build(inputs)
		if err != nil {
			t.Fatal(err)
		}
		dnsClusters := messagesOf(t, dns, model.ClusterType, func() *clusterv3.Cluster { return &clusterv3.Cluster{} })
		if dnsClusters[ExtProcCluster].GetType() != clusterv3.Cluster_STRICT_DNS ||
			!proto.Equal(dnsClusters[ExtProcCluster].TransportSocket, clusters[ExtProcCluster].TransportSocket) ||
			!proto.Equal(
				dnsClusters[ExtProcCluster].TypedExtensionProtocolOptions[httpProtocolOptionsType],
				clusters[ExtProcCluster].TypedExtensionProtocolOptions[httpProtocolOptionsType],
			) {
			t.Fatal("EDS changed TLS or HTTP/2 settings, or DNS compatibility was lost")
		}
		if assignments := messagesOf(
			t,
			dns,
			model.EndpointType,
			func() *endpointv3.ClusterLoadAssignment { return &endpointv3.ClusterLoadAssignment{} },
		); len(
			assignments,
		) != 0 {
			t.Fatalf("DNS configuration retained EDS assignments: %v", assignments)
		}
	}
}

func TestServiceEDSPortSelectionAndEmptyAssignments(t *testing.T) {
	target := ServiceTarget{Namespace: "system", Name: "backend", Port: 9002}
	service := model.Service{
		Namespace:                "system",
		Name:                     "backend",
		Hostname:                 "backend.system.svc",
		PublishNotReadyAddresses: true,
		Ports:                    []model.ServicePort{{Name: "grpc", Port: 9002, TargetPortName: "server"}},
	}
	ep := model.Endpoint{
		ServiceKey: service.ResourceName(),
		Address:    "10.0.0.1",
		PortName:   "grpc",
		Port:       19002,
		Ready:      true,
		Serving:    true,
	}
	notServing := ep
	notServing.Serving = false
	for _, tc := range []struct {
		name      string
		services  []model.Service
		endpoints []model.Endpoint
		want      int
	}{
		{"missing Service", nil, []model.Endpoint{ep}, 0},
		{"no endpoints", []model.Service{service}, nil, 0},
		{"unready despite publishNotReadyAddresses", []model.Service{service}, []model.Endpoint{{ServiceKey: ep.ServiceKey, Address: ep.Address, PortName: "grpc", Port: ep.Port}}, 0},
		{"ready but not serving despite publishNotReadyAddresses", []model.Service{service}, []model.Endpoint{notServing}, 0},
		{"named target port", []model.Service{service}, []model.Endpoint{ep}, 1},
		{"wrong Service", []model.Service{{Namespace: "other", Name: service.Name, Ports: service.Ports}}, []model.Endpoint{ep}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assignment := BuildServiceLoadAssignment("backend", target, tc.services, tc.endpoints)
			count := 0
			for _, locality := range assignment.Endpoints {
				count += len(locality.LbEndpoints)
			}
			if assignment.ClusterName != "backend" || count != tc.want {
				t.Fatalf("assignment=%v, want %d hosts", assignment, tc.want)
			}
		})
	}
	target.Port = 1234
	if got := BuildServiceLoadAssignment(
		"backend",
		target,
		[]model.Service{service},
		[]model.Endpoint{ep},
	); len(
		got.Endpoints,
	) != 0 {
		t.Fatal("missing Service port fell back to another port")
	}
}

func TestServiceEDSUsesActualEndpointPorts(t *testing.T) {
	service := model.Service{
		Namespace: "demo",
		Name:      "manual",
		Hostname:  "manual.demo.svc",
		Ports:     []model.ServicePort{{Name: "grpc", Port: 80, TargetPort: 8080}},
	}
	ep := model.Endpoint{
		ServiceKey: service.ResourceName(),
		Address:    "10.0.0.1",
		PortName:   "grpc",
		Port:       19002,
		Ready:      true,
		Serving:    true,
	}
	otherPort := ep
	otherPort.Port = 19001
	duplicate := ep
	duplicate.SourceKey = "overlapping-slice"
	endpoints := []model.Endpoint{ep, otherPort, duplicate}
	before := append([]model.Endpoint(nil), endpoints...)
	for _, named := range []bool{false, true} {
		if named {
			service.Ports[0].TargetPort = 0
			service.Ports[0].TargetPortName = "server"
		}
		assignment := BuildServiceLoadAssignment("backend", ServiceTarget{
			Namespace: service.Namespace,
			Name:      service.Name,
			Port:      80,
		}, []model.Service{service}, endpoints)
		var ports []uint32
		for _, locality := range assignment.Endpoints {
			for _, endpoint := range locality.LbEndpoints {
				ports = append(ports, endpoint.GetEndpoint().GetAddress().GetSocketAddress().GetPortValue())
			}
		}
		if !reflect.DeepEqual(ports, []uint32{19001, 19002}) {
			t.Fatalf("named=%v actual endpoint ports=%v", named, ports)
		}
		if !reflect.DeepEqual(endpoints, before) {
			t.Fatal("EDS selection mutated the shared endpoint input")
		}
	}
}
