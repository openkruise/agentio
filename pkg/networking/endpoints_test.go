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
	}
	endpoints := []model.Endpoint{endpoint}
	for _, change := range []func(*model.Endpoint){
		func(e *model.Endpoint) { e.SourceKey = "overlapping-slice" },
		func(e *model.Endpoint) { e.Address = "2001:db8::1" },
		func(e *model.Endpoint) { e.Ready = false },
		func(e *model.Endpoint) { e.Terminating = true },
		func(e *model.Endpoint) { e.PortName = "health" },
		func(e *model.Endpoint) { e.Port = 9003 },
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
			ExtProcServices:    []model.Service{service},
			ExtProcEndpoints:   endpoints,
			DiscoveryAddress:   "agentiod:15012",
			TrustDomain:        "cluster.local",
		}
		resources, err := Build(inputs)
		if err != nil {
			t.Fatal(err)
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

func TestExtProcEDSPortSelectionAndEmptyAssignments(t *testing.T) {
	provider := &configv1.ExtProcProvider{
		Service:    "fallback.invalid",
		ServiceRef: &configv1.ServiceReference{Namespace: "system", Name: "epe"},
	}
	service := model.Service{
		Namespace:                "system",
		Name:                     "epe",
		Hostname:                 "epe.system.svc",
		PublishNotReadyAddresses: true,
		Ports:                    []model.ServicePort{{Name: "grpc", Port: 9002, TargetPortName: "server"}},
	}
	ep := model.Endpoint{
		ServiceKey: service.ResourceName(),
		Address:    "10.0.0.1",
		PortName:   "grpc",
		Port:       19002,
		Ready:      true,
	}
	for _, tc := range []struct {
		name      string
		services  []model.Service
		endpoints []model.Endpoint
		want      int
	}{
		{"missing Service", nil, []model.Endpoint{ep}, 0},
		{"no endpoints", []model.Service{service}, nil, 0},
		{"unready despite publishNotReadyAddresses", []model.Service{service}, []model.Endpoint{{ServiceKey: ep.ServiceKey, Address: ep.Address, PortName: "grpc", Port: ep.Port}}, 0},
		{"named target port", []model.Service{service}, []model.Endpoint{ep}, 1},
		{"wrong Service", []model.Service{{Namespace: "other", Name: service.Name, Ports: service.Ports}}, []model.Endpoint{ep}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assignment := BuildExtProcLoadAssignment(ExtProcCluster, provider, tc.services, tc.endpoints)
			count := 0
			for _, locality := range assignment.Endpoints {
				count += len(locality.LbEndpoints)
			}
			if assignment.ClusterName != ExtProcCluster || count != tc.want {
				t.Fatalf("assignment=%v, want %d hosts", assignment, tc.want)
			}
		})
	}
	provider.Port = 1234
	if got := BuildExtProcLoadAssignment(
		ExtProcCluster,
		provider,
		[]model.Service{service},
		[]model.Endpoint{ep},
	); len(
		got.Endpoints,
	) != 0 {
		t.Fatal("missing Service port fell back to another port")
	}
}
