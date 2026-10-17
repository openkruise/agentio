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
	"reflect"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/test"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
)

func TestBuildWDSAddressPublishesCanonicalIdentity(t *testing.T) {
	workload := projectionTestWorkload()
	workload.CanonicalName = "client-api"
	workload.CanonicalRevision = "v2"

	resource, err := buildWDSAddress(wdsProjection{Workload: workload})
	if err != nil {
		t.Fatal(err)
	}
	address := &workloadv1.Address{}
	if err := resource.Value.UnmarshalTo(address); err != nil {
		t.Fatal(err)
	}
	if got := address.GetWorkload().GetCanonicalName(); got != "client-api" {
		t.Fatalf("canonical name = %q, want client-api", got)
	}
	if got := address.GetWorkload().GetCanonicalRevision(); got != "v2" {
		t.Fatalf("canonical revision = %q, want v2", got)
	}
}

func TestBuildWDSAddressPublishesDiscoveryOnlyWorkload(t *testing.T) {
	workload := projectionTestWorkload()
	workload.Principal = model.Principal{}

	resource, err := buildWDSAddress(wdsProjection{Workload: workload})
	if err != nil {
		t.Fatal(err)
	}
	if resource == nil {
		t.Fatal("missing Address resource")
	}
	address := &workloadv1.Address{}
	if err := resource.Value.UnmarshalTo(address); err != nil {
		t.Fatal(err)
	}
	wireWorkload := address.GetWorkload()
	if wireWorkload == nil {
		t.Fatal("Address does not contain a Workload")
	}
	if got := wireWorkload.GetServiceAccount(); got != "" {
		t.Fatalf("service account = %q, want empty", got)
	}
	refs := new(extensionsv1.PolicyReference)
	if !compatibilityExtension(t, wireWorkload, "traffic-policy-reference", refs) ||
		refs.TypeUrl != model.TrafficPolicyType || len(refs.ResourceNames) != 0 {
		t.Fatalf("native empty policy binding = %v", refs)
	}
	if resource.Facts.Workload == nil {
		t.Fatal("discovery-only Address lost its Workload facts")
	}
}

func TestBuildPreservesEmptyNetworkAddressAlias(t *testing.T) {
	workload := projectionTestWorkload()
	resource, err := buildWDSAddress(wdsProjection{
		Workload: workload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resource == nil {
		t.Fatal("missing Address resource")
	}
	{
		if got, want := resource.Aliases, []string{"/10.0.0.1"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("%s aliases = %v, want %v", resource.Key.TypeURL, got, want)
		}
	}
}

func TestBuildProjectsHostNetworkMode(t *testing.T) {
	workload := projectionTestWorkload()
	workload.HostNetwork = true

	resource, err := buildWDSAddress(wdsProjection{
		Workload: workload,
	})
	if err != nil {
		t.Fatal(err)
	}
	address := &workloadv1.Address{}
	if err := resource.Value.UnmarshalTo(address); err != nil {
		t.Fatal(err)
	}
	if got := address.GetWorkload().GetNetworkMode(); got != workloadv1.NetworkMode_HOST_NETWORK {
		t.Fatalf("network mode = %v, want HOST_NETWORK", got)
	}
}

func TestBuildWDSAddressOmitsNodeFactWithoutPlacement(t *testing.T) {
	resource, err := buildWDSAddress(wdsProjection{Workload: projectionTestWorkload()})
	if err != nil {
		t.Fatal(err)
	}
	if resource.Facts.Workload == nil || resource.Facts.Workload.NodeName != "" {
		t.Fatalf("node-less workload facts = %+v", resource.Facts)
	}
	if !resource.IsWorkloadAddress() {
		t.Fatal("node-less workload must remain a workload address via its Workload facts")
	}

	placed := projectionTestWorkload()
	placed.NodeName = "node-a"
	resource, err = buildWDSAddress(wdsProjection{Workload: placed})
	if err != nil {
		t.Fatal(err)
	}
	if resource.Facts.Workload == nil || resource.Facts.Workload.NodeName != "node-a" {
		t.Fatal("placed workload lost its node fact")
	}
}

func projectionTestWorkload() model.Workload {
	return model.Workload{
		UID:       "cluster//Pod/demo/client",
		Namespace: "demo",
		Name:      "client",
		Addresses: []string{"10.0.0.1"},
		Ready:     true,
		Principal: mustTestPrincipal("cluster.local", "ns/"+("demo")+"/sa/"+("client")),
	}
}

func TestWorkloadMetadataFiltersLabels(t *testing.T) {
	test.SetForTest(t, &features.MeshInternalTrafficPolicy,
		extensionsv1.MeshInternalTrafficPolicy_MESH_INTERNAL_PASSTHROUGH)
	labels := map[string]string{
		"keep":              "yes",
		"pod-template-hash": "no",
		"controller-a":      "no",
	}
	workloadInput := testWDSWorkload("sandbox", "sandbox-uid", "10.0.0.1")
	workloadInput.Labels = labels
	resource, err := buildWDSAddress(wdsProjection{
		ClusterID: "cluster",
		Workload:  workloadInput,
		MetadataConfiguration: &workloadMetadataConfiguration{
			IgnoredLabels: []string{"pod-template-hash", "controller-*"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	address := &workloadv1.Address{}
	if err := resource.Value.UnmarshalTo(address); err != nil {
		t.Fatalf("unmarshal Address: %v", err)
	}
	workload := address.GetWorkload()
	if got := workload.GetWorkloadType(); got != workloadv1.WorkloadType_POD {
		t.Fatalf("VM-compatible workload type = %v, want POD", got)
	}
	var metadataExtension *workloadv1.Extension
	for _, extension := range workload.GetExtensions() {
		if extension.GetName() == "workload-metadata" {
			metadataExtension = extension
			break
		}
	}
	if metadataExtension == nil {
		t.Fatalf("workload extensions = %+v, want workload metadata", workload.GetExtensions())
	}
	metadata := &extensionsv1.WorkloadMetadata{}
	if err := metadataExtension.GetConfig().UnmarshalTo(metadata); err != nil {
		t.Fatalf("unmarshal workload metadata: %v", err)
	}
	if got := metadata.GetLabels(); !reflect.DeepEqual(got, map[string]string{"keep": "yes"}) {
		t.Fatalf("metadata labels = %v, want keep label only", got)
	}
	if got := metadata.GetMeshInternalTrafficPolicy(); got != extensionsv1.MeshInternalTrafficPolicy_MESH_INTERNAL_PASSTHROUGH {
		t.Fatalf("mesh internal traffic policy = %v, want PASSTHROUGH", got)
	}
	if got := labels["pod-template-hash"]; got != "no" {
		t.Fatalf("source labels were mutated: pod-template-hash = %q", got)
	}
}

func TestServiceResourcePreservesNormalizedTargetPort(t *testing.T) {
	for _, test := range []struct {
		name string
		port model.ServicePort
		want *workloadv1.Port
	}{
		{
			name: "numeric target port",
			port: model.ServicePort{Name: "http", Port: 80, TargetPort: 8080, Protocol: "TCP"},
			want: &workloadv1.Port{ServicePort: 80, TargetPort: 8080},
		},
		{
			name: "named target sentinel",
			port: model.ServicePort{Name: "http", Port: 80, TargetPortName: "backend-http", Protocol: "TCP"},
			want: &workloadv1.Port{ServicePort: 80, TargetPort: 0},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			resource, err := buildWDSService(model.Service{
				Namespace: "demo",
				Name:      "backend",
				Hostname:  "backend.demo.svc.cluster.local",
				Ports:     []model.ServicePort{test.port},
			}, "")
			if err != nil {
				t.Fatal(err)
			}
			address := &workloadv1.Address{}
			if err := resource.Value.UnmarshalTo(address); err != nil {
				t.Fatalf("unmarshal Service Address: %v", err)
			}
			ports := address.GetService().GetPorts()
			if len(ports) != 1 || !proto.Equal(ports[0], test.want) {
				t.Fatalf("service ports = %+v, want [%+v]", ports, test.want)
			}
		})
	}
}

func TestServiceResourcePreservesNetworkingSemantics(t *testing.T) {
	resource, err := buildWDSService(model.Service{
		Namespace:                "demo",
		Name:                     "backend",
		Hostname:                 "backend.demo.svc.cluster.local",
		Canonical:                true,
		PublishNotReadyAddresses: true,
		Ports: []model.ServicePort{
			{
				Name:        "http",
				Port:        80,
				TargetPort:  8080,
				Protocol:    "TCP",
				AppProtocol: model.AppProtocolHTTP11,
			},
		},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	address := &workloadv1.Address{}
	if err := resource.Value.UnmarshalTo(address); err != nil {
		t.Fatalf("unmarshal Service Address: %v", err)
	}
	service := address.GetService()
	if !service.GetCanonical() {
		t.Fatal("canonical Service flag was not projected")
	}
	if got := service.GetLoadBalancing().GetHealthPolicy(); got != workloadv1.LoadBalancing_ALLOW_ALL {
		t.Fatalf("health policy = %v, want ALLOW_ALL", got)
	}
	if got := service.GetPorts()[0].GetAppProtocol(); got != workloadv1.AppProtocol_HTTP11 {
		t.Fatalf("app protocol = %v, want HTTP11", got)
	}
}

func TestServiceResourceTrafficPolicyEncoding(t *testing.T) {
	for _, test := range []struct {
		name     string
		service  model.Service
		wantLB   *workloadv1.LoadBalancing
		wantIPFs workloadv1.IPFamilies
	}{
		{
			name:    "internal traffic policy local",
			service: model.Service{InternalTrafficPolicyLocal: true},
			wantLB: &workloadv1.LoadBalancing{
				RoutingPreference: []workloadv1.LoadBalancing_Scope{workloadv1.LoadBalancing_NODE},
				Mode:              workloadv1.LoadBalancing_STRICT,
			},
		},
		{
			name: "local wins over traffic distribution",
			service: model.Service{
				InternalTrafficPolicyLocal: true,
				TrafficDistribution:        model.TrafficDistributionPreferSameZone,
			},
			wantLB: &workloadv1.LoadBalancing{
				RoutingPreference: []workloadv1.LoadBalancing_Scope{workloadv1.LoadBalancing_NODE},
				Mode:              workloadv1.LoadBalancing_STRICT,
			},
		},
		{
			name:    "prefer same zone",
			service: model.Service{TrafficDistribution: model.TrafficDistributionPreferSameZone},
			wantLB: &workloadv1.LoadBalancing{
				RoutingPreference: []workloadv1.LoadBalancing_Scope{
					workloadv1.LoadBalancing_NETWORK,
					workloadv1.LoadBalancing_REGION,
					workloadv1.LoadBalancing_ZONE,
				},
				Mode: workloadv1.LoadBalancing_FAILOVER,
			},
		},
		{
			name: "prefer same node with publish not ready",
			service: model.Service{
				TrafficDistribution:      model.TrafficDistributionPreferSameNode,
				PublishNotReadyAddresses: true,
			},
			wantLB: &workloadv1.LoadBalancing{
				RoutingPreference: []workloadv1.LoadBalancing_Scope{
					workloadv1.LoadBalancing_NETWORK,
					workloadv1.LoadBalancing_REGION,
					workloadv1.LoadBalancing_ZONE,
					workloadv1.LoadBalancing_SUBZONE,
					workloadv1.LoadBalancing_NODE,
				},
				Mode:         workloadv1.LoadBalancing_FAILOVER,
				HealthPolicy: workloadv1.LoadBalancing_ALLOW_ALL,
			},
		},
		{
			name:     "dual stack",
			service:  model.Service{IPFamilies: model.IPFamiliesDual},
			wantIPFs: workloadv1.IPFamilies_DUAL,
		},
		{
			name:     "ipv4 only",
			service:  model.Service{IPFamilies: model.IPFamiliesIPv4Only},
			wantIPFs: workloadv1.IPFamilies_IPV4_ONLY,
		},
		{
			name:     "ipv6 only",
			service:  model.Service{IPFamilies: model.IPFamiliesIPv6Only},
			wantIPFs: workloadv1.IPFamilies_IPV6_ONLY,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := test.service
			service.Namespace, service.Name = "demo", "backend"
			service.Hostname = "backend.demo.svc.cluster.local"
			resource, err := buildWDSService(service, "")
			if err != nil {
				t.Fatal(err)
			}
			address := &workloadv1.Address{}
			if err := resource.Value.UnmarshalTo(address); err != nil {
				t.Fatalf("unmarshal Service Address: %v", err)
			}
			wire := address.GetService()
			if !proto.Equal(wire.GetLoadBalancing(), test.wantLB) {
				t.Fatalf("load balancing = %+v, want %+v", wire.GetLoadBalancing(), test.wantLB)
			}
			if wire.GetIpFamilies() != test.wantIPFs {
				t.Fatalf("ip families = %v, want %v", wire.GetIpFamilies(), test.wantIPFs)
			}
		})
	}
}

func TestWorkloadResourceCarriesScopeAndServiceFacts(t *testing.T) {
	workloadInput := testWDSWorkload("pod-a", "pod-a-uid", "10.0.0.1")
	workloadInput.NodeName = "node-a"
	resource, err := buildWDSAddress(wdsProjection{
		ClusterID: "cluster",
		Workload:  workloadInput,
		Endpoints: []model.Endpoint{{
			ServiceKey: testServiceKey,
			SourceKey:  "demo/backend-a",
			Address:    "10.0.0.1",
			PortName:   "http",
			Port:       8080,
			Protocol:   "TCP",
			Ready:      true,
		}},
		Services: []model.Service{{
			Namespace: "demo",
			Name:      "backend",
			Hostname:  "backend.demo.svc.cluster.local",
			Ports: []model.ServicePort{{
				Name:       "http",
				Port:       80,
				TargetPort: 8080,
				Protocol:   "TCP",
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resource == nil || resource.Key.TypeURL != model.AddressType {
		t.Fatalf("workload resource = %+v, want canonical Address", resource)
	}
	{
		facts := resource.Facts.Workload
		if facts == nil || facts.WorkloadUID != workloadInput.UID ||
			facts.NodeName != "node-a" || facts.Principal != workloadInput.Principal ||
			!slices.Contains(facts.ServiceKeys, testServiceKey) {
			t.Fatalf("resource %s facts = %+v", resource.Key.TypeURL, resource.Facts)
		}
	}
}

func TestBuildWDSAddressEncodingIsDeterministic(t *testing.T) {
	workload := projectionTestWorkload()
	workload.Labels = map[string]string{"a": "1", "b": "2", "c": "3", "d": "4"}
	input := wdsProjection{
		Workload:              workload,
		MetadataConfiguration: &workloadMetadataConfiguration{},
		Services: []model.Service{
			{Namespace: "demo", Name: "a", Hostname: "a.demo.svc.cluster.local"},
			{Namespace: "demo", Name: "b", Hostname: "b.demo.svc.cluster.local"},
		},
	}
	first, err := buildWDSAddress(input)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		resource, err := buildWDSAddress(input)
		if err != nil {
			t.Fatal(err)
		}
		if resource.Hash != first.Hash {
			t.Fatalf("identical input changed hash at encoding %d: %s != %s", i, resource.Hash, first.Hash)
		}
	}
}

func TestWDSRejectsUnrepresentableIdentity(t *testing.T) {
	workload := projectionTestWorkload()
	workload.Principal = mustTestPrincipal(workload.Principal.TrustDomain(), "workload/app")
	if _, err := buildWDSAddress(wdsProjection{Workload: workload}); err == nil {
		t.Fatal("WDS accepted an unrepresentable principal")
	}
}

func TestWorkloadInstanceAliasSurvivesNameReuse(t *testing.T) {
	workload := projectionTestWorkload()
	for _, registry := range []string{"kubernetes/cluster-a", "substrate/installation-a"} {
		for _, uid := range []string{"instance-1", "instance-2"} {
			workload.Source = model.SourceRef{Registry: registry, Key: uid}
			resource, err := buildWDSAddress(wdsProjection{Workload: workload})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, alias := range resource.Aliases {
				if alias == workload.Source.WorkloadAlias() {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing instance alias: %v", resource.Aliases)
			}
		}
	}
}
