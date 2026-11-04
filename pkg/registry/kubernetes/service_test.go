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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/openkruise/agentio/pkg/model"
)

func TestWorkloadServicePortsNormalizeServiceAndEndpointIntent(t *testing.T) {
	service := serviceFromKubernetes("cluster.local", &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "backend"},
		Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{
			{Name: "numeric", Port: 80, TargetPort: intstr.FromInt32(8080), Protocol: corev1.ProtocolTCP},
			{Name: "named", Port: 81, TargetPort: intstr.FromString("http-backend"), Protocol: corev1.ProtocolTCP},
		}},
	})
	if len(service.Ports) != 2 {
		t.Fatalf("service ports = %+v, want 2", service.Ports)
	}
	if got := service.Ports[0]; got.Name != "numeric" || got.Port != 80 || got.TargetPort != 8080 || got.TargetPortName != "" || got.Protocol != "TCP" {
		t.Fatalf("numeric service port = %+v", got)
	}
	if got := service.Ports[1]; got.Name != "named" || got.Port != 81 || got.TargetPort != 0 || got.TargetPortName != "http-backend" || got.Protocol != "TCP" {
		t.Fatalf("named service port = %+v", got)
	}

	portName := "named"
	udpPortName := "named-udp"
	port := int32(9090)
	protocol, udpProtocol := corev1.ProtocolTCP, corev1.ProtocolUDP
	ready, serving, terminating := false, true, true
	endpoints := endpointsFromSlice("cluster.local", &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "backend-abc",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "backend"},
		},
		Ports: []discoveryv1.EndpointPort{
			{Name: &portName, Port: &port, Protocol: &protocol},
			{Name: &udpPortName, Port: &port, Protocol: &udpProtocol},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{"10.0.0.1"},
			Conditions: discoveryv1.EndpointConditions{
				Ready:       &ready,
				Serving:     &serving,
				Terminating: &terminating,
			},
			TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: "pod-a", UID: types.UID("pod-a-uid")},
		}},
	})
	if len(endpoints) != 1 {
		t.Fatalf("endpoints = %+v, want 1", endpoints)
	}
	got := endpoints[0]
	if got.PortName != "named" || got.Port != 9090 || got.Protocol != "TCP" {
		t.Fatalf("endpoint port = %+v", got)
	}
	if got.TargetUID != "pod-a-uid" || got.TargetName != "pod-a" || got.TargetNamespace != "demo" || !got.HasTargetRef {
		t.Fatalf("endpoint target = %+v", got)
	}
	if got.Ready || !got.Serving || !got.Terminating {
		t.Fatalf("terminating serving endpoint lost its conditions: %+v", got)
	}
}

func TestEndpointSliceConditions(t *testing.T) {
	ready, notServing, terminating := true, false, true
	port := int32(9002)
	for _, tc := range []struct {
		name        string
		conditions  discoveryv1.EndpointConditions
		serving     bool
		terminating bool
	}{
		{name: "unknown conditions are ready and serving", serving: true},
		{
			name:       "publishNotReadyAddresses does not imply serving",
			conditions: discoveryv1.EndpointConditions{Ready: &ready, Serving: &notServing},
		},
		{
			name:        "terminating can still be serving",
			conditions:  discoveryv1.EndpointConditions{Terminating: &terminating},
			serving:     true,
			terminating: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoints := endpointsFromSlice("cluster.local", &discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "demo",
					Name:      "manual",
					Labels:    map[string]string{discoveryv1.LabelServiceName: "manual"},
				},
				Ports: []discoveryv1.EndpointPort{{Port: &port}},
				Endpoints: []discoveryv1.Endpoint{{
					Addresses:  []string{"10.0.0.1"},
					Conditions: tc.conditions,
				}},
			})
			if len(endpoints) != 1 {
				t.Fatalf("endpoints=%v, want one endpoint", endpoints)
			}
			got := endpoints[0]
			if !got.Ready || got.Serving != tc.serving || got.Terminating != tc.terminating {
				t.Fatalf("endpoint lost its conditions: %+v", got)
			}
		})
	}
}

func TestHeadlessServiceDoesNotPublishNoneAddress(t *testing.T) {
	service := serviceFromKubernetes("cluster.local", &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "manual"},
		Spec: corev1.ServiceSpec{
			ClusterIP:  corev1.ClusterIPNone,
			ClusterIPs: []string{corev1.ClusterIPNone},
		},
	})
	if len(service.Addresses) != 0 {
		t.Fatalf("headless service addresses = %v, want none", service.Addresses)
	}
}

func TestServiceTrafficPolicyTranslation(t *testing.T) {
	local := corev1.ServiceInternalTrafficPolicyLocal
	preferSameNode := corev1.ServiceTrafficDistributionPreferSameNode
	service := serviceFromKubernetes("cluster.local", &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "backend"},
		Spec: corev1.ServiceSpec{
			InternalTrafficPolicy: &local,
			TrafficDistribution:   &preferSameNode,
			IPFamilies:            []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
		},
	})
	if !service.InternalTrafficPolicyLocal {
		t.Fatal("internalTrafficPolicy=Local was not translated")
	}
	if service.TrafficDistribution != model.TrafficDistributionPreferSameNode {
		t.Fatalf("traffic distribution = %v, want PreferSameNode", service.TrafficDistribution)
	}
	if service.IPFamilies != model.IPFamiliesDual {
		t.Fatalf("ip families = %v, want dual", service.IPFamilies)
	}

	annotated := serviceFromKubernetes("cluster.local", &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "demo",
			Name:        "annotated",
			Annotations: map[string]string{"networking.istio.io/traffic-distribution": "PreferClose"},
		},
		Spec: corev1.ServiceSpec{IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol}},
	})
	if annotated.TrafficDistribution != model.TrafficDistributionAny {
		t.Fatalf("legacy annotation changed traffic distribution to %v", annotated.TrafficDistribution)
	}
	if annotated.IPFamilies != model.IPFamiliesIPv6Only {
		t.Fatalf("annotated ip families = %v, want IPv6 only", annotated.IPFamilies)
	}
	if annotated.InternalTrafficPolicyLocal {
		t.Fatal("cluster internal traffic policy became local")
	}
	for _, preference := range []string{corev1.ServiceTrafficDistributionPreferClose, corev1.ServiceTrafficDistributionPreferSameZone} {
		t.Run(preference, func(t *testing.T) {
			service := serviceFromKubernetes("cluster.local", &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "backend"},
				Spec:       corev1.ServiceSpec{TrafficDistribution: &preference},
			})
			if service.TrafficDistribution != model.TrafficDistributionPreferSameZone {
				t.Fatalf("native traffic distribution = %v, want PreferSameZone", service.TrafficDistribution)
			}
		})
	}
}

func TestServicePreservesWDSNetworkingSemantics(t *testing.T) {
	h2c := "kubernetes.io/h2c"
	grpc := "grpc"
	service := serviceFromKubernetes("cluster.local", &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "backend",
		},
		Spec: corev1.ServiceSpec{
			PublishNotReadyAddresses: true,
			Ports: []corev1.ServicePort{
				{
					Name: "http-api",
					Port: 80,
				},
				{
					Name:        "backend",
					Port:        81,
					AppProtocol: &h2c,
				},
				{
					Name:        "rpc",
					Port:        82,
					AppProtocol: &grpc,
				},
			},
		},
	})

	if !service.Canonical {
		t.Fatal("Kubernetes Service was not marked canonical")
	}
	if !service.PublishNotReadyAddresses {
		t.Fatal("publishNotReadyAddresses was not preserved")
	}
	want := []model.AppProtocol{
		model.AppProtocolHTTP11,
		model.AppProtocolHTTP2,
		model.AppProtocolGRPC,
	}
	for index, port := range service.Ports {
		if port.AppProtocol != want[index] {
			t.Fatalf("port %d app protocol = %q, want %q", index, port.AppProtocol, want[index])
		}
	}
}

func TestEndpointTargetRefFQDNSliceIsIgnored(t *testing.T) {
	portName := "http"
	port := int32(8080)
	protocol := corev1.ProtocolTCP
	got := endpointsFromSlice("cluster.local", &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "external-abc",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "external"},
		},
		AddressType: discoveryv1.AddressTypeFQDN,
		Ports:       []discoveryv1.EndpointPort{{Name: &portName, Port: &port, Protocol: &protocol}},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{"backend.example.com"},
			TargetRef: &corev1.ObjectReference{
				Kind:      "Pod",
				Namespace: "demo",
				Name:      "pod-a",
				UID:       types.UID("pod-a-uid"),
			},
		}},
	})
	if len(got) != 0 {
		t.Fatalf("FQDN targetRef endpoints = %+v, want none", got)
	}
}

// Endpoints are derived from EndpointSlices, so deleting a slice has to withdraw
// exactly the endpoints it produced.
func TestEndpointsFollowTheirSlice(t *testing.T) {
	ctx := t.Context()
	port := int32(8080)
	ready := true
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "backend-abc",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "backend"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.1.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
			{Addresses: []string{"10.1.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
		Ports: []discoveryv1.EndpointPort{{Port: &port}},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{slice}, nil)

	eventually(t, func() bool { return len(r.Endpoints.List()) == 2 }, "endpoints derived from the slice")
	for _, endpoint := range r.Endpoints.List() {
		if endpoint.ServiceKey != "demo/backend.demo.svc.cluster.local" {
			t.Fatalf("service key = %q", endpoint.ServiceKey)
		}
		if endpoint.SourceKey != "demo/backend-abc" {
			t.Fatalf("source key = %q", endpoint.SourceKey)
		}
	}

	if err := r.client.DiscoveryV1().EndpointSlices("demo").Delete(ctx, "backend-abc", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return len(r.Endpoints.List()) == 0 }, "endpoints withdrawn with the slice")
}

// A slice with no service label produces nothing rather than a bogus hostname.
func TestEndpointSliceWithoutServiceLabelIsIgnored(t *testing.T) {
	ctx := t.Context()
	port := int32(8080)
	r := newTestRegistry(t, ctx, []runtime.Object{&discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "orphan"},
		Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"10.1.0.1"}}},
		Ports:      []discoveryv1.EndpointPort{{Port: &port}},
	}}, nil)

	// Nothing to wait for, so give the transformation a chance to run and then
	// assert the collection stayed empty.
	time.Sleep(200 * time.Millisecond)
	if got := r.Endpoints.List(); len(got) != 0 {
		t.Fatalf("endpoints = %+v, want none", got)
	}
}
