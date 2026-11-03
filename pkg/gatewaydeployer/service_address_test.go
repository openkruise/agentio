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

package gatewaydeployer

import (
	"encoding/json"
	"slices"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestReadyGatewayPublishesServiceAddress(t *testing.T) {
	for _, domain := range []string{"cluster.local", "example.internal", ""} {
		t.Run("domain="+domain, func(t *testing.T) {
			gw := egressGatewayFixture("egress", "agentio-system")
			deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "egress", Namespace: gw.Namespace,
				Labels: map[string]string{managedLabel: "agentio.kruise.io-egress-gateway-controller"}},
				Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue}}}}
			service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "egress", Namespace: gw.Namespace,
				Labels: map[string]string{managedLabel: "agentio.kruise.io-egress-gateway-controller"}},
				Spec: corev1.ServiceSpec{ClusterIP: "10.0.0.10"}}
			rig := newControllerTestRig(t, gw, deployment, service)
			defer rig.close()
			d := rig.newController()
			d.renderer = testRenderer(t, testValues(t, runtimeOverlay(Options{ClusterDomain: domain})))
			if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
				t.Fatal(err)
			}
			if domain == "" {
				domain = "cluster.local"
			}
			for _, patch := range rig.patcher.all() {
				if patch.gvr != gatewayGVR {
					continue
				}
				var result gatewayv1.Gateway
				if err := json.Unmarshal(patch.data, &result); err != nil {
					t.Fatal(err)
				}
				if len(result.Status.Addresses) == 2 && result.Status.Addresses[0].Value == "10.0.0.10" && result.Status.Addresses[1].Value == "egress.agentio-system.svc."+domain {
					if result.Status.Addresses[0].Type == nil || *result.Status.Addresses[0].Type != gatewayv1.IPAddressType || result.Status.Addresses[1].Type == nil || *result.Status.Addresses[1].Type != gatewayv1.HostnameAddressType {
						t.Fatal("gateway address must identify the Service hostname")
					}
					return
				}
			}
			t.Fatal("ready gateway has no Service address")
		})
	}
}

func TestPendingGatewayRetainsPublishedAddress(t *testing.T) {
	gw := egressGatewayFixture("egress", "agentio-system")
	addressType := gatewayv1.HostnameAddressType
	gw.Status.Addresses = []gatewayv1.GatewayStatusAddress{{Type: &addressType, Value: "egress.agentio-system.svc.cluster.local"}}
	rig := newControllerTestRig(t, gw)
	defer rig.close()
	if err := rig.newController().Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatal(err)
	}
	patches := 0
	for _, patch := range rig.patcher.all() {
		if patch.gvr != gatewayGVR {
			continue
		}
		var result gatewayv1.Gateway
		if err := json.Unmarshal(patch.data, &result); err != nil {
			t.Fatal(err)
		}
		patches++
		if len(result.Status.Addresses) != 1 || result.Status.Addresses[0].Value != gw.Status.Addresses[0].Value {
			t.Fatal("status update removed the published address")
		}
	}
	if patches == 0 {
		t.Fatal("no Gateway status update")
	}
}

func TestInvalidGatewayConfigRetainsPublishedAddress(t *testing.T) {
	gw, cm := agentgatewayFixture()
	addressType := gatewayv1.HostnameAddressType
	gw.Status.Addresses = []gatewayv1.GatewayStatusAddress{{Type: &addressType, Value: "agentgateway.demo.svc.cluster.local"}}
	cm.Data[agentgatewayConfigKey] = "binds: ["
	rig := newControllerTestRig(t, gw, cm)
	defer rig.close()
	d := rig.newController()
	d.renderer = agentgatewayRenderer(t)
	if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatal(err)
	}
	patch := rig.patcher.find("gateways")
	if patch == nil {
		t.Fatal("no Gateway status update")
	}
	var result gatewayv1.Gateway
	if err := json.Unmarshal(patch.data, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Status.Addresses) != 1 || result.Status.Addresses[0].Value != gw.Status.Addresses[0].Value {
		t.Fatal("invalid configuration removed the published address")
	}
}

func TestGatewayDoesNotPublishUnmanagedServiceAddress(t *testing.T) {
	gw := egressGatewayFixture("egress", "agentio-system")
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "egress", Namespace: gw.Namespace,
		Labels: map[string]string{managedLabel: "agentio.kruise.io-egress-gateway-controller"}},
		Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue}}}}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "egress", Namespace: gw.Namespace}}
	rig := newControllerTestRig(t, gw, deployment, service)
	defer rig.close()
	if err := rig.newController().Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatal(err)
	}
	for _, patch := range rig.patcher.all() {
		if patch.gvr != gatewayGVR {
			continue
		}
		var result gatewayv1.Gateway
		if err := json.Unmarshal(patch.data, &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Status.Addresses) != 0 {
			t.Fatal("published the address of an unmanaged Service")
		}
	}
}

func TestGatewayAddressSelectionMatchesRelease(t *testing.T) {
	const hostname = "egress.agentio-system.svc.cluster.local"
	for _, tc := range []struct {
		name        string
		service     corev1.ServiceSpec
		ingress     []corev1.LoadBalancerIngress
		override    string
		previous    string
		want        []string
		wantPending bool
	}{
		{name: "internal IP and hostname", service: corev1.ServiceSpec{ClusterIP: "10.0.0.10"}, want: []string{"10.0.0.10", hostname}},
		{name: "dual stack", service: corev1.ServiceSpec{ClusterIPs: []string{"fd00::10", "10.0.0.10"}}, want: []string{"10.0.0.10", "fd00::10", hostname}},
		{name: "hostname override", service: corev1.ServiceSpec{ClusterIP: "10.0.0.10"}, override: "Hostname", want: []string{hostname}},
		{name: "IP override", service: corev1.ServiceSpec{ClusterIP: "10.0.0.10"}, override: "IPAddress", want: []string{"10.0.0.10"}},
		{name: "external IP preferred", service: corev1.ServiceSpec{ClusterIP: "10.0.0.10", ExternalIPs: []string{"192.0.2.10"}}, override: "Hostname", want: []string{"192.0.2.10"}},
		{name: "load balancer hostname", service: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ClusterIP: "10.0.0.10"}, ingress: []corev1.LoadBalancerIngress{{Hostname: "lb.example.com"}}, want: []string{"lb.example.com"}},
		{name: "external address ordering and deduplication", service: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ClusterIP: "10.0.0.10", ExternalIPs: []string{"192.0.2.20", "192.0.2.10"}}, ingress: []corev1.LoadBalancerIngress{{IP: "192.0.2.10"}}, want: []string{"192.0.2.10", "192.0.2.20"}},
		{name: "pending load balancer reports internal IP", service: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ClusterIP: "10.0.0.10"}, want: []string{"10.0.0.10"}, wantPending: true},
		{name: "pending load balancer hides hostname", service: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ClusterIP: "10.0.0.10"}, override: "Hostname", wantPending: true},
		{name: "pending load balancer retains published address", service: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ClusterIP: "10.0.0.10"}, override: "Hostname", previous: "old.example.com", want: []string{"old.example.com"}, wantPending: true},
		{name: "headless service", service: corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone}, want: []string{hostname}},
		{name: "new address replaces previous address", service: corev1.ServiceSpec{ExternalIPs: []string{"192.0.2.30"}}, previous: "old.example.com", want: []string{"192.0.2.30"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw := egressGatewayFixture("egress", "agentio-system")
			if tc.override != "" {
				gw.Annotations = map[string]string{"networking.istio.io/address-type": tc.override}
			}
			if tc.previous != "" {
				typeHostname := gatewayv1.HostnameAddressType
				gw.Status.Addresses = []gatewayv1.GatewayStatusAddress{{Type: &typeHostname, Value: tc.previous}}
			}
			deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace,
				Labels: map[string]string{managedLabel: "agentio.kruise.io-egress-gateway-controller"}},
				Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue}}}}
			service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace,
				Labels: map[string]string{managedLabel: "agentio.kruise.io-egress-gateway-controller"}}, Spec: tc.service,
				Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: tc.ingress}}}
			rig := newControllerTestRig(t, gw, deployment, service)
			defer rig.close()
			if err := rig.newController().Reconcile(namespacedNameOf(gw)); err != nil {
				t.Fatal(err)
			}
			var result gatewayv1.Gateway
			for _, patch := range rig.patcher.all() {
				if patch.gvr == gatewayGVR {
					if err := json.Unmarshal(patch.data, &result); err != nil {
						t.Fatal(err)
					}
				}
			}
			values := make([]string, 0, len(result.Status.Addresses))
			for _, addr := range result.Status.Addresses {
				values = append(values, addr.Value)
				wantType := gatewayv1.IPAddressType
				if addr.Value == hostname || addr.Value == "lb.example.com" || addr.Value == tc.previous {
					wantType = gatewayv1.HostnameAddressType
				}
				if addr.Type == nil || *addr.Type != wantType {
					t.Fatalf("address %q type = %v, want %s", addr.Value, addr.Type, wantType)
				}
			}
			if !slices.Equal(values, tc.want) {
				t.Fatalf("addresses = %v, want %v", values, tc.want)
			}
			for _, condition := range result.Status.Conditions {
				if condition.Type != string(gatewayv1.GatewayConditionProgrammed) {
					continue
				}
				want := metav1.ConditionTrue
				if tc.wantPending {
					want = metav1.ConditionFalse
				}
				if condition.Status != want {
					t.Fatalf("Programmed = %v, want %v", condition, want)
				}
				if tc.wantPending && condition.Reason != string(gatewayv1.GatewayReasonAddressNotAssigned) {
					t.Fatalf("pending reason = %s", condition.Reason)
				}
				return
			}
			t.Fatal("missing Programmed condition")
		})
	}
}

func TestAgentgatewayAddressDefaultIsHostname(t *testing.T) {
	gw := egressGatewayFixture("egress", "agentio-system")
	gw.Spec.GatewayClassName = "agentio-agentgateway"
	ci := builtinClasses["agentio-agentgateway"]
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace},
		Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue}}}}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace,
		Labels: map[string]string{managedLabel: ci.controllerLabel}}, Spec: corev1.ServiceSpec{ClusterIP: "10.0.0.10"}}
	rig := newControllerTestRig(t, gw, deployment, service)
	defer rig.close()
	if err := rig.newController().setGatewayStatus(*gw, TemplateInput{DeploymentName: gw.Name, ControllerLabel: ci.controllerLabel}, ci); err != nil {
		t.Fatal(err)
	}
	patch := rig.patcher.find("gateways")
	if patch == nil {
		t.Fatal("no Gateway status update")
	}
	var result gatewayv1.Gateway
	if err := json.Unmarshal(patch.data, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Status.Addresses) != 1 || result.Status.Addresses[0].Value != "egress.agentio-system.svc.cluster.local" {
		t.Fatalf("agentgateway addresses = %+v", result.Status.Addresses)
	}
}
