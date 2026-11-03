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
				if len(result.Status.Addresses) == 1 && result.Status.Addresses[0].Value == "egress.agentio-system.svc."+domain {
					if result.Status.Addresses[0].Type == nil || *result.Status.Addresses[0].Type != gatewayv1.HostnameAddressType {
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
