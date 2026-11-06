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
	"context"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/model"
)

func TestPolicyDebounceDoesNotDelayIdentityAndNetworking(t *testing.T) {
	ctx := t.Context()
	pod := egressPod("agentio-system", "gateway", "egress", "10.0.0.1")
	pod.UID = "gateway-pod"
	client := &fakeKubeClient{
		Client: kube.NewFakeClient(
			pod,
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "origin"}},
			&discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "demo",
					Name:      "origin",
					Labels:    map[string]string{discoveryv1.LabelServiceName: "origin"},
				},
				AddressType: discoveryv1.AddressTypeIPv4,
				Ports:       []discoveryv1.EndpointPort{{Port: new(int32(80))}},
				Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.2"}}},
			},
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
				Data: map[string]string{
					"config": "egressGateways:\n- name: egress\n  namespace: agentio-system\n",
				},
			},
			&agentsv1alpha1.TrafficPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "policy"}},
		),
		watcher: newFakeGatewayCRDWatcher(
			trafficPolicyResource,
			globalTrafficPolicyResource,
			securityProfileResource,
			globalSecurityProfileResource,
			schema.GroupVersionResource{
				Group:    agentsv1alpha1.GroupVersion.Group,
				Version:  agentsv1alpha1.GroupVersion.Version,
				Resource: "sandboxes",
			},
		),
	}
	registry, err := New(client, Options{
		ClusterID:     "test",
		TrustDomain:   "cluster.local",
		RootNamespace: "agentio-system",
		EnableKruise:  true,
		DebounceAfter: time.Hour,
		DebounceMax:   time.Hour,
	}, ctx.Done())
	if err != nil {
		t.Fatal(err)
	}

	client.Run(ctx.Done())
	// Sync both sources before creating the Sandbox: the fake tracker cannot
	// replay an event sent between the Sandbox informer's initial list and watch.
	if err := wait.PollUntilContextTimeout(ctx, time.Millisecond, 3*time.Second, true,
		func(context.Context) (bool, error) {
			return registry.SecurityProfiles.HasSynced() && registry.Sandboxes.HasSynced(), nil
		}); err != nil {
		t.Fatal(err)
	}
	policyEvents := make(chan struct{}, 1)
	registration := registry.SecurityProfiles.RegisterBatch(func(events []krt.Event[model.SecurityProfile]) {
		if len(events) > 0 {
			policyEvents <- struct{}{}
		}
	}, false)
	defer registration.UnregisterHandler()
	if !registration.WaitUntilSynced(ctx.Done()) {
		t.Fatal("policy subscription did not sync")
	}
	// Seed through the generated client: the generic fake tracker guesses the
	// Sandbox plural incorrectly when it is supplied as an initial object.
	if _, err := client.AgentsAPI().AgentsV1alpha1().Sandboxes("demo").Create(ctx,
		&agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "sandbox",
			UID:       "sandbox-uid",
			Labels:    map[string]string{agentsv1alpha1.LabelSandboxID: "sandbox-id"},
			Annotations: map[string]string{
				agentsv1alpha1.AnnotationSecurityRules: `[{"name":"block","match":[{"domains":["example.com"]}],"actions":{"block":{}}}]`,
			},
		}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// The policy window is deliberately much longer than this timeout: non-policy
	// resources must propagate without waiting for a policy flush.
	if err := wait.PollUntilContextTimeout(
		ctx,
		time.Millisecond,
		3*time.Second,
		true,
		func(context.Context) (bool, error) {
			w := registry.Workloads.GetKey("test//Pod/agentio-system/gateway")
			return w != nil && w.GatewayKey == "agentio-system/egress" &&
				len(registry.Services.List()) == 1 && len(registry.Endpoints.List()) == 1 &&
				registry.Sandboxes.GetKey("kruise:sandbox-id") != nil &&
				registry.Sandboxes.GetKey("kruise:sandbox-id").Policies != nil, nil
		},
	); err != nil {
		t.Fatalf(
			"non-policy events waited for policy debounce: %v; workloads=%+v services=%+v endpoints=%+v sandboxes=%+v",
			err,
			registry.Workloads.List(),
			registry.Services.List(),
			registry.Endpoints.List(),
			registry.Sandboxes.List(),
		)
	}
	if len(registry.TrafficPolicies.List()) != 0 {
		t.Fatal("TrafficPolicy bypassed its debounce window")
	}
	// Sandbox policies belong to the Sandbox input, not the shared profile collection.
	if len(registry.SecurityProfiles.List()) != 0 {
		t.Fatal("inline policy leaked into shared profiles")
	}
	select {
	case <-policyEvents:
		t.Fatal("inline policy emitted an independent profile notification")
	default:
	}
	if err := client.Kube().CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := wait.PollUntilContextTimeout(
		ctx,
		time.Millisecond,
		3*time.Second,
		true,
		func(context.Context) (bool, error) {
			return registry.Workloads.GetKey("test//Pod/agentio-system/gateway") == nil, nil
		},
	); err != nil {
		t.Fatalf("identity removal waited for policy debounce: %v", err)
	}
}
