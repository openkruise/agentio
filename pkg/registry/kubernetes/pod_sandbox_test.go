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
	"fmt"
	"slices"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/compiler"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

func managedSandboxPod(name string, injected bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "demo",
			UID:       types.UID(name + "-uid"),
			Labels:    map[string]string{"app": "client"},
		},
		Spec:   corev1.PodSpec{ServiceAccountName: "client", NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodPending, PodIP: "10.0.0.1"},
	}
	if injected {
		p.Spec.Containers = []corev1.Container{{Name: "agentio-proxy",
			Args: []string{"proxy", "ztunnel"},
			Env: []corev1.EnvVar{
				{Name: "ENABLE_SIDECAR_MODE", Value: "true"}, {Name: "PROXY_MODE", Value: "dedicated"},
			}}}
	} else {
		p.Annotations = map[string]string{"ambient.istio.io/redirection": "enabled"}
	}
	return p
}

func TestRegistryPodSandboxesAndRuntimeOwnership(t *testing.T) {
	for _, kruiseEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("kruise=%t", kruiseEnabled), func(t *testing.T) {
			ctx := t.Context()
			injected, ambient := managedSandboxPod("injected", true), managedSandboxPod("ambient", false)
			ambient.Status.PodIP = "10.0.0.2"
			unmanaged, warm := managedSandboxPod("unmanaged", false), managedSandboxPod("warm", true)
			unmanaged.Annotations = nil
			unmanaged.Status.PodIP, warm.Status.PodIP = "10.0.0.3", "10.0.0.4"
			controller := true
			warm.OwnerReferences = []metav1.OwnerReference{
				{
					APIVersion: agentsv1alpha1.GroupVersion.String(),
					Kind:       "Sandbox",
					Name:       "pool",
					UID:        "pool-uid",
					Controller: &controller,
				},
			}
			client := &fakeKubeClient{Client: kube.NewFakeClient(injected, ambient, unmanaged, warm),
				watcher: newFakeGatewayCRDWatcher(agentsv1alpha1.GroupVersion.WithResource("sandboxes"))}
			// The host is already classified while its runtime Sandbox is still absent.
			r, err := New(
				client,
				Options{ClusterID: "test", TrustDomain: "cluster.local", EnableKruise: kruiseEnabled},
				ctx.Done(),
			)
			if err != nil {
				t.Fatal(err)
			}
			client.Run(ctx.Done())
			eventually(t, r.HasSynced, "registry synchronized")
			if got := r.Sandboxes.List(); len(got) != 0 {
				t.Fatalf("ordinary Pods must not create Sandbox resources: %+v", got)
			}
			for _, p := range []*corev1.Pod{injected, ambient, unmanaged, warm} {
				w := r.Workloads.GetKey(podsource.WorkloadUID("test", p))
				if w == nil {
					t.Fatalf("Workload for %s = %+v", p.Name, w)
				}
			}
			runtime := &agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{Name: "pool",
				Namespace: "demo",
				UID:       "pool-uid",
				Labels:    map[string]string{agentsv1alpha1.LabelSandboxPool: "pool"}},
				Status: agentsv1alpha1.SandboxStatus{PodInfo: agentsv1alpha1.PodInfo{PodUID: warm.UID}}}
			runtime, err = client.AgentsAPI().
				AgentsV1alpha1().
				Sandboxes("demo").
				Create(ctx, runtime, metav1.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			runtime.Labels[agentsv1alpha1.LabelSandboxID] = "assigned-sandbox"
			runtime.Labels[agentsv1alpha1.LabelSandboxIsClaimed] = agentsv1alpha1.True
			if _, err = client.AgentsAPI().
				AgentsV1alpha1().
				Sandboxes("demo").
				Update(ctx, runtime, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if kruiseEnabled {
				eventually(t, func() bool {
					s := r.Sandboxes.GetKey("kruise:assigned-sandbox")
					return s != nil && s.Attester != nil &&
						s.Attester.WorkloadUID == podsource.WorkloadUID("test", warm)
				}, "runtime binding joins ordinary Pod Sandboxes")
			}
			want := 0
			if kruiseEnabled {
				want = 1
			}
			if len(r.Sandboxes.List()) != want {
				t.Fatalf("Sandbox count = %d, want %d real runtime Sandbox", len(r.Sandboxes.List()), want)
			}

		})
	}
}

func TestPodPoliciesReachWorkloadsWithoutSandboxes(t *testing.T) {
	for _, sandboxMode := range []bool{false, true} {
		t.Run(fmt.Sprintf("sandboxMode=%t", sandboxMode), func(t *testing.T) {
			ctx := t.Context()
			injected, ambient := managedSandboxPod("injected", true), managedSandboxPod("ambient", false)
			// A disabled runtime must not exclude an otherwise managed Pod from
			// shared Workload policies.
			controller := true
			injected.OwnerReferences = []metav1.OwnerReference{
				{
					APIVersion: agentsv1alpha1.GroupVersion.String(),
					Kind:       "Sandbox",
					Name:       "actor",
					UID:        "actor-uid",
					Controller: &controller,
				},
			}
			ambient.Status.PodIP = "10.0.0.2"
			spec := func(priority int32) agentsv1alpha1.TrafficPolicySpec {
				return agentsv1alpha1.TrafficPolicySpec{
					Priority: priority,
					Egress: &agentsv1alpha1.TrafficPolicyDirection{
						Rules: []agentsv1alpha1.TrafficPolicyRule{
							{
								Action: agentsv1alpha1.RuleActionAllow,
								To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "192.0.2.0/24"}},
							},
						},
					},
				}
			}
			global := &agentsv1alpha1.GlobalTrafficPolicy{ObjectMeta: metav1.ObjectMeta{Name: "global"}, Spec: spec(5)}
			namespace := &agentsv1alpha1.TrafficPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "namespace"},
				Spec:       spec(20),
			}
			selected := &agentsv1alpha1.TrafficPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "selected"},
				Spec:       spec(10),
			}
			selected.Spec.Selector.MatchLabels = map[string]string{"app": "client"}
			security := &agentsv1alpha1.SecurityProfile{
				ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "security"},
				Spec: agentsv1alpha1.SecurityProfileSpec{
					Selector: selected.Spec.Selector,
					Rules: []agentsv1alpha1.SecurityRule{
						{Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"api.example"}}}},
					},
				},
			}
			config := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: "agentio-system", Name: "agentio-config"},
				Data: map[string]string{
					"config": "egressPolicies:\n- namespaces: [demo]\n  policy: PASSTHROUGH\n",
				},
			}
			client := &fakeKubeClient{
				Client: kube.NewFakeClient(injected, ambient, global, namespace, selected, security, config),
				watcher: newFakeGatewayCRDWatcher(
					trafficPolicyResource,
					globalTrafficPolicyResource,
					securityProfileResource,
				),
			}
			r, err := New(
				client,
				Options{ClusterID: "test", TrustDomain: "cluster.local", RootNamespace: "agentio-system"},
				ctx.Done(),
			)
			if err != nil {
				t.Fatal(err)
			}
			c, err := compiler.New(compiler.Inputs{
				SandboxMode:                sandboxMode,
				ClusterID:                  "test",
				RootNamespace:              "agentio-system",
				TrustDomain:                "cluster.local",
				DiscoveryAddress:           "agentiod:15012",
				Pods:                       r.Pods,
				KubernetesServices:         r.KubernetesServices,
				EndpointSlices:             r.EndpointSlices,
				ConfigMaps:                 r.ConfigMaps,
				Secrets:                    r.Secrets,
				Sandboxes:                  r.Sandboxes.Collection,
				Workloads:                  r.Workloads,
				Services:                   r.Services,
				Endpoints:                  r.Endpoints,
				Gateways:                   r.Gateways,
				TrafficPolicies:            r.TrafficPolicies,
				SecurityProfiles:           r.SecurityProfiles,
				GatewayPatches:             r.GatewayPatches,
				Telemetry:                  r.Telemetry,
				TelemetryProviderOverrides: r.TelemetryProviderOverrides,
				AgentioConfig:              r.AgentioConfig,
			}, krt.NewOptionsBuilder(ctx.Done(), "pod-sandbox", nil))
			if err != nil {
				t.Fatal(err)
			}
			client.Run(ctx.Done())
			eventually(
				t,
				func() bool { return r.HasSynced() && c.HasSynced() },
				"registry and compiler synchronized without Kruise integration",
			)
			snapshot := func() model.ResourceSet {
				s, err := c.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				return s
			}
			getWorkload := func(name string) *workloadv1.Workload {
				w := &workloadv1.Address{}
				resource, ok := snapshot().Get(model.ResourceKey{TypeURL: model.AddressType, Name: "test//Pod/demo/" + name})
				if ok {
					if err := resource.Value.UnmarshalTo(w); err != nil {
						t.Fatal(err)
					}
				}
				return w.GetWorkload()
			}
			refs := []string{
				"trafficPolicies/global",
				"namespaces/demo/trafficPolicies/selected",
				"namespaces/demo/trafficPolicies/namespace",
			}
			eventually(t, func() bool {
				if len(snapshot().List(model.SandboxType)) != 0 {
					return false
				}
				for _, name := range []string{"injected", "ambient"} {
					w := getWorkload(name)
					if w == nil || !slices.Equal(w.AuthorizationPolicies, []string{"demo/selected-egress"}) ||
						len(w.Extensions) != 5 {
						return false
					}
					if !slices.Equal(c.PolicyNames(w.Uid, model.PolicyKindTrafficPolicy), refs) {
						return false
					}
				}
				return true
			}, "ordinary Workloads receive shared policies without Sandbox resources")

			ambient.Labels = map[string]string{"app": "other"}
			if _, err := client.Kube().CoreV1().Pods("demo").Update(ctx, ambient, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			eventually(t, func() bool {
				w := getWorkload("ambient")
				return w != nil && len(w.AuthorizationPolicies) == 0 && len(w.Extensions) == 4 &&
					slices.Equal(c.PolicyNames(w.Uid, model.PolicyKindTrafficPolicy), []string{refs[0], refs[2]})
			}, "Pod label updates reselect Workload policies")
		})
	}
}
