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

package agentio

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/artifacts"
	"github.com/openkruise/agentio/test/e2e/cluster"
	"github.com/openkruise/agentio/test/e2e/kube"
)

func TestCollectorsWriteAgentioInventories(t *testing.T) {
	trafficPolicyGVR := schema.GroupVersionResource{
		Group:    "agents.kruise.io",
		Version:  "v1alpha1",
		Resource: "trafficpolicies",
	}
	policy := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "agents.kruise.io/v1alpha1", "kind": "TrafficPolicy",
		"metadata": map[string]any{"name": "allow", "namespace": "sandbox"},
	}}
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(), map[schema.GroupVersionResource]string{trafficPolicyGVR: "TrafficPolicyList"}, policy,
	)
	gatewayPod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-0",
			Namespace: "agentio-system",
			Labels:    map[string]string{"gateway.networking.k8s.io/gateway-name": "egress-gateway"},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "agentio-proxy"}}},
	}
	epePod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "epe-0",
			Namespace: "agentio-system",
			Labels:    map[string]string{"app.kubernetes.io/name": "agentio-epe"},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "agentio-epe"}}},
	}
	podsBySelector := map[string][]corev1.Pod{
		"gateway.networking.k8s.io/gateway-name=egress-gateway": {gatewayPod},
		"app.kubernetes.io/name=agentio-epe":                    {epePod},
	}
	typedServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/log") {
			switch {
			case strings.Contains(request.URL.Path, "/gateway-0/"):
				_, _ = io.WriteString(response, "gateway log\n")
			case strings.Contains(request.URL.Path, "/epe-0/"):
				_, _ = io.WriteString(response, "epe log\n")
			default:
				http.NotFound(response, request)
			}
			return
		}
		if strings.HasSuffix(request.URL.Path, "/pods") {
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(corev1.PodList{
				TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"},
				Items:    podsBySelector[request.URL.Query().Get("labelSelector")],
			})
			return
		}
		http.NotFound(response, request)
	}))
	defer typedServer.Close()
	typed, err := kubernetes.NewForConfig(&rest.Config{Host: typedServer.URL})
	if err != nil {
		t.Fatal(err)
	}
	clusterHandle := &cluster.Cluster{Dynamic: dynamicClient, Kube: typed}
	store, err := artifacts.New(t.TempDir(), "run-1")
	if err != nil {
		t.Fatal(err)
	}
	environment := &e2e.Environment{
		RunID:     "run-1",
		Cluster:   clusterHandle,
		Kube:      kube.NewClient("run-1", clusterHandle, kube.NewLedger()),
		Artifacts: store,
	}
	collectors := Collectors(Config{Profile: ProfileAmbient, Namespace: "agentio-system"})
	if len(collectors) != 5 {
		t.Fatalf("collector count = %d", len(collectors))
	}
	wantNames := []string{"agentiod", "egress-gateway", "agentio-epe", "ztunnel", "xds-config"}
	for index, collector := range collectors {
		if collector.Name() != wantNames[index] {
			t.Fatalf("collector %d name = %q, want %q", index, collector.Name(), wantNames[index])
		}
	}
	for _, collector := range collectors {
		if err := collector.Collect(context.Background(), environment, store); err != nil {
			t.Fatalf("collector %s: %v", collector.Name(), err)
		}
		if _, err := os.Stat(store.Path("setup", "agentio", collector.Name(), "inventory.json")); err != nil {
			t.Fatalf("collector %s inventory: %v", collector.Name(), err)
		}
	}
	for path, want := range map[string]string{
		store.Path("setup", "agentio", "egress-gateway", "pods", "agentio-system", "gateway-0", "agentio-proxy.log"): "gateway log\n",
		store.Path("setup", "agentio", "agentio-epe", "pods", "agentio-system", "epe-0", "agentio-epe.log"):          "epe log\n",
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read collected log %s: %v", path, err)
		}
		if got := string(data); got != want {
			t.Fatalf("collected log %s = %q, want %q", path, got, want)
		}
	}
}

func TestCollectorsSelectZtunnelForProfile(t *testing.T) {
	tests := []struct {
		profile, wantNamespace, wantSelector, wantNamespaceSelector, wantContainer string
	}{
		{
			profile:               "sidecar",
			wantNamespaceSelector: "agentio.kruise.io/dataplane-mode=sidecar",
			wantContainer:         "agentio-proxy",
		},
		{profile: "ambient", wantNamespace: "agentio-system", wantSelector: "app.kubernetes.io/name=ztunnel"},
	}
	for _, tc := range tests {
		t.Run(tc.profile, func(t *testing.T) {
			collectors := Collectors(Config{Profile: tc.profile, Namespace: "agentio-system"})
			ztunnel, ok := collectors[3].(podCollector)
			if !ok {
				t.Fatalf("ztunnel collector has type %T", collectors[3])
			}
			if ztunnel.namespace != tc.wantNamespace || ztunnel.selector != tc.wantSelector ||
				ztunnel.namespaceSelector != tc.wantNamespaceSelector || ztunnel.requiredContainer != tc.wantContainer {
				t.Fatalf("ztunnel collector = %#v", ztunnel)
			}
		})
	}
}

func TestPodCollectorSelectsSidecarsFromEnrolledNamespaces(t *testing.T) {
	client := kubernetesfake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name:   "sidecar",
			Labels: map[string]string{"agentio.kruise.io/dataplane-mode": "sidecar"},
		}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name:   "ambient",
			Labels: map[string]string{"agentio.kruise.io/dataplane-mode": "ambient"},
		}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "unenrolled"}},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "injected", Namespace: "sidecar"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}, {Name: "agentio-proxy"}}},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "not-injected", Namespace: "sidecar"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "ambient-pod", Namespace: "ambient"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "agentio-proxy"}}},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "unenrolled-pod", Namespace: "unenrolled"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "agentio-proxy"}}},
		},
	)
	collector := podCollector{
		namespaceSelector: "agentio.kruise.io/dataplane-mode=sidecar",
		requiredContainer: "agentio-proxy",
	}
	pods, err := collector.listPods(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods.Items) != 1 || pods.Items[0].Namespace != "sidecar" || pods.Items[0].Name != "injected" {
		t.Fatalf("selected Pods = %#v", pods.Items)
	}
}
