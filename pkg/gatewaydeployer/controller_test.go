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
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"istio.io/istio/pkg/util/sets"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientfeatures "k8s.io/client-go/features"
	clientfeaturestesting "k8s.io/client-go/features/testing"
	appsinformers "k8s.io/client-go/informers/apps/v1"
	autoscalinginformers "k8s.io/client-go/informers/autoscaling/v2"
	coreinformers "k8s.io/client-go/informers/core/v1"
	policyinformers "k8s.io/client-go/informers/policy/v1"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	appsclientv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	coreclientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
	gatewayclientv1 "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/typed/apis/v1"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apis/v1"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/kube/kclient"
)

// recordedPatch captures a single call into the recording Patcher.
type recordedPatch struct {
	gvr          schema.GroupVersionResource
	namespace    string
	name         string
	data         []byte
	subresources []string
}

// recordingPatcher is a test double for controllerClients.Patcher: it stores
// every patch instead of applying it, so tests can assert on both the target
// and the rendered object contents.
type recordingPatcher struct {
	mu      sync.Mutex
	patches []recordedPatch
}

func (p *recordingPatcher) patch(gvr schema.GroupVersionResource, name, namespace string, data []byte, subresources ...string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	p.patches = append(p.patches, recordedPatch{gvr: gvr, namespace: namespace, name: name, data: cp, subresources: append([]string{}, subresources...)})
	return nil
}

func (p *recordingPatcher) all() []recordedPatch {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]recordedPatch{}, p.patches...)
}

func (p *recordingPatcher) find(kind string) *recordedPatch {
	for _, rp := range p.all() {
		if rp.gvr.Resource == kind {
			return &rp
		}
	}
	return nil
}

func (rp recordedPatch) unmarshal(t *testing.T) map[string]any {
	t.Helper()
	out := map[string]any{}
	if err := json.Unmarshal(rp.data, &out); err != nil {
		t.Fatalf("unmarshal patch for %v: %v", rp.gvr, err)
	}
	return out
}

// controllerTestRig wires fake clientsets, real informers wrapped in kclient,
// and a recording Patcher, following the WatchListClient feature-gate
// workaround already used in classcontroller_test.go.
type controllerTestRig struct {
	t *testing.T

	gatewayClient *gatewayfake.Clientset
	kubeClient    *kubernetesfake.Clientset

	gateways        kclient.Client[*gatewayv1.Gateway]
	gatewayClasses  kclient.Client[*gatewayv1.GatewayClass]
	deployments     kclient.Client[*appsv1.Deployment]
	services        kclient.Client[*corev1.Service]
	serviceAccounts kclient.Client[*corev1.ServiceAccount]
	hpas            kclient.Informer[*autoscalingv2.HorizontalPodAutoscaler]
	pdbs            kclient.Informer[*policyv1.PodDisruptionBudget]
	configMaps      kclient.Informer[*corev1.ConfigMap]

	patcher *recordingPatcher

	stop chan struct{}
}

func newControllerTestRig(t *testing.T, objects ...runtime.Object) *controllerTestRig {
	t.Helper()
	clientfeaturestesting.SetFeatureDuringTest(t, clientfeatures.WatchListClient, false)

	// The fake client's pluralization guesses "gatewaies" for Kind Gateway, so
	// constructor seeding is unreachable; seed namespaced objects through the
	// typed Create instead.
	var gatewayClassObjs []runtime.Object
	var gatewayFixtures []*gatewayv1.Gateway
	var deploymentFixtures []*appsv1.Deployment
	var serviceFixtures []*corev1.Service
	var serviceAccountFixtures []*corev1.ServiceAccount
	var configMapFixtures []*corev1.ConfigMap
	for _, o := range objects {
		switch v := o.(type) {
		case *gatewayv1.Gateway:
			gatewayFixtures = append(gatewayFixtures, v)
		case *gatewayv1.GatewayClass:
			gatewayClassObjs = append(gatewayClassObjs, o)
		case *appsv1.Deployment:
			deploymentFixtures = append(deploymentFixtures, v)
		case *corev1.Service:
			serviceFixtures = append(serviceFixtures, v)
		case *corev1.ServiceAccount:
			serviceAccountFixtures = append(serviceAccountFixtures, v)
		case *corev1.ConfigMap:
			configMapFixtures = append(configMapFixtures, v)
		default:
			t.Fatalf("unsupported fixture object type %T", o)
		}
	}

	gatewayClient := gatewayfake.NewSimpleClientset(gatewayClassObjs...)
	kubeClient := kubernetesfake.NewSimpleClientset()

	ctx := context.Background()
	for _, gw := range gatewayFixtures {
		if _, err := gatewayClient.GatewayV1().Gateways(gw.Namespace).Create(ctx, gw, metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed gateway %s/%s: %v", gw.Namespace, gw.Name, err)
		}
	}
	for _, d := range deploymentFixtures {
		if _, err := kubeClient.AppsV1().Deployments(d.Namespace).Create(ctx, d, metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed deployment %s/%s: %v", d.Namespace, d.Name, err)
		}
	}
	for _, s := range serviceFixtures {
		if _, err := kubeClient.CoreV1().Services(s.Namespace).Create(ctx, s, metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed service %s/%s: %v", s.Namespace, s.Name, err)
		}
	}
	for _, sa := range serviceAccountFixtures {
		if _, err := kubeClient.CoreV1().ServiceAccounts(sa.Namespace).Create(ctx, sa, metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed service account %s/%s: %v", sa.Namespace, sa.Name, err)
		}
	}

	for _, cm := range configMapFixtures {
		if _, err := kubeClient.CoreV1().ConfigMaps(cm.Namespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	cmInformer := coreinformers.NewConfigMapInformer(kubeClient, metav1.NamespaceAll, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	gwInformer := gatewayinformers.NewGatewayInformer(gatewayClient, metav1.NamespaceAll, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	gcInformer := gatewayinformers.NewGatewayClassInformer(gatewayClient, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	depInformer := appsinformers.NewDeploymentInformer(kubeClient, metav1.NamespaceAll, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	svcInformer := coreinformers.NewServiceInformer(kubeClient, metav1.NamespaceAll, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	saInformer := coreinformers.NewServiceAccountInformer(kubeClient, metav1.NamespaceAll, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	hpaInformer := autoscalinginformers.NewHorizontalPodAutoscalerInformer(kubeClient, metav1.NamespaceAll, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	pdbInformer := policyinformers.NewPodDisruptionBudgetInformer(kubeClient, metav1.NamespaceAll, 0, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	gateways := kclient.NewWritable[*gatewayv1.Gateway, gatewayclientv1.GatewayInterface](gwInformer, func(ns string) gatewayclientv1.GatewayInterface {
		return gatewayClient.GatewayV1().Gateways(ns)
	})
	gatewayClasses := kclient.NewWritable[*gatewayv1.GatewayClass, gatewayclientv1.GatewayClassInterface](gcInformer, func(string) gatewayclientv1.GatewayClassInterface {
		return gatewayClient.GatewayV1().GatewayClasses()
	})
	deployments := kclient.NewWritable[*appsv1.Deployment, appsclientv1.DeploymentInterface](depInformer, func(ns string) appsclientv1.DeploymentInterface {
		return kubeClient.AppsV1().Deployments(ns)
	})
	services := kclient.NewWritable[*corev1.Service, coreclientv1.ServiceInterface](svcInformer, func(ns string) coreclientv1.ServiceInterface {
		return kubeClient.CoreV1().Services(ns)
	})
	serviceAccounts := kclient.NewWritableStatusless[*corev1.ServiceAccount, coreclientv1.ServiceAccountInterface](saInformer, func(ns string) coreclientv1.ServiceAccountInterface {
		return kubeClient.CoreV1().ServiceAccounts(ns)
	})
	hpas := kclient.New[*autoscalingv2.HorizontalPodAutoscaler](hpaInformer)
	pdbs := kclient.New[*policyv1.PodDisruptionBudget](pdbInformer)

	stop := make(chan struct{})
	go cmInformer.Run(stop)
	go gwInformer.Run(stop)
	go gcInformer.Run(stop)
	go depInformer.Run(stop)
	go svcInformer.Run(stop)
	go saInformer.Run(stop)
	go hpaInformer.Run(stop)
	go pdbInformer.Run(stop)
	if !cache.WaitForCacheSync(stop, cmInformer.HasSynced, gwInformer.HasSynced, gcInformer.HasSynced, depInformer.HasSynced, svcInformer.HasSynced, saInformer.HasSynced, hpaInformer.HasSynced, pdbInformer.HasSynced) {
		t.Fatal("informers failed to sync")
	}

	return &controllerTestRig{
		t:               t,
		gatewayClient:   gatewayClient,
		kubeClient:      kubeClient,
		gateways:        gateways,
		gatewayClasses:  gatewayClasses,
		deployments:     deployments,
		services:        services,
		serviceAccounts: serviceAccounts,
		hpas:            hpas,
		pdbs:            pdbs,
		configMaps:      kclient.New[*corev1.ConfigMap](cmInformer),
		patcher:         &recordingPatcher{},
		stop:            stop,
	}
}

func (r *controllerTestRig) close() {
	close(r.stop)
}

func (r *controllerTestRig) newController() *DeploymentController {
	return r.newControllerInNamespace("agentio-system")
}

func (r *controllerTestRig) newControllerInNamespace(systemNamespace string) *DeploymentController {
	rend := testRenderer(r.t, testValues(r.t, parityValuesOverlay()))
	clients := controllerClients{
		Gateways:        r.gateways,
		GatewayClasses:  r.gatewayClasses,
		Deployments:     r.deployments,
		Services:        r.services,
		ServiceAccounts: r.serviceAccounts,
		HPAs:            r.hpas,
		PDBs:            r.pdbs,
		ConfigMaps:      r.configMaps,
		Patcher:         r.patcher.patch,
	}
	d, _ := NewDeploymentController(
		clients,
		rend,
		"test-cluster",
		systemNamespace,
		parityKubeVersion,
		func(func()) func() { return func() {} },
	)
	return d
}

func egressGatewayFixture(name, namespace string) *gatewayv1.Gateway {
	mesh := gatewayv1.ProtocolType("HBONE")
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, UID: types.UID("uid-" + name)},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "agentio-egress",
			Listeners:        []gatewayv1.Listener{{Name: "mesh", Port: 15008, Protocol: mesh}},
		},
	}
}

func TestReconcileAppliesRenderedManifests(t *testing.T) {
	gw := egressGatewayFixture("egress", "agentio-system")
	rig := newControllerTestRig(t, gw)
	defer rig.close()
	d := rig.newController()

	if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	patches := rig.patcher.all()
	kinds := sets.New[string]()
	for _, p := range patches {
		if p.gvr == gatewayGVR {
			// The controller-version status-subresource patch targets the
			// Gateway itself, not a rendered child manifest; it carries
			// neither the managed label nor an ownerReference.
			continue
		}
		kinds.Insert(p.gvr.Resource)
		obj := p.unmarshal(t)
		labels, _ := obj["metadata"].(map[string]any)["labels"].(map[string]any)
		if labels[managedLabel] == nil {
			t.Fatalf("patch for %v missing managed label: %v", p.gvr, obj["metadata"])
		}
		owners, _ := obj["metadata"].(map[string]any)["ownerReferences"].([]any)
		if len(owners) == 0 {
			t.Fatalf("patch for %v missing ownerReferences", p.gvr)
		}
		owner := owners[0].(map[string]any)
		if owner["name"] != "egress" || owner["kind"] != "Gateway" {
			t.Fatalf("patch for %v has wrong owner reference: %v", p.gvr, owner)
		}
	}
	if !kinds.Contains("deployments") || !kinds.Contains("services") {
		t.Fatalf("expected Deployment and Service patches, got %v", kinds)
	}
}

func TestReconcileReportsGatewayAcceptedAndProgrammedFromDeploymentReadiness(t *testing.T) {
	for _, tc := range []struct {
		name             string
		deployment       *appsv1.Deployment
		programmedStatus metav1.ConditionStatus
		programmedReason string
	}{
		{
			name:             "deployment pending",
			programmedStatus: metav1.ConditionFalse,
			programmedReason: string(gatewayv1.GatewayReasonPending),
		},
		{
			name: "deployment available",
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "egress",
					Namespace: "agentio-system",
					Labels:    map[string]string{managedLabel: "agentio.kruise.io-egress-gateway-controller"},
				},
				Status: appsv1.DeploymentStatus{Conditions: []appsv1.DeploymentCondition{{
					Type:   appsv1.DeploymentAvailable,
					Status: corev1.ConditionTrue,
				}}},
			},
			programmedStatus: metav1.ConditionTrue,
			programmedReason: string(gatewayv1.GatewayReasonProgrammed),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw := egressGatewayFixture("egress", "agentio-system")
			gw.Generation = 4
			objects := []runtime.Object{gw}
			if tc.deployment != nil {
				objects = append(objects, tc.deployment)
			}
			rig := newControllerTestRig(t, objects...)
			defer rig.close()
			d := rig.newController()

			if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}

			var conditions []metav1.Condition
			for _, patch := range rig.patcher.all() {
				if patch.gvr != gatewayGVR {
					continue
				}
				obj := patch.unmarshal(t)
				status, _ := obj["status"].(map[string]any)
				rawConditions, _ := status["conditions"].([]any)
				if len(rawConditions) == 0 {
					continue
				}
				meta, _ := obj["metadata"].(map[string]any)
				annotations, _ := meta["annotations"].(map[string]any)
				if meta["name"] != gw.Name || meta["namespace"] != gw.Namespace || annotations[ControllerVersionAnnotation] != fmt.Sprint(ControllerVersion) {
					t.Fatalf("status apply must identify the Gateway and retain its controller version: %v", meta)
				}
				encoded, err := json.Marshal(rawConditions)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(encoded, &conditions); err != nil {
					t.Fatal(err)
				}
			}
			accepted := apiMeta.FindStatusCondition(conditions, string(gatewayv1.GatewayConditionAccepted))
			if accepted == nil || accepted.Status != metav1.ConditionTrue ||
				accepted.Reason != string(gatewayv1.GatewayReasonAccepted) || accepted.ObservedGeneration != gw.Generation {
				t.Fatalf("Accepted condition = %+v", accepted)
			}
			programmed := apiMeta.FindStatusCondition(conditions, string(gatewayv1.GatewayConditionProgrammed))
			if programmed == nil || programmed.Status != tc.programmedStatus ||
				programmed.Reason != tc.programmedReason || programmed.ObservedGeneration != gw.Generation {
				t.Fatalf("Programmed condition = %+v, want status=%s reason=%s generation=%d",
					programmed, tc.programmedStatus, tc.programmedReason, gw.Generation)
			}
		})
	}
}

func TestReconcileSkipsManualDeployments(t *testing.T) {
	gw := egressGatewayFixture("egress", "agentio-system")
	ipType := gatewayv1.IPAddressType
	other := gatewayv1.AddressType("Hostname")
	gw.Spec.Addresses = []gatewayv1.GatewaySpecAddress{{Type: &ipType, Value: "10.0.0.1"}, {Type: &other, Value: "example.com"}}
	rig := newControllerTestRig(t, gw)
	defer rig.close()
	d := rig.newController()

	if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if patches := rig.patcher.all(); len(patches) != 0 {
		t.Fatalf("expected no patches for manually-addressed gateway, got %d", len(patches))
	}
}

func TestReconcileSkipsUnknownClassButIgnoresLegacyRevision(t *testing.T) {
	unknownClass := egressGatewayFixture("nginx-gw", "demo")
	unknownClass.Spec.GatewayClassName = "nginx"

	foreignRevision := egressGatewayFixture("canary-gw", "demo")
	foreignRevision.Labels = map[string]string{"istio.io/rev": "canary"}

	rig := newControllerTestRig(t, unknownClass, foreignRevision)
	defer rig.close()
	d := rig.newController()

	if err := d.Reconcile(namespacedNameOf(unknownClass)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if patches := rig.patcher.all(); len(patches) != 0 {
		t.Fatalf("expected no patches for unknown class, got %d", len(patches))
	}
	if err := d.Reconcile(namespacedNameOf(foreignRevision)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if rig.patcher.find("deployments") == nil || rig.patcher.find("services") == nil {
		t.Fatalf("legacy revision suppressed Agentio reconciliation: %+v", rig.patcher.all())
	}
}

func TestCanManageRefusesUnlabelledExisting(t *testing.T) {
	gw := egressGatewayFixture("egress", "agentio-system")
	unlabelled := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "egress", Namespace: "agentio-system"},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"gateway.networking.k8s.io/gateway-name": "egress"}},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"gateway.networking.k8s.io/gateway-name": "egress"}}},
		},
	}
	rig := newControllerTestRig(t, gw, unlabelled)
	defer rig.close()
	d := rig.newController()

	if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	if p := rig.patcher.find("deployments"); p != nil {
		t.Fatalf("expected no Deployment patch for unlabelled existing deployment, got %+v", p)
	}
	if p := rig.patcher.find("services"); p == nil {
		t.Fatal("expected Service to still be applied")
	}
}

func TestReconcileReplacesLegacyGatewaySelector(t *testing.T) {
	gw := egressGatewayFixture("egress", "agentio-system")
	legacy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress",
			Namespace: "agentio-system",
			Labels:    map[string]string{managedLabel: "agentio.kruise.io-egress-gateway-controller"},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"istio.io/gateway-name": "egress"}},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{"istio.io/gateway-name": "egress"},
			}},
		},
	}
	rig := newControllerTestRig(t, gw, legacy)
	defer rig.close()

	if err := rig.newController().Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	patch := rig.patcher.find("deployments")
	if patch == nil {
		t.Fatal("expected Deployment patch")
	}
	object := patch.unmarshal(t)
	spec := object["spec"].(map[string]any)
	selector := spec["selector"].(map[string]any)["matchLabels"].(map[string]any)
	if got := selector["gateway.networking.k8s.io/gateway-name"]; got != "egress" {
		t.Fatalf("Deployment selector = %v, want Agentio Gateway selector", selector)
	}
	if _, found := selector["istio.io/gateway-name"]; found {
		t.Fatalf("Deployment selector retained legacy Istio key: %v", selector)
	}
}

func TestControllerVersionOwnership(t *testing.T) {
	t.Run("annotation absent", func(t *testing.T) {
		gw := egressGatewayFixture("egress", "agentio-system")
		rig := newControllerTestRig(t, gw)
		defer rig.close()
		d := rig.newController()

		if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
			t.Fatalf("Reconcile() error = %v", err)
		}
		var versionPatch *recordedPatch
		for _, p := range rig.patcher.all() {
			if p.gvr != gatewayGVR {
				continue
			}
			obj := p.unmarshal(t)
			metadata, _ := obj["metadata"].(map[string]any)
			annotations, _ := metadata["annotations"].(map[string]any)
			if annotations[ControllerVersionAnnotation] != nil {
				pc := p
				versionPatch = &pc
			}
		}
		if versionPatch == nil {
			t.Fatal("expected a status-subresource controller-version patch")
		}
		if len(versionPatch.subresources) != 1 || versionPatch.subresources[0] != "status" {
			t.Fatalf("controller-version patch subresources = %v, want [status]", versionPatch.subresources)
		}
		obj := versionPatch.unmarshal(t)
		anns, _ := obj["metadata"].(map[string]any)["annotations"].(map[string]any)
		if anns[ControllerVersionAnnotation] != "5" {
			t.Fatalf("controller-version patch annotation = %v, want 5", anns[ControllerVersionAnnotation])
		}
		if p := rig.patcher.find("deployments"); p == nil {
			t.Fatal("expected manifests to still be applied")
		}
	})

	t.Run("newer owner", func(t *testing.T) {
		gw := egressGatewayFixture("egress", "agentio-system")
		gw.Annotations = map[string]string{ControllerVersionAnnotation: "6"}
		rig := newControllerTestRig(t, gw)
		defer rig.close()
		d := rig.newController()

		if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
			t.Fatalf("Reconcile() error = %v", err)
		}
		if patches := rig.patcher.all(); len(patches) != 0 {
			t.Fatalf("expected no patches when a newer controller owns the gateway, got %d", len(patches))
		}
	})

	t.Run("current version", func(t *testing.T) {
		gw := egressGatewayFixture("egress", "agentio-system")
		gw.Annotations = map[string]string{ControllerVersionAnnotation: "5"}
		rig := newControllerTestRig(t, gw)
		defer rig.close()
		d := rig.newController()

		if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
			t.Fatalf("Reconcile() error = %v", err)
		}
		for _, p := range rig.patcher.all() {
			if p.gvr != gatewayGVR {
				continue
			}
			obj := p.unmarshal(t)
			metadata, _ := obj["metadata"].(map[string]any)
			annotations, _ := metadata["annotations"].(map[string]any)
			if annotations[ControllerVersionAnnotation] != nil && obj["status"] == nil {
				t.Fatalf("expected no separate version patch when already at current version, got %+v", p)
			}
		}
		if p := rig.patcher.find("deployments"); p == nil {
			t.Fatal("expected manifests to still be applied")
		}
	})
}

func TestReconcileContinuesOnParametersRef(t *testing.T) {
	gw := egressGatewayFixture("egress", "agentio-system")
	gw.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{
		ParametersRef: &gatewayv1.LocalParametersReference{
			Kind: "ConfigMap",
			Name: "gw-params",
		},
	}
	rig := newControllerTestRig(t, gw, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-params", Namespace: gw.Namespace},
		Data:       map[string]string{"config": "extProc: {service: epe.demo.svc.cluster.local}"},
	})
	defer rig.close()
	d := rig.newController()

	if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if p := rig.patcher.find("deployments"); p == nil {
		t.Fatal("expected manifests to remain independent of the xDS parametersRef")
	}
}

func TestChildResourceChangeRequeuesParentGateway(t *testing.T) {
	gw := egressGatewayFixture("egress", "agentio-system")
	rig := newControllerTestRig(t, gw)
	defer rig.close()
	d := rig.newController()

	// Prime the store with an applied Deployment owned by the Gateway, then
	// drive an Update through the fake clientset so the real informer emits
	// an event the parentHandler must translate into a queue Add.
	yes := true
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "egress",
			Namespace:       "agentio-system",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "gateway.networking.k8s.io/v1", Kind: "Gateway", Name: "egress", UID: gw.UID, Controller: &yes}},
		},
	}
	if _, err := rig.kubeClient.AppsV1().Deployments("agentio-system").Create(context.Background(), dep, metav1.CreateOptions{}); err != nil {
		t.Fatalf("seed deployment: %v", err)
	}
	testutil.WaitFor(t, 5*time.Second, func() bool {
		return rig.deployments.Get("egress", "agentio-system") != nil
	}, "deployment informer to observe seeded deployment")

	stop := make(chan struct{})
	defer close(stop)
	go d.Run(stop)

	testutil.WaitFor(t, 5*time.Second, func() bool {
		return rig.patcher.find("services") != nil
	}, "initial reconcile from Gateway Add to apply the Service")

	// Clear recorded patches, then update the child Deployment to trigger the
	// parent handler.
	rig.patcher.mu.Lock()
	rig.patcher.patches = nil
	rig.patcher.mu.Unlock()

	dep.Labels = map[string]string{"touched": "true"}
	if _, err := rig.kubeClient.AppsV1().Deployments("agentio-system").Update(context.Background(), dep, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update deployment: %v", err)
	}

	testutil.WaitFor(t, 5*time.Second, func() bool {
		return rig.patcher.find("services") != nil
	}, "child Deployment update to requeue and re-reconcile the owning Gateway")
}

func TestChildResourceChangeRequeuesParentGatewayNonControllerOwnerRef(t *testing.T) {
	gw := egressGatewayFixture("egress", "agentio-system")
	rig := newControllerTestRig(t, gw)
	defer rig.close()
	d := rig.newController()

	// Seed a Deployment owned by the Gateway but without Controller=true. Any
	// matching ownerReference must be sufficient, regardless of this field.
	no := false
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "egress",
			Namespace:       "agentio-system",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "gateway.networking.k8s.io/v1", Kind: "Gateway", Name: "egress", UID: gw.UID, Controller: &no}},
		},
	}
	if _, err := rig.kubeClient.AppsV1().Deployments("agentio-system").Create(context.Background(), dep, metav1.CreateOptions{}); err != nil {
		t.Fatalf("seed deployment: %v", err)
	}
	testutil.WaitFor(t, 5*time.Second, func() bool {
		return rig.deployments.Get("egress", "agentio-system") != nil
	}, "deployment informer to observe seeded deployment")

	stop := make(chan struct{})
	defer close(stop)
	go d.Run(stop)

	testutil.WaitFor(t, 5*time.Second, func() bool {
		return rig.patcher.find("services") != nil
	}, "initial reconcile from Gateway Add to apply the Service")

	// Clear recorded patches, then update the child Deployment to trigger the
	// parent handler. Controller=false must still requeue the parent.
	rig.patcher.mu.Lock()
	rig.patcher.patches = nil
	rig.patcher.mu.Unlock()

	dep.Labels = map[string]string{"touched": "true"}
	if _, err := rig.kubeClient.AppsV1().Deployments("agentio-system").Update(context.Background(), dep, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update deployment: %v", err)
	}

	testutil.WaitFor(t, 5*time.Second, func() bool {
		return rig.patcher.find("services") != nil
	}, "child Deployment update with Controller=false ownerReference to still requeue and re-reconcile the owning Gateway")
}

func namespacedNameOf(gw *gatewayv1.Gateway) types.NamespacedName {
	return types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
}

func TestGatewayOwnerRefResolvesControllerReference(t *testing.T) {
	yes := true
	no := false
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		OwnerReferences: []metav1.OwnerReference{
			{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", Controller: &yes},
			{APIVersion: "gateway.networking.k8s.io/v1", Kind: "Gateway", Name: "not-controller", Controller: &no},
			{APIVersion: "gateway.networking.k8s.io/v1", Kind: "Gateway", Name: "egress", Controller: &yes},
		},
	}}
	if got := gatewayOwnerRef(dep); got != "not-controller" {
		t.Fatalf("gatewayOwnerRef() = %q, want not-controller (first Gateway match)", got)
	}

	// Verify a Gateway ownerReference without Controller set also matches.
	depNoController := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		OwnerReferences: []metav1.OwnerReference{
			{APIVersion: "gateway.networking.k8s.io/v1", Kind: "Gateway", Name: "my-gw"},
		},
	}}
	if got := gatewayOwnerRef(depNoController); got != "my-gw" {
		t.Fatalf("gatewayOwnerRef() with nil Controller = %q, want my-gw", got)
	}

	if got := gatewayOwnerRef(&appsv1.Deployment{}); got != "" {
		t.Fatalf("gatewayOwnerRef() with no owners = %q, want empty", got)
	}

	// A Gateway-kind ownerReference from a different API group (networking.istio.io)
	// must NOT match. A gateway.networking.k8s.io ownerReference later in the list
	// should still be returned.
	depForeignGroup := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		OwnerReferences: []metav1.OwnerReference{
			{APIVersion: "networking.istio.io/v1", Kind: "Gateway", Name: "istio-gw"},
			{APIVersion: "gateway.networking.k8s.io/v1", Kind: "Gateway", Name: "real-gw"},
		},
	}}
	if got := gatewayOwnerRef(depForeignGroup); got != "real-gw" {
		t.Fatalf("gatewayOwnerRef() with foreign-group Gateway owner = %q, want real-gw", got)
	}

	// If only a foreign-group Gateway ownerReference is present, return "".
	depOnlyForeign := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		OwnerReferences: []metav1.OwnerReference{
			{APIVersion: "networking.istio.io/v1", Kind: "Gateway", Name: "istio-gw"},
		},
	}}
	if got := gatewayOwnerRef(depOnlyForeign); got != "" {
		t.Fatalf("gatewayOwnerRef() with only foreign-group Gateway owner = %q, want empty", got)
	}
}

func TestManagedGatewayControllerVersionProtocol(t *testing.T) {
	tests := []struct {
		name             string
		annotation       string
		hasAnnotation    bool
		wantTakeOver     bool
		wantShouldHandle bool
	}{
		{name: "absent", hasAnnotation: false, wantTakeOver: true, wantShouldHandle: true},
		{name: "older", annotation: "3", hasAnnotation: true, wantTakeOver: true, wantShouldHandle: true},
		{name: "current", annotation: fmt.Sprintf("%d", ControllerVersion), hasAnnotation: true, wantTakeOver: false, wantShouldHandle: true},
		{name: "newer", annotation: "6", hasAnnotation: true, wantTakeOver: false, wantShouldHandle: false},
		{name: "unparseable", annotation: "abc", hasAnnotation: true, wantTakeOver: false, wantShouldHandle: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gw := gatewayv1.Gateway{}
			if tc.hasAnnotation {
				gw.Annotations = map[string]string{ControllerVersionAnnotation: tc.annotation}
			}
			_, takeOver, shouldHandle := managedGatewayControllerVersion(gw)
			if takeOver != tc.wantTakeOver || shouldHandle != tc.wantShouldHandle {
				t.Fatalf("managedGatewayControllerVersion() = (takeOver=%v, shouldHandle=%v), want (%v, %v)",
					takeOver, shouldHandle, tc.wantTakeOver, tc.wantShouldHandle)
			}
		})
	}
}

// Verifies label overrides key off classInfo.templateName, not the class name.
func TestSetLabelOverridesUsesClassTemplateNotName(t *testing.T) {
	gw := gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "egress", Namespace: "ns"},
		Spec:       gatewayv1.GatewaySpec{GatewayClassName: "agentio-egress"},
	}

	input := buildTemplateInput(gw, builtinClasses["agentio-egress"], "cluster", 133, "net-a")
	if value, found := input.InfrastructureLabels[dataplaneModeLabel]; found {
		t.Fatalf("egress-gateway-template class must not get the %s default, got %q", dataplaneModeLabel, value)
	}
	if got := input.InfrastructureLabels[networkLabel]; got != "net-a" {
		t.Fatalf("egress-gateway-template class should default %s to the global network, got %q", networkLabel, got)
	}

	gw.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{Labels: map[gatewayv1.LabelKey]gatewayv1.LabelValue{
		"agentio.kruise.io/network": "net-explicit",
	}}
	input = buildTemplateInput(gw, builtinClasses["agentio-egress"], "cluster", 133, "net-a")
	if got := input.InfrastructureLabels["agentio.kruise.io/network"]; got != "net-explicit" {
		t.Fatalf("explicit Agentio network = %q, want net-explicit", got)
	}

	gw.Spec.Infrastructure = nil
	nonEgressGateway := classInfo{templateName: "other", defaultServiceType: corev1.ServiceTypeLoadBalancer}
	input = buildTemplateInput(gw, nonEgressGateway, "cluster", 133, "net-a")
	if got := input.InfrastructureLabels[dataplaneModeLabel]; got != dataplaneModeNone {
		t.Fatalf("non-egress-gateway-template class must default %s to %q, got %q", dataplaneModeLabel, dataplaneModeNone, got)
	}
	if value, found := input.InfrastructureLabels[networkLabel]; found {
		t.Fatalf("non-egress-gateway-template class must not get the network default, got %q", value)
	}
}
