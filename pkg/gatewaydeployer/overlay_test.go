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
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func overlayFixture() (*gatewayv1.Gateway, *corev1.ConfigMap) {
	gw := egressGatewayFixture("egress", "demo")
	gw.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{
		ParametersRef: &gatewayv1.LocalParametersReference{Kind: "ConfigMap", Name: "params"},
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "params", Namespace: "demo"},
		Data:       map[string]string{"config": "{}"},
	}
	return gw, cm
}

func lastDeployment(p *recordingPatcher) *appsv1.Deployment {
	all := p.all()
	for _, patch := range slices.Backward(all) {
		if patch.gvr.Resource == "deployments" {
			var dep appsv1.Deployment
			if json.Unmarshal(patch.data, &dep) == nil {
				return &dep
			}
		}
	}
	return nil
}

func TestGatewayDeploymentOverlayMergesContainers(t *testing.T) {
	gw, cm := overlayFixture()
	gw.Labels = map[string]string{"team": "platform"}
	gw.Annotations = map[string]string{"example.com/setting": "inherited"}
	cm.Data["deployment"] = `spec:
  template:
    spec:
      terminationGracePeriodSeconds: 60
      containers:
      - name: agentio-proxy
        securityContext:
          runAsUser: 0
          runAsNonRoot: false
          capabilities:
            add: [NET_ADMIN]
        resources:
          requests:
            cpu: 250m
        env:
        - name: OVERLAY_VERSION
          value: one
      - name: helper-sidecar
        image: example.com/helper:test
`
	rig := newControllerTestRig(t, gw, cm)
	defer rig.close()
	if err := rig.newController().Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatal(err)
	}
	dep := lastDeployment(rig.patcher)
	if dep == nil {
		t.Fatal("Deployment missing")
	}
	for _, meta := range []metav1.ObjectMeta{dep.ObjectMeta, dep.Spec.Template.ObjectMeta} {
		if meta.Labels["team"] != "platform" || meta.Annotations["example.com/setting"] != "inherited" {
			t.Fatalf("parametersRef lost inherited Gateway metadata: %+v", meta)
		}
	}
	containers := dep.Spec.Template.Spec.Containers
	if len(containers) != 2 ||
		!slices.ContainsFunc(containers, func(c corev1.Container) bool { return c.Name == "helper-sidecar" }) {
		t.Fatalf("containers: %+v", containers)
	}
	initContainers := dep.Spec.Template.Spec.InitContainers
	if len(initContainers) != 1 || initContainers[0].Name != "agentio-porter" ||
		initContainers[0].RestartPolicy == nil || *initContainers[0].RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("Porter must remain a native sidecar after overlay: %+v", initContainers)
	}

	c := containers[0]
	if c.Name != "agentio-proxy" || c.Image == "" || len(c.Args) == 0 || len(c.VolumeMounts) == 0 || len(c.Env) < 2 {
		t.Fatalf("proxy template was replaced: %+v", c)
	}
	if *c.SecurityContext.RunAsUser != 0 || *c.SecurityContext.RunAsNonRoot || *c.SecurityContext.RunAsGroup != 1337 ||
		c.SecurityContext.Capabilities.Add[0] != "NET_ADMIN" ||
		c.SecurityContext.Capabilities.Drop[0] != "ALL" {
		t.Fatalf("security context: %+v", c.SecurityContext)
	}
	if dep.Spec.Template.Spec.TerminationGracePeriodSeconds == nil ||
		*dep.Spec.Template.Spec.TerminationGracePeriodSeconds != 60 ||
		!slices.ContainsFunc(c.Env, func(e corev1.EnvVar) bool {
			return e.Name == "AGENTIO_TERMINATION_GRACE_PERIOD_SECONDS" && e.Value == "60" && e.ValueFrom == nil
		}) {
		t.Fatalf("termination budget did not follow the Gateway overlay: %+v", dep.Spec.Template.Spec)
	}
	if c.Resources.Requests.Cpu().String() != "250m" {
		t.Fatal("CPU override missing")
	}
}

func TestGatewayOverlayInvalidParameters(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   string
		patch string
	}{
		{"syntax", "deployment", "spec: ["},
		{"unsupported", "deploymnt", "{}"},
		{"name", "deployment", "metadata: {name: another}"},
		{"namespace", "deployment", "metadata: {namespace: another}"},
		{"ownership", "deployment", "metadata: {ownerReferences: null}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw, cm := overlayFixture()
			cm.Data[tc.key] = tc.patch
			rig := newControllerTestRig(t, gw, cm)
			defer rig.close()
			d := rig.newController()
			input := buildTemplateInput(*gw, builtinClasses["agentio-egress"], "test-cluster", parityKubeVersion, "")
			if _, err := d.renderGateway(egressGatewayTemplateName, input); err == nil {
				t.Fatal("invalid overlay rendered successfully")
			}
			if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
				t.Fatal(err)
			}
			if lastDeployment(rig.patcher) != nil || rig.patcher.find("services") != nil {
				t.Fatal("invalid overlay applied child resources")
			}
			for _, p := range rig.patcher.all() {
				if strings.Contains(string(p.data), "InvalidParameters") {
					t.Fatal("overlay rendering errors should only be logged")
				}
			}
		})
	}
}

func TestGatewayOverlayConfigMapEvents(t *testing.T) {
	gw, cm := overlayFixture()
	patch := func(version string) string {
		return "spec:\n  template:\n    spec:\n      containers:\n      - name: agentio-proxy\n        env:\n        - name: OVERLAY_VERSION\n          value: " + version + "\n"
	}
	cm.Data["deployment"] = patch("one")
	rig := newControllerTestRig(t, gw, cm)
	defer rig.close()
	d := rig.newController()
	stop := make(chan struct{})
	defer close(stop)
	go d.Run(stop)
	version := func() string {
		dep := lastDeployment(rig.patcher)
		if dep == nil {
			return "missing"
		}
		for _, env := range dep.Spec.Template.Spec.Containers[0].Env {
			if env.Name == "OVERLAY_VERSION" {
				return env.Value
			}
		}
		return ""
	}
	waitCondition(t, 5*time.Second, func() bool { return version() == "one" }, "initial patch")
	cm = cm.DeepCopy()
	cm.Data["deployment"] = patch("two")
	if _, err := rig.kubeClient.CoreV1().
		ConfigMaps(cm.Namespace).
		Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitCondition(t, 5*time.Second, func() bool { return version() == "two" }, "ConfigMap update to requeue Gateway")
	// Proxy configuration changes must not change the generated Pod template.
	before := lastDeployment(rig.patcher).Spec.Template.DeepCopy()
	cm = cm.DeepCopy()
	cm.Data["config"] = "accessLogFormat: {text: test}"
	if _, err := rig.kubeClient.CoreV1().
		ConfigMaps(cm.Namespace).
		Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitCondition(t, 5*time.Second, func() bool {
		return d.clients.ConfigMaps.Get(cm.Name, cm.Namespace).Data["config"] == cm.Data["config"]
	}, "proxy config change")
	if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatal(err)
	}
	if !equality.Semantic.DeepEqual(before, &lastDeployment(rig.patcher).Spec.Template) {
		t.Fatal("xDS-only update changed Pod template")
	}
	cm = cm.DeepCopy()
	delete(cm.Data, "deployment")
	if _, err := rig.kubeClient.CoreV1().
		ConfigMaps(cm.Namespace).
		Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitCondition(t, 5*time.Second, func() bool { return version() == "" }, "removing patch restores template")
	if err := rig.kubeClient.CoreV1().
		ConfigMaps(cm.Namespace).
		Delete(context.Background(), cm.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitCondition(t, 5*time.Second, func() bool {
		return d.clients.ConfigMaps.Get(cm.Name, cm.Namespace) == nil
	}, "ConfigMap deletion")
	before = lastDeployment(rig.patcher).Spec.Template.DeepCopy()
	if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatal(err)
	}
	if !equality.Semantic.DeepEqual(before, &lastDeployment(rig.patcher).Spec.Template) {
		t.Fatal("missing ConfigMap changed the last applied Pod template")
	}
	cm = cm.DeepCopy()
	cm.Data["deployment"] = patch("restored")
	if _, err := rig.kubeClient.CoreV1().
		ConfigMaps(cm.Namespace).
		Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitCondition(
		t,
		5*time.Second,
		func() bool { return version() == "restored" },
		"ConfigMap recreation restores reconciliation",
	)
}

func TestGatewayClassOverlayPrecedence(t *testing.T) {
	gw, cm := overlayFixture()
	cm.Data["deployment"] = `spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: agentio-proxy
        resources:
          requests:
            cpu: 250m
`
	cm.Data["horizontalPodAutoscaler"] = "spec: {maxReplicas: 5}"
	defaults := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "defaults",
			Namespace:         "custom-system",
			Labels:            map[string]string{"gateway.agentio.kruise.io/defaults-for-class": "agentio-egress"},
			CreationTimestamp: metav1.NewTime(time.Unix(1, 0)),
		},
		Data: map[string]string{
			"deployment": `spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: agentio-proxy
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
`,
			"service":                 "spec: {type: NodePort, trafficDistribution: PreferClose}",
			"horizontalPodAutoscaler": "spec: {minReplicas: 2, maxReplicas: 3}",
			"podDisruptionBudget":     "spec: {maxUnavailable: 1}",
		},
	}
	newer := defaults.DeepCopy()
	newer.Name = "newer"
	newer.CreationTimestamp = metav1.NewTime(time.Unix(2, 0))
	newer.Data = map[string]string{"deployment": "spec: ["}
	wrongNamespace := newer.DeepCopy()
	wrongNamespace.Name = "wrong-namespace"
	wrongNamespace.Namespace = gw.Namespace
	wrongNamespace.CreationTimestamp = metav1.NewTime(time.Unix(0, 0))
	wrongClass := wrongNamespace.DeepCopy()
	wrongClass.Name = "wrong-class"
	wrongClass.Namespace = defaults.Namespace
	wrongClass.Labels[gatewayClassDefaults] = "other-class"
	rig := newControllerTestRig(t, gw, cm, defaults, newer, wrongNamespace, wrongClass)
	defer rig.close()
	d := rig.newControllerInNamespace(defaults.Namespace)
	if err := d.Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatal(err)
	}
	dep := lastDeployment(rig.patcher)
	if dep == nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 3 {
		t.Fatalf("Gateway replica override missing: %+v", dep)
	}
	requests := dep.Spec.Template.Spec.Containers[0].Resources.Requests
	if requests.Cpu().String() != "250m" || requests.Memory().String() != "128Mi" {
		t.Fatalf("class and Gateway resource patches did not merge: %+v", requests)
	}
	servicePatch := rig.patcher.find("services")
	var svc corev1.Service
	if servicePatch == nil {
		t.Fatal("Service missing")
	}
	if err := json.Unmarshal(servicePatch.data, &svc); err != nil {
		t.Fatal(err)
	}
	if svc.Spec.Type != corev1.ServiceTypeNodePort {
		t.Fatalf("class Service default missing: %s", svc.Spec.Type)
	}
	if svc.Spec.TrafficDistribution == nil ||
		*svc.Spec.TrafficDistribution != corev1.ServiceTrafficDistributionPreferClose {
		t.Fatalf("class Service traffic distribution missing: %+v", svc.Spec)
	}
	hpaPatch := rig.patcher.find("horizontalpodautoscalers")
	if hpaPatch == nil || rig.patcher.find("poddisruptionbudgets") == nil {
		t.Fatal("class HPA/PDB patches did not enable the resources")
	}
	var hpa autoscalingv2.HorizontalPodAutoscaler
	if err := json.Unmarshal(hpaPatch.data, &hpa); err != nil {
		t.Fatal(err)
	}
	if hpa.Spec.MinReplicas == nil || *hpa.Spec.MinReplicas != 2 || hpa.Spec.MaxReplicas != 5 {
		t.Fatalf("class and Gateway HPA patches did not merge: %+v", hpa.Spec)
	}
}

func TestGatewayOptionalOverlays(t *testing.T) {
	for _, tc := range []struct {
		name string
		hpa  bool
		pdb  bool
	}{
		{name: "neither"},
		{name: "HPA only", hpa: true},
		{name: "PDB only", pdb: true},
		{name: "both", hpa: true, pdb: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw, cm := overlayFixture()
			if tc.hpa {
				cm.Data["horizontalPodAutoscaler"] = "spec: {maxReplicas: 3}"
			}
			if tc.pdb {
				cm.Data["podDisruptionBudget"] = "spec: {maxUnavailable: 1}"
			}
			rig := newControllerTestRig(t, gw, cm)
			defer rig.close()
			if err := rig.newController().Reconcile(namespacedNameOf(gw)); err != nil {
				t.Fatal(err)
			}
			if (rig.patcher.find("horizontalpodautoscalers") != nil) != tc.hpa ||
				(rig.patcher.find("poddisruptionbudgets") != nil) != tc.pdb {
				t.Fatal("HPA/PDB must only be applied when their overlay is present")
			}
			if lastDeployment(rig.patcher) == nil || rig.patcher.find("services") == nil ||
				rig.patcher.find("serviceaccounts") == nil {
				t.Fatal("required gateway resources missing")
			}
		})
	}
}

func TestGatewayClassOverlayConfigMapEvents(t *testing.T) {
	gw := egressGatewayFixture("egress", "demo")
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "defaults",
			Namespace: "agentio-system",
			Labels:    map[string]string{gatewayClassDefaults: "agentio-egress"},
		},
		Data: map[string]string{"deployment": "spec: {replicas: 2}"},
	}
	rig := newControllerTestRig(t, gw)
	defer rig.close()
	d := rig.newController()
	stop := make(chan struct{})
	defer close(stop)
	go d.Run(stop)
	waitCondition(t, 5*time.Second, func() bool { return lastDeployment(rig.patcher) != nil }, "initial deployment")
	if lastDeployment(rig.patcher).Spec.Replicas != nil {
		t.Fatal("template should not set replicas")
	}
	if _, err := rig.kubeClient.CoreV1().
		ConfigMaps(cm.Namespace).
		Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	replicas := func(n int32) bool {
		dep := lastDeployment(rig.patcher)
		return dep.Spec.Replicas != nil && *dep.Spec.Replicas == n
	}
	waitCondition(t, 5*time.Second, func() bool { return replicas(2) }, "class defaults creation")
	cm = cm.DeepCopy()
	cm.Data["deployment"] = "spec: {replicas: 3}"
	if _, err := rig.kubeClient.CoreV1().
		ConfigMaps(cm.Namespace).
		Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitCondition(t, 5*time.Second, func() bool { return replicas(3) }, "class defaults update")
	if err := rig.kubeClient.CoreV1().
		ConfigMaps(cm.Namespace).
		Delete(context.Background(), cm.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitCondition(t, 5*time.Second, func() bool {
		return lastDeployment(rig.patcher).Spec.Replicas == nil
	}, "class defaults deletion")
}

func TestGatewayClassOverlayLabelChanges(t *testing.T) {
	oldGateway := egressGatewayFixture("old-class", "one")
	newGateway := egressGatewayFixture("new-class", "two")
	newGateway.Spec.GatewayClassName = "other-egress"
	class := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "other-egress"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(builtinClasses["agentio-egress"].controller),
		},
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "defaults",
			Namespace:         "agentio-system",
			Labels:            map[string]string{gatewayClassDefaults: "agentio-egress"},
			CreationTimestamp: metav1.NewTime(time.Unix(1, 0)),
		},
		Data: map[string]string{"deployment": "spec: {replicas: 2}"},
	}
	fallback := cm.DeepCopy()
	fallback.Name = "fallback"
	fallback.CreationTimestamp = metav1.NewTime(time.Unix(2, 0))
	fallback.Data["deployment"] = "spec: {replicas: 3}"
	rig := newControllerTestRig(t, oldGateway, newGateway, class, cm, fallback)
	defer rig.close()
	d := rig.newController()
	stop := make(chan struct{})
	defer close(stop)
	go d.Run(stop)
	hasReplicas := func(gw *gatewayv1.Gateway, want *int32) bool {
		for _, p := range slices.Backward(rig.patcher.all()) {
			if p.gvr.Resource != "deployments" || p.namespace != gw.Namespace || p.name != gw.Name {
				continue
			}
			var dep appsv1.Deployment
			if err := json.Unmarshal(p.data, &dep); err != nil {
				t.Fatal(err)
			}
			return equality.Semantic.DeepEqual(dep.Spec.Replicas, want)
		}
		return false
	}
	two, three := int32(2), int32(3)
	waitCondition(t, 5*time.Second, func() bool {
		return hasReplicas(oldGateway, &two) && hasReplicas(newGateway, nil)
	}, "initial class defaults")
	updateClass := func(className string) {
		t.Helper()
		cm = cm.DeepCopy()
		if className == "" {
			delete(cm.Labels, gatewayClassDefaults)
		} else {
			cm.Labels[gatewayClassDefaults] = className
		}
		if _, err := rig.kubeClient.CoreV1().ConfigMaps(cm.Namespace).
			Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	updateClass("other-egress")
	waitCondition(t, 5*time.Second, func() bool {
		return hasReplicas(oldGateway, &three) && hasReplicas(newGateway, &two)
	}, "label reassignment updates both classes and selects the old class fallback")
	updateClass("")
	waitCondition(t, 5*time.Second, func() bool {
		return hasReplicas(oldGateway, &three) && hasReplicas(newGateway, nil)
	}, "label removal restores the new class template")
	updateClass("agentio-egress")
	waitCondition(t, 5*time.Second, func() bool {
		return hasReplicas(oldGateway, &two) && hasReplicas(newGateway, nil)
	}, "label addition restores the oldest class defaults")
}

func TestGatewayOverlayServiceDeleteDirective(t *testing.T) {
	gw, cm := overlayFixture()
	cm.Data["service"] = "spec:\n  ports:\n  - port: 15021\n    $patch: delete\n"
	rig := newControllerTestRig(t, gw, cm)
	defer rig.close()
	if err := rig.newController().Reconcile(namespacedNameOf(gw)); err != nil {
		t.Fatal(err)
	}
	p := rig.patcher.find("services")
	if p == nil {
		t.Fatal("Service missing")
	}
	var svc corev1.Service
	if err := json.Unmarshal(p.data, &svc); err != nil {
		t.Fatal(err)
	}
	if len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != 15008 {
		t.Fatalf("ports: %+v", svc.Spec.Ports)
	}
}

func TestFetchGatewayParameters(t *testing.T) {
	gw, _ := overlayFixture()
	ref, err := fetchParameters(gw)
	if err != nil || ref.Namespace != "demo" || ref.Name != "params" {
		t.Fatalf("ref=%v err=%v", ref, err)
	}
	gw.Spec.Infrastructure.ParametersRef.Kind = "Secret"
	if _, err = fetchParameters(gw); err == nil || !strings.Contains(err.Error(), "unknown infrastructure") {
		t.Fatalf("invalid ref: %v", err)
	}
}
