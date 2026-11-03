// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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
	"fmt"
	"maps"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/yaml"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/openkruise/agentio/pkg/kube/controllers"
	"github.com/openkruise/agentio/pkg/kube/kclient"
)

// managedLabel is the label the controller sets on every resource it applies,
// and the gate canManage checks before adopting an existing unmanaged resource.
const managedLabel = "gateway.agentio.kruise.io/managed"

// serviceTypeAnnotation, nameOverrideAnnotation, and serviceAccountAnnotation
// are the Gateway override annotations.
const (
	serviceTypeAnnotation    = "gateway.agentio.kruise.io/service-type"
	nameOverrideAnnotation   = "gateway.agentio.kruise.io/name-override"
	serviceAccountAnnotation = "gateway.agentio.kruise.io/service-account"
)

// dataplaneModeLabel, dataplaneModeNone, and networkLabel back setLabelOverrides.
const (
	dataplaneModeLabel = "agentio.kruise.io/dataplane-mode"
	dataplaneModeNone  = "none"
	networkLabel       = "agentio.kruise.io/network"
)

// ControllerVersionAnnotation and ControllerVersion implement the ownership
// takeover protocol for managed Gateway resources.
const (
	ControllerVersionAnnotation = "gateway.agentio.kruise.io/controller-version"
	ControllerVersion           = 5
)

// gatewayGVR is the GVR the controller-version status patch targets.
var gatewayGVR = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}

// controllerClients bundles every kclient.Client the DeploymentController
// reads and writes, plus the SSA patch seam.
type controllerClients struct {
	Gateways        kclient.Client[*gatewayv1.Gateway]
	GatewayClasses  kclient.Client[*gatewayv1.GatewayClass]
	Deployments     kclient.Client[*appsv1.Deployment]
	Services        kclient.Client[*corev1.Service]
	ServiceAccounts kclient.Client[*corev1.ServiceAccount]
	// HPAs and PDBs are a read-only surface: canManage reads go through the
	// informer and writes go through the dynamic SSA Patcher like every
	// other managed kind.
	HPAs kclient.Informer[*autoscalingv2.HorizontalPodAutoscaler]
	PDBs kclient.Informer[*policyv1.PodDisruptionBudget]
	// File configuration is supplied by the operator, never adopted or written.
	ConfigMaps kclient.Informer[*corev1.ConfigMap]
	// Patcher abstracts SSA so tests can capture patches.
	Patcher func(gvr schema.GroupVersionResource, name, namespace string, data []byte, subresources ...string) error
}

// getter is the minimal read surface apply/canManage need from each managed
// child kind: enough to check for the existing managed label and resource
// version. kclient.Client[*T] satisfies this through a small adapter below.
type getter interface {
	get(name, namespace string) (labels map[string]string, resourceVersion string, exists bool)
}

type deploymentGetter struct {
	c kclient.Client[*appsv1.Deployment]
}

func (g deploymentGetter) get(name, namespace string) (map[string]string, string, bool) {
	d := g.c.Get(name, namespace)
	if controllers.IsNil(d) {
		return nil, "", false
	}
	return d.GetLabels(), d.GetResourceVersion(), true
}

type serviceGetter struct {
	c kclient.Client[*corev1.Service]
}

func (g serviceGetter) get(name, namespace string) (map[string]string, string, bool) {
	s := g.c.Get(name, namespace)
	if controllers.IsNil(s) {
		return nil, "", false
	}
	return s.GetLabels(), s.GetResourceVersion(), true
}

type serviceAccountGetter struct {
	c kclient.Client[*corev1.ServiceAccount]
}

func (g serviceAccountGetter) get(name, namespace string) (map[string]string, string, bool) {
	sa := g.c.Get(name, namespace)
	if controllers.IsNil(sa) {
		return nil, "", false
	}
	return sa.GetLabels(), sa.GetResourceVersion(), true
}

type hpaGetter struct {
	c kclient.Informer[*autoscalingv2.HorizontalPodAutoscaler]
}

func (g hpaGetter) get(name, namespace string) (map[string]string, string, bool) {
	h := g.c.Get(name, namespace)
	if controllers.IsNil(h) {
		return nil, "", false
	}
	return h.GetLabels(), h.GetResourceVersion(), true
}

type pdbGetter struct {
	c kclient.Informer[*policyv1.PodDisruptionBudget]
}

func (g pdbGetter) get(name, namespace string) (map[string]string, string, bool) {
	p := g.c.Get(name, namespace)
	if controllers.IsNil(p) {
		return nil, "", false
	}
	return p.GetLabels(), p.GetResourceVersion(), true
}

// kindTarget associates an allowed apply() kind with its GVR and getter.
type kindTarget struct {
	gvr schema.GroupVersionResource
	get getter
}

// DeploymentController materializes a Gateway into a Deployment/Service/
// ServiceAccount trio via Server-Side Apply.
type DeploymentController struct {
	clients         controllerClients
	renderer        *renderer
	clusterID       string
	systemNamespace string
	kubeVersion     int
	queue           controllers.Queue

	targets map[string]kindTarget
}

// NewDeploymentController wires event handlers; requeueAll registers the
// values-reload hook and returns a deregister func the caller must invoke
// when the lease cycle ends.
func NewDeploymentController(clients controllerClients, renderer *renderer,
	clusterID, systemNamespace string, kubeVersion int, requeueAll func(fn func()) func(),
) (*DeploymentController, func()) {
	d := &DeploymentController{
		clients:         clients,
		renderer:        renderer,
		clusterID:       clusterID,
		systemNamespace: systemNamespace,
		kubeVersion:     kubeVersion,
	}
	d.targets = map[string]kindTarget{
		"Deployment":              {gvr: schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, get: deploymentGetter{clients.Deployments}},
		"Service":                 {gvr: schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}, get: serviceGetter{clients.Services}},
		"ServiceAccount":          {gvr: schema.GroupVersionResource{Group: "", Version: "v1", Resource: "serviceaccounts"}, get: serviceAccountGetter{clients.ServiceAccounts}},
		"HorizontalPodAutoscaler": {gvr: schema.GroupVersionResource{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"}, get: hpaGetter{clients.HPAs}},
		"PodDisruptionBudget":     {gvr: schema.GroupVersionResource{Group: "policy", Version: "v1", Resource: "poddisruptionbudgets"}, get: pdbGetter{clients.PDBs}},
	}
	// Based on Istio's upstream/release-0.1 deployment controller (see overlay.go).
	// Agentio's informer exposes a raw string index instead of kclient.CreateIndex.
	gatewaysByParamsRef := clients.Gateways.Index("parametersRef", func(gw *gatewayv1.Gateway) []string {
		p, err := fetchParameters(gw)
		if p == nil || err != nil {
			return nil
		}
		return []string{p.String()}
	})
	d.queue = controllers.NewQueue("gateway deployment",
		controllers.WithReconciler(d.Reconcile),
		controllers.WithMaxAttempts(5))

	// parentHandler resolves the owning Gateway of a child Deployment,
	// Service, ServiceAccount, HorizontalPodAutoscaler, or PodDisruptionBudget
	// through ownerReferences and requeues it.
	parentHandler := controllers.ObjectHandler(func(o controllers.Object) {
		if owner := gatewayOwnerRef(o); owner != "" {
			d.queue.Add(types.NamespacedName{Namespace: o.GetNamespace(), Name: owner})
		}
	})
	clients.Deployments.AddEventHandler(parentHandler)
	clients.Services.AddEventHandler(parentHandler)
	clients.ServiceAccounts.AddEventHandler(parentHandler)
	clients.HPAs.AddEventHandler(parentHandler)
	clients.PDBs.AddEventHandler(parentHandler)
	clients.ConfigMaps.AddEventHandler(controllers.FromEventHandler(func(e controllers.Event) {
		o := e.Latest()
		// This may be a per-Gateway parametersRef or a global GatewayClass default.
		key := types.NamespacedName{Namespace: o.GetNamespace(), Name: o.GetName()}
		for _, gw := range gatewaysByParamsRef.Lookup(key.String()) {
			d.queue.AddObject(gw.(*gatewayv1.Gateway))
		}
		if o.GetNamespace() != d.systemNamespace {
			return
		}
		// Reconcile both classes when the default label changes or is removed.
		affectedClasses := map[string]struct{}{}
		for _, obj := range []controllers.Object{e.Old, e.New} {
			if obj != nil {
				if class, found := obj.GetLabels()[gatewayClassDefaults]; found {
					affectedClasses[class] = struct{}{}
				}
			}
		}
		if len(affectedClasses) == 0 {
			return
		}
		for _, gw := range clients.Gateways.List(metav1.NamespaceAll, klabels.Everything()) {
			if _, found := affectedClasses[string(gw.Spec.GatewayClassName)]; found {
				d.queue.AddObject(gw)
			}
		}
	}))

	// Gateway handler: enqueue on Add/Delete, and on Update only when the
	// generation, labels, or annotations changed.
	clients.Gateways.AddEventHandler(controllers.FromEventHandler(func(e controllers.Event) {
		switch e.Event {
		case controllers.EventAdd:
			d.queue.AddObject(e.New)
		case controllers.EventUpdate:
			if e.New.GetGeneration() != e.Old.GetGeneration() {
				d.queue.AddObject(e.New)
				return
			}
			if !maps.Equal(e.New.GetLabels(), e.Old.GetLabels()) {
				d.queue.AddObject(e.New)
				return
			}
			if !maps.Equal(e.New.GetAnnotations(), e.Old.GetAnnotations()) {
				d.queue.AddObject(e.New)
				return
			}
		case controllers.EventDelete:
			d.queue.AddObject(e.Old)
		}
	}))

	// A GatewayClass change requeues every Gateway that references it.
	clients.GatewayClasses.AddEventHandler(controllers.ObjectHandler(func(o controllers.Object) {
		for _, gw := range clients.Gateways.List(metav1.NamespaceAll, klabels.Everything()) {
			if string(gw.Spec.GatewayClassName) == o.GetName() {
				d.queue.AddObject(gw)
			}
		}
	}))

	// requeueAll registers the values-file reload hook; the returned deregister func goes to the caller.
	deregister := requeueAll(func() {
		for _, gw := range clients.Gateways.List(metav1.NamespaceAll, klabels.Everything()) {
			d.queue.AddObject(gw)
		}
	})

	return d, deregister
}

// gatewayOwnerRef returns the name of the first Gateway (gateway.networking.k8s.io)
// ownerReference on o, or "" if none exists. Matches on group and kind regardless
// of the Controller field.
func gatewayOwnerRef(o controllers.Object) string {
	for _, ref := range o.GetOwnerReferences() {
		if ref.Kind != "Gateway" {
			continue
		}
		gv, err := schema.ParseGroupVersion(ref.APIVersion)
		if err != nil || gv.Group != "gateway.networking.k8s.io" {
			continue
		}
		return ref.Name
	}
	return ""
}

// Run waits for every informer to sync, then runs the reconcile queue until stop closes.
func (d *DeploymentController) Run(stop <-chan struct{}) {
	syncFuncs := []func() bool{
		d.clients.Deployments.HasSynced,
		d.clients.Services.HasSynced,
		d.clients.ServiceAccounts.HasSynced,
		d.clients.HPAs.HasSynced,
		d.clients.PDBs.HasSynced,
		d.clients.ConfigMaps.HasSynced,
		d.clients.Gateways.HasSynced,
		d.clients.GatewayClasses.HasSynced,
	}
	waitForCacheSync(stop, syncFuncs...)
	d.queue.Run(stop)
	controllers.ShutdownAll(
		d.clients.Deployments,
		d.clients.Services,
		d.clients.ServiceAccounts,
		d.clients.HPAs,
		d.clients.PDBs,
		d.clients.ConfigMaps,
		d.clients.Gateways,
		d.clients.GatewayClasses,
	)
}

// waitForCacheSync polls every sync func until all report true or stop closes.
func waitForCacheSync(stop <-chan struct{}, syncFuncs ...func() bool) bool {
	informerSynced := make([]cache.InformerSynced, len(syncFuncs))
	for i, f := range syncFuncs {
		informerSynced[i] = f
	}
	return cache.WaitForCacheSync(stop, informerSynced...)
}

// Reconcile takes the name of a Gateway and ensures the cluster is in the desired state.
func (d *DeploymentController) Reconcile(req types.NamespacedName) error {
	gw := d.clients.Gateways.Get(req.Name, req.Namespace)
	if controllers.IsNil(gw) {
		// Gateway no longer exists; not fixable by requeue.
		return nil
	}

	ci, ok := classFor(gw, d.clients.GatewayClasses)
	if !ok {
		// Unknown classes are expected in shared clusters; skip silently.
		return nil
	}

	return d.configureGateway(*gw, ci)
}

// configureGateway assembles the TemplateInput, applies the controller
// version takeover protocol, renders, and applies each document.
func (d *DeploymentController) configureGateway(gw gatewayv1.Gateway, ci classInfo) error {
	if !isManaged(&gw.Spec) {
		return nil
	}

	existingVersion, overwriteVersion, shouldHandle := managedGatewayControllerVersion(gw)
	if !shouldHandle {
		log.Info("skipping gateway managed by another controller version",
			"namespace", gw.Namespace, "name", gw.Name, "controller_version", existingVersion)
		return nil
	}

	input := buildTemplateInput(gw, ci, d.clusterID, d.kubeVersion, d.renderer.globalNetwork())
	if ci.templateName == agentgatewayTemplateName {
		if err := d.agentgatewayInput(&input); err != nil {
			return d.setGatewayConfigError(gw, err)
		}
	}

	if overwriteVersion {
		if err := d.setGatewayControllerVersion(gw); err != nil {
			return fmt.Errorf("update gateway annotation: %w", err)
		}
	}

	rendered, err := d.renderGateway(ci.templateName, input)
	if err != nil {
		// Rendering errors are not transient, so log without retrying.
		log.Error("error rendering templates", "namespace", gw.Namespace, "name", gw.Name, "error", err)
		return nil
	}
	for _, doc := range rendered {
		if err := d.apply(ci.controller, doc, input); err != nil {
			return fmt.Errorf("apply failed: %w", err)
		}
	}
	if err := d.setGatewayStatus(gw, input); err != nil {
		return fmt.Errorf("update gateway status: %w", err)
	}
	return nil
}

func valueOrDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// buildTemplateInput assembles the TemplateInput for a Gateway; shared by production reconciliation and parity tests.
func buildTemplateInput(gw gatewayv1.Gateway, ci classInfo, clusterID string, kubeVersion int, globalNetwork string) TemplateInput {
	defaultName := getDefaultName(gw.Name, string(gw.Spec.GatewayClassName), ci.disableNameSuffix)

	serviceType := ci.defaultServiceType
	if v, ok := gw.Annotations[serviceTypeAnnotation]; ok {
		serviceType = corev1.ServiceType(v)
	}

	input := TemplateInput{
		Gateway:                   &gw,
		GatewayClass:              string(gw.Spec.GatewayClassName),
		DeploymentName:            valueOrDefault(gw.Annotations[nameOverrideAnnotation], defaultName),
		ServiceAccount:            valueOrDefault(gw.Annotations[serviceAccountAnnotation], defaultName),
		Ports:                     extractServicePorts(gw),
		ServiceType:               serviceType,
		ClusterID:                 clusterID,
		KubeVersion:               kubeVersion,
		InfrastructureLabels:      extractInfrastructureLabels(gw),
		InfrastructureAnnotations: extractInfrastructureAnnotations(gw),
		GatewayNameLabel:          "gateway.networking.k8s.io/gateway-name",
		ControllerLabel:           ci.controllerLabel,
	}
	setLabelOverrides(gw, ci, &input, globalNetwork)
	return input
}

// setLabelOverrides defaults dataplane-mode to none for non-egress-gateway-template
// classes and the topology network label to global.network for egress-gateway-template
// classes, which are detected by templateName.
func setLabelOverrides(gw gatewayv1.Gateway, ci classInfo, input *TemplateInput, globalNetwork string) {
	isEgressGateway := ci.templateName == "egress-gateway"

	_, hasAmbientLabel := gw.Labels[dataplaneModeLabel]
	if !hasAmbientLabel {
		_, hasAmbientLabel = input.InfrastructureLabels[dataplaneModeLabel]
	}
	if !isEgressGateway && !hasAmbientLabel {
		input.InfrastructureLabels[dataplaneModeLabel] = dataplaneModeNone
	}

	if _, ok := input.InfrastructureLabels[networkLabel]; !ok && globalNetwork != "" && isEgressGateway {
		input.InfrastructureLabels[networkLabel] = globalNetwork
	}
}

// isManaged reports whether the Gateway's deployment should be managed; spec.addresses opts out.
func isManaged(spec *gatewayv1.GatewaySpec) bool {
	if len(spec.Addresses) == 0 {
		return true
	}
	if len(spec.Addresses) > 1 {
		return false
	}
	if t := spec.Addresses[0].Type; t == nil || *t == gatewayv1.IPAddressType {
		return true
	}
	return false
}

// managedGatewayControllerVersion decides whether this controller may manage
// or take over a Gateway based on its recorded controller version.
func managedGatewayControllerVersion(gw gatewayv1.Gateway) (existing string, takeOver bool, manage bool) {
	cur, ok := gw.Annotations[ControllerVersionAnnotation]
	if !ok {
		return "", true, true
	}
	curNum, err := strconv.Atoi(cur)
	if err != nil {
		return cur, false, false
	}
	if curNum > ControllerVersion {
		return cur, false, false
	}
	if curNum == ControllerVersion {
		return cur, false, true
	}
	return cur, true, true
}

// setGatewayControllerVersion patches the Gateway's controller-version
// annotation through the status subresource.
func (d *DeploymentController) setGatewayControllerVersion(gw gatewayv1.Gateway) error {
	patch, err := json.Marshal(map[string]any{
		"apiVersion": gatewayv1.GroupVersion.String(), "kind": "Gateway",
		"metadata": metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace,
			Annotations: map[string]string{ControllerVersionAnnotation: fmt.Sprint(ControllerVersion)}},
		"status": map[string]any{"addresses": gw.Status.Addresses},
	})
	if err != nil {
		return err
	}
	return d.clients.Patcher(gatewayGVR, gw.GetName(), gw.GetNamespace(), patch, "status")
}

func (d *DeploymentController) setGatewayStatus(gw gatewayv1.Gateway, input TemplateInput) error {
	programmedStatus := metav1.ConditionFalse
	programmedReason := string(gatewayv1.GatewayReasonPending)
	programmedMessage := "Waiting for gateway Deployment to become available"
	if deployment := d.clients.Deployments.Get(input.DeploymentName, gw.Namespace); !controllers.IsNil(deployment) {
		for _, condition := range deployment.Status.Conditions {
			if condition.Type == appsv1.DeploymentAvailable && condition.Status == corev1.ConditionTrue {
				if input.AgentgatewayConfigHash != "" && !agentgatewayRolloutReady(deployment, input.AgentgatewayConfigHash) {
					break
				}
				programmedStatus = metav1.ConditionTrue
				programmedReason = string(gatewayv1.GatewayReasonProgrammed)
				programmedMessage = "Gateway Deployment is available"
				break
			}
		}
	}
	conditions := []metav1.Condition{
		gatewayCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionAccepted), metav1.ConditionTrue,
			gw.Generation, string(gatewayv1.GatewayReasonAccepted), "Resource accepted"),
		gatewayCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), programmedStatus,
			gw.Generation, programmedReason, programmedMessage),
	}
	// Preserve the published address while a gateway is rolling out or temporarily unavailable.
	addresses := gw.Status.Addresses
	if programmedStatus == metav1.ConditionTrue {
		if service := d.clients.Services.Get(input.DeploymentName, gw.Namespace); !controllers.IsNil(service) && service.Labels[managedLabel] == input.ControllerLabel {
			domain := nestedString(d.renderer.state.Load().values, "global", "proxy", "clusterDomain")
			if domain == "" {
				domain = "cluster.local"
			}
			addressType := gatewayv1.HostnameAddressType
			addresses = []gatewayv1.GatewayStatusAddress{{Type: &addressType,
				Value: service.Name + "." + service.Namespace + ".svc." + domain}}
		}
	}
	// Retain the controller-version annotation owned by the same SSA field manager.
	patch := struct {
		APIVersion string            `json:"apiVersion"`
		Kind       string            `json:"kind"`
		Metadata   metav1.ObjectMeta `json:"metadata"`
		Status     struct {
			Conditions []metav1.Condition               `json:"conditions"`
			Addresses  []gatewayv1.GatewayStatusAddress `json:"addresses"`
		} `json:"status"`
	}{APIVersion: gatewayv1.GroupVersion.String(), Kind: "Gateway", Metadata: metav1.ObjectMeta{
		Name: gw.Name, Namespace: gw.Namespace,
		Annotations: map[string]string{ControllerVersionAnnotation: fmt.Sprint(ControllerVersion)},
	}}
	patch.Status.Conditions = conditions
	patch.Status.Addresses = addresses
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	return d.clients.Patcher(gatewayGVR, gw.Name, gw.Namespace, data, "status")
}

func gatewayCondition(existing []metav1.Condition, conditionType string, status metav1.ConditionStatus,
	generation int64, reason, message string,
) metav1.Condition {
	condition := metav1.Condition{
		Type:               conditionType,
		Status:             status,
		ObservedGeneration: generation,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	}
	if current := apiMeta.FindStatusCondition(existing, conditionType); conditionMatches(current, status, generation, reason, message) {
		condition.LastTransitionTime = current.LastTransitionTime
	}
	return condition
}

// apply server-side applies a single rendered document.
func (d *DeploymentController) apply(controller string, doc string, input TemplateInput) error {
	data := map[string]any{}
	if err := yaml.Unmarshal([]byte(doc), &data); err != nil {
		return err
	}
	us := unstructured.Unstructured{Object: data}

	kind := us.GetKind()
	target, ok := d.targets[kind]
	if !ok {
		return fmt.Errorf("unexpected object kind %q, only Deployment, Service, ServiceAccount, HorizontalPodAutoscaler, PodDisruptionBudget are allowed", kind)
	}

	objNamespace := us.GetNamespace()
	if objNamespace != input.Namespace {
		return fmt.Errorf("object namespace %q does not match gateway namespace %q", objNamespace, input.Namespace)
	}

	objName := us.GetName()
	validName := objName == input.DeploymentName || objName == input.ServiceAccount || strings.HasPrefix(objName, input.Name)
	if !validName {
		return fmt.Errorf("object name %q does not match expected pattern (expected %q or %q, or a prefix of %q)",
			objName, input.DeploymentName, input.ServiceAccount, input.Name)
	}

	clabel := strings.ReplaceAll(controller, "/", "-")
	if err := unstructured.SetNestedField(us.Object, clabel, "metadata", "labels", managedLabel); err != nil {
		return err
	}

	canManage, resourceVersion := d.canManage(target.get, objName, objNamespace)
	if !canManage {
		return nil
	}
	us.SetResourceVersion(resourceVersion)

	j, err := json.Marshal(us.Object)
	if err != nil {
		return err
	}
	if err := d.clients.Patcher(target.gvr, objName, objNamespace, j); err != nil {
		return fmt.Errorf("patch %v/%v/%v: %w", target.gvr, objNamespace, objName, err)
	}
	return nil
}

// canManage checks whether an existing resource can be adopted: if it exists
// without the managed label, refuse to overwrite it.
func (d *DeploymentController) canManage(get getter, name, namespace string) (bool, string) {
	labels, resourceVersion, exists := get.get(name, namespace)
	if !exists {
		return true, ""
	}
	_, managed := labels[managedLabel]
	return managed, resourceVersion
}
