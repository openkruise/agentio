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
	"reflect"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/mergepatch"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	gateway "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	"github.com/openkruise/agentio/pkg/kube/controllers"
)

// Based on Istio's gateway deployment controller in upstream/release-0.1:
// https://github.com/openkruise/agentio/blob/169bad3c36783711989757cd907465b8fe9cfc3a/pilot/pkg/config/kube/gateway/deploymentcontroller.go
// Preserve its class-default ordering, required overlays, strategic merge and
// metadata checks. Agentio adapts the renderer/client types and class-default
// label, and reserves config/config.yaml for its per-Gateway proxy configuration.

const gatewayClassDefaults = "gateway.agentio.kruise.io/defaults-for-class"

// overlayObject holds resource identity and metadata for patch validation.
type overlayObject struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
}

func (d *DeploymentController) renderGateway(templateName string, input TemplateInput) ([]string, error) {
	var overlays []map[string]string
	classConfigs := d.clients.ConfigMaps.List(d.systemNamespace, klabels.SelectorFromValidatedSet(map[string]string{
		gatewayClassDefaults: string(input.Spec.GatewayClassName),
	}))
	if len(classConfigs) > 0 {
		classConfig := controllers.OldestObject(classConfigs)
		overlays = append(overlays, classConfig.Data)
	}
	params, err := fetchParameters(input.Gateway)
	if err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	if params != nil {
		cm := d.clients.ConfigMaps.Get(params.Name, params.Namespace)
		if cm == nil {
			return nil, fmt.Errorf("parametersRef targeting configmap %q, but configmap does not exist", params)
		}
		data := maps.Clone(cm.Data)
		// Proxy configuration is consumed by the xDS registry or agentgatewayInput.
		delete(data, "config")
		delete(data, agentgatewayConfigKey)
		overlays = append(overlays, data)
	}
	rendered, err := d.renderer.Render(templateName, input)
	if err != nil {
		return nil, err
	}
	transformed := make([]string, 0, len(rendered))
	for _, doc := range rendered {
		output, err := applyOverlay(doc, overlays)
		if err != nil {
			return nil, err
		}
		if output != "" {
			transformed = append(transformed, output)
		}
	}
	return transformed, nil
}

var supportedOverlays = sets.New(
	"deployment",
	"service",
	"serviceAccount",
	"horizontalPodAutoscaler",
	"podDisruptionBudget",
)

var requiredOverlays = sets.New(
	"horizontalPodAutoscaler",
	"podDisruptionBudget",
)

// Keep merge and metadata validation together to simplify comparison with the source implementation.
//
//nolint:gocyclo
func applyOverlay(object string, overlaysList []map[string]string) (string, error) {
	var ik overlayObject
	if err := yaml.Unmarshal([]byte(object), &ik); err != nil {
		return "", fmt.Errorf("failed to find kind: %w", err)
	}
	gv, err := schema.ParseGroupVersion(ik.TypeMeta.APIVersion)
	if err != nil {
		return "", fmt.Errorf("failed to find kind: %w", err)
	}
	kind := &schema.GroupVersionKind{Group: gv.Group, Version: gv.Version, Kind: ik.TypeMeta.Kind}

	var data any
	var key string
	switch kind.Kind {
	case "ConfigMap":
		// Generated native configuration is not a Kubernetes resource customization surface.
		return object, nil
	case "Deployment":
		data = &appsv1.Deployment{}
		key = "deployment"
	case "Service":
		data = &corev1.Service{}
		key = "service"
	case "ServiceAccount":
		data = &corev1.ServiceAccount{}
		key = "serviceAccount"
	case "HorizontalPodAutoscaler":
		data = &autoscalingv2.HorizontalPodAutoscaler{}
		key = "horizontalPodAutoscaler"
	case "PodDisruptionBudget":
		data = &policyv1.PodDisruptionBudget{}
		key = "podDisruptionBudget"
	default:
		return "", fmt.Errorf("unknown overlay kind %q", kind.Kind)
	}
	applied := false
	for _, overlays := range overlaysList {
		for k := range overlays {
			if !supportedOverlays.Has(k) {
				return "", fmt.Errorf("unsupported overlay %q (supported: %v)", k, sets.List(supportedOverlays))
			}
		}
		overlay, f := overlays[key]
		if !f {
			continue
		}
		b, err := strategicMergePatchYAML([]byte(object), []byte(overlay), data)
		if err != nil {
			return "", fmt.Errorf("strategic merge patch failed: %w", err)
		}
		applied = true
		object = string(b)
	}
	if !applied && requiredOverlays.Has(key) {
		return "", nil
	}

	var finalIK overlayObject
	if err := yaml.Unmarshal([]byte(object), &finalIK); err != nil {
		return "", fmt.Errorf("failed to find final kind: %w", err)
	}

	a, b := ik.ObjectMeta, finalIK.ObjectMeta
	if !(a.Name == b.Name &&
		a.GenerateName == b.GenerateName &&
		a.Namespace == b.Namespace &&
		a.UID == b.UID &&
		a.ResourceVersion == b.ResourceVersion &&
		a.Generation == b.Generation &&
		a.CreationTimestamp == b.CreationTimestamp &&
		a.DeletionTimestamp == b.DeletionTimestamp &&
		a.DeletionGracePeriodSeconds == b.DeletionGracePeriodSeconds &&
		reflect.DeepEqual(a.OwnerReferences, b.OwnerReferences) &&
		slices.Equal(a.Finalizers, b.Finalizers)) {
		return "", fmt.Errorf("illegal metadata change")
	}
	// We could deep equal here but its a bit more tedious, so just never allow setting it
	if len(a.ManagedFields) != 0 || len(b.ManagedFields) != 0 {
		return "", fmt.Errorf("illegal metadata change")
	}

	if kind.Kind == "Deployment" {
		var deployment appsv1.Deployment
		if err := yaml.Unmarshal([]byte(object), &deployment); err != nil {
			return "", err
		}
		if slices.ContainsFunc(
			deployment.Spec.Template.Spec.Containers,
			func(c corev1.Container) bool { return c.Name == "agentio-proxy" },
		) {
			// Derive the agent budget after all per-Gateway Pod overrides.
			grace := int64(corev1.DefaultTerminationGracePeriodSeconds)
			if deployment.Spec.Template.Spec.TerminationGracePeriodSeconds != nil {
				grace = *deployment.Spec.Template.Spec.TerminationGracePeriodSeconds
			}
			patch := fmt.Sprintf(
				`{"spec":{"template":{"spec":{"containers":[{"name":"agentio-proxy","env":[{"name":"AGENTIO_TERMINATION_GRACE_PERIOD_SECONDS","value":"%d","valueFrom":null}]}]}}}}`,
				grace,
			)
			updated, err := strategicMergePatchYAML([]byte(object), []byte(patch), &appsv1.Deployment{})
			if err != nil {
				return "", fmt.Errorf("set gateway termination grace period: %w", err)
			}
			object = string(updated)
		}
	}

	return object, nil
}

// fetchParameters returns the infrastructure parameters for the Gateway. This is currently always a local configmap so we return the name only.
// An error is returned if the parameter is invalid. This does not check the configmap exists, though.
// If no parameter is specified, no name or error is returned.
func fetchParameters(gw *gateway.Gateway) (*types.NamespacedName, error) {
	if gw.Spec.Infrastructure != nil && gw.Spec.Infrastructure.ParametersRef != nil {
		pr := gw.Spec.Infrastructure.ParametersRef
		if string(pr.Kind) == "ConfigMap" && string(pr.Group) == "" {
			return &types.NamespacedName{
				Namespace: gw.Namespace,
				Name:      pr.Name,
			}, nil
		}
		return nil, fmt.Errorf("unknown infrastructure parameters type %v/%v", pr.Group, pr.Kind)
	}
	return nil, nil
}

// strategicMergePatchYAML is a small fork of strategicpatch.StrategicMergePatch to allow YAML patches
// This avoids expensive conversion from YAML to JSON
func strategicMergePatchYAML(originalYAML []byte, patchYAML []byte, dataStruct any) ([]byte, error) {
	schema, err := strategicpatch.NewPatchMetaFromStruct(dataStruct)
	if err != nil {
		return nil, err
	}

	originalMap, err := patchHandleUnmarshal(originalYAML)
	if err != nil {
		return nil, err
	}
	patchMap, err := patchHandleUnmarshal(patchYAML)
	if err != nil {
		return nil, err
	}

	result, err := strategicpatch.StrategicMergeMapPatchUsingLookupPatchMeta(originalMap, patchMap, schema)
	if err != nil {
		return nil, err
	}

	return json.Marshal(result)
}

func patchHandleUnmarshal(j []byte) (map[string]any, error) {
	if j == nil {
		j = []byte("{}")
	}

	m := map[string]any{}
	err := yaml.Unmarshal(j, &m)
	if err != nil {
		return nil, mergepatch.ErrBadJSONDoc
	}
	return m, nil
}
