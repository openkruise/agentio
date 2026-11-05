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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
)

const agentgatewayConfigKey = "config.yaml"

// An Available old ReplicaSet does not mean a newly supplied config is ready.
func agentgatewayRolloutReady(deployment *appsv1.Deployment, hash string) bool {
	replicas := int32(1)
	if deployment.Spec.Replicas != nil {
		replicas = *deployment.Spec.Replicas
	}
	return deployment.Spec.Template.Annotations["gateway.agentio.kruise.io/config-hash"] == hash &&
		deployment.Status.ObservedGeneration >= deployment.Generation &&
		deployment.Status.UpdatedReplicas == replicas && deployment.Status.Replicas == replicas &&
		deployment.Status.AvailableReplicas == replicas
}

// Agentgateway accepts either operator-owned native YAML or Agentio egress settings.
func (d *DeploymentController) agentgatewayInput(input *TemplateInput) error {
	if input.Spec.Infrastructure == nil || input.Spec.Infrastructure.ParametersRef == nil {
		return fmt.Errorf(
			"agentgateway requires spec.infrastructure.parametersRef to a ConfigMap containing config or config.yaml",
		)
	}
	ref := input.Spec.Infrastructure.ParametersRef
	if ref.Group != "" || ref.Kind != "ConfigMap" {
		return fmt.Errorf("agentgateway parametersRef must reference a core ConfigMap in the Gateway namespace")
	}
	cm := d.clients.ConfigMaps.Get(string(ref.Name), input.Namespace)
	if cm == nil {
		return fmt.Errorf("agentgateway ConfigMap %s/%s not found", input.Namespace, ref.Name)
	}
	content, native := cm.Data[agentgatewayConfigKey]
	if settings, generated := cm.Data["config"]; generated {
		if native {
			return fmt.Errorf("agentgateway parameters must contain only one of config or config.yaml")
		}
		data, err := yaml.YAMLToJSONStrict([]byte(settings))
		if err != nil {
			return fmt.Errorf("parse agentgateway egress settings: %w", err)
		}
		gateway := &configv1.EgressGateway{}
		if err := protojson.Unmarshal(data, gateway); err != nil {
			return fmt.Errorf("decode agentgateway egress settings: %w", err)
		}
		if err := model.ValidateUpstreamTrustBundle(gateway.GetUpstreamTrustBundle()); err != nil {
			return err
		}
		trustBundle, err := d.agentgatewayTrustBundle(gateway)
		if err != nil {
			return err
		}
		sources := d.agentgatewaySources
		settings := agentgatewayConfigInputs{
			TrustBundle: trustBundle,
			MITM:        input.Annotations["gateway.agentio.kruise.io/agentgateway-certs"] != "",
		}
		if sources.Config != nil {
			if current := sources.Config.GetKey("effective"); current != nil {
				settings.Global = current.Value
			}
		}
		if sources.Services != nil {
			settings.Services = sources.Services.List()
		}
		if sources.Endpoints != nil {
			settings.Endpoints = sources.Endpoints.List()
		}
		content, err = agentgatewayEgressConfig(gateway, input.Ports, settings)
		if err != nil {
			return err
		}
		enabled, _, err := unstructured.NestedBool(
			d.renderer.state.Load().values,
			"global",
			"agentgateway",
			"ca",
			"enabled",
		)
		if err != nil {
			return fmt.Errorf("read agentgateway CA setting: %w", err)
		}
		if !enabled {
			return fmt.Errorf(
				"generated agentgateway egress configuration requires egressGateway.agentgateway.ca.enabled",
			)
		}
		input.AgentgatewayConfig = content
		input.AgentgatewayTrustBundle = trustBundle
		input.AgentgatewayConfigName = input.DeploymentName + "-native"
		if input.AgentgatewayConfigName == cm.Name {
			return fmt.Errorf("parameters ConfigMap must not use the generated name %q", input.AgentgatewayConfigName)
		}
		if existing := d.clients.ConfigMaps.Get(input.AgentgatewayConfigName, input.Namespace); existing != nil &&
			(existing.Labels[managedLabel] != input.ControllerLabel || gatewayOwnerRef(existing) != input.Name) {
			return fmt.Errorf(
				"generated ConfigMap %s/%s already exists without matching Gateway ownership",
				input.Namespace,
				input.AgentgatewayConfigName,
			)
		}
	} else {
		input.AgentgatewayConfigName = cm.Name
	}
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf(
			"agentgateway ConfigMap %s/%s must contain non-empty data[%q]",
			input.Namespace,
			ref.Name,
			agentgatewayConfigKey,
		)
	}
	// Syntax checking catches broken YAML before rollout. Schema validation is
	// performed by the pinned agentgateway binary when the new Pod starts.
	var config map[string]any
	if err := yaml.UnmarshalStrict([]byte(content), &config); err != nil {
		return fmt.Errorf("agentgateway config must be a YAML object: %w", err)
	}
	if config == nil {
		return fmt.Errorf("agentgateway config must be a YAML object")
	}
	input.AgentgatewayConfigHash = fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	if input.AgentgatewayConfig != "" {
		// Generated runtime settings are file-watched; only changing mode needs a rollout.
		input.AgentgatewayConfigHash = "generated-v1.7.0"
	}
	return nil
}

func (d *DeploymentController) setGatewayConfigError(gw gatewayv1.Gateway, configErr error) error {
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
	patch.Status.Conditions = []metav1.Condition{
		gatewayCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionAccepted), metav1.ConditionFalse,
			gw.Generation, string(gatewayv1.GatewayReasonInvalidParameters), configErr.Error()),
		gatewayCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), metav1.ConditionFalse,
			gw.Generation, string(gatewayv1.GatewayReasonInvalid), configErr.Error()),
	}
	patch.Status.Addresses = append([]gatewayv1.GatewayStatusAddress{}, gw.Status.Addresses...)
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	return d.clients.Patcher(gatewayGVR, gw.Name, gw.Namespace, data, "status")
}

// AgentgatewayCAAddress resolves CA bootstrap on demand. Using a template data
// method keeps this shared template parseable by the sidecar injector as well.
func (in derivedInput) AgentgatewayCAAddress() (string, error) {
	return agentgatewayCAAddress(nestedString(in.Values, "global", "caAddress"))
}

// agentgatewayCAAddress normalizes Agentiod's CA endpoint and requires TLS for
// the proxy's bearer credential.
func agentgatewayCAAddress(address string) (string, error) {
	if address == "" {
		return "", fmt.Errorf("agentgateway CA requires global.caAddress")
	}
	if !strings.Contains(address, "://") {
		address = "https://" + address
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("agentgateway CA address must be an HTTPS endpoint without credentials, query or path")
	}
	return strings.TrimSuffix(address, "/"), nil
}
