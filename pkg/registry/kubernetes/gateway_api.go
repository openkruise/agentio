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
	"strings"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	"google.golang.org/protobuf/encoding/protojson"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

const (
	agentioGatewayController = gatewayv1.GatewayController("agentio.kruise.io/egress-gateway-controller")
	gatewayConfigKey         = "config"
)

var (
	gatewayResource = schema.GroupVersionResource{
		Group:    gatewayv1.GroupName,
		Version:  "v1",
		Resource: "gateways",
	}
	gatewayClassResource = schema.GroupVersionResource{
		Group:    gatewayv1.GroupName,
		Version:  "v1",
		Resource: "gatewayclasses",
	}
)

func decodeEgressGateway(content string) (*configv1.EgressGateway, error) {
	data, err := yaml.YAMLToJSONStrict([]byte(content))
	if err != nil {
		return nil, fmt.Errorf("parse egress gateway YAML: %w", err)
	}
	value := &configv1.EgressGateway{}
	if err := protojson.Unmarshal(data, value); err != nil {
		return nil, fmt.Errorf("decode egress gateway: %w", err)
	}
	if value.GetName() != "" || value.GetNamespace() != "" {
		return nil, fmt.Errorf("name and namespace must be omitted; Gateway metadata is authoritative")
	}
	if err := model.ValidateDnsCacheSettings(value.GetDnsCache()); err != nil {
		return nil, err
	}
	if err := model.ValidateExtProcServiceRef(value.GetExtProc()); err != nil {
		return nil, fmt.Errorf("extProc: %w", err)
	}
	if service := value.GetExtProc().
		GetService(); value.GetExtProc().GetServiceRef() == nil && service != "" &&
		strings.TrimSpace(service) == "" {
		return nil, fmt.Errorf("ext_proc service must not be whitespace-only")
	}
	if err := model.ValidateUpstreamTLS(value.GetTls().GetOrigination()); err != nil {
		return nil, err
	}
	if err := model.ValidateUpstreamTrustBundle(value.GetUpstreamTrustBundle()); err != nil {
		return nil, err
	}
	if err := model.ValidateAccessLogFormat(value.GetAccessLogFormat()); err != nil {
		return nil, err
	}
	if err := model.ValidateBandwidthLimit(value.GetBandwidthLimit()); err != nil {
		return nil, err
	}
	if err := model.ValidateConnectRateLimit(value.GetConnectRateLimit()); err != nil {
		return nil, err
	}
	if err := model.ValidateConnectConcurrencyLimit(value.GetConnectConcurrencyLimit()); err != nil {
		return nil, err
	}
	normalized, err := model.NormalizeEgressGatewayServiceEntries(value)
	if err != nil {
		return nil, fmt.Errorf("egress gateway: %w", err)
	}
	return normalized, nil
}

func newGatewayAPIConfigurations(
	gateways krt.Collection[*gatewayv1.Gateway],
	classes krt.Collection[*gatewayv1.GatewayClass],
	configMaps krt.Collection[*corev1.ConfigMap],
	options ...krt.CollectionOption,
) krt.Collection[model.Gateway] {
	return krt.NewCollection(gateways,
		func(ctx krt.HandlerContext, gateway *gatewayv1.Gateway) *model.Gateway {
			class := krt.FetchOne(ctx, classes, krt.FilterKey(string(gateway.Spec.GatewayClassName)))
			if class == nil || (*class).Spec.ControllerName != agentioGatewayController {
				return nil
			}
			config := &configv1.EgressGateway{}
			if gateway.Spec.Infrastructure != nil && gateway.Spec.Infrastructure.ParametersRef != nil {
				ref := gateway.Spec.Infrastructure.ParametersRef
				if ref.Group != "" || ref.Kind != "ConfigMap" {
					log.Warn("retain last-known-good Gateway: unsupported parameters reference",
						"namespace", gateway.Namespace, "gateway", gateway.Name,
						"group", ref.Group, "kind", ref.Kind)
					ctx.DiscardResult()
					return nil
				}
				configMap := krt.FetchOne(ctx, configMaps, krt.FilterKey(gateway.Namespace+"/"+string(ref.Name)))
				if configMap == nil {
					log.Warn("retain last-known-good Gateway: parameters ConfigMap not found",
						"namespace", gateway.Namespace, "gateway", gateway.Name,
						"configmap", ref.Name)
					ctx.DiscardResult()
					return nil
				}
				content, hasConfig := (*configMap).Data[gatewayConfigKey]
				if !hasConfig {
					// parametersRef may customize only Kubernetes resources.
					content = "{}"
				}
				if strings.TrimSpace(content) == "" {
					log.Warn("retain last-known-good Gateway: parameters ConfigMap has no configuration data",
						"namespace", gateway.Namespace, "gateway", gateway.Name,
						"configmap", ref.Name, "key", gatewayConfigKey)
					ctx.DiscardResult()
					return nil
				}
				var err error
				config, err = decodeEgressGateway(content)
				if err != nil {
					log.Warn("retain last-known-good Gateway: invalid parameters ConfigMap",
						"namespace", gateway.Namespace, "gateway", gateway.Name,
						"configmap", ref.Name, "error", err)
					ctx.DiscardResult()
					return nil
				}
			}
			return &model.Gateway{
				Namespace: gateway.Namespace,
				Name:      gateway.Name,
				Config:    config,
				Source:    model.GatewaySourceGatewayAPI,
			}
		}, options...)
}
