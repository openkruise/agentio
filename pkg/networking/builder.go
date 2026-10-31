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

package networking

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/openkruise/agentio/pkg/util/protoutil"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/proto"
	meshv1alpha1 "istio.io/api/mesh/v1alpha1"

	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/model"
	envoyfilterpatch "github.com/openkruise/agentio/pkg/networking/envoyfilter"
	"github.com/openkruise/agentio/pkg/networking/telemetry"
)

const (
	ConnectTerminate        = "connect_terminate"
	MainInternal            = "main_internal"
	MainForward             = "main_forward"
	PassthroughCluster      = "PassthroughCluster"
	BlackHoleCluster        = "BlackHoleCluster"
	HTTPDynamicForwardProxy = "http_dynamic_forward_proxy"
	TLSConnectOriginate     = "tls_connect_originate"
	TLSProxyOriginate       = "tls_proxy_originate"
	ExtProcCluster          = "sandbox-ext-proc"
	PorterCluster           = "agentio-porter"
	UDPPassthroughCluster   = "agentio_udp_passthrough"
	DNSCacheName            = "agentio_dns_cache"
)

type Inputs struct {
	// LegacyGateway preserves the Istio-derived proxy wire contract during rolling upgrades.
	LegacyGateway              bool
	Gateway                    model.Gateway
	GlobalExtProc              *configv1.ExtProcProvider
	AdditionalExtProcs         []*configv1.ExtProcProvider
	GatewayPatches             []model.GatewayPatch
	TelemetryRootNamespace     string
	TelemetryClusterID         string
	Telemetry                  []model.Telemetry
	TelemetryProviderOverrides *model.TelemetryProviderOverrides
	DiscoveryAddress           string
	TrustDomain                string
}

type effectiveConfig struct {
	gateway            *configv1.EgressGateway
	gatewayIdentity    string
	extProc            *configv1.ExtProcProvider
	additionalExtProcs []*configv1.ExtProcProvider
	telemetry          *telemetry.Output
}

func Build(inputs Inputs) ([]model.Resource, error) {
	if err := inputs.Gateway.ValidateForUse(); err != nil {
		return nil, err
	}
	if inputs.LegacyGateway && inputs.Gateway.Config.GetBandwidthLimit() != nil {
		return nil, fmt.Errorf("bandwidthLimit requires the community gateway image; legacy proxyv2 is unsupported")
	}
	if inputs.LegacyGateway && inputs.Gateway.Config.GetConnectConcurrencyLimit() != nil {
		return nil, fmt.Errorf(
			"connectConcurrencyLimit requires the community gateway image; legacy proxyv2 is unsupported",
		)
	}
	if inputs.DiscoveryAddress == "" {
		return nil, fmt.Errorf("discovery address is required")
	}
	if inputs.TrustDomain == "" {
		return nil, fmt.Errorf("trust domain is required")
	}
	if features.GatewayConnectTimeout <= 0 {
		return nil, fmt.Errorf("gateway connect timeout must be positive")
	}
	rootCA := features.ResolveGatewayRootCAPath()
	if strings.TrimSpace(rootCA) == "" {
		return nil, fmt.Errorf("gateway root CA path is required (no OS CA bundle found)")
	}
	if !filepath.IsAbs(rootCA) {
		return nil, fmt.Errorf("gateway root CA path must be absolute")
	}
	effective, err := resolveConfig(inputs.Gateway, inputs.GlobalExtProc)
	if err != nil {
		return nil, err
	}
	if err := model.ValidateAdditionalExtProcs(inputs.AdditionalExtProcs); err != nil {
		return nil, err
	}
	if effective.extProc != nil {
		effective.additionalExtProcs = inputs.AdditionalExtProcs
	}
	if inputs.TelemetryRootNamespace != "" || inputs.Telemetry != nil || inputs.TelemetryProviderOverrides != nil ||
		inputs.Gateway.Config.GetAccessLogFormat() != nil {
		effective.telemetry, err = telemetry.Build(telemetry.Inputs{
			Gateway:           inputs.Gateway,
			LegacyGateway:     inputs.LegacyGateway,
			RootNamespace:     inputs.TelemetryRootNamespace,
			ClusterID:         inputs.TelemetryClusterID,
			Telemetry:         inputs.Telemetry,
			ProviderOverrides: inputs.TelemetryProviderOverrides,
		})
		if err != nil {
			return nil, fmt.Errorf("build Gateway Telemetry: %w", err)
		}
	}
	b := &resourceBuilder{legacyGateway: inputs.LegacyGateway}
	clusters, err := b.clusters(effective)
	if err != nil {
		return nil, err
	}
	routes, err := b.routes(effective.gateway)
	if err != nil {
		return nil, err
	}
	listeners, err := b.listeners(effective, inputs.TrustDomain)
	if err != nil {
		return nil, err
	}
	extensionConfigurations := b.extensions
	if len(inputs.GatewayPatches) > 0 {
		patches := envoyfilterpatch.NewPatchSet(inputs.GatewayPatches)
		clusters, err = envoyfilterpatch.ApplyClusters(patches, clusters)
		if err != nil {
			return nil, fmt.Errorf("apply EnvoyFilter cluster patches: %w", err)
		}
		listeners, err = envoyfilterpatch.ApplyListeners(patches, listeners)
		if err != nil {
			return nil, fmt.Errorf("apply EnvoyFilter listener patches: %w", err)
		}
		routes, err = envoyfilterpatch.ApplyRoutes(patches, routes)
		if err != nil {
			return nil, fmt.Errorf("apply EnvoyFilter route patches: %w", err)
		}
		extensionConfigurations, err = envoyfilterpatch.ApplyExtensionConfigurations(patches, extensionConfigurations)
		if err != nil {
			return nil, fmt.Errorf("apply EnvoyFilter extension patches: %w", err)
		}
		if err := validatePatchedMessages(clusters, listeners, routes, extensionConfigurations); err != nil {
			return nil, err
		}
	}

	resources := make([]model.Resource, 0, len(clusters)+len(routes)+len(listeners)+len(extensionConfigurations))
	for _, message := range clusters {
		resource, err := scopedResource(inputs.Gateway, model.ClusterType, message.GetName(), message)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	for _, message := range routes {
		resource, err := scopedResource(inputs.Gateway, model.RouteType, message.GetName(), message)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	for _, message := range listeners {
		resource, err := scopedResource(inputs.Gateway, model.ListenerType, message.GetName(), message)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	for _, message := range extensionConfigurations {
		resource, err := scopedResource(inputs.Gateway, model.ExtensionConfigurationType, message.GetName(), message)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	if inputs.LegacyGateway {
		resource, err := scopedResource(
			inputs.Gateway,
			model.ProxyConfigType,
			"agentio-proxy",
			&meshv1alpha1.ProxyConfig{DiscoveryAddress: inputs.DiscoveryAddress},
		)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	} else {
		// Same Envoy names, separate cache keys and selection facts. A mixed
		// rollout must never replace the other proxy's resource graph.
		for i := range resources {
			resources[i].Key.Name = inputs.Gateway.ResourceName() + "|agentio-egress|" + resources[i].XDSName
			resources[i].Facts.AgentioEgress = true
		}
	}
	return resources, nil
}

func validatePatchedMessages(
	clusters []*clusterv3.Cluster,
	listeners []*listenerv3.Listener,
	routes []*routev3.RouteConfiguration,
	extensions []*corev3.TypedExtensionConfig,
) error {
	if err := validatePatchedGroup(clusters); err != nil {
		return err
	}
	if err := validatePatchedGroup(listeners); err != nil {
		return err
	}
	if err := validatePatchedGroup(routes); err != nil {
		return err
	}
	return validatePatchedGroup(extensions)
}

func validatePatchedGroup[T interface{ ValidateAll() error }](messages []T) error {
	for _, message := range messages {
		if err := message.ValidateAll(); err != nil {
			return fmt.Errorf("EnvoyFilter produced invalid gateway resource: %w", err)
		}
	}
	return nil
}

func resolveConfig(gateway model.Gateway, globalExtProc *configv1.ExtProcProvider) (effectiveConfig, error) {
	result := effectiveConfig{gateway: gateway.Config, gatewayIdentity: gateway.ResourceName()}
	if override := gateway.Config.GetExtProc(); override != nil {
		// An explicit empty service disables ext_proc for this gateway;
		// only an absent override inherits the global provider.
		if override.GetService() != "" {
			result.extProc = override
		}
	} else if globalExtProc.GetService() != "" {
		result.extProc = globalExtProc
	}
	if err := model.ValidateExtProcTLS(result.extProc.GetTls()); err != nil {
		return effectiveConfig{}, err
	}
	return result, nil
}

func scopedResource(gateway model.Gateway, typeURL, name string, message proto.Message) (model.Resource, error) {
	value, err := protoutil.MarshalAny(message)
	if err != nil {
		return model.Resource{}, fmt.Errorf("marshal gateway resource %s: %w", name, err)
	}
	return model.Resource{
		Key:     model.ResourceKey{TypeURL: typeURL, Name: gateway.ResourceName() + "|" + name},
		XDSName: name,
		Value:   value,
		Facts:   model.ResourceFacts{GatewayOwner: gateway.ResourceName()},
	}, nil
}

func additionalExtProcName(provider *configv1.ExtProcProvider) string {
	return "agentio.additional-ext-proc." + provider.GetName()
}
