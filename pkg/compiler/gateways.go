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

package compiler

import (
	"fmt"
	"slices"
	"sort"
	"time"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	"google.golang.org/protobuf/proto"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/clienttrust"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
)

type compiledGateway struct {
	Name string
	networking.GatewayCompilation
}

func (g compiledGateway) ResourceName() string { return g.Name }

func (g compiledGateway) Equals(other compiledGateway) bool {
	return g.Name == other.Name &&
		slices.EqualFunc(g.StaticResources, other.StaticResources, model.Resource.Equals) &&
		slices.Equal(g.EndpointBindings, other.EndpointBindings)
}

type gatewayGlobalExtProc struct {
	Provider   *configv1.ExtProcProvider
	Additional []*configv1.ExtProcProvider
}

func (g gatewayGlobalExtProc) ResourceName() string { return "gateway-global-ext-proc" }

func (g gatewayGlobalExtProc) Equals(other gatewayGlobalExtProc) bool {
	return proto.Equal(g.Provider, other.Provider) &&
		slices.EqualFunc(
			g.Additional,
			other.Additional,
			func(a, b *configv1.ExtProcProvider) bool { return proto.Equal(a, b) },
		)
}

// newGatewayGlobalExtProc projects the primary provider and ordered additions.
// Per-gateway overrides replace only the primary provider in the networking transform.
func newGatewayGlobalExtProc(
	configurations krt.Singleton[configuration],
	options collectionOptions,
) krt.Singleton[gatewayGlobalExtProc] {
	return krt.NewSingleton(func(ctx krt.HandlerContext) *gatewayGlobalExtProc {
		current := krt.FetchOne(ctx, configurations.AsCollection())
		var provider *configv1.ExtProcProvider
		var additional []*configv1.ExtProcProvider
		if current != nil && current.Config.GetSandboxExtProc() != nil {
			provider = proto.Clone(current.Config.GetSandboxExtProc()).(*configv1.ExtProcProvider)
		}
		if current != nil {
			for _, p := range current.Config.GetAdditionalExtProcs() {
				additional = append(additional, proto.Clone(p).(*configv1.ExtProcProvider))
			}
		}
		return &gatewayGlobalExtProc{Provider: provider, Additional: additional}
	}, options("gateway-global-ext-proc")...)
}

// newGatewayDeclarations merges external and AgentioConfig-derived Gateway declarations.
func newGatewayDeclarations(
	configurations krt.Singleton[configuration],
	declarations krt.Collection[model.Gateway],
	options collectionOptions,
) krt.Collection[model.Gateway] {
	agentioDeclarations := krt.NewManyCollection(configurations.AsCollection(),
		func(_ krt.HandlerContext, current configuration) []model.Gateway {
			return model.GatewaysFromAgentioConfig(current.Config)
		}, options("validated-agentio-config-gateways")...)
	externalDeclarations := krt.NewCollection(declarations,
		func(_ krt.HandlerContext, declaration model.Gateway) *model.Gateway {
			if declaration.Source == model.GatewaySourceAgentioConfig {
				return nil
			}
			return &declaration
		}, options("external-gateway-declarations")...)
	return krt.JoinWithMergeCollection(
		[]krt.Collection[model.Gateway]{agentioDeclarations, externalDeclarations},
		model.MergeGatewaySources,
		options("gateway-declarations")...,
	)
}

func newGatewayResources(
	inputs Inputs,
	base baseIndexes,
	globalExtProc krt.Singleton[gatewayGlobalExtProc],
	gateways krt.Collection[model.Gateway],
	failures *failureRecorder,
	options collectionOptions,
) krt.Collection[model.Resource] {
	extProcs := globalExtProc.AsCollection()
	// Overrides retain additional processors without depending on the global primary.
	additionalExtProcs := krt.NewCollection(extProcs,
		func(_ krt.HandlerContext, current gatewayGlobalExtProc) *gatewayGlobalExtProc {
			return &gatewayGlobalExtProc{Additional: current.Additional}
		}, options("gateway-additional-ext-proc")...)
	providerOverrides := inputs.TelemetryProviderOverrides.AsCollection()
	// A primary-input delete bypasses the transformation below. Clear any
	// recorded builder failure once that gateway identity no longer exists.
	gateways.Register(func(event krt.Event[model.Gateway]) {
		if event.New == nil {
			gateway := event.Latest()
			failures.clearIf("Gateway", gateway.ResourceName(), func() bool {
				return gateways.GetKey(gateway.ResourceName()) == nil
			})
		}
	})
	compiled := krt.NewCollection(gateways,
		func(ctx krt.HandlerContext, item model.Gateway) *compiledGateway {
			trustBundle, err := gatewayUpstreamTrustBundle(ctx, inputs, item)
			if err != nil {
				recordGatewayFailureIfCurrent(gateways, failures, item, err)
				ctx.DiscardResult()
				return nil
			}
			gatewayPatches := krt.Fetch(ctx, inputs.GatewayPatches,
				krt.FilterIndex(base.gatewayPatchesByGateway, item.ResourceName()))
			if err := validateGatewayPatches(
				ctx,
				inputs.GatewayPatches,
				base.gatewayPatchesByName,
				gatewayPatches,
			); err != nil {
				recordGatewayFailureIfCurrent(gateways, failures, item, err)
				ctx.DiscardResult()
				return nil
			}
			telemetry := krt.Fetch(ctx, inputs.Telemetry,
				krt.FilterIndex(base.telemetryByGateway, item.ResourceName()))
			telemetry = append(telemetry, krt.Fetch(ctx, inputs.Telemetry,
				krt.FilterIndex(base.telemetryDefaultsByNamespace, item.Namespace))...)
			if inputs.RootNamespace != item.Namespace {
				telemetry = append(telemetry, krt.Fetch(ctx, inputs.Telemetry,
					krt.FilterIndex(base.telemetryDefaultsByNamespace, inputs.RootNamespace))...)
			}
			providerOverride := krt.FetchOne(ctx, providerOverrides)
			var provider *configv1.ExtProcProvider
			var additional []*configv1.ExtProcProvider
			if override := item.Config.GetExtProc(); override == nil {
				if current := krt.FetchOne(ctx, extProcs); current != nil {
					provider = current.Provider
					additional = current.Additional
				}
			} else if model.ExtProcEnabled(override) {
				if current := krt.FetchOne(ctx, additionalExtProcs); current != nil {
					additional = current.Additional
				}
			}
			resources, err := gatewayResourcesFor(networking.Inputs{
				Gateway:                    item,
				GlobalExtProc:              provider,
				AdditionalExtProcs:         additional,
				DiscoveryAddress:           inputs.DiscoveryAddress,
				TrustDomain:                inputs.TrustDomain,
				UpstreamTrustBundle:        trustBundle,
				GatewayPatches:             gatewayPatches,
				TelemetryClusterID:         inputs.ClusterID,
				TelemetryRootNamespace:     inputs.RootNamespace,
				Telemetry:                  telemetry,
				TelemetryProviderOverrides: providerOverride,
			})
			if err != nil {
				recordGatewayFailureIfCurrent(gateways, failures, item, err)
				ctx.DiscardResult()
				return nil
			}
			failures.clearIf("Gateway", item.ResourceName(), func() bool {
				current := gateways.GetKey(item.ResourceName())
				return current != nil && current.Equals(item)
			})
			return resources
		}, options("compiled-gateways")...)
	compiled.Register(func(event krt.Event[compiledGateway]) {
		if event.New == nil {
			failures.clear("GatewayEndpoints", event.Latest().ResourceName())
		}
	})
	return krt.NewManyCollection(compiled, func(ctx krt.HandlerContext, item compiledGateway) []model.Resource {
		resources, err := gatewayEndpointResources(ctx, inputs, base, item)
		if err != nil {
			failures.record("GatewayEndpoints", item.Name, err)
			ctx.DiscardResult()
			return nil
		}
		failures.clear("GatewayEndpoints", item.Name)
		return resources
	}, options("gateway-resources")...)
}

func gatewayEndpointResources(
	ctx krt.HandlerContext,
	inputs Inputs,
	base baseIndexes,
	gateway compiledGateway,
) ([]model.Resource, error) {
	resources := slices.Clone(gateway.StaticResources)
	for _, binding := range gateway.EndpointBindings {
		target := binding.Target
		var services []model.Service
		var endpoints []model.Endpoint
		if service := krt.FetchOne(ctx, inputs.Services,
			krt.FilterIndex(base.servicesByName, target.Namespace+"/"+target.Name)); service != nil {
			services = []model.Service{*service}
			endpoints = krt.Fetch(
				ctx,
				inputs.Endpoints,
				krt.FilterIndex(base.endpointsByService, service.ResourceName()),
			)
		}
		resource, err := binding.BuildResource(services, endpoints)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func gatewayUpstreamTrustBundle(ctx krt.HandlerContext, inputs Inputs, gateway model.Gateway) (string, error) {
	bundle := gateway.Config.GetUpstreamTrustBundle()
	if err := model.ValidateUpstreamTrustBundle(bundle); err != nil {
		return "", err
	}
	if len(bundle.GetAdditionalSources()) == 0 {
		return inputs.GatewayTrustBundle, nil
	}
	// Additional sources must preserve the public CA baseline.
	if inputs.GatewayTrustBundle == "" {
		return "", fmt.Errorf(
			"upstreamTrustBundle requires the built-in public CA package (AGENTIO_CLIENT_TRUST_PACKAGE_PATH)",
		)
	}
	sources := [][]byte{[]byte(inputs.GatewayTrustBundle)}
	for i, source := range bundle.GetAdditionalSources() {
		ref := source.GetConfigMapRef()
		kind := "ConfigMap"
		if ref == nil {
			ref = source.GetSecretRef()
			kind = "Secret"
		}
		name := inputs.RootNamespace + "/" + ref.GetName()
		field := fmt.Sprintf("upstreamTrustBundle.additionalSources[%d]: %s %s key %q", i, kind, name, ref.GetKey())
		var data []byte
		var found bool
		if kind == "ConfigMap" {
			cm := krt.FetchOne(ctx, inputs.ConfigMaps, krt.FilterKey(name))
			if cm == nil {
				return "", fmt.Errorf("%s: not found", field)
			}
			value, exists := (*cm).Data[ref.GetKey()]
			data, found = []byte(value), exists
		} else {
			secret := krt.FetchOne(ctx, inputs.Secrets, krt.FilterKey(name))
			if secret == nil {
				return "", fmt.Errorf("%s: not found", field)
			}
			data, found = (*secret).Data[ref.GetKey()]
		}
		if !found {
			return "", fmt.Errorf("%s: data key not found", field)
		}
		validated, warnings, err := clienttrust.Merge([][]byte{data}, time.Now())
		if err != nil {
			return "", fmt.Errorf("%s: %w", field, err)
		}
		for _, warning := range warnings {
			log.Warn("upstream CA warning", "gateway", gateway.ResourceName(), "source", field, "warning", warning)
		}
		sources = append(sources, validated)
	}
	merged, _, err := clienttrust.Merge(sources, time.Now())
	if err != nil {
		return "", fmt.Errorf("upstreamTrustBundle: %w", err)
	}
	return string(merged), nil
}

func recordGatewayFailureIfCurrent(
	gateways krt.Collection[model.Gateway],
	failures *failureRecorder,
	item model.Gateway,
	err error,
) {
	name := item.ResourceName()
	failures.recordIf("Gateway", name, err, func() bool {
		current := gateways.GetKey(name)
		return current != nil && current.Equals(item)
	})
}

func gatewayResourcesFor(inputs networking.Inputs) (*compiledGateway, error) {
	item := inputs.Gateway
	var built []model.Resource
	var bindings []networking.EndpointBinding
	for _, legacy := range []bool{true, false} {
		// Limits require the community module; do not publish an unprotected legacy variant.
		if legacy && (item.Config.GetBandwidthLimit() != nil || item.Config.GetConnectConcurrencyLimit() != nil) {
			continue
		}
		inputs.LegacyGateway = legacy
		variant, err := networking.BuildGateway(inputs)
		if err != nil {
			return nil, fmt.Errorf("compile gateway %s (legacy=%t): %w", item.ResourceName(), legacy, err)
		}
		built = append(built, variant.StaticResources...)
		bindings = append(bindings, variant.EndpointBindings...)
	}
	result := make([]model.Resource, 0, len(built))
	for _, resource := range built {
		normalized, err := model.NewResource(
			resource.Key,
			resource.XDSName,
			resource.Value,
			resource.Aliases,
			resource.Facts,
		)
		if err != nil {
			return nil, fmt.Errorf("compile gateway %s: %w", item.ResourceName(), err)
		}
		result = append(result, normalized)
	}
	return &compiledGateway{
		Name: item.ResourceName(),
		GatewayCompilation: networking.GatewayCompilation{
			StaticResources:  result,
			EndpointBindings: bindings,
		},
	}, nil
}

func validateGatewayPatches(
	ctx krt.HandlerContext,
	all krt.Collection[model.GatewayPatch],
	byLogicalName krt.Index[string, model.GatewayPatch],
	patches []model.GatewayPatch,
) error {
	names := sets.NewWithLength[string](len(patches))
	for _, patch := range patches {
		names.Insert(patch.LogicalName())
	}
	orderedNames := make([]string, 0, len(names))
	for name := range names {
		orderedNames = append(orderedNames, name)
	}
	sort.Strings(orderedNames)
	for _, name := range orderedNames {
		declarations := krt.Fetch(ctx, all, krt.FilterIndex(byLogicalName, name))
		if len(declarations) < 2 {
			continue
		}
		sources := make([]string, 0, len(declarations))
		for _, declaration := range declarations {
			sources = append(sources, declaration.Source)
		}
		sort.Strings(sources)
		return fmt.Errorf("EnvoyFilter %s is declared by multiple sources: %v", name, sources)
	}
	return nil
}
