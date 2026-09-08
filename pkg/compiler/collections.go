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

	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// collectionOptions names a derived collection and applies the caller's options.
type collectionOptions func(name string) []krt.CollectionOption

// baseIndexes are the shared indexes over the registry input collections.
type baseIndexes struct {
	servicesByNamespace          krt.Index[string, model.Service]
	endpointsByService           krt.Index[string, model.Endpoint]
	endpointsByAddress           krt.Index[string, model.Endpoint]
	endpointsByTargetUID         krt.Index[string, model.Endpoint]
	endpointsByTargetName        krt.Index[string, model.Endpoint]
	gatewayPatchesByGateway      krt.Index[string, model.GatewayPatch]
	gatewayPatchesByName         krt.Index[string, model.GatewayPatch]
	telemetryByGateway           krt.Index[string, model.Telemetry]
	telemetryDefaultsByNamespace krt.Index[string, model.Telemetry]
}

func newBaseIndexes(inputs Inputs) baseIndexes {
	servicesByNamespace := krt.NewIndex(inputs.Services, "servicesByNamespace",
		func(service model.Service) []string { return []string{service.Namespace} })
	endpointsByService := krt.NewIndex(inputs.Endpoints, "endpointsByService",
		func(endpoint model.Endpoint) []string { return []string{endpoint.ServiceKey} })
	endpointsByAddress := krt.NewIndex(inputs.Endpoints, "endpointsByAddress",
		func(endpoint model.Endpoint) []string {
			if endpoint.HasTargetRef {
				return nil
			}
			return []string{endpoint.Address}
		})
	endpointsByTargetUID := krt.NewIndex(inputs.Endpoints, "endpointsByTargetUID",
		func(endpoint model.Endpoint) []string {
			if !endpoint.HasTargetRef || endpoint.TargetKind != "Pod" || endpoint.TargetUID == "" {
				return nil
			}
			return []string{endpoint.TargetUID}
		})
	endpointsByTargetName := krt.NewIndex(inputs.Endpoints, "endpointsByTargetName",
		func(endpoint model.Endpoint) []string {
			if !endpoint.HasTargetRef || endpoint.TargetKind != "Pod" || endpoint.TargetUID != "" ||
				endpoint.TargetNamespace == "" || endpoint.TargetName == "" {
				return nil
			}
			return []string{endpoint.TargetNamespace + "/" + endpoint.TargetName}
		})
	gatewayPatchesByGateway := krt.NewIndex(inputs.GatewayPatches, "gatewayPatchesByGateway",
		func(policy model.GatewayPatch) []string { return policy.TargetGateways })
	gatewayPatchesByName := krt.NewIndex(inputs.GatewayPatches, "gatewayPatchesByName",
		func(policy model.GatewayPatch) []string { return []string{policy.LogicalName()} })
	telemetryByGateway := krt.NewIndex(inputs.Telemetry, "telemetryByGateway",
		func(policy model.Telemetry) []string { return policy.TargetGateways })
	telemetryDefaultsByNamespace := krt.NewIndex(inputs.Telemetry, "telemetryDefaultsByNamespace",
		func(policy model.Telemetry) []string {
			if len(policy.TargetGateways) == 0 {
				return []string{policy.Namespace}
			}
			return nil
		})
	return baseIndexes{
		servicesByNamespace:          servicesByNamespace,
		endpointsByService:           endpointsByService,
		endpointsByAddress:           endpointsByAddress,
		endpointsByTargetUID:         endpointsByTargetUID,
		endpointsByTargetName:        endpointsByTargetName,
		gatewayPatchesByGateway:      gatewayPatchesByGateway,
		gatewayPatchesByName:         gatewayPatchesByName,
		telemetryByGateway:           telemetryByGateway,
		telemetryDefaultsByNamespace: telemetryDefaultsByNamespace,
	}
}

type policyCollections struct {
	sandboxSNIPolicies krt.Collection[SandboxSNIPolicy]

	authorizations krt.Collection[policy.CompiledAuthorization]
	sniPolicies    krt.Collection[policy.CompiledSNIPolicy]
	egressPolicies krt.Collection[policy.CompiledEgressPolicy]

	sandboxBindings krt.Collection[policy.SandboxPolicyBindings]
}

// graph retains the derived collections the Compiler reads after construction.
type graph struct {
	configuration krt.Singleton[configuration]
	gateways      krt.Collection[model.Gateway]
	policies      policyCollections
	resources     krt.Collection[model.Resource]
}

// buildGraph wires the derived configuration, gateway, policy, and resource layers together.
func buildGraph(inputs Inputs, failures *failureRecorder, builder krt.OptionsBuilder) (*graph, error) {
	collectionOptions := func(name string) []krt.CollectionOption {
		return builder.WithName(name)
	}
	inputs = validatedDomainInputs(inputs, failures, collectionOptions)
	base := newBaseIndexes(inputs)
	configuration := newConfiguration(inputs, failures, collectionOptions)
	workloadMetadataConfiguration := newWorkloadMetadataConfiguration(configuration, collectionOptions)
	gateways := newGatewayDeclarations(configuration, inputs.Gateways, collectionOptions)
	gatewayGlobalExtProc := newGatewayGlobalExtProc(configuration, collectionOptions)
	policies := newPolicyCollections(inputs, configuration, failures, collectionOptions, builder)

	// Each key must identify exactly one family; build resources via model.NewResource.
	workloadResources := newWorkloadResources(
		inputs,
		base,
		workloadMetadataConfiguration,
		gateways,
		policies,
		failures,
		collectionOptions,
	)
	resources := krt.JoinCollection([]krt.Collection[model.Resource]{
		newAuthorizationResources(policies, failures, collectionOptions),
		workloadResources,
		newServiceResources(inputs, gateways, failures, collectionOptions),
		newGatewayResources(inputs, base, gatewayGlobalExtProc, gateways, failures, collectionOptions),
	}, collectionOptions("resources")...)

	if resources == nil {
		return nil, fmt.Errorf("build resource collection")
	}
	return &graph{
		configuration: configuration,
		gateways:      gateways,
		policies:      policies,
		resources:     resources,
	}, nil
}

// workloadMetadataConfiguration is the part of Agentio configuration that
// affects Workload metadata encoding. Keeping this projection separate stops
// DNS-only changes in compiled egress policy from invalidating Workloads
// through the full configuration as well as through their policy payloads.
type workloadMetadataConfiguration struct {
	IgnoredLabels []string
}

func (c workloadMetadataConfiguration) ResourceName() string {
	return "workload-metadata-configuration"
}

func (c workloadMetadataConfiguration) Equals(other workloadMetadataConfiguration) bool {
	return slices.Equal(c.IgnoredLabels, other.IgnoredLabels)
}

func newWorkloadMetadataConfiguration(
	configuration krt.Singleton[configuration],
	options collectionOptions,
) krt.Singleton[workloadMetadataConfiguration] {
	return krt.NewSingleton(func(ctx krt.HandlerContext) *workloadMetadataConfiguration {
		current := krt.FetchOne(ctx, configuration.AsCollection())
		if current == nil || current.Config == nil {
			return nil
		}
		return &workloadMetadataConfiguration{
			IgnoredLabels: slices.Clone(current.Config.GetSandboxIgnoredLabels()),
		}
	}, options("workload-metadata-configuration")...)
}

// configuration is the Agentio configuration after overlay merging together
// with its compiled egress policy payload.
type configuration struct {
	ResourceVersion string
	Config          *configv1.AgentioConfig
	Egress          *extensionsv1.EgressPolicies
}

func (c configuration) ResourceName() string { return "configuration" }

func (c configuration) Equals(other configuration) bool {
	// Egress is compared explicitly: DNS resolution can change it while the
	// ConfigMap ResourceVersion stays the same.
	return c.ResourceVersion == other.ResourceVersion &&
		proto.Equal(c.Config, other.Config) &&
		proto.Equal(c.Egress, other.Egress)
}

func newConfiguration(inputs Inputs, failures *failureRecorder, options collectionOptions) krt.Singleton[configuration] {
	return krt.NewSingleton(func(ctx krt.HandlerContext) *configuration {
		var raw *configv1.AgentioConfig
		resourceVersion := ""
		if current := krt.FetchOne(ctx, inputs.AgentioConfig); current != nil {
			raw = current.Value
			resourceVersion = current.ResourceVersion
		}
		egress, err := policy.CompileEgressPolicies(ctx, raw, inputs.Resolve)
		if err != nil {
			failures.record("AgentioConfig", "configuration", err)
			// Discard the result to retain the last known good configuration.
			ctx.DiscardResult()
			return nil
		}
		// Validate attachment targets and Gateway identities before committing.
		if _, err := policy.CompiledEgressPolicies(inputs.RootNamespace, egress); err != nil {
			failures.record("AgentioConfig", "configuration", err)
			ctx.DiscardResult()
			return nil
		}
		compiled := &configuration{
			ResourceVersion: resourceVersion,
			Config:          raw,
			Egress:          egress,
		}
		failures.clear("AgentioConfig", "configuration")
		return compiled
	}, options("configuration")...)
}
