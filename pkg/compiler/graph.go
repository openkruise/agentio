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
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// collectionOptions names a derived collection and applies the caller's options.
type collectionOptions func(name string) []krt.CollectionOption

// graph retains the derived collections the Compiler reads after construction.
type graph struct {
	configuration krt.Singleton[configuration]
	gateways      krt.Collection[model.Gateway]
	policies      policyCollections
	resources     krt.Collection[model.Resource]
}

// buildGraph wires the derived configuration, gateway, policy, and resource layers together.
func buildGraph(inputs Inputs, failures *failureRecorder, builder krt.OptionsBuilder) *graph {
	collectionOptions := func(name string) []krt.CollectionOption {
		return builder.WithName(name)
	}
	inputs = validatedDomainInputs(inputs, failures, collectionOptions)
	base := newBaseIndexes(inputs)
	configuration := newConfiguration(inputs, failures, collectionOptions)
	workloadMetadataConfiguration := newWorkloadMetadataConfiguration(configuration, collectionOptions)
	gateways := newGatewayDeclarations(configuration, inputs.Gateways, collectionOptions)
	gatewayGlobalExtProc := newGatewayGlobalExtProc(configuration, collectionOptions)
	trafficPolicyInputs := newTrafficPolicyInputs(inputs)
	policies := newPolicyCollections(inputs, configuration, trafficPolicyInputs, failures, collectionOptions, builder)

	compiledSandboxes := newCompiledSandboxes(inputs, failures, collectionOptions)
	selectedWorkloadPolicies := newWorkloadPolicies(inputs, policies, compiledSandboxes, failures, collectionOptions)

	// Each key must identify exactly one family; build resources via model.NewResource.
	workloadResources := newWorkloadResources(
		inputs,
		base,
		workloadMetadataConfiguration,
		selectedWorkloadPolicies,
		failures,
		collectionOptions,
	)
	sandboxResources := newSandboxResources(inputs.Sandboxes, compiledSandboxes, failures, collectionOptions)
	resources := krt.JoinCollection([]krt.Collection[model.Resource]{
		sandboxResources,
		newTrafficPolicyResources(policies.trafficPolicies, failures, collectionOptions),
		workloadResources,
		newServiceResources(inputs, gateways, failures, collectionOptions),
		newGatewayResources(inputs, base, gatewayGlobalExtProc, gateways, failures, collectionOptions),
	}, collectionOptions("resources")...)

	return &graph{
		configuration: configuration,
		gateways:      gateways,
		policies:      policies,
		resources:     resources,
	}
}
