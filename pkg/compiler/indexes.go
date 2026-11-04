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

// baseIndexes are the shared indexes over the registry input collections.
type baseIndexes struct {
	servicesByName               krt.Index[string, model.Service]
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
		servicesByName: krt.NewIndex(inputs.Services, "servicesByName", func(service model.Service) []string {
			return []string{service.Namespace + "/" + service.Name}
		}),
		endpointsByService: krt.NewIndex(
			inputs.Endpoints,
			"endpointsByService",
			func(endpoint model.Endpoint) []string {
				return []string{endpoint.ServiceKey}
			},
		),
		endpointsByAddress:           endpointsByAddress,
		endpointsByTargetUID:         endpointsByTargetUID,
		endpointsByTargetName:        endpointsByTargetName,
		gatewayPatchesByGateway:      gatewayPatchesByGateway,
		gatewayPatchesByName:         gatewayPatchesByName,
		telemetryByGateway:           telemetryByGateway,
		telemetryDefaultsByNamespace: telemetryDefaultsByNamespace,
	}
}
