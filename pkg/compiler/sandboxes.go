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
	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// Runtime metadata and policies are published independently. SNI compilation
// retains the last valid policy on failed updates, matching legacy EPE behavior.
func newSandboxResources(
	sandboxes krt.Collection[model.Sandbox],
	policies policyCollections,
	failures *failureRecorder,
	options collectionOptions,
) krt.Collection[model.Resource] {
	for _, kind := range []string{"SandboxResource", "SandboxInlinePolicies"} {
		clearFailureOnSourceDelete(sandboxes, failures, kind)
	}
	return krt.NewCollection(sandboxes, func(ctx krt.HandlerContext, sandbox model.Sandbox) *model.Resource {
		payload := &sandboxv1.Sandbox{Uid: sandbox.UID}
		if sandbox.Attester != nil {
			payload.Attester = &sandboxv1.Sandbox_Attester{WorkloadUid: sandbox.Attester.WorkloadUID}
		}
		currentInput := func() bool {
			current := sandboxes.GetKey(sandbox.ResourceName())
			return current != nil && current.Equals(sandbox)
		}
		record := func(kind string, err error) {
			if err != nil {
				failures.recordIf(kind, sandbox.UID, err, currentInput)
			} else {
				failures.clearIf(kind, sandbox.UID, currentInput)
			}
		}
		if compiled := krt.FetchOne(
			ctx,
			policies.trafficPolicies,
			krt.FilterKey(model.SandboxTrafficPolicyName(sandbox.UID)),
		); compiled != nil {
			payload.TrafficPolicy = compiled.Policy
		}
		var inlineErr error
		if compiled := krt.FetchOne(
			ctx,
			policies.sniPolicies,
			krt.FilterKey(model.SandboxSecurityProfileName(sandbox.UID)),
		); compiled != nil {
			extension, err := marshalDeterministicAny(compiled.Policy)
			inlineErr = err
			if err == nil {
				payload.Extensions = append(payload.Extensions, extension)
			}
		}
		record("SandboxInlinePolicies", inlineErr)

		facts := &model.SandboxResourceFacts{AttesterWorkloadUID: payload.GetAttester().GetWorkloadUid()}
		value, err := marshalDeterministicAny(payload)
		if err != nil {
			record("SandboxResource", err)
			return nil
		}
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.SandboxType, Name: sandbox.UID},
			"",
			value,
			nil,
			model.ResourceFacts{Sandbox: facts},
		)
		if err != nil {
			record("SandboxResource", err)
			return nil
		}
		record("SandboxResource", nil)
		return &resource
	}, options("sandbox-resources")...)
}
