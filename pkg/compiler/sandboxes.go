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
	"sort"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// Sandbox resources exist independently of active Workloads. Invalid or unresolved
// policy views are withdrawn rather than published as empty policies.
func newSandboxResources(sandboxes krt.Collection[model.Sandbox], policies policyCollections, failures *failureRecorder, options collectionOptions) krt.Collection[model.Resource] {
	clearFailureOnSourceDelete(sandboxes, failures, "SandboxResource")
	return krt.NewCollection(sandboxes, func(ctx krt.HandlerContext, sandbox model.Sandbox) *model.Resource {
		payload := &sandboxv1.Sandbox{Uid: sandbox.UID, State: sandboxv1.SandboxState(sandbox.State)}
		if sandbox.Attester != nil {
			payload.Attester = &sandboxv1.Sandbox_Attester{WorkloadUid: sandbox.Attester.WorkloadUID}
		}
		currentInput := func() bool {
			current := sandboxes.GetKey(sandbox.ResourceName())
			return current != nil && current.Equals(sandbox)
		}
		facts := &model.SandboxResourceFacts{AttesterWorkloadUID: payload.GetAttester().GetWorkloadUid()}
		policyAvailable := false
		var routingErr error
		invalidPayload := false
		bindings := krt.FetchOne(ctx, policies.policyBindings, krt.FilterKey(policy.BindingsKey(policy.PolicyTargetSandbox, sandbox.UID)))
		if bindings != nil && bindings.Valid() {
			policyAvailable = true
			if names := bindings.PolicyNames(model.PolicyKindEgressPolicy); len(names) > 0 {
				fetched := krt.Fetch(ctx, policies.egressPolicies, krt.FilterKeys(append([]string(nil), names...)...))
				effective, gatewayKeys, err := policy.SelectEgressPolicies(names, fetched)
				facts.GatewayReferences = gatewayKeys
				if err != nil || len(fetched) != len(names) {
					policyAvailable = false
				} else {
					payload.EgressRouting, routingErr = policy.CompileEgressRouting(effective)
					if routingErr != nil {
						invalidPayload = true
					}
				}
			}
			bodiesAvailable, bodiesInvalid := loadSandboxPolicyBodies(ctx, bindings, policies, payload)
			policyAvailable = policyAvailable && bodiesAvailable
			invalidPayload = invalidPayload || bodiesInvalid
		}
		if invalidPayload || (bindings != nil && bindings.InvalidReason != "") {
			policyAvailable = false
		}
		if !policyAvailable {
			err := sandboxPolicyError(routingErr, bindings)
			failures.recordIf("SandboxResource", sandbox.UID, err, currentInput)
			return nil
		}
		value, err := marshalDeterministicAny(payload)
		if err != nil {
			failures.recordIf("SandboxResource", sandbox.UID, err, currentInput)
			return nil
		}
		resource, err := model.NewResource(model.ResourceKey{TypeURL: model.SandboxType, Name: sandbox.UID}, "", value, nil, model.ResourceFacts{Sandbox: facts})
		if err != nil {
			failures.recordIf("SandboxResource", sandbox.UID, err, currentInput)
			return nil
		}
		failures.clearIf("SandboxResource", sandbox.UID, currentInput)
		return &resource
	}, options("sandbox-resources")...)
}

// loadSandboxPolicyBodies resolves ordered native and extension policies from one binding set.
func loadSandboxPolicyBodies(ctx krt.HandlerContext, bindings *policy.Bindings, policies policyCollections, payload *sandboxv1.Sandbox) (bool, bool) {
	policyAvailable, invalidPayload := true, false
	for _, name := range bindings.PolicyNames(model.PolicyKindAuthorization) {
		compiled := krt.FetchOne(ctx, policies.trafficPolicies, krt.FilterKey(name))
		if compiled == nil {
			policyAvailable = false
			continue
		}
		payload.TrafficPolicies = append(payload.TrafficPolicies, proto.Clone(compiled.Policy).(*securityv1.TrafficPolicy))
	}
	// Native TrafficPolicy uses lower numeric priority first. Resolve ties
	// by stable identity so attachment insertion order cannot change a decision.
	sort.Slice(payload.TrafficPolicies, func(i, j int) bool {
		left, right := payload.TrafficPolicies[i], payload.TrafficPolicies[j]
		if left.Priority != right.Priority {
			return left.Priority < right.Priority
		}
		return left.Name < right.Name
	})
	for _, name := range bindings.PolicyNames(model.PolicyKindSNIPolicy) {
		compiled := krt.FetchOne(ctx, policies.sniPolicies, krt.FilterKey(name))
		if compiled == nil {
			policyAvailable = false
			continue
		}
		extension := new(anypb.Any)
		if err := anypb.MarshalFrom(extension, compiled.Policy, proto.MarshalOptions{Deterministic: true}); err != nil {
			invalidPayload = true
			continue
		}
		payload.Extensions = append(payload.Extensions, extension)
	}
	return policyAvailable, invalidPayload
}

func sandboxPolicyError(routingErr error, bindings *policy.Bindings) error {
	err := routingErr
	if err == nil && bindings != nil && bindings.InvalidReason != "" {
		err = fmt.Errorf("invalid sandbox policy bindings: %s", bindings.InvalidReason)
	}
	if err == nil {
		err = fmt.Errorf("sandbox policy view is incomplete or invalid")
	}
	return err
}
