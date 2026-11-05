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

	"google.golang.org/protobuf/proto"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// compiledSandbox is the complete result shared by Sandbox delivery and the
// single-Sandbox Workload compatibility projection.
type compiledSandbox struct {
	Payload        *sandboxv1.Sandbox
	SNIPolicy      *extensionsv1.SniTrafficPolicy
	SourceIdentity model.SourceIdentity
}

func (s compiledSandbox) ResourceName() string { return s.Payload.Uid }

func (s compiledSandbox) Equals(other compiledSandbox) bool {
	return s.SourceIdentity == other.SourceIdentity &&
		proto.Equal(s.Payload, other.Payload) && proto.Equal(s.SNIPolicy, other.SNIPolicy)
}

func newCompiledSandboxes(
	inputs Inputs,
	trafficInputs policy.TrafficPolicyInputs,
	failures *failureRecorder,
	options collectionOptions,
) krt.Collection[compiledSandbox] {
	clearFailureOnSourceDelete(inputs.Sandboxes, failures, "SandboxPolicies")
	return krt.NewCollection(inputs.Sandboxes, func(ctx krt.HandlerContext, sandbox model.Sandbox) *compiledSandbox {
		result, err := compileSandbox(ctx, sandbox, trafficInputs)
		currentInput := func() bool {
			current := inputs.Sandboxes.GetKey(sandbox.UID)
			return current != nil && current.Equals(sandbox)
		}
		if err != nil {
			failures.recordIf("SandboxPolicies", sandbox.UID, err, currentInput)
			ctx.DiscardResult()
			return nil
		}
		failures.clearIf("SandboxPolicies", sandbox.UID, currentInput)
		return result
	}, options("compiled-sandboxes")...)
}

func compileSandbox(
	ctx krt.HandlerContext,
	sandbox model.Sandbox,
	trafficInputs policy.TrafficPolicyInputs,
) (*compiledSandbox, error) {
	result := &compiledSandbox{
		Payload:        &sandboxv1.Sandbox{Uid: sandbox.UID},
		SourceIdentity: sandbox.SourceIdentity,
	}
	if sandbox.Attester != nil {
		result.Payload.Attester = &sandboxv1.Sandbox_Attester{WorkloadUid: sandbox.Attester.WorkloadUID}
	}

	references := &extensionsv1.PolicyReference{TypeUrl: model.SecurityProfileType}
	if policies := sandbox.Policies; policies != nil {
		if policies.InputError != "" {
			return nil, fmt.Errorf("sandbox policies: %s", policies.InputError)
		}
		if policies.TrafficRules != nil {
			traffic, err := policy.CompileTrafficPolicyRules(
				ctx,
				*policies.TrafficRules,
				sandbox.Namespace,
				trafficInputs,
			)
			if err != nil {
				return nil, fmt.Errorf("sandbox traffic rules: %w", err)
			}
			result.Payload.TrafficPolicy = traffic
		}
		if policies.SecurityRules != nil {
			sni, err := policy.CompileSNIRules(policies.SecurityRules)
			if err != nil {
				return nil, fmt.Errorf("sandbox security rules: %w", err)
			}
			result.SNIPolicy = sni
			if len(sni.GetRules()) > 0 {
				extension, err := marshalDeterministicAny(sni)
				if err != nil {
					return nil, err
				}
				result.Payload.Extensions = append(result.Payload.Extensions, extension)
			}
			references.Resources = []*extensionsv1.PolicyResourceReference{{
				Name: model.SandboxSecurityProfileName(sandbox.UID),
				Uid:  sandbox.SourceIdentity.UID,
			}}
		}
	}
	extension, err := marshalDeterministicAny(references)
	if err != nil {
		return nil, err
	}
	result.Payload.Extensions = append(result.Payload.Extensions, extension)
	return result, nil
}

func newSandboxResources(
	inputs krt.Collection[model.Sandbox],
	sandboxes krt.Collection[compiledSandbox],
	failures *failureRecorder,
	options collectionOptions,
) krt.Collection[model.Resource] {
	clearFailureOnSourceDelete(inputs, failures, "SandboxResource")
	return krt.NewCollection(inputs, func(ctx krt.HandlerContext, source model.Sandbox) *model.Resource {
		sandbox := krt.FetchOne(ctx, sandboxes, krt.FilterKey(source.UID))
		if sandbox == nil || sandbox.SourceIdentity.UID != source.SourceIdentity.UID {
			return nil
		}
		workloadUID := ""
		if source.Attester != nil {
			workloadUID = source.Attester.WorkloadUID
		}
		// Failed policy updates may retain a complete result, but cannot retain an obsolete binding.
		if sandbox.Payload.GetAttester().GetWorkloadUid() != workloadUID {
			return nil
		}
		currentInput := func() bool {
			current := inputs.GetKey(source.UID)
			return current != nil && current.Equals(source)
		}
		value, err := marshalDeterministicAny(sandbox.Payload)
		if err != nil {
			failures.recordIf("SandboxResource", sandbox.ResourceName(), err, currentInput)
			return nil
		}
		resource, err := model.NewResource(
			model.ResourceKey{TypeURL: model.SandboxType, Name: sandbox.ResourceName()},
			"",
			value,
			nil,
			model.ResourceFacts{
				SourceIdentity: sandbox.SourceIdentity,
				Sandbox:        &model.SandboxResourceFacts{AttesterWorkloadUID: workloadUID},
			},
		)
		if err != nil {
			failures.recordIf("SandboxResource", sandbox.ResourceName(), err, currentInput)
			return nil
		}
		failures.clearIf("SandboxResource", sandbox.ResourceName(), currentInput)
		return &resource
	}, options("sandbox-resources")...)
}
