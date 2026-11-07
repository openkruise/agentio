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
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// workloadPolicies is computed once per Workload and shared by all ADS clients.
// Legacy inline SNI is appended after shared policy selection.
type workloadPolicies struct {
	WorkloadUID               string
	TrafficPolicyReferences   []*extensionsv1.PolicyResourceReference
	SecurityProfileReferences []*extensionsv1.PolicyResourceReference
	AuthorizationNames        []string
	SNIPolicy                 *extensionsv1.SniTrafficPolicy
	EgressPolicies            *extensionsv1.EgressPolicies
	GatewayReferences         []string
}

func (p workloadPolicies) ResourceName() string { return p.WorkloadUID }

func (p workloadPolicies) Equals(other workloadPolicies) bool {
	return p.WorkloadUID == other.WorkloadUID &&
		slices.EqualFunc(p.TrafficPolicyReferences, other.TrafficPolicyReferences, equalPolicyReference) &&
		slices.EqualFunc(p.SecurityProfileReferences, other.SecurityProfileReferences, equalPolicyReference) &&
		slices.Equal(p.AuthorizationNames, other.AuthorizationNames) &&
		slices.Equal(p.GatewayReferences, other.GatewayReferences) &&
		proto.Equal(p.SNIPolicy, other.SNIPolicy) && proto.Equal(p.EgressPolicies, other.EgressPolicies)
}

func equalPolicyReference(a, b *extensionsv1.PolicyResourceReference) bool {
	return proto.Equal(a, b)
}

// trafficWorkloadBinding excludes rule bodies so their updates do not recompute Workloads.
type trafficWorkloadBinding struct {
	Name               string
	UID                string
	AuthorizationNames []string
}

func (p trafficWorkloadBinding) ResourceName() string { return p.Name }

func (p trafficWorkloadBinding) Equals(other trafficWorkloadBinding) bool {
	return p.Name == other.Name && p.UID == other.UID && slices.Equal(p.AuthorizationNames, other.AuthorizationNames)
}

func newTrafficWorkloadBindings(
	policies krt.Collection[policy.CompiledTrafficPolicy],
	options collectionOptions,
) krt.Collection[trafficWorkloadBinding] {
	return krt.NewCollection(
		policies,
		func(_ krt.HandlerContext, compiled policy.CompiledTrafficPolicy) *trafficWorkloadBinding {
			result := &trafficWorkloadBinding{Name: compiled.Name, UID: compiled.Attachment.UID}
			// Global and namespace Authorizations apply through the data plane's scope handling.
			for _, authorization := range compiled.AsAuthorization {
				if authorization.Policy.Scope == securityv1.Scope_WORKLOAD_SELECTOR {
					result.AuthorizationNames = append(result.AuthorizationNames, authorization.Name)
				}
			}
			return result
		},
		options("traffic-workload-bindings")...,
	)
}

func newWorkloadPolicies(
	inputs Inputs,
	policies policyCollections,
	compiledSandboxes krt.Collection[compiledSandbox],
	failures *failureRecorder,
	options collectionOptions,
) krt.Collection[workloadPolicies] {
	sandboxesByWorkload := krt.NewIndex(inputs.Sandboxes, "sandboxesByWorkload", func(sandbox model.Sandbox) []string {
		if sandbox.Attester == nil {
			return nil
		}
		return []string{sandbox.Attester.WorkloadUID}
	})
	clearFailureOnSourceDelete(inputs.Workloads, failures, "WorkloadPolicies")
	return krt.NewCollection(inputs.Workloads, func(ctx krt.HandlerContext, workload model.Workload) *workloadPolicies {
		result, err := compileWorkloadPolicies(ctx, workload, policies)
		if inputs.SandboxMode {
			sandboxes := krt.Fetch(ctx, inputs.Sandboxes, krt.FilterIndex(sandboxesByWorkload, workload.UID))
			// shortcut: only project a single Sandbox; shared hosts need Sandbox-aware consumers.
			if len(sandboxes) == 1 {
				if compiled := krt.FetchOne(ctx, compiledSandboxes,
					krt.FilterKey(sandboxes[0].UID)); compiled != nil &&
					compiled.SourceIdentity.UID == sandboxes[0].SourceIdentity.UID &&
					compiled.Payload.GetAttester().GetWorkloadUid() == workload.UID {
					result.appendSNI(compiled.SNIPolicy)
				}
			}
		}
		currentInput := func() bool {
			current := inputs.Workloads.GetKey(workload.UID)
			return current != nil && current.Equals(workload)
		}
		if err != nil {
			failures.recordIf("WorkloadPolicies", workload.UID, err, currentInput)
		} else {
			failures.clearIf("WorkloadPolicies", workload.UID, currentInput)
		}
		return result
	}, options("workload-policies")...)
}

func compileWorkloadPolicies(
	ctx krt.HandlerContext,
	workload model.Workload,
	policies policyCollections,
) (*workloadPolicies, error) {
	result := &workloadPolicies{WorkloadUID: workload.UID}
	bindings := krt.FetchOne(ctx, policies.policyBindings, krt.FilterKey(workload.UID))
	if bindings == nil {
		return result, nil
	}
	var policyErr error
	// Preserve the complete ordered binding, including global and namespace
	// policies. A temporarily missing body must not silently remove its reference.
	for _, name := range bindings.PolicyNames(model.PolicyKindTrafficPolicy) {
		reference := &extensionsv1.PolicyResourceReference{Name: name}
		result.TrafficPolicyReferences = append(result.TrafficPolicyReferences, reference)
		binding := krt.FetchOne(ctx, policies.trafficBindings, krt.FilterKey(name))
		if binding == nil {
			policyErr = errors.Join(policyErr, fmt.Errorf("TrafficPolicy %q is unavailable", name))
			continue
		}
		reference.Uid = binding.UID
		result.AuthorizationNames = append(result.AuthorizationNames, binding.AuthorizationNames...)
	}
	for _, name := range bindings.PolicyNames(model.PolicyKindSecurityProfile) {
		reference := &extensionsv1.PolicyResourceReference{Name: name}
		result.SecurityProfileReferences = append(result.SecurityProfileReferences, reference)
		compiled := krt.FetchOne(ctx, policies.securityProfiles, krt.FilterKey(name))
		if compiled == nil {
			policyErr = errors.Join(policyErr, fmt.Errorf("SecurityProfile %q is unavailable", name))
			continue
		}
		reference.Uid = compiled.Attachment.UID
		result.appendSNI(compiled.SNIPolicy)
	}
	if names := bindings.PolicyNames(model.PolicyKindEgressPolicy); len(names) > 0 {
		compiled := krt.Fetch(ctx, policies.egressPolicies, krt.FilterKeys(append([]string(nil), names...)...))
		effective, keys, err := policy.SelectEgressPolicies(names, compiled)
		if err == nil {
			result.EgressPolicies, result.GatewayReferences = effective, keys
		}
		policyErr = errors.Join(policyErr, err)
	}
	return result, policyErr
}

func (p *workloadPolicies) appendSNI(value *extensionsv1.SniTrafficPolicy) {
	if len(value.GetRules()) == 0 {
		return
	}
	if p.SNIPolicy == nil {
		p.SNIPolicy = &extensionsv1.SniTrafficPolicy{}
	}
	p.SNIPolicy.Rules = append(p.SNIPolicy.Rules, value.Rules...)
}
