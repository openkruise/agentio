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
// Shared policies and legacy inline SNI attachments use the same ordered bindings.
type workloadPolicies struct {
	WorkloadUID        string
	TrafficPolicyNames []string
	AuthorizationNames []string
	SNIPolicy          *extensionsv1.SniTrafficPolicy
	EgressPolicies     *extensionsv1.EgressPolicies
	GatewayReferences  []string
}

func (p workloadPolicies) ResourceName() string { return p.WorkloadUID }

func (p workloadPolicies) Equals(other workloadPolicies) bool {
	return p.WorkloadUID == other.WorkloadUID &&
		slices.Equal(p.TrafficPolicyNames, other.TrafficPolicyNames) &&
		slices.Equal(p.AuthorizationNames, other.AuthorizationNames) &&
		slices.Equal(p.GatewayReferences, other.GatewayReferences) &&
		proto.Equal(p.SNIPolicy, other.SNIPolicy) && proto.Equal(p.EgressPolicies, other.EgressPolicies)
}

func newWorkloadPolicies(
	inputs Inputs,
	policies policyCollections,
	failures *failureRecorder,
	options collectionOptions,
) krt.Collection[workloadPolicies] {
	clearFailureOnSourceDelete(inputs.Workloads, failures, "WorkloadPolicies")
	return krt.NewCollection(inputs.Workloads, func(ctx krt.HandlerContext, workload model.Workload) *workloadPolicies {
		result, err := compileWorkloadPolicies(ctx, workload, policies)
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
	result.TrafficPolicyNames = append([]string(nil), bindings.PolicyNames(model.PolicyKindTrafficPolicy)...)
	for _, name := range result.TrafficPolicyNames {
		compiled := krt.FetchOne(ctx, policies.trafficPolicies, krt.FilterKey(name))
		if compiled == nil {
			policyErr = errors.Join(policyErr, fmt.Errorf("TrafficPolicy %q is unavailable", name))
			continue
		}
		result.addAuthorizationReferences(compiled)
	}
	for _, name := range bindings.PolicyNames(model.PolicyKindSNIPolicy) {
		compiled := krt.FetchOne(ctx, policies.sniPolicies, krt.FilterKey(name))
		if compiled == nil {
			policyErr = errors.Join(policyErr, fmt.Errorf("SNI policy %q is unavailable", name))
			continue
		}
		result.appendSNI(compiled.Policy)
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

// Global and namespace Authorizations apply through the existing data plane's
// scope handling. Selector policies need explicit Workload references.
func (p *workloadPolicies) addAuthorizationReferences(compiled *policy.CompiledTrafficPolicy) {
	for _, authorization := range compiled.AsAuthorization {
		if authorization.Policy.Scope == securityv1.Scope_WORKLOAD_SELECTOR {
			p.AuthorizationNames = append(p.AuthorizationNames, authorization.Name)
		}
	}
}
