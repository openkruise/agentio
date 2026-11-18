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

package policystatus

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
	"github.com/openkruise/agentio/pkg/validation"
)

func (c *Controller) compileProfile(s source) *compiledProfile {
	err := validation.ValidateSecurityProfile(profileModel(s)).ToAggregate()
	accepted := condition(conditionAccepted, metav1.ConditionTrue, reasonAccepted,
		messageAccepted, s.Metadata.Generation)
	if err != nil {
		accepted.Status, accepted.Reason, accepted.Message = metav1.ConditionFalse, reasonInvalidConfiguration, err.Error()
	}
	return &compiledProfile{Source: s,
		Accepted: accepted}
}

func profileModel(s source) model.SecurityProfile {
	return model.SecurityProfile{
		Name:         s.Metadata.Name,
		Namespace:    s.Metadata.Namespace,
		Global:       s.Kind == "GlobalSecurityProfile",
		CreationTime: s.Metadata.CreationTimestamp.Time,
		Spec:         *s.Profile,
	}
}

func (c *Controller) trafficStatus(ctx krt.HandlerContext, s source) *result {
	p := model.TrafficPolicy{
		Name:         s.Metadata.Name,
		Namespace:    s.Metadata.Namespace,
		Global:       s.Kind == "GlobalTrafficPolicy",
		CreationTime: s.Metadata.CreationTimestamp.Time,
		Spec:         *s.Traffic,
	}
	var err error
	if errs := policy.ValidateTrafficPolicy(p.Spec); len(errs) != 0 {
		err = errs.ToAggregate()
	} else {
		compiled, compileErr := policy.CompileTrafficPolicy(ctx, p, c.traffic)
		err = compileErr
		if err == nil {
			_, err = policy.TrafficPolicyAsAuthorizations(*compiled, p, c.namespace)
		}
	}
	accepted := condition(conditionAccepted, metav1.ConditionTrue, reasonAccepted,
		messageAccepted, s.Metadata.Generation)
	var issues []validation.ReferenceIssue
	programmed := accepted
	programmed.Type = conditionProgrammed
	if err != nil {
		accepted.Status, accepted.Reason, accepted.Message = metav1.ConditionFalse, reasonInvalidConfiguration, err.Error()
		programmed.Status, programmed.Reason, programmed.Message = accepted.Status, accepted.Reason, accepted.Message
	} else {
		issues = c.references.TrafficPolicy(ctx, p)
		programmed.Reason = reasonProgrammed
		programmed.Message = messageProgrammed
	}
	resolved := referenceCondition(s.Metadata.Generation, issues)
	return &result{Source: s,
		Conditions: []metav1.Condition{accepted, resolved, programmed}}
}

func (c *Controller) profileStatus(ctx krt.HandlerContext, p compiledProfile) *result {
	var issues []validation.ReferenceIssue
	programmed := p.Accepted
	programmed.Type = conditionProgrammed
	if p.Accepted.Status == metav1.ConditionTrue {
		issues = c.references.SecurityProfile(ctx, profileModel(p.Source))
		programmed.Reason = reasonProgrammed
		programmed.Message = messageProgrammed
	}
	resolved := referenceCondition(p.Source.Metadata.Generation, issues)
	return &result{Source: p.Source,
		Conditions: []metav1.Condition{p.Accepted, resolved, programmed}}
}

func referenceCondition(generation int64, issues []validation.ReferenceIssue) metav1.Condition {
	if len(issues) != 0 {
		return condition(conditionResolvedRefs, metav1.ConditionFalse, issues[0].Reason, issues[0].Message, generation)
	}
	return condition(conditionResolvedRefs, metav1.ConditionTrue, reasonResolvedRefs, messageResolvedRefs, generation)
}
