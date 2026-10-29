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
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

func (c *Controller) compileProfile(s source) *compiledProfile {
	err := c.validateProfile(s)
	accepted := condition("Accepted", metav1.ConditionTrue, "Accepted",
		"L7 rules, SNI projection and binding metadata compiled successfully", s.Metadata.Generation)
	if err != nil {
		accepted.Status, accepted.Reason, accepted.Message = metav1.ConditionFalse, "InvalidConfiguration", err.Error()
	}
	return &compiledProfile{Source: s,
		Accepted: accepted}
}

func (c *Controller) validateProfile(s source) error {
	_, err := policy.CompileSecurityProfile(model.SecurityProfile{
		Name:         s.Metadata.Name,
		Namespace:    s.Metadata.Namespace,
		Global:       s.Kind == "GlobalSecurityProfile",
		CreationTime: s.Metadata.CreationTimestamp.Time,
		Spec:         *s.Profile,
	})
	if err != nil {
		return fmt.Errorf("SNI/binding: %w", err)
	}
	profile, err := securityprofile.NewProfile(&s.Metadata, s.Profile)
	if err != nil {
		return fmt.Errorf("L7: %w", err)
	}
	if err := profile.Project(c.filters); err != nil {
		return fmt.Errorf("L7: %w", err)
	}
	return nil
}

func (c *Controller) trafficStatus(ctx krt.HandlerContext, s source) *result {
	p := model.TrafficPolicy{
		Name:         s.Metadata.Name,
		Namespace:    s.Metadata.Namespace,
		Global:       s.Kind == "GlobalTrafficPolicy",
		CreationTime: s.Metadata.CreationTimestamp.Time,
		Spec:         *s.Traffic,
	}
	compiled, err := policy.CompileTrafficPolicy(ctx, p, c.traffic)
	if err == nil {
		_, err = policy.TrafficPolicyAsAuthorizations(*compiled, p, c.namespace)
	}
	accepted := condition("Accepted", metav1.ConditionTrue, "Accepted",
		"Traffic rules and binding metadata compiled successfully", s.Metadata.Generation)
	resolved := condition("ResolvedRefs", metav1.ConditionUnknown, "NotChecked",
		"Reference checks require a valid configuration", s.Metadata.Generation)
	if err != nil {
		accepted.Status, accepted.Reason, accepted.Message = metav1.ConditionFalse, "InvalidConfiguration", err.Error()
	} else {
		resolved = c.trafficRefs(ctx, s)
	}
	return &result{Source: s,
		Conditions: []metav1.Condition{accepted, resolved}}
}

func (c *Controller) profileStatus(ctx krt.HandlerContext, p compiledProfile) *result {
	resolved := condition("ResolvedRefs", metav1.ConditionUnknown, "NotChecked",
		"Reference checks require a valid configuration", p.Source.Metadata.Generation)
	if p.Accepted.Status == metav1.ConditionTrue {
		resolved = c.profileRefs(ctx, p.Source)
	}
	return &result{Source: p.Source,
		Conditions: []metav1.Condition{p.Accepted, resolved}}
}
