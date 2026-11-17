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
	"encoding/json"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

func securityProfilePayload(
	payload *securityv1.SecurityProfile,
	spec *agentsv1alpha1.SecurityProfileSpec,
) (*securityv1.SecurityProfile, error) {
	config := model.HTTPPolicy{Inputs: spec.Inputs, Audit: spec.Audit}
	for _, rule := range spec.Rules {
		if rule.Actions.TLS == nil {
			config.Rules = append(config.Rules, rule)
		}
	}
	data, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	payload.PolicyJson = data
	return payload, nil
}

func newSecurityProfileResources(
	profiles krt.Collection[policy.CompiledSecurityProfile],
	failures *failureRecorder,
	options collectionOptions,
) krt.Collection[model.Resource] {
	clearFailureOnSourceDelete(profiles, failures, "SecurityProfileResource")
	return krt.NewCollection(
		profiles,
		func(ctx krt.HandlerContext, profile policy.CompiledSecurityProfile) *model.Resource {
			if profile.TCPPolicy == nil {
				return nil
			}
			payload, err := securityProfilePayload(&securityv1.SecurityProfile{
				Name:      profile.Attachment.SourceName,
				Namespace: profile.Attachment.SourceNamespace,
				Uid:       profile.Attachment.UID,
				SniPolicy: policy.ProjectSNIPolicy(profile.SNIPolicy),
				TcpPolicy: profile.TCPPolicy,
			}, &profile.Spec)
			if err == nil {
				value, marshalErr := marshalDeterministicAny(payload)
				err = marshalErr
				if err == nil {
					resource, resourceErr := model.NewResource(
						model.ResourceKey{TypeURL: model.SecurityProfileType, Name: profile.Name},
						"",
						model.Prebuilt(value),
						nil,
						model.ResourceFacts{},
					)
					err = resourceErr
					if err == nil {
						failures.clear("SecurityProfileResource", profile.Name)
						return &resource
					}
				}
			}
			failures.record("SecurityProfileResource", profile.Name, err)
			ctx.DiscardResult()
			return nil
		},
		options("security-profile-resources")...)
}
