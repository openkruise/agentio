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

package securityprofile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"k8s.io/apimachinery/pkg/labels"

	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/pkg/model"
)

// FromXDS compiles the HTTP view; sandboxUID comes from the enclosing Sandbox, if any.
func FromXDS(value *securityv1.SecurityProfile, sandboxUID string, regs []filter.Registration) (*Profile, error) {
	var config *model.HTTPPolicy
	decoder := json.NewDecoder(bytes.NewReader(value.PolicyJson))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode HTTP policy: %w", err)
	}
	if config == nil {
		return nil, fmt.Errorf("HTTP policy must be a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple HTTP policy JSON values")
		}
		return nil, err
	}
	if value.Name == "" {
		return nil, fmt.Errorf("SecurityProfile source name is required")
	}
	meta := Meta{
		Name:           value.Name,
		Namespace:      value.Namespace,
		SourceIdentity: model.SourceIdentity{UID: value.Uid},
		SandboxUID:     sandboxUID,
	}
	if sandboxUID != "" {
		meta.Match = MatchSandbox
		for i := range config.Rules {
			escapeSandboxHeaderValues(config.Rules[i].Actions.HeaderManipulation)
		}
	}
	profile, err := newProfile(
		meta,
		&agentsv1alpha1.SecurityProfileSpec{Rules: config.Rules, Audit: config.Audit, Inputs: config.Inputs},
	)
	if err != nil {
		return nil, err
	}
	// xDS selection and ordering belong to the control plane's Workload binding.
	profile.Selector = labels.Nothing()
	if err := profile.Project(regs); err != nil {
		return nil, err
	}
	return profile, nil
}
