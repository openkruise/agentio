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

package validation

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/policy"
)

// ValidateSecurityProfile shares the production SNI, binding and L7 parsers
// between admission and policy status, without accessing external references.
func ValidateSecurityProfile(profile model.SecurityProfile, filters []filter.Registration) error {
	if _, err := policy.CompileSecurityProfile(profile); err != nil {
		return fmt.Errorf("SNI/binding: %w", err)
	}
	p, err := securityprofile.NewProfile(
		&metav1.ObjectMeta{Name: profile.Name, Namespace: profile.Namespace},
		&profile.Spec,
	)
	if err != nil {
		return fmt.Errorf("L7: %w", err)
	}
	if err := p.Project(filters); err != nil {
		return fmt.Errorf("L7: %w", err)
	}
	return nil
}
