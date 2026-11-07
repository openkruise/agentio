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

package model

import (
	"fmt"
	"reflect"
	"strings"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

// Attester identifies the one Workload currently hosting a Sandbox.
type Attester struct{ WorkloadUID string }

// SandboxKindKruise identifies the provider used to qualify a Kruise instance ID.
const SandboxKindKruise = "kruise"

// SandboxUID qualifies a provider's instance ID with its Sandbox kind. Providers
// supply stable IDs unique within their kind; consumers compare the full string.
func SandboxUID(kind, instanceID string) string {
	return kind + ":" + instanceID
}

// Sandbox is an execution unit discovered from a sandbox runtime.
// Sandbox policies share the identity and binding source version.
type Sandbox struct {
	SourceIdentity SourceIdentity
	Attester       *Attester
	UID            string
	Name           string
	Namespace      string
	Policies       *SandboxPolicies
}

// SandboxPolicies contains rules owned by the Sandbox, including source parse errors.
// A nil value means the source declares no Sandbox policies.
type SandboxPolicies struct {
	TrafficRules *TrafficPolicyRules
	// Nil means no Sandbox SecurityProfile; an empty slice declares an empty profile.
	SecurityRules []agentsv1alpha1.SecurityRule
	InputError    string
}

func (s Sandbox) Validate() error {
	if strings.TrimSpace(s.UID) == "" {
		return fmt.Errorf("sandbox UID is required")
	}
	if s.Attester != nil && strings.TrimSpace(s.Attester.WorkloadUID) == "" {
		return fmt.Errorf("attester workload UID is required")
	}
	return nil
}

func (s Sandbox) ResourceName() string {
	return s.UID
}

// Equals compares identity, host binding, and Sandbox policy inputs.
func (s Sandbox) Equals(other Sandbox) bool {
	return s.UID == other.UID &&
		s.Name == other.Name &&
		s.SourceIdentity == other.SourceIdentity &&
		reflect.DeepEqual(s.Policies, other.Policies) &&
		s.Namespace == other.Namespace &&
		attestersEqual(s.Attester, other.Attester)
}

func attestersEqual(left, right *Attester) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

// GetUID returns the source object's UID, independently of the Sandbox delivery ID.
func (s Sandbox) GetUID() types.UID { return types.UID(s.SourceIdentity.UID) }

// GetSourceIdentity exposes input provenance to generic source adapters.
func (s Sandbox) GetSourceIdentity() SourceIdentity { return s.SourceIdentity }

// SourceKey uses the Sandbox delivery identity, independently of the source UID.
func (s Sandbox) SourceKey() ResourceKey {
	return ResourceKey{TypeURL: SandboxType, Name: s.UID}
}
