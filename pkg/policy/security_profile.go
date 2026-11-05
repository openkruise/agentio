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

package policy

import (
	"fmt"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"

	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/model"
)

// CompiledSecurityProfile contains one profile's binding metadata and SNI projection.
// A nil SNI projection does not affect binding.
type CompiledSecurityProfile struct {
	Name       string
	Attachment *PolicyAttachment
	SNIPolicy  *extensionsv1.SniTrafficPolicy
}

// ResourceName identifies the profile in the compiled collection.
func (p CompiledSecurityProfile) ResourceName() string { return p.Name }

// Equals includes binding metadata and the optional SNI projection.
func (p CompiledSecurityProfile) Equals(other CompiledSecurityProfile) bool {
	if p.Name != other.Name || !proto.Equal(p.SNIPolicy, other.SNIPolicy) {
		return false
	}
	if p.Attachment == nil || other.Attachment == nil {
		return p.Attachment == nil && other.Attachment == nil
	}
	return p.Attachment.Equals(*other.Attachment)
}

// PolicyAttachment exposes binding metadata independently of the SNI projection.
func (p CompiledSecurityProfile) PolicyAttachment() *PolicyAttachment { return p.Attachment }

// CompileSecurityProfile validates binding metadata and projects SNI once per
// source. Callers retain both outputs together when an update fails.
func CompileSecurityProfile(profile model.SecurityProfile) (*CompiledSecurityProfile, error) {
	attachment, err := SecurityProfileAttachment(profile)
	if err != nil {
		return nil, err
	}
	payload, err := CompileSNIRules(profile.Spec.Rules)
	if err != nil {
		return nil, fmt.Errorf("security profile %s: %w", profile.ResourceName(), err)
	}
	return &CompiledSecurityProfile{
		Name:       profile.ResourceName(),
		Attachment: attachment,
		SNIPolicy:  payload,
	}, nil
}

// SecurityProfileAttachment selects shared profiles independently of their
// rules or SNI projection. Sandbox rules use their aggregate compilation path.
func SecurityProfileAttachment(profile model.SecurityProfile) (*PolicyAttachment, error) {
	priority := agentsv1alpha1.DefaultSecurityProfilePriority
	if profile.Spec.Priority != nil {
		priority = *profile.Spec.Priority
	}
	if priority < 0 {
		return nil, fmt.Errorf("security profile %s priority %d is negative", profile.ResourceName(), priority)
	}
	target := AttachmentTarget{Selector: profile.Spec.Selector}
	if profile.Global {
		target.Global = true
	} else {
		target.Namespaces = []string{profile.Namespace}
	}
	attachment, err := NewPolicyAttachment(PolicyAttachment{
		Kind:            PolicyKindSecurityProfile,
		Name:            profile.ResourceName(),
		UID:             profile.UID,
		Target:          target,
		Priority:        priority,
		CreationTime:    profile.CreationTime,
		SourceName:      profile.Name,
		SourceNamespace: profile.Namespace,
	})
	if err != nil {
		return nil, err
	}
	return &attachment, nil
}
