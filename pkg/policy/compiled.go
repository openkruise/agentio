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
	"google.golang.org/protobuf/proto"

	"github.com/openkruise/agentio/pkg/krt"
)

// CompiledPolicy contains a typed wire payload and its optional, payload-free
// Sandbox attachment. Published values and their nested data are immutable.
// Name and Attachment.Name must agree when an attachment is present.
// A nil Attachment means the policy does not use Sandbox reference binding.
type CompiledPolicy[P proto.Message] struct {
	Name       string
	Policy     P
	Attachment *PolicyAttachment
}

func (p CompiledPolicy[P]) ResourceName() string { return p.Name }

func (p CompiledPolicy[P]) Equals(other CompiledPolicy[P]) bool {
	if p.Name != other.Name || !proto.Equal(p.Policy, other.Policy) {
		return false
	}
	if p.Attachment == nil || other.Attachment == nil {
		return p.Attachment == nil && other.Attachment == nil
	}
	return p.Attachment.Equals(*other.Attachment)
}

// PolicyAttachment returns only binding metadata, so payload-only changes do
// not propagate beyond the attachment collection.
func (p CompiledPolicy[P]) PolicyAttachment() *PolicyAttachment {
	if p.Name == "" || proto.Message(p.Policy) == nil || !p.Policy.ProtoReflect().IsValid() {
		return nil
	}
	return p.Attachment
}

// NewPolicyAttachmentsCollection projects any compiled policy family, including
// wrappers that embed CompiledPolicy and carry family-specific metadata.
func NewPolicyAttachmentsCollection[T interface{ PolicyAttachment() *PolicyAttachment }](
	policies krt.Collection[T], options krt.OptionsBuilder, name string,
) krt.Collection[PolicyAttachment] {
	return krt.NewCollection(policies, func(_ krt.HandlerContext, compiled T) *PolicyAttachment {
		return compiled.PolicyAttachment()
	}, options.WithName(name)...)
}
