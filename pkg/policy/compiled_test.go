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
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestCompiledPolicyEqualityAndOptionalAttachment(t *testing.T) {
	base := CompiledAuthorization{
		Name: "demo/allow", Policy: &securityv1.Authorization{Name: "allow", Namespace: "demo"},
	}
	clone := base
	clone.Policy = proto.Clone(base.Policy).(*securityv1.Authorization)
	if !base.Equals(clone) || base.PolicyAttachment() != nil {
		t.Fatal("equivalent unbound policies must compare equal and have no attachment")
	}
	bound := clone
	bound.Attachment = &PolicyAttachment{Kind: PolicyKindAuthorization, Name: base.Name}
	if base.Equals(bound) || bound.Equals(base) {
		t.Fatal("adding or removing an attachment must change the compiled policy")
	}
	renamed := base
	renamed.Name = "demo/other"
	if base.Equals(renamed) {
		t.Fatal("resource identity must participate in equality")
	}
	var empty CompiledPolicy[proto.Message]
	if empty.PolicyAttachment() != nil || !empty.Equals(empty) {
		t.Fatal("zero policies must be safe to project and compare")
	}
	empty.Name = "demo/empty"
	if empty.PolicyAttachment() != nil {
		t.Fatal("nil interface payload must not produce an attachment")
	}
}

func TestCompiledEgressPolicyEqualityIncludesGateway(t *testing.T) {
	base := CompiledEgressPolicy{
		CompiledPolicy: CompiledPolicy[*extensionsv1.EgressPolicy]{
			Name: "egress", Policy: &extensionsv1.EgressPolicy{},
		},
		GatewayKey: "demo/gateway-a",
	}
	changed := base
	changed.GatewayKey = "demo/gateway-b"
	if base.Equals(changed) {
		t.Fatal("gateway dependencies must participate in equality")
	}
}
