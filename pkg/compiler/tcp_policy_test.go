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
	"testing"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/model"
)

func TestSecurityProfileDeliveryAndInvalidUpdates(t *testing.T) {
	f := newIncrementalFixture(t, func(inputs *Inputs) { inputs.SandboxMode = true })
	worker := testWorkload("ns", "client", "192.0.2.10")
	f.workloads.ConditionalUpdateObject(worker)
	profile := model.SecurityProfile{
		Name:      "shared",
		Namespace: "ns",
		UID:       "profile-1",
		Spec: agents.SecurityProfileSpec{
			TCPRules: []agents.TCPRule{
				{Name: "private", Action: "bad", Match: []agents.TCPMatch{{CIDRs: []string{"10.0.0.0/8"}}}},
			},
		},
	}
	f.securityProfiles.ConditionalUpdateObject(profile)
	waitSynced(t, f.compiler)
	current := func() *securityv1.TCPPolicy {
		resource, found := currentSnapshot(
			t,
			f.compiler,
		).Get(model.ResourceKey{TypeURL: model.SecurityProfileType, Name: profile.ResourceName()})
		if !found {
			return nil
		}
		p := new(securityv1.SecurityProfile)
		if err := resource.Value.UnmarshalTo(p); err != nil {
			t.Fatal(err)
		}
		return p.TcpPolicy
	}

	testutil.Eventually(t, func() bool {
		refs, _ := securityReferencesAt(t, f.compiler, model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
		return current() == nil && len(refs.GetResources()) == 1 && refs.Resources[0].Uid == profile.UID &&
			f.compiler.Failures()["SecurityProfile/"+profile.ResourceName()] != ""
	}, "invalid first policy keeps its reference without publishing an empty allow policy")
	profile.Spec = *profile.Spec.DeepCopy()
	profile.Spec.TCPRules[0].Action = agents.TCPActionDeny
	f.securityProfiles.ConditionalUpdateObject(profile)
	testutil.Eventually(t, func() bool {
		p := current()
		return p != nil && len(p.Rules) == 1 && p.Rules[0].Action == securityv1.TCPAction_TCP_ACTION_DENY
	}, "valid TCP policy appears in the shared profile")
	profile.Spec = *profile.Spec.DeepCopy()
	profile.Spec.TCPRules[0].Action = "invalid"
	f.securityProfiles.ConditionalUpdateObject(profile)
	testutil.Eventually(t, func() bool { return len(f.compiler.Failures()) > 0 }, "invalid update recorded")
	if p := current(); p == nil || len(p.Rules) != 1 || p.Rules[0].Action != securityv1.TCPAction_TCP_ACTION_DENY {
		t.Fatalf("lost last good TCP policy: %v", p)
	}
	profile.UID = "profile-2"
	f.securityProfiles.ConditionalUpdateObject(profile)
	testutil.Eventually(t, func() bool {
		refs, _ := securityReferencesAt(t, f.compiler, model.ResourceKey{TypeURL: model.AddressType, Name: worker.UID})
		return current() == nil && len(refs.GetResources()) == 1 && refs.Resources[0].Uid == profile.UID
	}, "invalid replacement cannot inherit the previous profile body")
	profile.Spec = *profile.Spec.DeepCopy()
	profile.Spec.TCPRules = nil
	f.securityProfiles.ConditionalUpdateObject(profile)
	testutil.Eventually(t, func() bool {
		p := current()
		return p != nil && len(p.Rules) == 0 && f.compiler.Failures()["SecurityProfile/"+profile.ResourceName()] == ""
	}, "valid empty policy is published without a compilation status")
	sandbox := model.Sandbox{
		UID:       "kruise:sandbox",
		Namespace: "ns",
		Attester:  &model.Attester{WorkloadUID: worker.UID},
		Policies: &model.SandboxPolicies{
			TCPRules: []agents.TCPRule{{Name: "all", Action: "invalid", Match: []agents.TCPMatch{{}}}},
		},
	}
	f.sandboxes.ConditionalUpdateObject(sandbox)
	testutil.Eventually(
		t,
		func() bool { return f.compiler.Failures()["SandboxPolicies/"+sandbox.UID] != "" },
		"invalid inline Sandbox is not published",
	)
	if manifestAt(t, f.compiler, sandbox.UID) != nil {
		t.Fatal("invalid Sandbox was published")
	}
	sandbox.Policies = &model.SandboxPolicies{
		TCPRules: []agents.TCPRule{{Name: "all", Action: agents.TCPActionDeny, Match: []agents.TCPMatch{{}}}},
	}
	f.sandboxes.ConditionalUpdateObject(sandbox)
	testutil.Eventually(t, func() bool {
		manifest := manifestAt(t, f.compiler, sandbox.UID)
		if manifest == nil {
			return false
		}
		p := inlineProfileAt(t, manifest).GetTcpPolicy()
		return p != nil && len(p.Rules) == 1 && p.Rules[0].Name == "all"
	}, "TCP-only Sandbox policy is delivered without HTTP rules")
}

func inlineProfileAt(t *testing.T, manifest *sandboxv1.Sandbox) *securityv1.SecurityProfile {
	t.Helper()
	for _, extension := range manifest.GetExtensions() {
		if extension.MessageIs(&securityv1.SecurityProfile{}) {
			result := new(securityv1.SecurityProfile)
			if err := extension.UnmarshalTo(result); err != nil {
				t.Fatal(err)
			}
			return result
		}
	}
	return nil
}
