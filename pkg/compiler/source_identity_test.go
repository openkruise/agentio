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

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/model"
)

// Identity and inline rules are committed as one complete result.
func TestSandboxInlineCompilation(t *testing.T) {
	f := newIncrementalFixture(t)
	sandbox := model.Sandbox{
		UID:            "kruise:pending",
		Namespace:      "demo",
		SourceIdentity: model.SourceIdentity{UID: "source"},
		Attester:       &model.Attester{WorkloadUID: "host"},
		Policies:       &model.SandboxPolicies{InputError: "invalid annotation"},
	}
	f.sandboxes.UpdateObject(sandbox)
	waitSynced(t, f.compiler)
	if got := manifestAt(t, f.compiler, sandbox.UID); got != nil {
		t.Fatal("published Sandbox with failed initial policy")
	}
	sandbox.Policies = &model.SandboxPolicies{}
	f.sandboxes.UpdateObject(sandbox)
	key := sandbox.SourceKey()
	testutil.Eventually(t, func() bool {
		resource, found := currentSnapshot(t, f.compiler).Get(key)
		return found && resource.Facts.SourceIdentity == sandbox.SourceIdentity
	}, "valid inline input publishes complete Sandbox")
	initial, _ := currentSnapshot(t, f.compiler).Get(key)
	sandbox.Policies = &model.SandboxPolicies{InputError: "invalid update"}
	f.sandboxes.UpdateObject(sandbox)
	testutil.Eventually(t, func() bool {
		return f.compiler.Failures()["SandboxPolicies/"+sandbox.UID] != ""
	}, "invalid update recorded")
	current, found := currentSnapshot(t, f.compiler).Get(key)
	if !found || current.Hash != initial.Hash {
		t.Fatal("failed update replaced last complete Sandbox")
	}
	sandbox.Policies = &model.SandboxPolicies{}
	f.sandboxes.UpdateObject(sandbox)
	testutil.Eventually(t, func() bool {
		resource, found := currentSnapshot(t, f.compiler).Get(key)
		return found && resource.Hash == initial.Hash && len(f.compiler.Failures()) == 0
	}, "same-content recovery clears failure without changing published output")
}

func TestSandboxInvalidUpdateWithdrawsObsoleteResult(t *testing.T) {
	for _, change := range []string{"unbind", "recreate"} {
		t.Run(change, func(t *testing.T) {
			f := newIncrementalFixture(t)
			sandbox := model.Sandbox{
				UID:            "sandbox",
				SourceIdentity: model.SourceIdentity{UID: "source"},
				Attester:       &model.Attester{WorkloadUID: "old-host"},
			}
			f.sandboxes.UpdateObject(sandbox)
			waitSynced(t, f.compiler)
			testutil.Eventually(t, func() bool { return manifestAt(t, f.compiler, sandbox.UID) != nil },
				"initial Sandbox")
			sandbox.Policies = &model.SandboxPolicies{InputError: "invalid"}
			switch change {
			case "unbind":
				sandbox.Attester = nil
			case "recreate":
				sandbox.SourceIdentity.UID = "replacement"
			}
			f.sandboxes.UpdateObject(sandbox)
			testutil.Eventually(t, func() bool { return manifestAt(t, f.compiler, sandbox.UID) == nil },
				"incompatible update withdraws old complete result")
			if change == "unbind" {
				sandbox.Attester = &model.Attester{WorkloadUID: "new-host"}
			}
			sandbox.Policies = nil
			f.sandboxes.UpdateObject(sandbox)
			testutil.Eventually(t, func() bool {
				resource, found := currentSnapshot(t, f.compiler).Get(sandbox.SourceKey())
				return found && resource.Facts.SourceIdentity == sandbox.SourceIdentity &&
					resource.Facts.Sandbox.AttesterWorkloadUID == sandbox.Attester.WorkloadUID
			}, "successful compilation publishes the current object and binding")
		})
	}
}

func TestRecreatedPolicyDoesNotRetainPreviousObject(t *testing.T) {
	f := newIncrementalFixture(t)
	policy := model.TrafficPolicy{
		Name:      "reused",
		Namespace: "demo",
		UID:       "old",
	}
	f.trafficPolicies.ConditionalUpdateObject(policy)
	waitSynced(t, f.compiler)
	key := model.ResourceKey{TypeURL: model.TrafficPolicyType, Name: "namespaces/demo/trafficPolicies/reused"}
	testutil.Eventually(t, func() bool {
		_, found := currentSnapshot(t, f.compiler).Get(key)
		return found
	}, "valid policy published")
	policy.UID = "replacement"
	policy.Spec.Priority = -1
	f.trafficPolicies.ConditionalUpdateObject(policy)
	testutil.Eventually(
		t,
		func() bool {
			_, found := currentSnapshot(t, f.compiler).Get(key)
			return !found
		},
		"invalid replacement must withdraw previous source incarnation",
	)
	policy.Spec.Priority = 0
	f.trafficPolicies.UpdateObject(policy)
	testutil.Eventually(t, func() bool {
		_, found := currentSnapshot(t, f.compiler).Get(key)
		return found
	}, "replacement with identical compiled content is published")
}

func TestRecreatedSecurityProfileWithdrawsPreviousBinding(t *testing.T) {
	f := newIncrementalFixture(t)
	workload := testWorkload("demo", "client", "10.1.0.1")
	f.workloads.UpdateObject(workload)
	profile := model.SecurityProfile{
		Name:      "reused",
		Namespace: "demo",
		UID:       "old",
	}
	f.securityProfiles.UpdateObject(profile)
	key := model.ResourceKey{TypeURL: model.AddressType, Name: workload.UID}
	waitSynced(t, f.compiler)
	testutil.Eventually(t, func() bool {
		refs, _ := securityReferencesAt(t, f.compiler, key)
		return len(refs.GetResources()) == 1 && refs.Resources[0].Name == profile.ResourceName() &&
			refs.Resources[0].Uid == "old"
	}, "initial SecurityProfile binding")
	profile.UID = "replacement"
	priority := int32(-1)
	profile.Spec.Priority = &priority
	f.securityProfiles.UpdateObject(profile)
	testutil.Eventually(t, func() bool {
		refs, _ := securityReferencesAt(t, f.compiler, key)
		return refs != nil && len(refs.Resources) == 0
	}, "invalid replacement withdraws previous profile binding")
	profile.Spec.Priority = nil
	f.securityProfiles.UpdateObject(profile)
	testutil.Eventually(t, func() bool {
		refs, _ := securityReferencesAt(t, f.compiler, key)
		return len(refs.GetResources()) == 1 && refs.Resources[0].Name == profile.ResourceName() &&
			refs.Resources[0].Uid == "replacement"
	}, "recovered replacement restores profile binding")
}

func TestSandboxInlineRemoval(t *testing.T) {
	f := newIncrementalFixture(t)
	sandbox := model.Sandbox{
		UID:            "kruise:clear",
		SourceIdentity: model.SourceIdentity{UID: "source"},
		Policies: &model.SandboxPolicies{SecurityRules: []agentsv1alpha1.SecurityRule{
			{Name: "old", Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"old.example"}}}},
		}},
	}
	f.sandboxes.UpdateObject(sandbox)
	waitSynced(t, f.compiler)
	testutil.Eventually(
		t,
		func() bool { return len(manifestAt(t, f.compiler, sandbox.UID).GetExtensions()) == 2 },
		"initial inline policy",
	)
	sandbox.Policies = nil
	f.sandboxes.UpdateObject(sandbox)
	testutil.Eventually(t, func() bool {
		resource, found := currentSnapshot(t, f.compiler).Get(sandbox.SourceKey())
		return found && resource.Facts.SourceIdentity == sandbox.SourceIdentity &&
			len(manifestAt(t, f.compiler, sandbox.UID).GetExtensions()) == 0
	}, "inline removal publishes complete Sandbox")
	if got := len(manifestAt(t, f.compiler, sandbox.UID).GetExtensions()); got != 0 {
		t.Fatalf("stale inline SNI retained: %d extensions", got)
	}
}

func TestFailedPolicyRetainsLastGoodOutput(t *testing.T) {
	f := newIncrementalFixture(t)
	policy := model.TrafficPolicy{
		Name:      "example",
		Namespace: "demo",
		UID:       "source",
	}
	f.trafficPolicies.UpdateObject(policy)
	waitSynced(t, f.compiler)
	key := model.ResourceKey{TypeURL: model.TrafficPolicyType, Name: "namespaces/demo/trafficPolicies/example"}
	testutil.Eventually(t, func() bool {
		_, found := currentSnapshot(t, f.compiler).Get(key)
		return found
	}, "initial policy published")
	initial, _ := currentSnapshot(t, f.compiler).Get(key)
	policy.Spec.Priority = -1
	f.trafficPolicies.UpdateObject(policy)
	testutil.Eventually(t, func() bool { return len(f.compiler.Failures()) > 0 }, "invalid update recorded")
	if got := f.trafficPolicies.GetKey(policy.ResourceName()); got == nil || !got.Equals(policy) {
		t.Fatalf("input did not advance independently of compilation: %v", got)
	}
	if current, found := currentSnapshot(
		t,
		f.compiler,
	).Get(key); !found ||
		current.Hash != initial.Hash {
		t.Fatal("failed update replaced last valid publication")
	}
	policy.Spec.Priority = 0
	f.trafficPolicies.UpdateObject(policy)
	testutil.Eventually(t, func() bool {
		current, found := currentSnapshot(t, f.compiler).Get(key)
		return found && current.Hash == initial.Hash && len(f.compiler.Failures()) == 0
	}, "same-content recovery clears failure without changing published output")
}

func TestSandboxTrafficFailureRetainsCompleteResult(t *testing.T) {
	f := newIncrementalFixture(t)
	sandbox := model.Sandbox{
		UID:            "kruise:traffic",
		Namespace:      "demo",
		SourceIdentity: model.SourceIdentity{UID: "source"},
		Policies:       &model.SandboxPolicies{SecurityRules: compatibilitySecurity("first.example").Rules},
	}
	f.sandboxes.UpdateObject(sandbox)
	waitSynced(t, f.compiler)
	testutil.Eventually(t, func() bool {
		_, found := currentSnapshot(t, f.compiler).Get(sandbox.SourceKey())
		return found
	}, "initial Sandbox published")
	before, _ := currentSnapshot(t, f.compiler).Get(sandbox.SourceKey())
	sandbox.Policies = &model.SandboxPolicies{
		SecurityRules: compatibilitySecurity("updated.example").Rules,
		TrafficRules: &model.TrafficPolicyRules{
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: "invalid",
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "192.0.2.0/24"}},
			}}},
		},
	}
	f.sandboxes.UpdateObject(sandbox)
	testutil.Eventually(
		t,
		func() bool { return f.compiler.Failures()["SandboxPolicies/"+sandbox.UID] != "" },
		"traffic failure recorded",
	)
	after, found := currentSnapshot(t, f.compiler).Get(sandbox.SourceKey())
	if !found || after.Hash != before.Hash {
		t.Fatal("failed traffic rules partially published new security rules")
	}
	sandbox.Policies = &model.SandboxPolicies{SecurityRules: compatibilitySecurity("updated.example").Rules}
	f.sandboxes.UpdateObject(sandbox)
	testutil.Eventually(t, func() bool {
		resource, found := currentSnapshot(t, f.compiler).Get(sandbox.SourceKey())
		return found && resource.Hash != before.Hash && resource.Facts.SourceIdentity == sandbox.SourceIdentity &&
			manifestAt(t, f.compiler, sandbox.UID).GetTrafficPolicy() == nil
	}, "removing invalid traffic rules publishes the new complete result")
}
