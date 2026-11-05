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
	"maps"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestWorkloadMetadataConfigurationLifecycle(t *testing.T) {
	fixture := newIncrementalFixture(t)
	workload := testWorkload("demo", "client", "10.0.0.2")
	workload.Labels = map[string]string{
		"keep":   "yes",
		"drop-a": "a",
		"drop-b": "b",
	}
	fixture.workloads.ConditionalUpdateObject(workload)
	waitSynced(t, fixture.compiler)
	awaitSteadyState(t, fixture.compiler, addressResourceName("demo", "client"))

	if labels, found := compiledWorkloadMetadataLabels(t, fixture.compiler, workload.UID); found {
		t.Fatalf("metadata labels without AgentioConfig = %v, want no metadata extension", labels)
	}

	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "empty",
		Value:           &configv1.AgentioConfig{},
	})
	testutil.Eventually(t, func() bool {
		labels, found := compiledWorkloadMetadataLabels(t, fixture.compiler, workload.UID)
		return found && maps.Equal(labels, workload.Labels)
	}, "non-nil empty configuration publishes unfiltered metadata")

	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "ignore-a",
		Value: &configv1.AgentioConfig{
			SandboxIgnoredLabels: []string{"drop-a"},
		},
	})
	wantIgnoreA := map[string]string{"keep": "yes", "drop-b": "b"}
	testutil.Eventually(t, func() bool {
		labels, found := compiledWorkloadMetadataLabels(t, fixture.compiler, workload.UID)
		return found && maps.Equal(labels, wantIgnoreA)
	}, "ignored-label update republishes filtered workload metadata")

	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "invalid",
		Value: &configv1.AgentioConfig{
			SandboxIgnoredLabels: []string{"drop-b"},
			EgressPolicies: []*extensionsv1.EgressPolicy{{
				MatchCidrs: []string{"not-a-cidr"},
				Policy:     extensionsv1.EgressPolicyAction_DENY,
			}},
		},
	})
	testutil.Eventually(t, func() bool {
		_, failed := fixture.compiler.Failures()["AgentioConfig/configuration"]
		current := fixture.compiler.graph.configuration.Get()
		return failed && current != nil && current.ResourceVersion == "ignore-a"
	}, "invalid configuration retains the accepted configuration")
	if labels, found := compiledWorkloadMetadataLabels(
		t,
		fixture.compiler,
		workload.UID,
	); !found ||
		!maps.Equal(labels, wantIgnoreA) {
		t.Fatalf("metadata labels after rejected configuration = %v, found %v, want %v", labels, found, wantIgnoreA)
	}

	fixture.agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "recovered",
		Value: &configv1.AgentioConfig{
			SandboxIgnoredLabels: []string{"drop-b"},
		},
	})
	wantRecovered := map[string]string{"keep": "yes", "drop-a": "a"}
	testutil.Eventually(t, func() bool {
		labels, found := compiledWorkloadMetadataLabels(t, fixture.compiler, workload.UID)
		return found && maps.Equal(labels, wantRecovered)
	}, "valid recovery republishes workload metadata")
}

// DNS results are keyed krt objects, so changing an address propagates to the
// policies that fetched that hostname.
func TestDNSChangePropagatesThroughCollection(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(testSandboxForWorkload(testWorkload("alpha", "client", "10.1.0.1")))
	fixture.workloads.ConditionalUpdateObject(testWorkload("alpha", "client", "10.1.0.1"))
	fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
		Name:      "fqdn",
		Namespace: "alpha",
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionAllow,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{FQDN: "api.example.com"}},
			}}},
		},
	})
	waitSynced(t, fixture.compiler)

	authorizationKey := model.ResourceKey{
		TypeURL: model.TrafficPolicyType,
		Name:    "namespaces/alpha/trafficPolicies/fqdn",
	}
	var unresolvedHash string
	testutil.Eventually(t, func() bool {
		resource, found := currentSnapshot(t, fixture.compiler).Get(authorizationKey)
		if found {
			unresolvedHash = resource.Hash
		}
		return found
	}, "authorization published before resolution")

	fixture.setResolved("api.example.com", netip.MustParseAddr("203.0.113.7"))

	testutil.Eventually(t, func() bool {
		resource, found := currentSnapshot(t, fixture.compiler).Get(authorizationKey)
		return found && resource.Hash != unresolvedHash
	}, "DNS resolution recompiled the authorization")
}

func TestDNSChangeOnlyRecompilesPoliciesForThatHostname(t *testing.T) {
	fixture := newIncrementalFixture(t)
	fixture.sandboxes.ConditionalUpdateObject(model.Sandbox{UID: "actor", Namespace: "alpha"})
	for _, policy := range []struct {
		name string
		host string
	}{
		{name: "api", host: "api.example.com"},
		{name: "database", host: "database.example.com"},
	} {
		fixture.trafficPolicies.ConditionalUpdateObject(model.TrafficPolicy{
			Name:      policy.name,
			Namespace: "alpha",
			Spec: agentsv1alpha1.TrafficPolicySpec{
				Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
					Action: agentsv1alpha1.RuleActionAllow,
					To:     []agentsv1alpha1.TrafficPolicyPeer{{FQDN: policy.host}},
				}}},
			},
		})
	}
	waitSynced(t, fixture.compiler)
	testutil.Eventually(t, func() bool {
		return fixture.resolutionCount("api.example.com") > 0 && fixture.resolutionCount("database.example.com") > 0
	}, "both policies compiled")

	authorizationKey := model.ResourceKey{
		TypeURL: model.TrafficPolicyType,
		Name:    "namespaces/alpha/trafficPolicies/api",
	}
	var unresolvedHash string
	testutil.Eventually(t, func() bool {
		resource, found := currentSnapshot(t, fixture.compiler).Get(authorizationKey)
		if found {
			unresolvedHash = resource.Hash
		}
		return found
	}, "API authorization published before resolution")
	databaseCalls := fixture.resolutionCount("database.example.com")

	fixture.setResolved("api.example.com", netip.MustParseAddr("203.0.113.7"))
	testutil.Eventually(t, func() bool {
		resource, found := currentSnapshot(t, fixture.compiler).Get(authorizationKey)
		return found && resource.Hash != unresolvedHash
	}, "API DNS resolution recompiled its authorization")
	settle()

	if got := fixture.resolutionCount("database.example.com"); got != databaseCalls {
		t.Fatalf("unrelated DNS policy recompiled: database resolution calls = %d, want %d", got, databaseCalls)
	}
}

// TestDNSFlipUsesNarrowWorkloadConfigurationDependency protects the production
// graph from wiring Workloads directly to the full configuration as well as to
// the compiled egress policy produced by that configuration.
func TestDNSFlipUsesNarrowWorkloadConfigurationDependency(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	dnsResults := krt.NewMutableCollection[dnsBenchmarkResult](nil,
		[]dnsBenchmarkResult{{host: "api.example.com", address: netip.MustParseAddr("10.1.0.1")}}, options...)
	debugger := new(krt.DebugHandler)
	compiler := dnsScaleCompiler(t, 1, dnsResults.AsCollection(), stop, options, debugger)
	waitSynced(t, compiler)

	debugDump, err := json.Marshal(debugger)
	if err != nil {
		t.Fatalf("marshal KRT debug collections: %v", err)
	}
	var collections []struct {
		Name  string `json:"name"`
		State struct {
			Inputs map[string]struct {
				Dependencies []string `json:"dependencies"`
			} `json:"inputs"`
		} `json:"state"`
	}
	if err := json.Unmarshal(debugDump, &collections); err != nil {
		t.Fatalf("unmarshal KRT debug collections: %v", err)
	}
	var dependencies []string
	for _, collection := range collections {
		if collection.Name == "workload-resources" {
			dependencies = collection.State.Inputs["cluster//Pod/demo/workload-0"].Dependencies
			break
		}
	}
	if !slices.Contains(dependencies, "workload-metadata-configuration") {
		t.Fatalf("workload dependencies = %v, want workload-metadata-configuration", dependencies)
	}
	if slices.Contains(dependencies, "configuration") {
		t.Fatalf("workload dependencies = %v, must not include full configuration", dependencies)
	}

	var addressUpdates atomic.Uint64
	registration := compiler.Resources().RegisterBatch(func(events []krt.Event[model.Resource]) {
		for _, event := range events {
			if event.Latest().Key.TypeURL == model.AddressType {
				addressUpdates.Add(1)
			}
		}
	}, false)
	t.Cleanup(registration.UnregisterHandler)

	dnsResults.ConditionalUpdateObject(dnsBenchmarkResult{
		host:    "api.example.com",
		address: netip.MustParseAddr("10.1.0.2"),
	})
	testutil.Eventually(t, func() bool { return addressUpdates.Load() == 1 }, "DNS update published one Address update")
}
