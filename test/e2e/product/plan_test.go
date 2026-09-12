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

package product

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/openkruise/agentio/test/e2e/command"
)

func catalogInventory() map[string][]string {
	result := map[string][]string{}
	for _, s := range Catalog() {
		result[s.Name] = []string{"TestDefault"}
		for name := range s.Overrides {
			result[s.Name] = append(result[s.Name], name)
		}
	}
	return result
}

func TestRequiredCoverage(t *testing.T) {
	inventory, err := Discover(t.Context(), "..", command.Runner{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Build(Catalog(), inventory, Selection{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"sidecar-auto":     {"trafficpolicy", "gateway", "securitypolicy", "epe", "clienttrust"},
		"ambient-auto":     {"trafficpolicy", "gateway", "securitypolicy", "epe"},
		"sidecar-iptables": {"trafficpolicy"},
		"ambient-iptables": {"trafficpolicy"},
	}
	if len(plan.Include) != len(want) {
		t.Fatalf("groups=%d", len(plan.Include))
	}
	counts := map[string]int{}
	clusters := map[string]bool{}
	invocations := 0
	for _, group := range plan.Include {
		if clusters[group.Cluster] {
			t.Fatal("environments share a cluster")
		}
		clusters[group.Cluster] = true
		var suites []string
		for _, invocation := range group.Invocations {
			invocations++
			suites = append(suites, invocation.Suite)
			for _, test := range invocation.Tests {
				counts[invocation.Suite+"/"+test]++
			}
		}
		if !reflect.DeepEqual(suites, want[group.ID]) {
			t.Fatalf("%s: %v", group.ID, suites)
		}
		if slices.Contains(group.Fixtures, "clienttrust") != (group.ID == "sidecar-auto") {
			t.Fatal("clienttrust fixture scheduled unnecessarily")
		}
	}
	if invocations != 11 {
		t.Fatalf("invocations=%d, want 11", invocations)
	}
	for test, want := range map[string]int{
		"trafficpolicy/TestControlPlaneConfigDebug":      1,
		"trafficpolicy/TestSandboxTrafficPolicyProtocol": 4,
		"epe/TestEPEServiceAccountCanWatchItsInputs":     1,
		"epe/TestPodIdentityReachesEPE":                  2,
		"clienttrust/TestClientTrustHTTPS":               1,
	} {
		if counts[test] != want {
			t.Errorf("%s scheduled %d times, want %d", test, counts[test], want)
		}
	}
	again, err := Build(Catalog(), inventory, Selection{})
	if err != nil || !reflect.DeepEqual(plan, again) {
		t.Fatal("plan is not deterministic", err)
	}
}

func TestSelectionAndManualCoverage(t *testing.T) {
	for _, tc := range []struct {
		name       string
		selection  Selection
		wantGroups int
		wantError  string
	}{
		{"ambient", Selection{Profile: "ambient"}, 2, ""},
		{"iptables", Selection{Backend: "iptables"}, 2, ""},
		{"clienttrust", Selection{Suites: []string{"clienttrust"}}, 1, ""},
		{"opt-in", Selection{Suites: []string{"agentgateway"}}, 2, ""},
		{"outside-coverage", Selection{Suites: []string{"clienttrust"}, Backend: "iptables"}, 0, "no tests"},
		{"manual-backend", Selection{Suites: []string{"clienttrust"}, Profile: "sidecar", Backend: "iptables", Force: true}, 1, ""},
		{"unsupported-profile", Selection{Suites: []string{"clienttrust"}, Profile: "ambient", Backend: "auto", Force: true}, 0, "no tests"},
		{"incomplete-force", Selection{Force: true}, 0, "force requires"},
		{"missing-test", Selection{Tests: "^TestRenamed$"}, 0, "no tests"},
		{"unknown-suite", Selection{Suites: []string{"typo"}}, 0, "unknown suite"},
		{"duplicate-suite", Selection{Suites: []string{"epe", "epe"}}, 0, "duplicate selected"},
		{"unknown-profile", Selection{Profile: "typo"}, 0, "unknown profile"},
		{"unknown-backend", Selection{Backend: "typo"}, 0, "unknown backend"},
		{"invalid-regexp", Selection{Tests: "["}, 0, "test filter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := Build(Catalog(), catalogInventory(), tc.selection)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("error=%v", err)
				}
				return
			}
			if err != nil || len(plan.Include) != tc.wantGroups {
				t.Fatalf("plan=%+v error=%v", plan, err)
			}
			if tc.name == "iptables" {
				for _, group := range plan.Include {
					if len(group.Invocations) != 1 || group.Invocations[0].Suite != "trafficpolicy" {
						t.Fatal(group)
					}
				}
			}
		})
	}
}

func TestInvalidCoverageFailsBeforeExecution(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]Suite, map[string][]string) []Suite
	}{
		{"renamed-test", func(c []Suite, i map[string][]string) []Suite { i["epe"] = []string{"TestRenamed"}; return c }},
		{"unregistered-suite", func(c []Suite, i map[string][]string) []Suite { i["newfeature"] = []string{"TestFeature"}; return c }},
		{"missing-suite", func(c []Suite, i map[string][]string) []Suite { delete(i, "clienttrust"); return c }},
		{"duplicate-suite", func(c []Suite, _ map[string][]string) []Suite { return append(c, c[0]) }},
		{"duplicate-test", func(c []Suite, i map[string][]string) []Suite {
			i["clienttrust"] = []string{"TestX", "TestX"}
			return c
		}},
		{"duplicate-backend", func(c []Suite, _ map[string][]string) []Suite {
			c[0].Coverage.Backends = []string{"auto", "auto"}
			return c
		}},
		{"empty-profiles", func(c []Suite, _ map[string][]string) []Suite { c[0].Coverage.Profiles = []string{}; return c }},
		{"invalid-override", func(c []Suite, _ map[string][]string) []Suite {
			c[0].Overrides["TestDefault"] = Coverage{Backends: []string{"bad"}}
			return c
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inventory := catalogInventory()
			if _, err := Build(tc.change(Catalog(), inventory), inventory, Selection{}); err == nil {
				t.Fatal("invalid coverage accepted")
			}
		})
	}
}

func TestNewTestsInheritSuiteCoverage(t *testing.T) {
	inventory := catalogInventory()
	inventory["trafficpolicy"] = append(inventory["trafficpolicy"], "TestNewPolicy")
	plan, err := Build(Catalog(), inventory, Selection{Tests: "^TestNewPolicy$"})
	if err != nil || len(plan.Include) != 4 {
		t.Fatalf("plan=%+v error=%v", plan, err)
	}
	for _, group := range plan.Include {
		if len(group.Invocations) != 1 || !reflect.DeepEqual(group.Invocations[0].Tests, []string{"TestNewPolicy"}) {
			t.Fatal(group)
		}
	}
}

// Keep discovery independent of TestMain, even with live mode inherited.
func TestDiscoveryDoesNotRunLiveSetup(t *testing.T) {
	t.Setenv("AGENTIO_E2E", "1")
	t.Setenv("AGENTIO_E2E_AGENTIOD_IMAGE", "")
	inventory, err := Discover(context.Background(), "..", command.Runner{})
	if err != nil || len(inventory) != len(Catalog()) {
		t.Fatalf("inventory=%v error=%v", inventory, err)
	}
}
