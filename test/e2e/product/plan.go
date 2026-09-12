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
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Selection filters required coverage or explicitly requests a supported manual run.
type Selection struct {
	Suites  []string
	Profile string
	Backend string
	Tests   string // Regular expression over top-level Go test names.
	Force   bool   // Run selected tests regardless of required CI coverage.
}

// Invocation is one suite process with an exact list of top-level Go tests.
type Invocation struct {
	Suite   string   `json:"suite"`
	Package string   `json:"package"`
	Tests   []string `json:"tests"`
}

// Group collects suites that use the same deployment environment.
type Group struct {
	ID               string       `json:"id"`
	Profile          string       `json:"profile"`
	Backend          string       `json:"backend"`
	GatewayDataplane string       `json:"gatewayDataplane"`
	Cluster          string       `json:"cluster"`
	Fixtures         []string     `json:"fixtures"`
	Invocations      []Invocation `json:"invocations"`
}

// Plan also has the shape accepted by a GitHub Actions matrix.
type Plan struct {
	Include []Group `json:"include"`
}

// Build expands required coverage and validates it against the discovered tests.
func Build(catalog []Suite, inventory map[string][]string, selection Selection) (Plan, error) {
	if err := validateCatalog(catalog, inventory); err != nil {
		return Plan{}, err
	}
	selected, err := selection.suites(catalog)
	if err != nil {
		return Plan{}, err
	}
	filter, err := regexp.Compile(selection.Tests)
	if err != nil {
		return Plan{}, fmt.Errorf("test filter: %w", err)
	}
	groups := map[string]*Group{}
	matched := map[string]bool{}
	for _, suite := range catalog {
		if len(selected) > 0 && !selected[suite.Name] || len(selected) == 0 && suite.OptIn {
			continue
		}
		for _, candidate := range suiteGroups(suite, inventory[suite.Name], selection, filter) {
			group := groups[candidate.ID]
			if group == nil {
				copy := candidate
				groups[candidate.ID] = &copy
			} else {
				group.Invocations = append(group.Invocations, candidate.Invocations...)
				group.Fixtures = append(group.Fixtures, candidate.Fixtures...)
			}
			matched[suite.Name] = true
		}
	}
	for name := range selected {
		if !matched[name] {
			return Plan{}, fmt.Errorf("suite %s has no tests for this selection (use force for supported combinations outside required coverage)", name)
		}
	}
	if len(groups) == 0 {
		return Plan{}, fmt.Errorf("selection has no tests")
	}
	plan := Plan{}
	for _, group := range groups {
		sort.Strings(group.Fixtures)
		group.Fixtures = slices.Compact(group.Fixtures)
		plan.Include = append(plan.Include, *group)
	}
	sort.Slice(plan.Include, func(i, j int) bool { return plan.Include[i].ID < plan.Include[j].ID })
	return plan, nil
}

func (s Selection) suites(catalog []Suite) (map[string]bool, error) {
	if s.Profile != "" && !slices.Contains([]string{"sidecar", "ambient"}, s.Profile) {
		return nil, fmt.Errorf("unknown profile %q", s.Profile)
	}
	if s.Backend != "" && !slices.Contains([]string{"auto", "iptables"}, s.Backend) {
		return nil, fmt.Errorf("unknown backend %q", s.Backend)
	}
	if s.Force && (s.Profile == "" || s.Backend == "" || len(s.Suites) == 0) {
		return nil, fmt.Errorf("force requires explicit suites, profile and backend")
	}
	selected := map[string]bool{}
	for _, name := range s.Suites {
		if selected[name] {
			return nil, fmt.Errorf("duplicate selected suite %q", name)
		}
		if !slices.ContainsFunc(catalog, func(suite Suite) bool { return suite.Name == name }) {
			return nil, fmt.Errorf("unknown suite %q", name)
		}
		selected[name] = true
	}
	return selected, nil
}

func suiteGroups(suite Suite, inventory []string, selection Selection, filter *regexp.Regexp) []Group {
	var groups []Group
	for _, profile := range supportedProfiles(suite) {
		for _, backend := range []string{"auto", "iptables"} {
			if selection.Profile != "" && profile != selection.Profile || selection.Backend != "" && backend != selection.Backend {
				continue
			}
			tests := selectedTests(suite, inventory, profile, backend, selection.Force, filter)
			if len(tests) == 0 {
				continue
			}
			dataplane := suite.GatewayDataplane
			if dataplane == "" {
				dataplane = "envoy"
			}
			id := profile + "-" + backend
			if dataplane != "envoy" {
				id = dataplane + "-" + id
			}
			groups = append(groups, Group{
				ID: id, Profile: profile, Backend: backend, GatewayDataplane: dataplane, Cluster: "agentio-" + id + "-e2e",
				Fixtures:    append([]string{}, suite.Fixtures...),
				Invocations: []Invocation{{Suite: suite.Name, Package: "./suites/" + suite.Name, Tests: tests}},
			})
		}
	}
	return groups
}

func selectedTests(suite Suite, inventory []string, profile, backend string, force bool, filter *regexp.Regexp) []string {
	base := coverage(suite.Coverage, Coverage{Backends: []string{"auto"}})
	var tests []string
	for _, name := range inventory {
		wanted := coverage(suite.Overrides[name], base)
		if filter.MatchString(name) && (force || slices.Contains(wanted.Profiles, profile) && slices.Contains(wanted.Backends, backend)) {
			tests = append(tests, name)
		}
	}
	sort.Strings(tests)
	return tests
}

func coverage(override, base Coverage) Coverage {
	if override.Profiles == nil {
		override.Profiles = base.Profiles
	}
	if override.Backends == nil {
		override.Backends = base.Backends
	}
	return override
}

func supportedProfiles(s Suite) []string {
	if s.SupportedProfiles != nil {
		return s.SupportedProfiles
	}
	return []string{"sidecar", "ambient"}
}

func validateCatalog(catalog []Suite, inventory map[string][]string) error {
	known := map[string]bool{}
	for _, suite := range catalog {
		if !regexp.MustCompile(`^[a-z][a-z0-9]*$`).MatchString(suite.Name) || known[suite.Name] {
			return fmt.Errorf("invalid or duplicate suite %q", suite.Name)
		}
		known[suite.Name] = true
		if suite.GatewayDataplane != "" && suite.GatewayDataplane != "envoy" && suite.GatewayDataplane != "agentgateway" {
			return fmt.Errorf("suite %s has unknown gateway dataplane", suite.Name)
		}
		base := coverage(suite.Coverage, Coverage{Backends: []string{"auto"}})
		if err := validateCoverage(base, supportedProfiles(suite)); err != nil {
			return fmt.Errorf("suite %s: %w", suite.Name, err)
		}
		names := map[string]bool{}
		for _, name := range inventory[suite.Name] {
			if name == "TestMain" || !strings.HasPrefix(name, "Test") || names[name] {
				return fmt.Errorf("suite %s has invalid or duplicate test %q", suite.Name, name)
			}
			names[name] = true
		}
		if len(names) == 0 {
			return fmt.Errorf("suite %s has no discovered tests", suite.Name)
		}
		for name, override := range suite.Overrides {
			if !names[name] {
				return fmt.Errorf("suite %s override names missing test %s", suite.Name, name)
			}
			if err := validateCoverage(coverage(override, base), supportedProfiles(suite)); err != nil {
				return fmt.Errorf("suite %s test %s: %w", suite.Name, name, err)
			}
		}
	}
	for suite := range inventory {
		if !known[suite] {
			return fmt.Errorf("discovered suite %s has no coverage declaration", suite)
		}
	}
	return nil
}

func validateCoverage(c Coverage, supported []string) error {
	for _, dimension := range []struct {
		name            string
		values, allowed []string
	}{
		{"supported profiles", supported, []string{"sidecar", "ambient"}},
		{"profiles", c.Profiles, supported},
		{"backends", c.Backends, []string{"auto", "iptables"}},
	} {
		if len(dimension.values) == 0 {
			return fmt.Errorf("%s must not be empty", dimension.name)
		}
		seen := map[string]bool{}
		for _, value := range dimension.values {
			if seen[value] || !slices.Contains(dimension.allowed, value) {
				return fmt.Errorf("invalid or duplicate %s value %q", dimension.name, value)
			}
			seen[value] = true
		}
	}
	return nil
}
