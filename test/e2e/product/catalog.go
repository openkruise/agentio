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

// Package product declares and schedules Agentio product-test coverage. It
// keeps deployment dimensions out of the reusable Kubernetes test framework.
package product

// Coverage lists the deployment dimensions required for a suite or test.
type Coverage struct {
	Profiles []string
	Backends []string // Omitted means auto; test overrides inherit suite coverage.
}

// Suite declares product coverage, exact-name exceptions and fixture requirements.
type Suite struct {
	Name              string
	Coverage          Coverage
	Overrides         map[string]Coverage
	Fixtures          []string
	SupportedProfiles []string // Omitted means sidecar and ambient.
	GatewayDataplane  string   // Omitted means envoy.
	OptIn             bool
}

// Catalog is the single source of required coverage for local and CI runs.
// New top-level tests inherit their suite's coverage. Overrides name exact Go
// tests and are checked against the build-selected source files before setup.
func Catalog() []Suite {
	both := []string{"sidecar", "ambient"}
	once := Coverage{Profiles: []string{"sidecar"}, Backends: []string{"auto"}}
	return []Suite{
		{Name: "trafficpolicy", Coverage: Coverage{Profiles: both, Backends: []string{"auto", "iptables"}},
			Overrides: map[string]Coverage{"TestControlPlaneConfigDebug": once}},
		{Name: "gateway", Coverage: Coverage{Profiles: both}, Fixtures: []string{"extproc", "forwardproxy"}},
		{Name: "securitypolicy", Coverage: Coverage{Profiles: both}},
		{Name: "epe", Coverage: Coverage{Profiles: both},
			Overrides: map[string]Coverage{"TestEPEServiceAccountCanWatchItsInputs": once}},
		{Name: "clienttrust", Coverage: once, SupportedProfiles: []string{"sidecar"}, Fixtures: []string{"clienttrust"}},
		{Name: "agentgateway", Coverage: Coverage{Profiles: both}, GatewayDataplane: "agentgateway", Fixtures: []string{"extproc"}, OptIn: true},
	}
}
