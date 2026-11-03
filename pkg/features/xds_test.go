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

package features

import (
	"testing"

	"istio.io/istio/pkg/test"
)

func TestXDSCPUAdmissionBudget(t *testing.T) {
	for _, tc := range []struct {
		name        string
		budget      string
		runtimeCPUs int
		configured  float64
		wantCores   float64
		wantRate    float64
	}{
		{"half core", "500m", 2, 0, .5, 125},
		{"one core", "1", 2, 0, 1, 250},
		{"two cores", "2", 4, 0, 2, 500},
		{"four cores", "4", 8, 0, 4, 1000},
		{"default cap", "8", 8, 0, 8, 1000},
		{"runtime bound", "4", 1, 0, 1, 250},
		{"runtime fallback", "", 2, 0, 2, 500},
		{"explicit rate", "500m", 2, 2345, .5, 2345},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cores, err := xdsCPUCores(tc.budget, tc.runtimeCPUs)
			if err != nil || cores != tc.wantCores {
				t.Fatalf("CPU cores = %v, error = %v; want %v", cores, err, tc.wantCores)
			}
			test.SetForTest(t, &XDSCPUCores, cores)
			if got := effectiveRequestRateLimit(tc.configured); got != tc.wantRate {
				t.Fatalf("rate = %v, want %v", got, tc.wantRate)
			}
		})
	}
}

func TestXDSCPUAdmissionRejectsInvalidBudget(t *testing.T) {
	for _, budget := range []string{"0", "-500m", "invalid", "NaN"} {
		t.Run(budget, func(t *testing.T) {
			_, err := xdsCPUCores(budget, 2)
			if err == nil {
				t.Fatal("invalid CPU budget accepted")
			}
			test.SetForTest(t, &xdsCPUBudgetErr, err)
			if err := validateXDS(); err == nil {
				t.Fatal("startup accepted invalid CPU budget")
			}
		})
	}
}
