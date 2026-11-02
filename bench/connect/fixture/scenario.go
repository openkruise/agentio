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

package fixture

// Scenario describes an opt-in, assertion-based real Envoy stability test.
// Seconds controls churn duration; other cases complete finite verified transfers.
type Scenario struct {
	Name      string
	Kind      string
	Sandboxes int
	Flows     int
	Workers   int
	Seconds   int
	Upload    bool
}

// Scenarios deliberately use fixed profiles so a failure can be replayed verbatim.
func Scenarios(profile string) []Scenario {
	switch profile {
	case "smoke":
		return []Scenario{
			{Name: "active", Kind: "active", Sandboxes: 64, Flows: 4, Workers: 2},
			{Name: "upload", Kind: "active", Sandboxes: 64, Flows: 4, Workers: 2, Upload: true},
			{Name: "reload", Kind: "reload", Sandboxes: 64, Flows: 4, Workers: 2},
			{Name: "combined", Kind: "combined", Workers: 2},
			{Name: "churn", Kind: "churn", Sandboxes: 128, Flows: 2, Workers: 2, Seconds: 30},
		}
	case "scale":
		return []Scenario{
			{Name: "1000x4", Kind: "active", Sandboxes: 1000, Flows: 4, Workers: 2},
			{Name: "5000x2", Kind: "active", Sandboxes: 5000, Flows: 2, Workers: 4},
			{Name: "10000x1", Kind: "active", Sandboxes: 10000, Flows: 1, Workers: 8},
			{Name: "upload-1000x4", Kind: "active", Sandboxes: 1000, Flows: 4, Workers: 4, Upload: true},
			{Name: "shared-1024", Kind: "active", Sandboxes: 1, Flows: 1024, Workers: 4},
			{Name: "reload-1024", Kind: "reload", Sandboxes: 256, Flows: 4, Workers: 4},
			{Name: "combined", Kind: "combined", Workers: 4},
		}
	case "soak":
		return []Scenario{{Name: "churn-30m", Kind: "churn", Sandboxes: 512, Flows: 2, Workers: 4, Seconds: 1800}}
	default:
		return nil
	}
}
