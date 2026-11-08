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

import "testing"

func TestSnapshotVersionIsStable(t *testing.T) {
	c := scaleCompiler(t, 500, scalePolicies)
	waitSynced(t, c)
	first, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		next, err := c.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if next.Version() != first.Version() {
			t.Fatalf("iteration %d: version drifted %s -> %s", i, first.Version(), next.Version())
		}
		if next.Len() != first.Len() {
			t.Fatalf("iteration %d: length drifted %d -> %d", i, first.Len(), next.Len())
		}
	}
}
