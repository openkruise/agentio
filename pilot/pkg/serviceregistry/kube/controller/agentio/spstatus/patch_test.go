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

package spstatus

import (
	"encoding/json"
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/pkg/test/util/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func decodePatch(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("patch is not valid JSON: %v\n%s", err, string(b))
	}
	return m
}

func TestBuildPatchEnvelope(t *testing.T) {
	st := BuildStatus(profileGen(3), nil, nil)
	b, err := BuildPatch("sp-a", st)
	assert.NoError(t, err)

	m := decodePatch(t, b)
	assert.Equal(t, m["apiVersion"], "agents.kruise.io/v1alpha1")
	assert.Equal(t, m["kind"], "SecurityProfile")

	meta, ok := m["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata missing: %s", string(b))
	}
	assert.Equal(t, meta["name"], "sp-a")

	// Namespace is passed to ApplyStatus separately and must not appear here.
	if _, found := meta["namespace"]; found {
		t.Errorf("metadata.namespace must not be in the apply body: %s", string(b))
	}
	// Anything outside status would claim ownership of fields we do not own.
	for k := range m {
		switch k {
		case "apiVersion", "kind", "metadata", "status":
		default:
			t.Errorf("unexpected top-level key %q in apply body: %s", k, string(b))
		}
	}
}

// Server-side apply prunes fields this fieldManager owned but stopped
// declaring, so every reconcile must carry all three conditions.
func TestBuildPatchCarriesAllThreeConditions(t *testing.T) {
	st := BuildStatus(profileGen(3), nil, nil)
	b, err := BuildPatch("sp-a", st)
	assert.NoError(t, err)

	m := decodePatch(t, b)
	status, ok := m["status"].(map[string]any)
	if !ok {
		t.Fatalf("status missing: %s", string(b))
	}
	conds, ok := status["conditions"].([]any)
	if !ok {
		t.Fatalf("status.conditions missing: %s", string(b))
	}
	assert.Equal(t, len(conds), 3)

	got := map[string]bool{}
	for _, raw := range conds {
		c := raw.(map[string]any)
		typ, _ := c["type"].(string)
		got[typ] = true
		// The CRD requires these on every condition; omitting one makes the
		// apiserver reject the whole patch.
		for _, required := range []string{"type", "status", "reason", "lastTransitionTime"} {
			if _, found := c[required]; !found {
				t.Errorf("condition %q is missing required field %q: %s", typ, required, string(b))
			}
		}
	}
	for _, typ := range []string{
		agentsv1alpha1.SecurityProfileConditionAccepted,
		ConditionResolvedRefs,
		agentsv1alpha1.SecurityProfileConditionProgrammed,
	} {
		if !got[typ] {
			t.Errorf("condition %q missing from patch: %s", typ, string(b))
		}
	}
}

func TestBuildPatchObservedGeneration(t *testing.T) {
	st := BuildStatus(profileGen(11), nil, nil)
	b, err := BuildPatch("sp-a", st)
	assert.NoError(t, err)

	status := decodePatch(t, b)["status"].(map[string]any)
	// JSON numbers decode to float64.
	assert.Equal[any](t, status["observedGeneration"], float64(11))
}

// observedGeneration 0 must still be emitted: omitempty would drop it and the
// apiserver would then prune the field we previously owned.
func TestBuildPatchEmitsZeroObservedGeneration(t *testing.T) {
	st := BuildStatus(profileGen(0), nil, nil)
	b, err := BuildPatch("sp-a", st)
	assert.NoError(t, err)

	status := decodePatch(t, b)["status"].(map[string]any)
	v, found := status["observedGeneration"]
	if !found {
		t.Fatalf("observedGeneration must be emitted even when 0: %s", string(b))
	}
	assert.Equal[any](t, v, float64(0))
}

// Two identical inputs must produce byte-identical bodies, otherwise every
// reconcile looks like a change to the apiserver.
func TestBuildPatchIsDeterministic(t *testing.T) {
	existing := []metav1.Condition{
		{
			Type:               agentsv1alpha1.SecurityProfileConditionAccepted,
			Status:             metav1.ConditionTrue,
			Reason:             ReasonAccepted,
			Message:            "Rule chain compiled",
			ObservedGeneration: 1,
			LastTransitionTime: metav1.NewTime(metav1.Now().Rfc3339Copy().Time),
		},
	}
	a, err := BuildPatch("sp-a", BuildStatus(profileGen(1, existing...), nil, nil))
	assert.NoError(t, err)
	b, err := BuildPatch("sp-a", BuildStatus(profileGen(1, existing...), nil, nil))
	assert.NoError(t, err)

	// The Accepted condition keeps its timestamp; the other two are generated
	// fresh each call, so compare only the Accepted entry.
	condA := findCondJSON(t, a, agentsv1alpha1.SecurityProfileConditionAccepted)
	condB := findCondJSON(t, b, agentsv1alpha1.SecurityProfileConditionAccepted)
	assert.Equal(t, condA, condB)
}

func findCondJSON(t *testing.T, patch []byte, typ string) map[string]any {
	t.Helper()
	status := decodePatch(t, patch)["status"].(map[string]any)
	for _, raw := range status["conditions"].([]any) {
		c := raw.(map[string]any)
		if c["type"] == typ {
			return c
		}
	}
	t.Fatalf("condition %q not found", typ)
	return nil
}
