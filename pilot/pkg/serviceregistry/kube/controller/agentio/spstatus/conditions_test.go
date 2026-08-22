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
	"strings"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/test/util/assert"
)

func profileGen(gen int64, existing ...metav1.Condition) *agentsv1alpha1.SecurityProfile {
	return &agentsv1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "sp", Generation: gen},
		Status:     agentsv1alpha1.SecurityProfileStatus{Conditions: existing},
	}
}

func condOf(t *testing.T, st agentsv1alpha1.SecurityProfileStatus, typ string) metav1.Condition {
	t.Helper()
	for _, c := range st.Conditions {
		if c.Type == typ {
			return c
		}
	}
	t.Fatalf("condition %q missing from %+v", typ, st.Conditions)
	return metav1.Condition{}
}

// All three conditions must always be present: server-side apply prunes any
// condition we owned previously but stop declaring.
func TestBuildStatusAlwaysEmitsAllThreeConditions(t *testing.T) {
	cases := []struct {
		name     string
		specErrs []SpecError
		refErrs  []RefError
	}{
		{name: "all clean"},
		{name: "spec error only", specErrs: []SpecError{{Field: "f", Reason: ReasonInvalidRegex, Message: "m"}}},
		{name: "ref error only", refErrs: []RefError{{Field: "f", Reason: ReasonSecretNotFound, Message: "m"}}},
		{
			name:     "both",
			specErrs: []SpecError{{Field: "f", Reason: ReasonInvalidCEL, Message: "m"}},
			refErrs:  []RefError{{Field: "f", Reason: ReasonSecretNotFound, Message: "m"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := BuildStatus(profileGen(7), tc.specErrs, tc.refErrs)
			assert.Equal(t, len(st.Conditions), 3)
			for _, typ := range []string{
				agentsv1alpha1.SecurityProfileConditionAccepted,
				ConditionResolvedRefs,
				agentsv1alpha1.SecurityProfileConditionProgrammed,
			} {
				c := condOf(t, st, typ)
				assert.Equal(t, c.ObservedGeneration, int64(7))
				if c.Reason == "" {
					t.Errorf("condition %q has empty Reason; metav1.Condition requires it", typ)
				}
				if c.Message == "" {
					t.Errorf("condition %q has empty Message", typ)
				}
			}
		})
	}
}

func TestBuildStatusObservedGeneration(t *testing.T) {
	st := BuildStatus(profileGen(42), nil, nil)
	assert.Equal(t, st.ObservedGeneration, int64(42))
}

func TestBuildStatusConditionValues(t *testing.T) {
	cases := []struct {
		name          string
		specErrs      []SpecError
		refErrs       []RefError
		wantAccepted  metav1.ConditionStatus
		wantResolved  metav1.ConditionStatus
		wantProgram   metav1.ConditionStatus
		wantAcceptRsn string
		wantProgRsn   string
	}{
		{
			name:          "all clean",
			wantAccepted:  metav1.ConditionTrue,
			wantResolved:  metav1.ConditionTrue,
			wantProgram:   metav1.ConditionTrue,
			wantAcceptRsn: ReasonAccepted,
			wantProgRsn:   ReasonProgrammed,
		},
		{
			name:          "spec invalid drags Programmed down",
			specErrs:      []SpecError{{Field: "spec.rules[0]", Reason: ReasonInvalidRegex, Message: "bad regex"}},
			wantAccepted:  metav1.ConditionFalse,
			wantResolved:  metav1.ConditionTrue,
			wantProgram:   metav1.ConditionFalse,
			wantAcceptRsn: ReasonInvalidRegex,
			wantProgRsn:   ReasonNotAccepted,
		},
		{
			// Deliberate: ResolvedRefs carries reference problems on its own so
			// the RestrictedSecretsScope default does not contaminate Programmed.
			name:          "unresolved refs do NOT drag Programmed down",
			refErrs:       []RefError{{Field: "spec.rules[0]", Reason: ReasonSecretNotFound, Message: "no secret"}},
			wantAccepted:  metav1.ConditionTrue,
			wantResolved:  metav1.ConditionFalse,
			wantProgram:   metav1.ConditionTrue,
			wantAcceptRsn: ReasonAccepted,
			wantProgRsn:   ReasonProgrammed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := BuildStatus(profileGen(1), tc.specErrs, tc.refErrs)
			assert.Equal(t, condOf(t, st, agentsv1alpha1.SecurityProfileConditionAccepted).Status, tc.wantAccepted)
			assert.Equal(t, condOf(t, st, ConditionResolvedRefs).Status, tc.wantResolved)
			assert.Equal(t, condOf(t, st, agentsv1alpha1.SecurityProfileConditionProgrammed).Status, tc.wantProgram)
			assert.Equal(t, condOf(t, st, agentsv1alpha1.SecurityProfileConditionAccepted).Reason, tc.wantAcceptRsn)
			assert.Equal(t, condOf(t, st, agentsv1alpha1.SecurityProfileConditionProgrammed).Reason, tc.wantProgRsn)
		})
	}
}

// The first error's Field must reach the message so a user can locate it.
func TestBuildStatusMessageCitesField(t *testing.T) {
	st := BuildStatus(profileGen(1),
		[]SpecError{{Field: "spec.rules[3].match[0].paths[1].value", Reason: ReasonInvalidRegex, Message: "unbalanced paren"}},
		nil)
	msg := condOf(t, st, agentsv1alpha1.SecurityProfileConditionAccepted).Message
	assert.Equal(t, strings.Contains(msg, "spec.rules[3].match[0].paths[1].value"), true)
	assert.Equal(t, strings.Contains(msg, "unbalanced paren"), true)
}

// LastTransitionTime is preserved while the status value is unchanged and
// refreshed when it flips. BuildStatus carries the live timestamp forward only
// when the live condition of the same type has a matching Status.
func TestBuildStatusPreservesLastTransitionTime(t *testing.T) {
	old := metav1.NewTime(time.Now().Add(-time.Hour).Truncate(time.Second))
	existing := []metav1.Condition{
		{
			Type:               agentsv1alpha1.SecurityProfileConditionAccepted,
			Status:             metav1.ConditionTrue,
			Reason:             ReasonAccepted,
			Message:            "Rule chain compiled",
			ObservedGeneration: 1,
			LastTransitionTime: old,
		},
	}

	// Same generation, same outcome, same message -> timestamp preserved.
	same := BuildStatus(profileGen(1, existing...), nil, nil)
	assert.Equal(t, condOf(t, same, agentsv1alpha1.SecurityProfileConditionAccepted).LastTransitionTime, old)

	// Flipping to False must refresh the timestamp.
	flipped := BuildStatus(profileGen(1, existing...),
		[]SpecError{{Field: "f", Reason: ReasonInvalidRegex, Message: "m"}}, nil)
	got := condOf(t, flipped, agentsv1alpha1.SecurityProfileConditionAccepted).LastTransitionTime
	if !got.After(old.Time) {
		t.Errorf("LastTransitionTime must advance when Status flips; old=%v got=%v", old, got)
	}
}

// A condition written by a different fieldManager must never appear in the
// output: declaring it in our SSA apply body would seize ownership of it.
func TestBuildStatusDropsForeignConditions(t *testing.T) {
	owned := BuildStatus(profileGen(1), nil, nil)
	foreign := metav1.Condition{
		Type:               "SomeOtherController",
		Status:             metav1.ConditionTrue,
		Reason:             "External",
		Message:            "written by someone else",
		ObservedGeneration: 1,
		LastTransitionTime: metav1.Now(),
	}
	existing := append([]metav1.Condition{foreign}, owned.Conditions...)

	st := BuildStatus(profileGen(1, existing...), nil, nil)

	assert.Equal(t, len(st.Conditions), 3)
	for _, c := range st.Conditions {
		if c.Type == "SomeOtherController" {
			t.Errorf("foreign condition %q leaked into the output", c.Type)
		}
	}
}

// BuildStatus must never mutate the live object it reads from: that slice
// belongs to the shared informer cache.
func TestBuildStatusDoesNotMutateInput(t *testing.T) {
	owned := BuildStatus(profileGen(1), nil, nil)
	// Seed the live conditions in an order that differs from the emitted one.
	existing := []metav1.Condition{owned.Conditions[2], owned.Conditions[1], owned.Conditions[0]}
	sp := profileGen(1, existing...)

	before := make([]metav1.Condition, len(sp.Status.Conditions))
	for i := range sp.Status.Conditions {
		before[i] = *sp.Status.Conditions[i].DeepCopy()
	}

	BuildStatus(sp, nil, nil)

	assert.Equal(t, len(sp.Status.Conditions), len(before))
	for i := range before {
		assert.Equal(t, sp.Status.Conditions[i], before[i])
	}
}

// Conditions must come out in a stable order so the SSA patch body is
// byte-identical across reconciles when nothing changed.
func TestBuildStatusConditionOrderIsStable(t *testing.T) {
	a := BuildStatus(profileGen(1), nil, nil)
	b := BuildStatus(profileGen(1), nil, nil)
	for i := range a.Conditions {
		assert.Equal(t, a.Conditions[i].Type, b.Conditions[i].Type)
	}
	assert.Equal(t, a.Conditions[0].Type, agentsv1alpha1.SecurityProfileConditionAccepted)
	assert.Equal(t, a.Conditions[1].Type, agentsv1alpha1.SecurityProfileConditionProgrammed)
	assert.Equal(t, a.Conditions[2].Type, ConditionResolvedRefs)
}
