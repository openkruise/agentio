// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package profilestore

import (
	"fmt"
	"reflect"
	"slices"
	"testing"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
)

func TestEligibleRequirements(t *testing.T) {
	seventeenValues := make([]string, 17)
	for i := range seventeenValues {
		seventeenValues[i] = fmt.Sprint(i)
	}
	sixteenValues := slices.Clone(seventeenValues[:16])
	slices.Sort(sixteenValues)

	tests := []struct {
		name     string
		selector metav1.LabelSelector
		want     []indexRequirement
	}{
		{
			name:     "match labels produces equality requirement",
			selector: metav1.LabelSelector{MatchLabels: map[string]string{"sandbox-id": "a"}},
			want:     []indexRequirement{{key: "sandbox-id", values: []string{"a"}}},
		},
		{
			name: "in values are sorted",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      "tenant",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"b", "a"},
			}}},
			want: []indexRequirement{{key: "tenant", values: []string{"a", "b"}}},
		},
		{
			name: "not in and exists are fallback only",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "tenant", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"a"}},
				{Key: "team", Operator: metav1.LabelSelectorOpExists},
			}},
			want: nil,
		},
		{
			name: "sixteen in values remain eligible",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      "tenant",
				Operator: metav1.LabelSelectorOpIn,
				Values:   sixteenValues,
			}}},
			want: []indexRequirement{{key: "tenant", values: sixteenValues}},
		},
		{
			name: "seventeen in values fall back",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      "tenant",
				Operator: metav1.LabelSelectorOpIn,
				Values:   seventeenValues,
			}}},
			want: nil,
		},
		{
			name:     "empty selector falls back",
			selector: metav1.LabelSelector{},
			want:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			profile := mustCompileIndexedProfile(t, "eligible", "default", tc.selector)
			if got := eligibleRequirements(profile.Selector); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("eligibleRequirements() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestBuildProfileIndexSelectsLeastPopulatedAnchor(t *testing.T) {
	profiles := []*securityprofile.Profile{
		mustCompileIndexedProfile(t, "first", "default", metav1.LabelSelector{MatchLabels: map[string]string{
			"app": "agent", "sandbox-id": "one",
		}}),
		mustCompileIndexedProfile(t, "middle", "default", metav1.LabelSelector{MatchLabels: map[string]string{
			"app": "agent", "sandbox-id": "two",
		}}),
		mustCompileIndexedProfile(t, "last", "default", metav1.LabelSelector{MatchLabels: map[string]string{
			"app": "agent", "sandbox-id": "three",
		}}),
	}
	securityprofile.SortProfiles(profiles)

	index := buildProfileIndex(profiles)
	if got := bucketProfileNames(index.buckets); !reflect.DeepEqual(got, map[labelBucket][]string{
		{key: "sandbox-id", value: "one"}:   {"first"},
		{key: "sandbox-id", value: "two"}:   {"middle"},
		{key: "sandbox-id", value: "three"}: {"last"},
	}) {
		t.Fatalf("buckets = %v, want unique sandbox-id buckets", got)
	}
	if len(index.fallback) != 0 {
		t.Fatalf("fallback = %v, want empty", profileNames(index.fallback))
	}

	matched := index.appendMatches(labels.Set{"app": "agent", "sandbox-id": "two"}, nil)
	if got := profileNames(matched); !slices.Equal(got, []string{"middle"}) {
		t.Fatalf("appendMatches() = %v, want [middle]", got)
	}
}

func TestBuildProfileIndexHandlesInAndFallbackSelectors(t *testing.T) {
	in := mustCompileIndexedProfile(t, "tenant-in", "default", metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "tenant",
			Operator: metav1.LabelSelectorOpIn,
			Values:   []string{"a", "b"},
		}},
	})
	exists := mustCompileIndexedProfile(t, "team-exists", "default", metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "team",
			Operator: metav1.LabelSelectorOpExists,
		}},
	})
	notIn := mustCompileIndexedProfile(t, "tenant-not-in", "default", metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "tenant",
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   []string{"blocked"},
		}},
	})
	all := mustCompileIndexedProfile(t, "all", "default", metav1.LabelSelector{})
	profiles := []*securityprofile.Profile{in, exists, notIn, all}
	securityprofile.SortProfiles(profiles)

	index := buildProfileIndex(profiles)
	if got := bucketProfileNames(index.buckets); !reflect.DeepEqual(got, map[labelBucket][]string{
		{key: "tenant", value: "a"}: {"tenant-in"},
		{key: "tenant", value: "b"}: {"tenant-in"},
	}) {
		t.Fatalf("buckets = %v, want tenant In buckets", got)
	}
	if got := profileNames(index.fallback); !slices.Equal(got, []string{"all", "team-exists", "tenant-not-in"}) {
		t.Fatalf("fallback = %v, want [all team-exists tenant-not-in]", got)
	}

	matched := index.appendMatches(labels.Set{"tenant": "b", "team": "core"}, nil)
	securityprofile.SortProfiles(matched)
	if got := profileNames(matched); !slices.Equal(got, []string{"all", "team-exists", "tenant-in", "tenant-not-in"}) {
		t.Fatalf("appendMatches() = %v, want every matching profile exactly once", got)
	}
}

func TestBuildProfileIndexRechecksCompleteSelector(t *testing.T) {
	profile := mustCompileIndexedProfile(t, "two-requirements", "default", metav1.LabelSelector{MatchLabels: map[string]string{
		"app": "agent", "sandbox-id": "pod-1",
	}})
	index := buildProfileIndex([]*securityprofile.Profile{profile})

	if got := index.appendMatches(labels.Set{"app": "other", "sandbox-id": "pod-1"}, nil); len(got) != 0 {
		t.Fatalf("appendMatches() = %v, want no match when a non-anchor requirement fails", profileNames(got))
	}
}

func TestBuildProfileIndexBreaksAnchorTiesDeterministically(t *testing.T) {
	tests := []struct {
		name       string
		selector   metav1.LabelSelector
		wantBucket labelBucket
	}{
		{
			name: "fewer values wins",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "app", Operator: metav1.LabelSelectorOpIn, Values: []string{"a", "b"}},
				{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"backend"}},
			}},
			wantBucket: labelBucket{key: "tier", value: "backend"},
		},
		{
			name:       "lexical key wins",
			selector:   metav1.LabelSelector{MatchLabels: map[string]string{"z-key": "value", "a-key": "value"}},
			wantBucket: labelBucket{key: "a-key", value: "value"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			profile := mustCompileIndexedProfile(t, "tie", "default", tc.selector)
			index := buildProfileIndex([]*securityprofile.Profile{profile})
			if _, found := index.buckets[tc.wantBucket]; !found {
				t.Fatalf("buckets = %v, want anchor bucket %#v", bucketProfileNames(index.buckets), tc.wantBucket)
			}
			if len(index.buckets) != 1 {
				t.Fatalf("bucket count = %d, want 1", len(index.buckets))
			}
		})
	}
}

func mustCompileIndexedProfile(
	t testing.TB,
	name, namespace string,
	selector metav1.LabelSelector,
) *securityprofile.Profile {
	t.Helper()
	profile := &v1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       v1alpha1.SecurityProfileSpec{Selector: selector},
	}
	compiled, err := securityprofile.NewProfile(profile, &profile.Spec)
	if err != nil {
		t.Fatalf("compile profile %q: %v", name, err)
	}
	return compiled
}

func bucketProfileNames(buckets map[labelBucket][]*securityprofile.Profile) map[labelBucket][]string {
	names := make(map[labelBucket][]string, len(buckets))
	for bucket, profiles := range buckets {
		names[bucket] = profileNames(profiles)
	}
	return names
}
