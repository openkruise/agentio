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
	"errors"
	"testing"
	"time"

	"istio.io/istio/extensions/epe/pkg/policy/securityprofile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
)

func newTestProfile(name, namespace string, matchLabels map[string]string) *v1alpha1.SecurityProfile {
	return &v1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{
				MatchLabels: matchLabels,
			},
		},
	}
}

func newTestGlobalProfile(name string, matchLabels map[string]string) *v1alpha1.GlobalSecurityProfile {
	return &v1alpha1.GlobalSecurityProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: v1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{
				MatchLabels: matchLabels,
			},
		},
	}
}

func TestProfileSetAndGet(t *testing.T) {
	store := MakeFakeStore()

	nn := types.NamespacedName{Name: "test-profile", Namespace: "default"}
	profile := newTestProfile("test-profile", "default", map[string]string{"app": "test"})

	store.ProfileSet(profile)

	got, ok := store.ProfileGet(nn)
	if !ok {
		t.Fatal("expected to find profile, but got not ok")
	}
	if got.Meta.Name != "test-profile" {
		t.Errorf("expected profile name 'test-profile', got %q", got.Meta.Name)
	}

	list := store.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 profile in list, got %d", len(list))
	}
}

// TestMatches drives label- and namespace-based selection through one table:
// each case stores a single profile with the given matchLabels and asserts how
// many profiles a pod with the given namespace/labels selects.
func TestMatches(t *testing.T) {
	tests := []struct {
		name          string
		profileLabels map[string]string
		ns            string
		podLabels     map[string]string
		want          int
	}{
		{
			name:          "matching labels and namespace",
			profileLabels: map[string]string{"app": "test"},
			ns:            "default",
			podLabels:     map[string]string{"app": "test"},
			want:          1,
		},
		{
			name:          "non-matching labels",
			profileLabels: map[string]string{"app": "test"},
			ns:            "default",
			podLabels:     map[string]string{"app": "other"},
			want:          0,
		},
		{
			name:          "wrong namespace",
			profileLabels: map[string]string{"app": "test"},
			ns:            "other-ns",
			podLabels:     map[string]string{"app": "test"},
			want:          0, // namespace-scoped profiles never cross namespaces
		},
		{
			name:          "all selector labels present",
			profileLabels: map[string]string{"app": "test", "env": "prod"},
			ns:            "default",
			podLabels:     map[string]string{"app": "test", "env": "prod"},
			want:          1,
		},
		{
			name:          "partial labels do not match",
			profileLabels: map[string]string{"app": "test", "env": "prod"},
			ns:            "default",
			podLabels:     map[string]string{"app": "test", "env": "dev"},
			want:          0,
		},
		{
			name:          "extra pod labels still match",
			profileLabels: map[string]string{"app": "test", "env": "prod"},
			ns:            "default",
			podLabels:     map[string]string{"app": "test", "env": "prod", "extra": "label"},
			want:          1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := MakeFakeStore()
			store.ProfileSet(newTestProfile("test-profile", "default", tt.profileLabels))

			matched := store.Matches("", tt.ns, tt.podLabels)
			if len(matched) != tt.want {
				t.Fatalf("expected %d profiles, got %d", tt.want, len(matched))
			}
		})
	}
}

func TestMatches_TieBreakOnName(t *testing.T) {
	// When CreationTimestamps are equal (common in unit tests and inside the
	// same reconcile second in production), ordering must remain
	// deterministic — name ascending — to keep downstream rule evaluation
	// reproducible. Run the build a few times to make a regression to
	// non-stable sort visible.
	for attempt := range 10 {
		store := MakeFakeStore()
		ts := metav1.NewTime(time.Now())
		names := []string{"charlie", "alpha", "bravo", "delta"}
		for _, n := range names {
			p := newTestProfile(n, "default", map[string]string{"app": "ai-agent"})
			p.CreationTimestamp = ts
			store.ProfileSet(p)
		}

		matched := store.Matches("", "default", map[string]string{"app": "ai-agent"})
		if len(matched) != 4 {
			t.Fatalf("attempt %d: expected 4 profiles, got %d", attempt, len(matched))
		}
		want := []string{"alpha", "bravo", "charlie", "delta"}
		for i, w := range want {
			if matched[i].Meta.Name != w {
				t.Fatalf("attempt %d: position %d: expected %q, got %q (full order: %v)",
					attempt, i, w, matched[i].Meta.Name, profileNames(matched))
			}
		}
	}
}

func TestMatches_PriorityOrdering(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		profiles []*v1alpha1.SecurityProfile
		want     []string
	}{
		{
			// No priority set on either profile: creation time alone orders
			// them (earlier first), regardless of insertion order or name.
			name: "no priority orders by creation time",
			profiles: func() []*v1alpha1.SecurityProfile {
				p1 := newTestProfile("beta-profile", "default", map[string]string{"app": "test"})
				p1.CreationTimestamp = metav1.NewTime(now)
				p2 := newTestProfile("alpha-profile", "default", map[string]string{"app": "test"})
				p2.CreationTimestamp = metav1.NewTime(now.Add(time.Second))
				return []*v1alpha1.SecurityProfile{p1, p2}
			}(),
			want: []string{"beta-profile", "alpha-profile"},
		},
		{
			name: "lower priority value comes first",
			profiles: func() []*v1alpha1.SecurityProfile {
				p1 := newTestProfile("high-pri", "default", map[string]string{"app": "test"})
				p1.Spec.Priority = ptr.To[int32](10)
				p1.CreationTimestamp = metav1.NewTime(now)
				p2 := newTestProfile("low-pri", "default", map[string]string{"app": "test"})
				p2.Spec.Priority = ptr.To[int32](1)
				p2.CreationTimestamp = metav1.NewTime(now.Add(time.Second))
				return []*v1alpha1.SecurityProfile{p1, p2}
			}(),
			want: []string{"low-pri", "high-pri"},
		},
		{
			name: "equal priority falls back to creation time",
			profiles: func() []*v1alpha1.SecurityProfile {
				p1 := newTestProfile("newer", "default", map[string]string{"app": "test"})
				p1.Spec.Priority = ptr.To[int32](5)
				p1.CreationTimestamp = metav1.NewTime(now.Add(time.Second))
				p2 := newTestProfile("older", "default", map[string]string{"app": "test"})
				p2.Spec.Priority = ptr.To[int32](5)
				p2.CreationTimestamp = metav1.NewTime(now)
				return []*v1alpha1.SecurityProfile{p1, p2}
			}(),
			want: []string{"older", "newer"},
		},
		{
			name: "equal priority and timestamp falls back to name",
			profiles: func() []*v1alpha1.SecurityProfile {
				ts := metav1.NewTime(now)
				p1 := newTestProfile("zebra", "default", map[string]string{"app": "test"})
				p1.Spec.Priority = ptr.To[int32](5)
				p1.CreationTimestamp = ts
				p2 := newTestProfile("apple", "default", map[string]string{"app": "test"})
				p2.Spec.Priority = ptr.To[int32](5)
				p2.CreationTimestamp = ts
				return []*v1alpha1.SecurityProfile{p1, p2}
			}(),
			want: []string{"apple", "zebra"},
		},
		{
			// An explicit priority of 0 (the minimum permitted by the CRD's
			// +kubebuilder:validation:Minimum=0 marker) must sort ahead of a
			// profile that omits Priority and thus defaults to 1000.
			name: "explicit zero priority sorts before default",
			profiles: func() []*v1alpha1.SecurityProfile {
				ts := metav1.NewTime(now)
				p1 := newTestProfile("default-pri", "default", map[string]string{"app": "test"})
				p1.CreationTimestamp = ts
				p2 := newTestProfile("override", "default", map[string]string{"app": "test"})
				p2.Spec.Priority = ptr.To[int32](0)
				p2.CreationTimestamp = ts
				return []*v1alpha1.SecurityProfile{p1, p2}
			}(),
			want: []string{"override", "default-pri"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := MakeFakeStore()
			for _, p := range tt.profiles {
				store.ProfileSet(p)
			}
			matched := store.Matches("", "default", map[string]string{"app": "test"})
			if len(matched) != len(tt.want) {
				t.Fatalf("expected %d profiles, got %d", len(tt.want), len(matched))
			}
			got := profileNames(matched)
			for i, w := range tt.want {
				if got[i] != w {
					t.Fatalf("position %d: expected %q, got %q (full order: %v)", i, w, got[i], got)
				}
			}
		})
	}
}

func profileNames(profiles []*securityprofile.Profile) []string {
	out := make([]string, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, p.Meta.Name)
	}
	return out
}

func TestGlobalProfileSetGet(t *testing.T) {
	store := MakeFakeStore()

	gsp := newTestGlobalProfile("g1", map[string]string{"app": "test"})
	store.GlobalProfileSet(gsp)

	// Cluster-scoped profiles are keyed with an empty namespace.
	nn := types.NamespacedName{Name: "g1"}
	got, ok := store.ProfileGet(nn)
	if !ok {
		t.Fatal("expected to find global profile, got not ok")
	}
	if got.Meta.Name != "g1" || got.Meta.Namespace != "" {
		t.Errorf("unexpected meta: name=%q namespace=%q", got.Meta.Name, got.Meta.Namespace)
	}
}

// TestMatches_GlobalMatchesAllNamespaces verifies that a
// cluster-scoped GlobalSecurityProfile matches pods in any namespace, whereas
// a namespace-scoped SecurityProfile only matches its own namespace.
func TestMatches_GlobalMatchesAllNamespaces(t *testing.T) {
	store := MakeFakeStore()

	store.GlobalProfileSet(newTestGlobalProfile("g1", map[string]string{"app": "test"}))
	store.ProfileSet(newTestProfile("ns-profile", "ns-a", map[string]string{"app": "test"}))

	// Pod in ns-a: matched by both the global and the namespace profile.
	matchedA := store.Matches("", "ns-a", map[string]string{"app": "test"})
	if got := profileNames(matchedA); len(got) != 2 {
		t.Fatalf("ns-a: expected 2 profiles, got %v", got)
	}

	// Pod in ns-b: matched by the global profile only.
	matchedB := store.Matches("", "ns-b", map[string]string{"app": "test"})
	if got := profileNames(matchedB); len(got) != 1 || got[0] != "g1" {
		t.Fatalf("ns-b: expected [g1], got %v", got)
	}

	// Non-matching labels match nothing, even for the global profile.
	if got := store.Matches("", "ns-b", map[string]string{"app": "other"}); len(got) != 0 {
		t.Fatalf("expected 0 profiles for non-matching labels, got %d", len(got))
	}
}

// TestMatches_GlobalAndNamespaceInterleaveByPriority verifies
// that global and namespace-scoped profiles are ordered together by the shared
// comparator (priority, then creation time, then name, then namespace) rather
// than by scope.
func TestMatches_GlobalAndNamespaceInterleaveByPriority(t *testing.T) {
	store := MakeFakeStore()

	g := newTestGlobalProfile("global-mid", map[string]string{"app": "test"})
	g.Spec.Priority = ptr.To[int32](5)
	store.GlobalProfileSet(g)

	nsHigh := newTestProfile("ns-high", "ns-a", map[string]string{"app": "test"})
	nsHigh.Spec.Priority = ptr.To[int32](1)
	store.ProfileSet(nsHigh)

	nsLow := newTestProfile("ns-low", "ns-a", map[string]string{"app": "test"})
	nsLow.Spec.Priority = ptr.To[int32](10)
	store.ProfileSet(nsLow)

	matched := store.Matches("", "ns-a", map[string]string{"app": "test"})
	want := []string{"ns-high", "global-mid", "ns-low"}
	got := profileNames(matched)
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("position %d: expected %q, got %q (full: %v)", i, w, got[i], got)
		}
	}
}

func TestProfileSet_InvalidSelectorIsSkipped(t *testing.T) {
	store := MakeFakeStore()

	bad := &v1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "bad", Namespace: "default"},
		Spec: v1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{
				// "!" is not a valid label key.
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "!",
					Operator: metav1.LabelSelectorOpExists,
				}},
			},
		},
	}
	store.ProfileSet(bad)

	if _, ok := store.ProfileGet(types.NamespacedName{Name: "bad", Namespace: "default"}); ok {
		t.Fatal("expected invalid-selector profile to be skipped on initial Set, but it was stored")
	}
	if got := store.Matches("", "default", map[string]string{"app": "ai-agent"}); len(got) != 0 {
		t.Fatalf("expected 0 matched profiles, got %d", len(got))
	}
}

func TestProfileSet_InvalidSelectorOnUpdateRetainsLastKnownGood(t *testing.T) {
	// A malformed update must not turn an enforced SecurityProfile into an
	// implicit delete. The last compiled profile remains effective until a
	// valid replacement or a real source deletion arrives.
	store := MakeFakeStore()
	nn := types.NamespacedName{Name: "p", Namespace: "default"}

	good := newTestProfile("p", "default", map[string]string{"app": "ai-agent"})
	store.ProfileSet(good)
	if _, ok := store.ProfileGet(nn); !ok {
		t.Fatal("precondition: expected good profile in store")
	}

	bad := &v1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"},
		Spec: v1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "!",
					Operator: metav1.LabelSelectorOpExists,
				}},
			},
		},
	}
	store.ProfileSet(bad)

	got, ok := store.ProfileGet(nn)
	if !ok {
		t.Fatal("expected last-known-good profile to survive invalid update")
	}
	if got.Meta.Version != good.ResourceVersion {
		t.Fatalf("effective version = %q, want original %q", got.Meta.Version, good.ResourceVersion)
	}
	if matched := store.Matches("", "default", map[string]string{"app": "ai-agent"}); len(matched) != 1 {
		t.Fatalf("expected last-known-good profile to keep matching, got %d", len(matched))
	}
}

func TestProfileSet_NilIsNoop(t *testing.T) {
	store := MakeFakeStore()
	store.ProfileSet(nil)
	if len(store.List()) != 0 {
		t.Fatalf("expected nil ProfileSet to be a noop, got %d profiles", len(store.List()))
	}
}

// TestApplyBatch_AddUpdateDelete exercises the krt-driven write path directly
// with pre-compiled profiles, without a kube fixture.
func TestApplyBatch_AddUpdateDelete(t *testing.T) {
	s := NewStore()

	add := newTestProfile("p", "default", map[string]string{"app": "x"})
	compiledAdd, err := securityprofile.NewProfile(add, &add.Spec)
	if err != nil {
		t.Fatal(err)
	}
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: compiledAdd, Event: controllers.EventAdd},
	})
	if matched := s.Matches("", "default", map[string]string{"app": "x"}); len(matched) != 1 {
		t.Fatalf("after add: expected 1 match, got %d", len(matched))
	}

	updated := newTestProfile("p", "default", map[string]string{"app": "y"})
	compiledUpdated, err := securityprofile.NewProfile(updated, &updated.Spec)
	if err != nil {
		t.Fatal(err)
	}
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: compiledAdd, New: compiledUpdated, Event: controllers.EventUpdate},
	})
	if matched := s.Matches("", "default", map[string]string{"app": "y"}); len(matched) != 1 {
		t.Fatalf("after update: expected 1 match for app=y, got %d", len(matched))
	}
	if matched := s.Matches("", "default", map[string]string{"app": "x"}); len(matched) != 0 {
		t.Fatalf("after update: stale app=x entry still matches")
	}

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: compiledUpdated, Event: controllers.EventDelete},
	})
	if got := len(s.List()); got != 0 {
		t.Fatalf("after delete: expected 0 profiles, got %d", got)
	}
}

func TestApplyBatch_InvalidUpdateRetainsLastKnownGood(t *testing.T) {
	s := NewStore()

	good := newTestProfile("p", "default", map[string]string{"app": "x"})
	compiled, err := securityprofile.NewProfile(good, &good.Spec)
	if err != nil {
		t.Fatal(err)
	}
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: compiled, Event: controllers.EventAdd},
	})

	bad := good.DeepCopy()
	bad.ResourceVersion = "invalid-update"
	invalid := securityprofile.InvalidProfile(bad, &bad.Spec, errors.New("invalid selector"))
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: compiled, New: invalid, Event: controllers.EventUpdate},
	})

	matched := s.Matches("", "default", map[string]string{"app": "x"})
	if len(matched) != 1 {
		t.Fatalf("matched profiles = %d, want retained last-known-good profile", len(matched))
	}
	if matched[0].Meta.Version != good.ResourceVersion {
		t.Fatalf("effective version = %q, want %q", matched[0].Meta.Version, good.ResourceVersion)
	}
}
