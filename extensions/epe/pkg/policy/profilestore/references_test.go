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

package profilestore

import (
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube/controllers"
)

func TestDeletedProfileGraceOnlyServesExplicitReferences(t *testing.T) {
	for _, global := range []bool{false, true} {
		t.Run(map[bool]string{false: "namespaced", true: "global"}[global], func(t *testing.T) {
			s := MakeFakeStore()
			s.store = NewStore(time.Minute)
			name := "namespaced/ns/a"
			if global {
				s.GlobalProfileSet(newTestGlobalProfile("a", nil))
				name = "global/a"
			} else {
				s.ProfileSet(newTestProfile("a", "ns", nil))
			}
			w := subject.Subject{
				Workload: subject.Workload{Namespace: "ns", Name: "pod", SecurityProfileReferences: []string{name}},
			}
			before, err := s.ResolveProfiles(t.Context(), w)
			if err != nil || len(before) != 1 {
				t.Fatalf("initial binding: %v %v", before, err)
			}
			deletion := []krt.Event[securityprofile.Profile]{{Event: controllers.EventDelete, Old: before[0]}}
			s.applyBatch(deletion)
			expires := s.snapshot.Load().retired[name].expires
			for range 3 {
				got, err := s.ResolveProfiles(t.Context(), w)
				if err != nil || len(got) != 1 || got[0] != before[0] {
					t.Fatalf("retired binding: %v %v", got, err)
				}
			}
			s.applyBatch(deletion)
			if s.snapshot.Load().retired[name].expires != expires {
				t.Fatal("duplicate delete extended grace")
			}
			if len(s.List()) != 0 || len(s.ProfilesFor(w)) != 0 {
				t.Fatal("retired profile remained selectable")
			}
			w.Workload.SecurityProfileReferences = []string{}
			if got, err := s.ResolveProfiles(t.Context(), w); err != nil || len(got) != 0 {
				t.Fatalf("withdrawn binding: %v %v", got, err)
			}
			w.Workload.SecurityProfileReferences = []string{"unknown"}
			if _, err := s.ResolveProfiles(t.Context(), w); err == nil {
				t.Fatal("unknown reference accepted")
			}
			// Reads enforce the deadline even if timer cleanup has not run yet.
			old := s.snapshot.Load()
			next := reuseSnapshot(old, old.installed)
			next.retired = map[string]retiredProfile{name: {profile: before[0], expires: time.Now().Add(-time.Second)}}
			s.snapshot.Store(next)
			w.Workload.SecurityProfileReferences = []string{name}
			if _, err := s.ResolveProfiles(t.Context(), w); err == nil {
				t.Fatal("expired reference accepted")
			}
		})
	}
}

func TestDeletedProfileGraceRecreationAndCleanup(t *testing.T) {
	s := MakeFakeStore()
	s.store = NewStore(time.Hour)
	s.ProfileSet(newTestProfile("a", "ns", nil))
	old := s.List()[0]
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventDelete, Old: old}})
	deadline := s.snapshot.Load().retired["namespaced/ns/a"].expires
	replacement := newTestProfile("a", "ns", nil)
	replacement.ResourceVersion = "2"
	s.ProfileSet(replacement)
	if len(s.snapshot.Load().retired) != 0 {
		t.Fatal("recreation retained deleted body")
	}
	current := s.List()[0]
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventDelete, Old: current}})
	s.expireRetiredProfile("namespaced/ns/a", deadline)
	if len(s.snapshot.Load().retired) != 1 {
		t.Fatal("old timer removed a newer deletion")
	}
	s.expireRetiredProfile("namespaced/ns/a", s.snapshot.Load().retired["namespaced/ns/a"].expires)
	if len(s.snapshot.Load().retired) != 0 {
		t.Fatal("expired body was not reclaimed")
	}
}

func TestDeletedProfileGraceTimerReclaimsBody(t *testing.T) {
	s := MakeFakeStore()
	s.store = NewStore(20 * time.Millisecond)
	s.ProfileSet(newTestProfile("a", "ns", nil))
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventDelete, Old: s.List()[0]}})
	deadline := time.Now().Add(5 * time.Second)
	for len(s.snapshot.Load().retired) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("timer did not reclaim retired body")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDeletedProfileGraceSnapshotsRemainImmutable(t *testing.T) {
	s := MakeFakeStore()
	s.store = NewStore(time.Minute)
	s.ProfileSet(newTestProfile("a", "ns", nil))
	old := s.List()[0]
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventDelete, Old: old}})
	before := s.snapshot.Load()
	sandbox := inlineProfile("pod", "ns", "1")
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventAdd, New: sandbox}})
	after := s.snapshot.Load()
	replacement := newTestProfile("a", "ns", nil)
	replacement.ResourceVersion = "2"
	s.ProfileSet(replacement)
	workload := subject.Workload{SecurityProfileReferences: []string{"namespaced/ns/a"}}
	for _, snapshot := range []*profileSnapshot{before, after} {
		got, err := boundProfilesFor(snapshot, workload)
		if err != nil || len(got) != 1 || got[0] != old {
			t.Fatalf("retained snapshot changed after recreation: %v %v", got, err)
		}
	}
	got, err := boundProfilesFor(s.snapshot.Load(), workload)
	if err != nil || len(got) != 1 || got[0].Meta.Version != "2" {
		t.Fatalf("current snapshot did not install replacement: %v %v", got, err)
	}
}

func TestSandboxDeletionIgnoresAdministratorGrace(t *testing.T) {
	s := NewStore(time.Minute)
	p := inlineProfile("pod", "ns", "1")
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventAdd, New: p}})
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventDelete, Old: p}})
	if len(s.List()) != 0 || len(s.snapshot.Load().retired) != 0 {
		t.Fatal("Sandbox deletion retained policy")
	}
}

func TestResolveSecurityProfileReferences(t *testing.T) {
	s := MakeFakeStore()
	s.ProfileSet(newTestProfile("a", "ns", map[string]string{"app": "different"}))
	s.ProfileSet(newTestProfile("b", "ns", map[string]string{"app": "different"}))
	s.GlobalProfileSet(newTestGlobalProfile("g", nil))
	subj := subject.Subject{
		Workload: subject.Workload{
			Namespace:                 "ns",
			Name:                      "pod",
			SecurityProfileReferences: []string{"namespaced/ns/b", "global/g", "namespaced/ns/a"},
		},
	}
	got, err := s.ResolveProfiles(t.Context(), subj)
	if err != nil || len(got) != 3 || got[0].Meta.Name != "b" || got[1].Meta.Name != "g" || got[2].Meta.Name != "a" {
		t.Fatalf("ordered references: %v %v", got, err)
	}
	subj.Workload.SecurityProfileReferences = []string{}
	got, err = s.ResolveProfiles(t.Context(), subj)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty binding fell back to selectors: %v %v", got, err)
	}
	for _, refs := range [][]string{{"missing"}, {""}, {"global/g", "global/g"}} {
		subj.Workload.SecurityProfileReferences = refs
		if _, err := s.ResolveProfiles(t.Context(), subj); err == nil {
			t.Fatalf("invalid binding accepted: %v", refs)
		}
	}
	subj.Workload.SecurityProfileReferences = []string{"namespaced/ns/a"}
	profile := newTestProfile("a", "ns", map[string]string{"app": "changed"})
	profile.ResourceVersion = "2"
	s.ProfileSet(profile)
	got, err = s.ResolveProfiles(t.Context(), subj)
	if err != nil || len(got) != 1 || got[0].Meta.Version != "2" {
		t.Fatalf("updated referenced body: %v %v", got, err)
	}
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventDelete, Old: got[0]}})
	if _, err := s.ResolveProfiles(t.Context(), subj); err == nil {
		t.Fatal("deleted reference did not fail closed")
	}
}

func TestReferencedProfilesRetainSandboxOrdering(t *testing.T) {
	s := MakeFakeStore()
	s.ProfileSet(newTestProfile("admin", "ns", map[string]string{"app": "different"}))
	sandbox := inlineProfile("pod", "ns", "1")
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventAdd, New: sandbox}})
	subj := subject.Subject{
		Workload: subject.Workload{
			Namespace:                 "ns",
			Name:                      "pod",
			SecurityProfileReferences: []string{"namespaced/ns/admin"},
		},
	}
	got, err := s.ResolveProfiles(t.Context(), subj)
	if err != nil || len(got) != 2 || got[0].Meta.Name != "admin" || got[1] != sandbox {
		t.Fatalf("sandbox must follow administrator references: %v %v", got, err)
	}
}
