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

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube/controllers"
)

func TestResolveSecurityProfileReferences(t *testing.T) {
	s := MakeFakeStore()
	s.ProfileSet(newTestProfile("a", "ns", map[string]string{"app": "different"}))
	s.ProfileSet(newTestProfile("b", "ns", map[string]string{"app": "different"}))
	s.GlobalProfileSet(newTestGlobalProfile("g", nil))
	subj := subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod", SecurityProfileReferences: []string{"namespaced/ns/b", "global/g", "namespaced/ns/a"}}}
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
	subj := subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "pod", SecurityProfileReferences: []string{"namespaced/ns/admin"}}}
	got, err := s.ResolveProfiles(t.Context(), subj)
	if err != nil || len(got) != 2 || got[0].Meta.Name != "admin" || got[1] != sandbox {
		t.Fatalf("sandbox must follow administrator references: %v %v", got, err)
	}
}
