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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/extensions/epe/pkg/policy/securityprofile"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
)

func inlineProfile(name, ns, version string) *securityprofile.Profile {
	p, err := securityprofile.NewInlineProfile(&metav1.PartialObjectMetadata{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Annotations: map[string]string{
				securityprofile.AnnotationSecurityRules: `[{"name":"r","match":[{"domains":["*"]}],"actions":{"block":{}}}]`,
			},
			ResourceVersion: version,
		},
	})
	if err != nil || p == nil {
		panic("test fixture failed to compile")
	}
	return p
}

// Inline profiles are installed and removed by the same event batches as
// CRD profiles, and the lookup is an exact identity match appended after
// selector matches: a different pod name in the same namespace must see
// nothing, and an empty pod name must skip the inline lookup entirely.
func TestStoreInlineProfiles(t *testing.T) {
	s := NewStore()

	p := inlineProfile("sbx-1", "sandboxes", "1")
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventAdd, New: p},
	})

	got := s.Matches("sbx-1", "sandboxes", nil)
	if len(got) != 1 || got[0].Meta.Version != "1" {
		t.Fatalf("Matches(sbx-1) = %+v, want the installed inline profile", got)
	}
	if got := s.Matches("sbx-2", "sandboxes", nil); len(got) != 0 {
		t.Fatalf("Matches(sbx-2) = %+v, want no match for another identity", got)
	}
	if got := s.Matches("sbx-1", "other", nil); len(got) != 0 {
		t.Fatalf("Matches(other/sbx-1) = %+v, want no match across namespaces", got)
	}
	if got := s.Matches("", "sandboxes", nil); len(got) != 0 {
		t.Fatalf("Matches with empty pod name = %+v, want the inline lookup skipped", got)
	}

	// Inline profiles appear on the listing surface alongside CRD profiles.
	if got := s.List(); len(got) != 1 || got[0].Meta.Source != securityprofile.SourceInline {
		t.Fatalf("List() = %+v, want the inline profile listed", got)
	}

	// An update replaces the profile in place (new resourceVersion).
	p2 := inlineProfile("sbx-1", "sandboxes", "2")
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventUpdate, Old: p, New: p2},
	})
	got = s.Matches("sbx-1", "sandboxes", nil)
	if len(got) != 1 || got[0].Meta.Version != "2" {
		t.Fatalf("after update = %+v, want version 2", got)
	}

	// A delete removes it.
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventDelete, Old: p2},
	})
	if got := s.Matches("sbx-1", "sandboxes", nil); len(got) != 0 {
		t.Fatalf("after delete = %+v, want no profile", got)
	}
}

// A Sandbox and a SecurityProfile can share a namespace and name; both the
// joined collection (via the source-prefixed ResourceName) and the snapshot
// (via source routing) must keep the two apart, with the inline profile
// evaluating after the selector match.
func TestStoreInlineAndCRDProfilesShareIdentity(t *testing.T) {
	s := NewStore()

	crdObj := newTestProfile("shared", "sandboxes", map[string]string{"app": "x"})
	crd, err := securityprofile.NewProfile(crdObj, &crdObj.Spec)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	inline := inlineProfile("shared", "sandboxes", "1")

	if crd.ResourceName() == inline.ResourceName() {
		t.Fatalf("krt keys collide: %q", crd.ResourceName())
	}

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventAdd, New: crd},
		{Event: controllers.EventAdd, New: inline},
	})

	got := s.Matches("shared", "sandboxes", map[string]string{"app": "x"})
	if len(got) != 2 {
		t.Fatalf("Matches = %d profiles, want the CRD match plus the inline profile", len(got))
	}
	if got[0].Meta.Source != "" || got[1].Meta.Source != securityprofile.SourceInline {
		t.Fatalf("order = [%q, %q], want the selector profile before the inline profile",
			got[0].Meta.Source, got[1].Meta.Source)
	}

	// Deleting the inline profile must not disturb the CRD profile.
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventDelete, Old: inline},
	})
	if got := s.Matches("shared", "sandboxes", map[string]string{"app": "x"}); len(got) != 1 || got[0].Meta.Source != "" {
		t.Fatalf("after inline delete = %+v, want only the CRD profile", got)
	}
}
