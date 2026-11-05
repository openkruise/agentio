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
	"encoding/json"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube/controllers"
)

func inlineProfile(name, ns, version string) *securityprofile.Profile {
	p, err := securityprofile.NewSandboxProfile(&metav1.PartialObjectMetadata{
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
// selector matches: a different workload name in the same namespace must see
// nothing, and an empty workload name must skip the inline lookup entirely.
func TestStoreInlineProfiles(t *testing.T) {
	s := NewStore(0)

	p := inlineProfile("sbx-1", "sandboxes", "1")
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventAdd, New: p},
	})

	got := s.ProfilesFor(subject.Subject{Workload: subject.Workload{Name: "sbx-1", Namespace: "sandboxes"}})
	if len(got) != 1 || got[0].Meta.Version != "1" {
		t.Fatalf("Matches(sbx-1) = %+v, want the installed inline profile", got)
	}
	if got := s.ProfilesFor(
		subject.Subject{Workload: subject.Workload{Name: "sbx-2", Namespace: "sandboxes"}},
	); len(
		got,
	) != 0 {
		t.Fatalf("Matches(sbx-2) = %+v, want no match for another identity", got)
	}
	if got := s.ProfilesFor(
		subject.Subject{Workload: subject.Workload{Name: "sbx-1", Namespace: "other"}},
	); len(
		got,
	) != 0 {
		t.Fatalf("Matches(other/sbx-1) = %+v, want no match across namespaces", got)
	}
	if got := s.ProfilesFor(subject.Subject{Workload: subject.Workload{Namespace: "sandboxes"}}); len(got) != 0 {
		t.Fatalf("Matches with empty workload name = %+v, want the inline lookup skipped", got)
	}

	// Inline profiles appear on the listing surface alongside CRD profiles.
	if got := s.List(); len(got) != 1 || got[0].Meta.Match != securityprofile.MatchSandbox {
		t.Fatalf("List() = %+v, want the inline profile listed", got)
	}

	// An update replaces the profile in place (new resourceVersion).
	p2 := inlineProfile("sbx-1", "sandboxes", "2")
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventUpdate, Old: p, New: p2},
	})
	got = s.ProfilesFor(subject.Subject{Workload: subject.Workload{Name: "sbx-1", Namespace: "sandboxes"}})
	if len(got) != 1 || got[0].Meta.Version != "2" {
		t.Fatalf("after update = %+v, want version 2", got)
	}

	// A delete removes it.
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventDelete, Old: p2},
	})
	if got := s.ProfilesFor(
		subject.Subject{Workload: subject.Workload{Name: "sbx-1", Namespace: "sandboxes"}},
	); len(
		got,
	) != 0 {
		t.Fatalf("after delete = %+v, want no profile", got)
	}
}

// A Sandbox and a SecurityProfile can share a namespace and name; both the
// joined collection (via the source-prefixed ResourceName) and the snapshot
// (via source routing) must keep the two apart, with the inline profile
// evaluating after the selector match.
func TestStoreInlineAndCRDProfilesShareIdentity(t *testing.T) {
	s := NewStore(0)

	crdObj := newTestProfile("shared", "sandboxes", map[string]string{"app": "x"})
	crd, err := securityprofile.NewProfile(crdObj, &crdObj.Spec)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	inline := inlineProfile("shared", "sandboxes", "1")
	if key := sandboxProfileKey("sandboxes", "shared"); key.Name != inline.ResourceName() {
		t.Fatalf("source key %q differs from compiled resource name %q", key.Name, inline.ResourceName())
	}

	if crd.ResourceName() == inline.ResourceName() {
		t.Fatalf("krt keys collide: %q", crd.ResourceName())
	}

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventAdd, New: crd},
		{Event: controllers.EventAdd, New: inline},
	})

	got := s.ProfilesFor(
		subject.Subject{
			Workload: subject.Workload{Name: "shared", Namespace: "sandboxes", Labels: map[string]string{"app": "x"}},
		},
	)
	if len(got) != 2 {
		t.Fatalf("Matches = %d profiles, want the CRD match plus the inline profile", len(got))
	}
	if got[0].Meta.Match != securityprofile.MatchSelector || got[1].Meta.Match != securityprofile.MatchSandbox {
		t.Fatalf("order = [%q, %q], want the selector profile before the inline profile",
			got[0].Meta.Match, got[1].Meta.Match)
	}

	// Deleting the inline profile must not disturb the CRD profile.
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventDelete, Old: inline},
	})
	if got := s.ProfilesFor(
		subject.Subject{
			Workload: subject.Workload{Name: "shared", Namespace: "sandboxes", Labels: map[string]string{"app": "x"}},
		},
	); len(got) != 1 ||
		got[0].Meta.Match != securityprofile.MatchSelector {
		t.Fatalf("after inline delete = %+v, want only the CRD profile", got)
	}
}

// TestStoreInlineBatchReusesLabelIndex pins the write-path optimization: only
// only selector profiles feed the label index, so a batch of inline events must carry the
// previous index forward. Rebuilding it is the expensive part of a write
// (~9ms and 12MB at 10k profiles) and Sandbox churn is the high-frequency
// event source, so this must not regress into a full rebuild.
func TestStoreInlineBatchReusesLabelIndex(t *testing.T) {
	s := NewStore(0)

	crdObj := newTestProfile("guard", "sandboxes", map[string]string{"app": "x"})
	crd, err := securityprofile.NewProfile(crdObj, &crdObj.Spec)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventAdd, New: crd}})
	indexed := s.snapshot.Load().selectorIndex

	inline := inlineProfile("sbx-1", "sandboxes", "1")
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventAdd, New: inline}})
	if got := s.snapshot.Load().selectorIndex; !sameIndexMap(got, indexed) {
		t.Error("an inline-only batch rebuilt the label index")
	}
	// A delete for a CRD profile that was never installed is equally inert.
	absent := newTestProfile("absent", "sandboxes", map[string]string{"app": "y"})
	absentCompiled, err := securityprofile.NewProfile(absent, &absent.Spec)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventDelete, Old: absentCompiled}})
	if got := s.snapshot.Load().selectorIndex; !sameIndexMap(got, indexed) {
		t.Error("a delete for an uninstalled profile rebuilt the label index")
	}

	// The reused index must still be the right answer, and the inline profile
	// must be visible through it.
	got := s.ProfilesFor(
		subject.Subject{
			Workload: subject.Workload{Name: "sbx-1", Namespace: "sandboxes", Labels: map[string]string{"app": "x"}},
		},
	)
	if len(got) != 2 || got[0].Meta.Match != securityprofile.MatchSelector ||
		got[1].Meta.Match != securityprofile.MatchSandbox {
		t.Fatalf("Matches = %+v, want the CRD match plus the inline profile", got)
	}

	// A CRD event does rebuild it.
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventDelete, Old: crd}})
	if got := s.snapshot.Load().selectorIndex; sameIndexMap(got, indexed) {
		t.Error("a CRD delete reused a stale label index")
	}
}

// sameIndexMap reports whether both values are the same map, not merely equal
// ones: the point is that no rebuild happened.
func sameIndexMap(a, b map[string]profileIndex) bool {
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

// TestInlineProfileInvalidVersionUsesLastKnownGood pins the inline half of
// the projection contract, which now matches the CRD profile's: a version
// that fails to compile or project is rejected. On first create nothing
// installs — the Sandbox author's rules take effect only as published — and
// on an update the store keeps serving the last-known-good version instead
// of silently removing rules that were enforcing.
func TestInlineProfileInvalidVersionUsesLastKnownGood(t *testing.T) {
	regs, err := filter.Build(tokentransform.NewDefinition(tokentransform.Deps{}))
	if err != nil {
		t.Fatal(err)
	}
	store := MakeFakeStore(regs...)

	badCel := "this is not CEL ((("
	badRules, err := json.Marshal([]v1alpha1.SecurityRule{{
		Name:  "sign",
		Match: []v1alpha1.RuleMatch{{Domains: []string{"api.example.com"}}},
		Actions: v1alpha1.SecurityRuleActions{TokenTransformation: &v1alpha1.TokenTransformationAction{
			Type: v1alpha1.TokenTransformationTypeApiKey,
			CredentialRef: v1alpha1.CredentialRef{CredentialProvider: &v1alpha1.CredentialProviderRef{
				Name:       "provider",
				Parameters: map[string]v1alpha1.ValueSource{"tenant": {Cel: &badCel}},
			}},
			ApiKey: &v1alpha1.ApiKeyConfig{ValueTemplate: "Bearer {{ .Token }}"},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	goodRules := `[{"name":"deny-exfil","match":[{"domains":["evil.example.com"]}],"actions":{"block":{"statusCode":403}}}]`
	sandbox := func(version, rules string) *metav1.PartialObjectMetadata {
		return &metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "sbx-1",
				Namespace:       "sandboxes",
				ResourceVersion: version,
				Annotations:     map[string]string{securityprofile.AnnotationSecurityRules: rules},
			},
		}
	}

	// A bad first version installs nothing.
	store.SandboxProfileSet(sandbox("1", string(badRules)))
	if got := store.ProfilesFor(
		subject.Subject{Workload: subject.Workload{Name: "sbx-1", Namespace: "sandboxes"}},
	); len(
		got,
	) != 0 {
		t.Fatalf("Matches = %+v, want nothing for a bad first version", got)
	}

	// A good version installs.
	store.SandboxProfileSet(sandbox("2", goodRules))
	got := store.ProfilesFor(subject.Subject{Workload: subject.Workload{Name: "sbx-1", Namespace: "sandboxes"}})
	if len(got) != 1 || got[0].Rules[0].Name != "deny-exfil" {
		t.Fatalf("Matches = %+v, want the good version installed", got)
	}

	// A bad update retains the last-known-good version.
	store.SandboxProfileSet(sandbox("3", string(badRules)))
	got = store.ProfilesFor(subject.Subject{Workload: subject.Workload{Name: "sbx-1", Namespace: "sandboxes"}})
	if len(got) != 1 || got[0].Meta.Version != "2" {
		t.Fatalf("Matches = %+v, want version 2 retained after a bad update", got)
	}

	// A fixed update replaces it.
	store.SandboxProfileSet(sandbox("4", goodRules))
	got = store.ProfilesFor(subject.Subject{Workload: subject.Workload{Name: "sbx-1", Namespace: "sandboxes"}})
	if len(got) != 1 || got[0].Meta.Version != "4" {
		t.Fatalf("Matches = %+v, want the fixed version 4 installed", got)
	}

	// Reassigning a pooled object's delivery identity cannot inherit old rules.
	reassigned := sandbox("5", string(badRules))
	reassigned.Labels = map[string]string{v1alpha1.LabelSandboxID: "new-delivery"}
	store.SandboxProfileSet(reassigned)
	if got := store.ProfilesFor(
		subject.Subject{Workload: subject.Workload{Name: "sbx-1", Namespace: "sandboxes"}},
	); len(
		got,
	) != 0 {
		t.Fatalf("new delivery inherited the previous identity's rules: %+v", got)
	}
}
