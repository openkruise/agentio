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
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube/controllers"
	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
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
// selector matches: a different pod name in the same namespace must see
// nothing, and an empty pod name must skip the inline lookup entirely.
func TestStoreInlineProfiles(t *testing.T) {
	s := NewStore()

	p := inlineProfile("sbx-1", "sandboxes", "1")
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventAdd, New: p},
	})

	got := s.ProfilesFor(inputs.Pod{Name: "sbx-1", Namespace: "sandboxes"})
	if len(got) != 1 || got[0].Meta.Version != "1" {
		t.Fatalf("Matches(sbx-1) = %+v, want the installed inline profile", got)
	}
	if got := s.ProfilesFor(inputs.Pod{Name: "sbx-2", Namespace: "sandboxes"}); len(got) != 0 {
		t.Fatalf("Matches(sbx-2) = %+v, want no match for another identity", got)
	}
	if got := s.ProfilesFor(inputs.Pod{Name: "sbx-1", Namespace: "other"}); len(got) != 0 {
		t.Fatalf("Matches(other/sbx-1) = %+v, want no match across namespaces", got)
	}
	if got := s.ProfilesFor(inputs.Pod{Namespace: "sandboxes"}); len(got) != 0 {
		t.Fatalf("Matches with empty pod name = %+v, want the inline lookup skipped", got)
	}

	// Inline profiles appear on the listing surface alongside CRD profiles.
	if got := s.List(); len(got) != 1 || got[0].Meta.Match != securityprofile.MatchPod {
		t.Fatalf("List() = %+v, want the inline profile listed", got)
	}

	// An update replaces the profile in place (new resourceVersion).
	p2 := inlineProfile("sbx-1", "sandboxes", "2")
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventUpdate, Old: p, New: p2},
	})
	got = s.ProfilesFor(inputs.Pod{Name: "sbx-1", Namespace: "sandboxes"})
	if len(got) != 1 || got[0].Meta.Version != "2" {
		t.Fatalf("after update = %+v, want version 2", got)
	}

	// A delete removes it.
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventDelete, Old: p2},
	})
	if got := s.ProfilesFor(inputs.Pod{Name: "sbx-1", Namespace: "sandboxes"}); len(got) != 0 {
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

	got := s.ProfilesFor(inputs.Pod{Name: "shared", Namespace: "sandboxes", Labels: map[string]string{"app": "x"}})
	if len(got) != 2 {
		t.Fatalf("Matches = %d profiles, want the CRD match plus the inline profile", len(got))
	}
	if got[0].Meta.Match != securityprofile.MatchSelector || got[1].Meta.Match != securityprofile.MatchPod {
		t.Fatalf("order = [%q, %q], want the selector profile before the inline profile",
			got[0].Meta.Match, got[1].Meta.Match)
	}

	// Deleting the inline profile must not disturb the CRD profile.
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventDelete, Old: inline},
	})
	if got := s.ProfilesFor(inputs.Pod{Name: "shared", Namespace: "sandboxes", Labels: map[string]string{"app": "x"}}); len(got) != 1 || got[0].Meta.Match != securityprofile.MatchSelector {
		t.Fatalf("after inline delete = %+v, want only the CRD profile", got)
	}
}

// TestStoreInlineBatchReusesLabelIndex pins the write-path optimization: only
// only selector profiles feed the label index, so a batch of inline events must carry the
// previous index forward. Rebuilding it is the expensive part of a write
// (~9ms and 12MB at 10k profiles) and Sandbox churn is the high-frequency
// event source, so this must not regress into a full rebuild.
func TestStoreInlineBatchReusesLabelIndex(t *testing.T) {
	s := NewStore()

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
	got := s.ProfilesFor(inputs.Pod{Name: "sbx-1", Namespace: "sandboxes", Labels: map[string]string{"app": "x"}})
	if len(got) != 2 || got[0].Meta.Match != securityprofile.MatchSelector || got[1].Meta.Match != securityprofile.MatchPod {
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

// sandboxPod is the caller identity a wait is keyed on: namespace and name
// only. The gate deliberately ignores propagated labels — the pod's claimed
// label is frozen at creation and never flips — so tests set up store state
// through seedUnknownSandbox, not labels.
func sandboxPod(name string) inputs.Pod {
	return inputs.Pod{Name: name, Namespace: "sandboxes"}
}

// seedUnknownSandbox installs the state an unclaimed pooled Sandbox has in the
// store: present (so the gate applies), Unknown (so a request must wait).
func seedUnknownSandbox(t *testing.T, s *store, name string) {
	t.Helper()
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventAdd, New: sandboxStateProfile(name, "1", securityprofile.SandboxPolicyUnknown)},
	})
}

func sandboxStateProfile(name, version string, state securityprofile.SandboxPolicyState) *securityprofile.Profile {
	return securityprofile.NewSandboxStateProfile(&metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: "sandboxes", ResourceVersion: version,
	}}, state)
}

func waitForWaiters(t *testing.T, s *store, total int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		got := s.waiters
		s.mu.Unlock()
		if got == total {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("waiters never reached %d", total)
}

func TestAwaitSnapshotWakesWithAtomicReadyProfile(t *testing.T) {
	s := NewStore(WithWaitLimits(4, 2))
	pod := inputs.Pod{Name: "sbx-1", Namespace: "sandboxes"}
	unknown := sandboxStateProfile("sbx-1", "1", securityprofile.SandboxPolicyUnknown)
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventAdd, New: unknown}})
	result := make(chan securityprofile.PolicySnapshot, 1)
	errCh := make(chan error, 1)
	go func() {
		snapshot, err := s.AwaitSnapshot(context.Background(), pod, time.Second)
		result <- snapshot
		errCh <- err
	}()
	waitForWaiters(t, s, 1)

	inline := inlineProfile("sbx-1", "sandboxes", "2")
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventUpdate, Old: unknown, New: inline}})

	if err := <-errCh; err != nil {
		t.Fatalf("AwaitSnapshot: %v", err)
	}
	snapshot := <-result
	if !snapshot.SandboxExists {
		t.Fatal("ready snapshot does not report the Sandbox as existing")
	}
	if snapshot.SandboxState != securityprofile.SandboxPolicyReady {
		t.Fatalf("state = %v, want Ready", snapshot.SandboxState)
	}
	if len(snapshot.Profiles) != 1 || snapshot.Profiles[0].Meta.Version != "2" {
		t.Fatalf("profiles = %+v, want ready version 2 from the same snapshot", snapshot.Profiles)
	}
	waitForWaiters(t, s, 0)
}

func TestAwaitSnapshotExistingUnknownSandboxWithoutPropagatedIdentityWaits(t *testing.T) {
	s := NewStore()
	pod := inputs.Pod{Name: "sbx-1", Namespace: "sandboxes"}
	unknown := sandboxStateProfile("sbx-1", "1", securityprofile.SandboxPolicyUnknown)
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventAdd, New: unknown}})

	result := make(chan securityprofile.PolicySnapshot, 1)
	go func() {
		snapshot, _ := s.AwaitSnapshot(context.Background(), pod, 25*time.Millisecond)
		result <- snapshot
	}()
	waitForWaiters(t, s, 1)
	snapshot := <-result
	if !snapshot.SandboxExists {
		t.Fatal("timeout snapshot does not report the Sandbox as existing")
	}
	if snapshot.SandboxState != securityprofile.SandboxPolicyUnknown {
		t.Fatalf("state = %v, want Unknown", snapshot.SandboxState)
	}
	waitForWaiters(t, s, 0)
}

func TestAwaitSnapshotOrdinaryPodReturnsImmediately(t *testing.T) {
	s := NewStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	snapshot, err := s.AwaitSnapshot(ctx, inputs.Pod{
		Name: "pod-1", Namespace: "default",
	}, time.Hour)
	if err != nil {
		t.Fatalf("AwaitSnapshot: %v", err)
	}
	if snapshot.SandboxExists {
		t.Fatal("ordinary Pod was reported as a Sandbox")
	}
	waitForWaiters(t, s, 0)
}

// A delete while a request waits is a resolution, not a countdown: the store
// stops knowing the caller, the request becomes an ordinary-Pod pass-through,
// and the waiter must return on that publish instead of holding until the
// deadline.
func TestAwaitSnapshotDeleteReleasesWaiterOnPublish(t *testing.T) {
	s := NewStore()
	unknown := sandboxStateProfile("sbx-1", "1", securityprofile.SandboxPolicyUnknown)
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventAdd, New: unknown}})

	result := make(chan securityprofile.PolicySnapshot, 1)
	go func() {
		snapshot, _ := s.AwaitSnapshot(context.Background(), sandboxPod("sbx-1"), time.Hour)
		result <- snapshot
	}()
	waitForWaiters(t, s, 1)

	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventDelete, Old: unknown}})

	select {
	case snapshot := <-result:
		if snapshot.SandboxExists {
			t.Fatal("deleted Sandbox still reported as existing")
		}
	case <-time.After(time.Second):
		t.Fatal("waiter held until the deadline after the Sandbox was deleted")
	}
	waitForWaiters(t, s, 0)
}

// The waiter path is entered only for a Sandbox the store has observed. A
// claimed label on a pod the store does not know must not schedule a waiter:
// the label is propagation-controlled metadata whose pod-side copy is frozen
// at creation, so a stale value must never be able to withhold traffic.
func TestAwaitSnapshotClaimedLabelWithoutStoreEntryDoesNotWait(t *testing.T) {
	s := NewStore(WithWaitLimits(4, 2))
	pod := inputs.Pod{Name: "sbx-1", Namespace: "sandboxes", Labels: map[string]string{
		v1alpha1.LabelSandboxIsClaimed: v1alpha1.True,
	}}

	done := make(chan securityprofile.PolicySnapshot, 1)
	go func() {
		snapshot, _ := s.AwaitSnapshot(context.Background(), pod, time.Hour)
		done <- snapshot
	}()
	select {
	case snapshot := <-done:
		if snapshot.SandboxExists {
			t.Fatal("store reported an existence it never observed")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("AwaitSnapshot waited on a propagated label instead of the store")
	}
	waitForWaiters(t, s, 0)
}

func TestAwaitSnapshotTimeoutAndCancellationReleaseSlots(t *testing.T) {
	s := NewStore(WithWaitLimits(1, 1))
	seedUnknownSandbox(t, s, "sbx-1")
	pod := sandboxPod("sbx-1")

	snapshot, err := s.AwaitSnapshot(context.Background(), pod, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("timeout: %v", err)
	}
	if snapshot.SandboxState != securityprofile.SandboxPolicyUnknown {
		t.Fatalf("timeout state = %v, want Unknown", snapshot.SandboxState)
	}
	waitForWaiters(t, s, 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := s.AwaitSnapshot(ctx, pod, time.Second)
		done <- err
	}()
	waitForWaiters(t, s, 1)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v, want context.Canceled", err)
	}
	waitForWaiters(t, s, 0)
}

func TestAwaitSnapshotTimeoutReturnsLatestSnapshot(t *testing.T) {
	s := NewStore()
	seedUnknownSandbox(t, s, "sbx-1")
	// The administrator profile below selects by label, so the pod carries it
	// for the selector to match; the readiness gate itself is keyed on the
	// store, never on labels.
	pod := sandboxPod("sbx-1")
	pod.Labels = map[string]string{v1alpha1.LabelSandboxIsClaimed: v1alpha1.True}
	result := make(chan securityprofile.PolicySnapshot, 1)
	go func() {
		snapshot, _ := s.AwaitSnapshot(context.Background(), pod, 50*time.Millisecond)
		result <- snapshot
	}()
	waitForWaiters(t, s, 1)

	profileObj := newTestProfile("admin", "sandboxes", map[string]string{v1alpha1.LabelSandboxIsClaimed: v1alpha1.True})
	profile, err := securityprofile.NewProfile(profileObj, &profileObj.Spec)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventAdd, New: profile}})

	snapshot := <-result
	if len(snapshot.Profiles) != 1 || snapshot.Profiles[0].Meta.Name != "admin" {
		t.Fatalf("profiles = %+v, want latest administrator profile", snapshot.Profiles)
	}
}

func TestAwaitSnapshotEnforcesWaitLimits(t *testing.T) {
	t.Run("per Sandbox", func(t *testing.T) {
		s := NewStore(WithWaitLimits(2, 1))
		seedUnknownSandbox(t, s, "sbx-1")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := s.AwaitSnapshot(ctx, sandboxPod("sbx-1"), time.Second)
			done <- err
		}()
		waitForWaiters(t, s, 1)

		_, overloadErr := s.AwaitSnapshot(context.Background(), sandboxPod("sbx-1"), time.Second)
		cancel()
		waitErr := <-done
		waitForWaiters(t, s, 0)
		if !errors.Is(overloadErr, ErrSandboxPolicyWaitOverloaded) {
			t.Fatalf("error = %v, want overload", overloadErr)
		}
		if !errors.Is(waitErr, context.Canceled) {
			t.Fatalf("waiter error = %v, want context.Canceled", waitErr)
		}
	})

	t.Run("global", func(t *testing.T) {
		s := NewStore(WithWaitLimits(1, 1))
		seedUnknownSandbox(t, s, "sbx-1")
		seedUnknownSandbox(t, s, "sbx-2")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := s.AwaitSnapshot(ctx, sandboxPod("sbx-1"), time.Second)
			done <- err
		}()
		waitForWaiters(t, s, 1)

		_, overloadErr := s.AwaitSnapshot(context.Background(), sandboxPod("sbx-2"), time.Second)
		cancel()
		waitErr := <-done
		waitForWaiters(t, s, 0)
		if !errors.Is(overloadErr, ErrSandboxPolicyWaitOverloaded) {
			t.Fatalf("error = %v, want overload", overloadErr)
		}
		if !errors.Is(waitErr, context.Canceled) {
			t.Fatalf("waiter error = %v, want context.Canceled", waitErr)
		}
	})
}

func TestSandboxStateInvalidAndDeleteArePublished(t *testing.T) {
	s := NewStore()
	pod := sandboxPod("sbx-1")
	invalid := securityprofile.InvalidSandboxProfile(&metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
		Name: "sbx-1", Namespace: "sandboxes", ResourceVersion: "1",
	}}, errors.New("invalid rules"))
	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventAdd, New: invalid}})

	snapshot, err := s.AwaitSnapshot(context.Background(), pod, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SandboxState != securityprofile.SandboxPolicyInvalid {
		t.Fatalf("state = %v, want Invalid", snapshot.SandboxState)
	}

	s.applyBatch([]krt.Event[securityprofile.Profile]{{Event: controllers.EventDelete, Old: invalid}})
	snapshot, err = s.AwaitSnapshot(context.Background(), pod, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SandboxState != securityprofile.SandboxPolicyUnknown {
		t.Fatalf("state after delete = %v, want Unknown", snapshot.SandboxState)
	}
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
	if got := store.ProfilesFor(inputs.Pod{Name: "sbx-1", Namespace: "sandboxes"}); len(got) != 0 {
		t.Fatalf("Matches = %+v, want nothing for a bad first version", got)
	}

	// A good version installs.
	store.SandboxProfileSet(sandbox("2", goodRules))
	got := store.ProfilesFor(inputs.Pod{Name: "sbx-1", Namespace: "sandboxes"})
	if len(got) != 1 || got[0].Rules[0].Name != "deny-exfil" {
		t.Fatalf("Matches = %+v, want the good version installed", got)
	}

	// A bad update retains the last-known-good version.
	store.SandboxProfileSet(sandbox("3", string(badRules)))
	got = store.ProfilesFor(inputs.Pod{Name: "sbx-1", Namespace: "sandboxes"})
	if len(got) != 1 || got[0].Meta.Version != "2" {
		t.Fatalf("Matches = %+v, want version 2 retained after a bad update", got)
	}

	// A fixed update replaces it.
	store.SandboxProfileSet(sandbox("4", goodRules))
	got = store.ProfilesFor(inputs.Pod{Name: "sbx-1", Namespace: "sandboxes"})
	if len(got) != 1 || got[0].Meta.Version != "4" {
		t.Fatalf("Matches = %+v, want the fixed version 4 installed", got)
	}
}
