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
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"istio.io/istio/pkg/test"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	metadatafake "k8s.io/client-go/metadata/fake"
	ktesting "k8s.io/client-go/testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/testsupport"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/controllers"
	"github.com/openkruise/agentio/pkg/model"
)

type sandboxProfileTestClient struct{ kube.Client }

func (c sandboxProfileTestClient) CrdWatcher() kube.CrdWatcher {
	return knownCRDWatcher{securityProfileGVR: {}, globalSecurityProfileGVR: {}, sandboxGVR: {}}
}

func testSandboxSource(subj subject.Subject, uid string) sandboxSource {
	return sandboxSource{
		name:     types.NamespacedName{Namespace: subj.Workload.Namespace, Name: subj.Workload.Name},
		identity: model.SourceIdentity{UID: uid},
	}
}

func TestResolveProfilesSandboxWithDistinctWorkloadName(t *testing.T) {
	test.SetForTest(t, &features.SandboxMode, true)
	for _, labeled := range []bool{false, true} {
		t.Run(fmt.Sprintf("delivery label=%t", labeled), func(t *testing.T) {
			c := sandboxProfileTestClient{Client: kube.NewFakeClient()}
			metadata := c.Metadata().(*metadatafake.FakeMetadataClient)
			resource := metadata.Resource(sandboxGVR).Namespace("ns").(metadatafake.MetadataClient)
			sandbox := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
				Name:      "sandbox",
				Namespace: "ns",
				UID:       "source-uid",
				Labels: map[string]string{
					agentsv1alpha1.LabelSandboxPool:      "pool",
					agentsv1alpha1.LabelSandboxIsClaimed: agentsv1alpha1.True,
				},
				Annotations: map[string]string{
					securityprofile.AnnotationSecurityRules: `[{"name":"deny","match":[{"domains":["*"]}],"actions":{"block":{}}}]`,
				},
			}}
			uid := "kruise:ns--sandbox"
			if labeled {
				sandbox.Labels[agentsv1alpha1.LabelSandboxID] = "delivery"
				uid = "kruise:delivery"
			}
			if _, err := resource.CreateFake(sandbox, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			decoy := sandbox.DeepCopy()
			decoy.Name, decoy.UID, decoy.Labels = "runtime", "decoy-uid", nil
			if _, err := resource.CreateFake(decoy, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			profiles := NewCollection(c, nil, nil, t.Context().Done())
			s := MakeFakeStore()
			s.ProfileSet(newTestProfile("admin", "ns", map[string]string{"app": "runtime"}))
			reg := s.RegisterCollection(profiles)
			c.Run(t.Context().Done())
			if !reg.WaitUntilSynced(t.Context().Done()) {
				t.Fatal("initial sync failed")
			}
			metadata.PrependReactor("*", "sandboxes", func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("ready lookup must use the informer")
			})
			subj := subject.Subject{
				Workload: subject.Workload{
					Name:      "runtime",
					Namespace: "ns",
					Labels:    map[string]string{"app": "runtime"},
				},
				Sandbox: &subject.Sandbox{UID: uid},
			}
			got, err := s.ResolveProfiles(t.Context(), subj)
			if err != nil || len(got) != 2 || got[0].Meta.Name != "admin" || got[1].Meta.Name != "sandbox" {
				t.Fatalf("resolve distinct Workload: %v, %v", got, err)
			}
			if len(s.pending) != 0 || subj.Workload.Name != "runtime" {
				t.Fatal("ready lookup registered a waiter or changed workload identity")
			}
		})
	}
}

func TestSandboxUIDLookupFromCache(t *testing.T) {
	test.SetForTest(t, &features.SandboxMode, true)
	for _, tc := range []struct {
		name      string
		rules     string
		duplicate bool
		missing   bool
		namespace string
		wantError bool
	}{
		{name: "rules", namespace: "ns", rules: "pending"},
		{name: "no rules", namespace: "ns"},
		{name: "missing UID with same-name Sandbox", namespace: "ns", missing: true, wantError: true},
		{name: "duplicate UID", namespace: "ns", rules: "pending", duplicate: true, wantError: true},
		{name: "different namespace", namespace: "other", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := sandboxProfileTestClient{Client: kube.NewFakeClient()}
			metadata := c.Metadata().(*metadatafake.FakeMetadataClient)
			resource := metadata.Resource(sandboxGVR).Namespace(tc.namespace).(metadatafake.MetadataClient)
			sandbox := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
				Name:        "sandbox",
				Namespace:   tc.namespace,
				UID:         "source-uid",
				Labels:      map[string]string{agentsv1alpha1.LabelSandboxID: "delivery"},
				Annotations: map[string]string{securityprofile.AnnotationSecurityRules: tc.rules},
			}}
			if _, err := resource.CreateFake(sandbox, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			if tc.duplicate {
				duplicate := sandbox.DeepCopy()
				duplicate.Name, duplicate.UID = "duplicate", "duplicate-source"
				if _, err := resource.CreateFake(duplicate, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			profiles := NewCollection(c, nil, nil, t.Context().Done())
			s := NewStore(0)
			reg := s.RegisterCollection(profiles)
			c.Run(t.Context().Done())
			if !reg.WaitUntilSynced(t.Context().Done()) {
				t.Fatal("initial sync failed")
			}
			metadata.ClearActions()
			subj := subject.Subject{
				Workload: subject.Workload{Name: "runtime", Namespace: "ns"},
				Sandbox:  &subject.Sandbox{UID: "kruise:delivery"},
			}
			if tc.missing {
				subj.Workload.Name = sandbox.Name
				subj.Sandbox.UID = "kruise:missing"
			}
			source, found, err := profiles.sandbox(t.Context(), subj)
			if actions := metadata.Actions(); len(actions) != 0 {
				t.Fatalf("cached UID lookup called the API: %v", actions)
			}
			if tc.wantError {
				if err == nil {
					t.Fatal("invalid UID lookup accepted")
				}
				return
			}
			if err != nil || source.name != (types.NamespacedName{Namespace: "ns", Name: "sandbox"}) ||
				source.identity.UID != "source-uid" ||
				found != (tc.rules != "") {
				t.Fatalf("UID lookup = %+v, %v, %v", source, found, err)
			}
		})
	}
}

func TestSandboxFirstRequestWaitsForSource(t *testing.T) {
	test.SetForTest(t, &features.SandboxMode, true)
	for _, event := range []string{"publication", "delete", "remove rules", "publication by UID", "delete by UID", "remove rules by UID"} {
		t.Run(event, func(t *testing.T) {
			explicitUID := strings.HasSuffix(event, " by UID")
			event := strings.TrimSuffix(event, " by UID")
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			c := sandboxProfileTestClient{Client: kube.NewFakeClient()}
			profiles := NewCollection(c, nil, nil, ctx.Done())
			publish := make(chan struct{})
			defer func() {
				select {
				case <-publish:
				default:
					close(publish)
				}
			}()
			// Hold the compiled profile before the store receives it.
			profiles.Collection = krt.NewCollection(
				profiles.Collection,
				func(_ krt.HandlerContext, p securityprofile.Profile) *securityprofile.Profile {
					<-publish
					return &p
				},
				krt.WithStop(ctx.Done()),
			)
			lookedUp := make(chan struct{}, 1)
			lookup := profiles.sandbox
			profiles.sandbox = func(ctx context.Context, subj subject.Subject) (sandboxSource, bool, error) {
				identity, found, err := lookup(ctx, subj)
				select {
				case lookedUp <- struct{}{}:
				default:
				}
				return identity, found, err
			}
			s := NewStore(0)
			reg := s.RegisterCollection(profiles)
			unregister := profiles.Registry.RegisterDeletes(s.NotifyKeys)
			defer unregister()
			c.Run(ctx.Done())
			if !reg.WaitUntilSynced(ctx.Done()) {
				t.Fatal("initial sync failed")
			}
			sandbox := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
				Name:            "new-sandbox",
				Namespace:       "ns",
				UID:             "new-uid",
				ResourceVersion: "1",
				Annotations: map[string]string{
					securityprofile.AnnotationSecurityRules: `[{"name":"deny","match":[{"domains":["*"]}],"actions":{"block":{}}}]`,
				},
			}}
			resource := c.Metadata().Resource(sandboxGVR).Namespace("ns").(metadatafake.MetadataClient)
			if _, err := resource.CreateFake(sandbox, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			type resolution struct {
				profiles []*securityprofile.Profile
				err      error
			}
			result := make(chan resolution, 1)
			subj := subject.Subject{Workload: subject.Workload{Name: sandbox.Name, Namespace: sandbox.Namespace}}
			if explicitUID {
				subj.Workload.Name = "different-runtime"
				subj.Sandbox = &subject.Sandbox{UID: "kruise:ns--new-sandbox"}
			}
			// Observe the source event before checking the asynchronous compilation gate.
			testsupport.Eventually(t, time.Second, func() error {
				_, found, err := lookup(ctx, subj)
				if err != nil {
					return err
				}
				if !found {
					return fmt.Errorf("Sandbox source event not observed")
				}
				return nil
			})
			go func() {
				got, err := s.ResolveProfiles(ctx, subj)
				result <- resolution{profiles: got, err: err}
			}()
			select {
			case <-lookedUp:
			case <-ctx.Done():
				t.Fatal("first request did not look up Sandbox")
			}
			select {
			case <-result:
				t.Fatal("first request escaped before publication")
			case <-time.After(20 * time.Millisecond):
			}
			switch event {
			case "publication":
				close(publish)
			case "delete":
				if err := resource.Delete(ctx, sandbox.Name, metav1.DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
			case "remove rules":
				sandbox = sandbox.DeepCopy()
				sandbox.Annotations = nil
				sandbox.ResourceVersion = "2"
				if _, err := resource.UpdateFake(sandbox, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case resolved := <-result:
				if explicitUID && event == "delete" {
					if resolved.err == nil {
						t.Fatal("deleted explicit Sandbox accepted as no policy")
					}
					return
				}
				if resolved.err != nil {
					t.Fatal(resolved.err)
				}
				got := resolved.profiles
				if event != "publication" {
					if len(got) != 0 {
						t.Fatalf("removed source still has rules: %v", got)
					}
				} else if len(got) != 1 || got[0].Meta.SourceIdentity.UID != "new-uid" || got[0].Rules[0].Name != "deny" {
					t.Fatalf("first request did not receive Sandbox rules: %v", got)
				}
			case <-ctx.Done():
				t.Fatal("first request did not wake after source event")
			}
		})
	}
}

func TestResolveProfilesWaitsOnlyForSandbox(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := MakeFakeStore()
		sandbox := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
			Name:            "sbx-1",
			Namespace:       "ns",
			UID:             "uid-1",
			ResourceVersion: "2",
			Annotations: map[string]string{
				securityprofile.AnnotationSecurityRules: `[{"name":"r","match":[{"domains":["*"]}],"actions":{"block":{}}}]`,
			},
		}}
		s.sandbox = func(_ context.Context, subj subject.Subject) (sandboxSource, bool, error) {
			return testSandboxSource(subj, string(sandbox.UID)), subj.Workload.Name == sandbox.Name, nil
		}
		subj := subject.Subject{
			Workload: subject.Workload{Name: "sbx-1", Namespace: "ns", Labels: map[string]string{"app": "test"}},
		}
		results := make(chan []*securityprofile.Profile, 8)
		for range cap(results) {
			go func() {
				profiles, err := s.ResolveProfiles(t.Context(), subj)
				if err != nil {
					t.Error(err)
				}
				results <- profiles
			}()
		}
		synctest.Wait()
		if len(results) != 0 {
			t.Fatal("request escaped before Sandbox publication")
		}

		// An unrelated policy publication cannot release Sandbox waiters.
		s.ProfileSet(newTestProfile("admin", "ns", subj.Workload.Labels))
		synctest.Wait()
		if len(results) != 0 {
			t.Fatal("administrator policy released Sandbox requests")
		}
		ordinary, err := s.ResolveProfiles(
			t.Context(),
			subject.Subject{
				Workload: subject.Workload{Name: "ordinary", Namespace: "ns", Labels: subj.Workload.Labels},
			},
		)
		if err != nil || len(ordinary) != 1 {
			t.Fatalf("ordinary request: %v, %v", ordinary, err)
		}

		s.SandboxProfileSet(sandbox)
		synctest.Wait()
		for range cap(results) {
			got := <-results
			if len(got) != 2 || got[0].Meta.Name != "admin" || got[1].Meta.SourceIdentity.UID != "uid-1" {
				t.Fatalf("profiles = %v, want administrator then current Sandbox", got)
			}
		}
		// Updates of the same object need not have reached the installed snapshot.
		sandbox.ResourceVersion = "3"
		sandbox.Annotations[securityprofile.AnnotationSecurityRules] = "invalid update"
		got, err := s.ResolveProfiles(t.Context(), subj)
		if err != nil || len(got) != 2 || got[1].Meta.Version != "2" {
			t.Fatalf("same UID must retain last known-good policy: %v, %v", got, err)
		}
	})
}

func TestResolveProfilesRejectsUnpublishedSandbox(t *testing.T) {
	for name, recreate := range map[string]bool{"first create": false, "recreated": true} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := MakeFakeStore()
				sandbox := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
					Name:            "sbx-1",
					Namespace:       "ns",
					UID:             "new",
					ResourceVersion: "2",
					Annotations: map[string]string{
						securityprofile.AnnotationSecurityRules: "invalid first version",
					},
				}}
				if recreate {
					old := inlineProfile("sbx-1", "ns", "1")
					old.Meta.SourceIdentity.UID = "old"
					s.applyBatch([]krt.Event[securityprofile.Profile]{{New: old, Event: controllers.EventAdd}})
				}
				s.sandbox = func(_ context.Context, subj subject.Subject) (sandboxSource, bool, error) {
					return testSandboxSource(
						subj,
						string(sandbox.UID),
					), sandbox.Annotations[securityprofile.AnnotationSecurityRules] != "", nil
				}
				s.SandboxProfileSet(sandbox)
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				got, err := s.ResolveProfiles(
					ctx,
					subject.Subject{Workload: subject.Workload{Name: "sbx-1", Namespace: "ns"}},
				)
				if !errors.Is(err, context.DeadlineExceeded) || len(got) != 0 {
					t.Fatalf("unpublished Sandbox = %v, %v; want deadline", got, err)
				}
				if got := s.ProfilesFor(
					subject.Subject{Workload: subject.Workload{Name: "sbx-1", Namespace: "ns"}},
				); len(
					got,
				) != 0 {
					t.Fatal("recreated Sandbox inherited predecessor's policy")
				}
				// An explicitly empty policy needs no compiled publication.
				delete(sandbox.Annotations, securityprofile.AnnotationSecurityRules)
				if _, err := s.ResolveProfiles(
					t.Context(),
					subject.Subject{Workload: subject.Workload{Name: "sbx-1", Namespace: "ns"}},
				); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestResolveProfilesWorkloadMetadata(t *testing.T) {
	s := MakeFakeStore()
	s.GlobalProfileSet(newTestGlobalProfile("global", nil))
	for _, tc := range []struct {
		name     string
		workload subject.Workload
		want     int
	}{
		{name: "zero workload"},
		{name: "empty labels", workload: subject.Workload{Labels: map[string]string{}}},
		{name: "namespace only", workload: subject.Workload{Namespace: "ns"}, want: 1},
		{name: "labels only", workload: subject.Workload{Labels: map[string]string{"app": "test"}}, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subj := subject.Subject{Workload: tc.workload}
			if got := s.ProfilesFor(subj); len(got) != tc.want {
				t.Fatalf("ProfilesFor = %v, want %d profiles", got, tc.want)
			}
			if got, err := s.ResolveProfiles(t.Context(), subj); err != nil || len(got) != tc.want {
				t.Fatalf("ResolveProfiles = %v, %v; want %d profiles", got, err, tc.want)
			}
		})
	}
	subj := subject.Subject{Sandbox: &subject.Sandbox{UID: "kruise:sbx"}}
	if _, err := s.ResolveProfiles(t.Context(), subj); err == nil {
		t.Fatal("local backend accepted Sandbox identity without host lookup metadata")
	}
}

func TestSandboxCacheMissDoesNotQueryAPI(t *testing.T) {
	test.SetForTest(t, &features.SandboxMode, true)
	for _, crd := range []bool{false, true} {
		t.Run(fmt.Sprintf("Sandbox CRD=%t", crd), func(t *testing.T) {
			c := &profileTestClient{
				Client:     kube.NewFakeClient(newTestGlobalProfile("admin", nil)),
				sandboxCRD: crd,
			}
			profiles := NewCollection(c, nil, nil, t.Context().Done())
			s := NewStore(0)
			reg := s.RegisterCollection(profiles)
			c.Run(t.Context().Done())
			if !reg.WaitUntilSynced(t.Context().Done()) {
				t.Fatal("initial sync failed")
			}
			testsupport.Eventually(t, 5*time.Second, func() error {
				if len(s.List()) != 1 {
					return fmt.Errorf("administrator profile is not installed")
				}
				return nil
			})
			metadata := c.Metadata().(*metadatafake.FakeMetadataClient)
			metadata.ClearActions()
			for range 10 {
				subj := subject.Subject{Workload: subject.Workload{
					Name:                      "missing",
					Namespace:                 "ns",
					SecurityProfileReferences: []string{"global/admin"},
				}}
				if got, err := s.ResolveProfiles(
					t.Context(),
					subj,
				); err != nil || len(got) != 1 ||
					got[0].Meta.Name != "admin" {
					t.Fatalf("absent optional Sandbox = %v, %v", got, err)
				}
				subj.Sandbox = &subject.Sandbox{UID: "kruise:missing"}
				if _, err := s.ResolveProfiles(t.Context(), subj); err == nil {
					t.Fatal("explicit missing Sandbox accepted as no policy")
				}
			}
			if actions := metadata.Actions(); len(actions) != 0 {
				t.Fatalf("cache misses called the API: %v", actions)
			}
		})
	}
}
