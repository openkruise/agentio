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
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube/controllers"
	"github.com/openkruise/agentio/pkg/model"
)

func TestPendingProfilesFilterNotificationsAndCancelIndependently(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewStore(0)
		var aCalls, bCalls atomic.Int64
		var bRemoved atomic.Bool
		s.sandbox = func(_ context.Context, subj subject.Subject) (sandboxSource, bool, error) {
			if subj.Workload.Name == "a" {
				aCalls.Add(1)
			} else {
				bCalls.Add(1)
			}
			return testSandboxSource(subj, "uid"), subj.Workload.Name == "a" || !bRemoved.Load(), nil
		}
		a := subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "a"}}
		b := subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "b"}}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		canceled, aDone, bDone := make(chan error, 1), make(chan error, 1), make(chan error, 1)
		go func() {
			_, err := s.ResolveProfiles(ctx, a)
			canceled <- err
		}()
		go func() {
			_, err := s.ResolveProfiles(t.Context(), a)
			aDone <- err
		}()
		go func() {
			_, err := s.ResolveProfiles(t.Context(), b)
			bDone <- err
		}()
		synctest.Wait()
		aBefore, bBefore := aCalls.Load(), bCalls.Load()
		if aBefore != 2 || bBefore != 1 {
			t.Fatalf("registration repeated source lookup: a=%d, b=%d", aBefore, bBefore)
		}
		other := inlineProfile("other", "ns", "1")
		s.applyBatch([]krt.Event[securityprofile.Profile]{{New: other, Event: controllers.EventAdd}})
		s.NotifyKeys([]model.ResourceKey{sandboxProfileKey("ns", "other")})
		synctest.Wait()
		if aCalls.Load() != aBefore || bCalls.Load() != bBefore {
			t.Fatal("unrelated update woke requests")
		}
		cancel()
		synctest.Wait()
		if !errors.Is(<-canceled, context.Canceled) {
			t.Fatal("cancellation lost")
		}
		profile := inlineProfile("a", "ns", "1")
		profile.Meta.SourceIdentity.UID = "uid"
		s.applyBatch([]krt.Event[securityprofile.Profile]{{New: profile, Event: controllers.EventAdd}})
		synctest.Wait()
		if err := <-aDone; err != nil {
			t.Fatal(err)
		}
		if bCalls.Load() != bBefore || len(bDone) != 0 {
			t.Fatal("a publication woke b")
		}
		bRemoved.Store(true)
		s.NotifyKeys([]model.ResourceKey{sandboxProfileKey("ns", "b")})
		synctest.Wait()
		if err := <-bDone; err != nil {
			t.Fatal(err)
		}
		if len(s.pending) != 0 {
			t.Fatal("waiter registration leaked")
		}
	})
}

func TestPendingProfilePublicationBeforeRegistration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewStore(0)
		profile := inlineProfile("a", "ns", "1")
		profile.Meta.SourceIdentity.UID = "uid"
		published := false
		s.sandbox = func(_ context.Context, subj subject.Subject) (sandboxSource, bool, error) {
			if !published {
				published = true
				s.applyBatch([]krt.Event[securityprofile.Profile]{{New: profile, Event: controllers.EventAdd}})
			}
			return testSandboxSource(subj, "uid"), true, nil
		}
		got, err := s.ResolveProfiles(
			t.Context(),
			subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "a"}},
		)
		if err != nil || len(got) != 1 {
			t.Fatalf("resolve: %v, %v", got, err)
		}
		if len(s.pending) != 0 {
			t.Fatal("waiter registration leaked")
		}
	})
}

func TestPendingProfileSourceRemovalBeforeRegistration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewStore(0)
		calls := 0
		s.sandbox = func(_ context.Context, subj subject.Subject) (sandboxSource, bool, error) {
			calls++
			if calls == 1 {
				// The source disappears after lookup but before the request can register.
				s.NotifyKeys([]model.ResourceKey{sandboxProfileKey("ns", "a")})
				return testSandboxSource(subj, "uid"), true, nil
			}
			return sandboxSource{}, false, nil
		}
		got, err := s.ResolveProfiles(
			t.Context(),
			subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "a"}},
		)
		if err != nil || len(got) != 0 || calls != 2 {
			t.Fatalf("resolve: %v, %v, calls=%d", got, err, calls)
		}
		if len(s.pending) != 0 {
			t.Fatal("waiter registration leaked")
		}
	})
}

func TestPendingProfileRechecksAndReleasesCanceledWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewStore(0)
		calls := 0
		s.sandbox = func(_ context.Context, subj subject.Subject) (sandboxSource, bool, error) {
			calls++
			return testSandboxSource(subj, "uid"), true, nil
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := s.ResolveProfiles(ctx, subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "a"}})
			done <- err
		}()
		synctest.Wait()
		key := sandboxProfileKey("ns", "a")
		previous := s.pending[key]
		s.NotifyKeys([]model.ResourceKey{key, key})
		synctest.Wait()
		if calls != 2 || len(done) != 0 || s.pending[key] == nil || s.pending[key] == previous {
			t.Fatal("notification did not recheck and renew the pending wait")
		}
		cancel()
		synctest.Wait()
		if !errors.Is(<-done, context.Canceled) || len(s.pending) != 0 {
			t.Fatal("canceled request retained its pending registration")
		}
	})
}

func TestPendingProfileConcurrentChangeRespectsCancellation(t *testing.T) {
	s := NewStore(0)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s.sandbox = func(_ context.Context, subj subject.Subject) (sandboxSource, bool, error) {
		s.NotifyKeys([]model.ResourceKey{sandboxProfileKey("ns", "a")})
		cancel()
		return testSandboxSource(subj, "uid"), true, nil
	}
	_, err := s.ResolveProfiles(ctx, subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "a"}})
	if !errors.Is(err, context.Canceled) || len(s.pending) != 0 {
		t.Fatalf("resolve after concurrent invalidation: %v, pending=%d", err, len(s.pending))
	}
}
