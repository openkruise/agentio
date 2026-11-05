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
	"fmt"
	"sync"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube/controllers"
)

func BenchmarkReadinessReady(b *testing.B) {
	for _, parallel := range []bool{false, true} {
		b.Run(fmt.Sprintf("parallel=%t", parallel), func(b *testing.B) {
			s := NewStore(0)
			profile := inlineProfile("ready", "ns", "1")
			profile.Meta.SourceIdentity.UID = "uid"
			s.applyBatch([]krt.Event[securityprofile.Profile]{{New: profile, Event: controllers.EventAdd}})
			s.sandbox = func(_ context.Context, subj subject.Subject) (sandboxSource, bool, error) {
				return testSandboxSource(subj, "uid"), true, nil
			}
			subj := subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: "ready"}}
			ctx := b.Context()
			b.ReportAllocs()
			b.ResetTimer()
			if parallel {
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						got, err := s.ResolveProfiles(ctx, subj)
						if err != nil || len(got) != 1 {
							b.Errorf("resolve: %v, %v", got, err)
							return
						}
					}
				})
			} else {
				for range b.N {
					got, err := s.ResolveProfiles(ctx, subj)
					if err != nil || len(got) != 1 {
						b.Fatalf("resolve: %v, %v", got, err)
					}
				}
			}
		})
	}
}

// Each round starts pending requests, then publishes their profiles one by one.
// Source lookup models a local cache hit; no API server or network is simulated.
// Repeated invalidations may coalesce naturally, as in the actual store.
func BenchmarkReadinessPending(b *testing.B) {
	for _, tc := range []struct {
		waiters   int
		keys      int
		unrelated int
	}{
		{1, 1, 0}, {32, 32, 0}, {256, 256, 0},
		{32, 32, 4}, {256, 256, 4}, {256, 1, 0},
	} {
		b.Run(fmt.Sprintf("waiters=%d/keys=%d/unrelated=%d", tc.waiters, tc.keys, tc.unrelated), func(b *testing.B) {
			profiles := make([]*securityprofile.Profile, tc.keys)
			for i := range profiles {
				profiles[i] = inlineProfile(fmt.Sprintf("sandbox-%d", i), "ns", "1")
				profiles[i].Meta.SourceIdentity.UID = "uid"
			}
			other := inlineProfile("unrelated", "ns", "1")
			otherEvent := []krt.Event[securityprofile.Profile]{{New: other, Event: controllers.EventUpdate}}
			var calls int64
			ctx := b.Context()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				s := NewStore(0)
				var started, finished sync.WaitGroup
				started.Add(tc.waiters)
				finished.Add(tc.waiters)
				// A request reports its first lookup, regardless of extra checks.
				type marker struct{ calls int64 }
				type markerKey struct{}
				markers := make([]marker, tc.waiters)
				s.sandbox = func(ctx context.Context, subj subject.Subject) (sandboxSource, bool, error) {
					m := ctx.Value(markerKey{}).(*marker)
					m.calls++
					if m.calls == 1 {
						started.Done()
					}
					return testSandboxSource(subj, "uid"), true, nil
				}
				done := make([]chan struct{}, tc.keys)
				for i := range done {
					done[i] = make(chan struct{}, tc.waiters)
				}
				for i := range tc.waiters {
					key := i % tc.keys
					subj := subject.Subject{Workload: subject.Workload{Namespace: "ns", Name: profiles[key].Meta.Name}}
					requestCtx := context.WithValue(ctx, markerKey{}, &markers[i])
					go func() {
						defer finished.Done()
						got, err := s.ResolveProfiles(requestCtx, subj)
						if err != nil || len(got) != 1 {
							b.Errorf("resolve: %v, %v", got, err)
						}
						done[key] <- struct{}{}
					}()
				}
				started.Wait()
				for key, profile := range profiles {
					for range tc.unrelated {
						s.applyBatch(otherEvent)
					}
					s.applyBatch([]krt.Event[securityprofile.Profile]{{New: profile, Event: controllers.EventAdd}})
					for n := key; n < tc.waiters; n += tc.keys {
						<-done[key]
					}
				}
				finished.Wait()
				for _, m := range markers {
					calls += m.calls
				}
			}
			b.ReportMetric(float64(calls)/float64(b.N*tc.waiters), "lookups/request")
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*tc.waiters), "ns/request")
		})
	}
}
