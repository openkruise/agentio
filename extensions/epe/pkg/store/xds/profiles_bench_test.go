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

package xds

import (
	"context"
	"fmt"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	"github.com/openkruise/agentio/pkg/krt"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/demandcache"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

// Immutable publications isolate request-side adaptation and cache maintenance
// from transport, decoding and policy compilation.
type profileBenchSource struct {
	*fakeSource
	done chan struct{}
}

func (s *profileBenchSource) SnapshotFor(names map[string][]string) xdsclient.Snapshot {
	result := xdsclient.Snapshot{
		Synced:    s.snapshot.Synced,
		Changed:   s.snapshot.Changed,
		Resources: map[string]map[string]*xdsclient.Resource{},
	}
	for typ := range s.snapshot.Synced {
		values := make(map[string]*xdsclient.Resource, len(names[typ]))
		for _, name := range names[typ] {
			if resource := s.snapshot.Resources[typ][name]; resource != nil {
				values[name] = resource
			}
		}
		result.Resources[typ] = values
	}
	return result
}

func (s *profileBenchSource) Acquire(typ, name string) (demandcache.Lease[*xdsclient.Resource], error) {
	return profileBenchLease{source: s, typ: typ, name: name}, nil
}

type profileBenchLease struct {
	source *profileBenchSource
	typ    string
	name   string
}

func (s profileBenchLease) Done() <-chan struct{} { return s.source.done }
func (s profileBenchLease) Release()              {}
func (s profileBenchLease) Demand(context.Context) (*xdsclient.Resource, error) {
	return s.source.snapshot.Resources[s.typ][s.name], nil
}

func BenchmarkResolveProfilesHot(b *testing.B) {
	for _, shared := range []int{0, 2} {
		b.Run(fmt.Sprintf("Shared%d", shared), func(b *testing.B) {
			source := &profileBenchSource{fakeSource: testSource(), done: make(chan struct{})}
			source.snapshot.Synced[model.SandboxType], source.snapshot.Synced[model.SecurityProfileType] = true, true
			source.snapshot.Resources[model.SandboxType] = map[string]*xdsclient.Resource{}
			source.snapshot.Resources[model.SecurityProfileType] = map[string]*xdsclient.Resource{}
			subjects := make([]subject.Subject, 128)
			prepared := make([]securityprofile.Profile, 0, 50002)
			for i := range 50000 {
				uid := fmt.Sprintf("sandbox-%d", i)
				host := fmt.Sprintf("host-%d", i)
				source.snapshot.Resources[model.SandboxType][uid] = &xdsclient.Resource{Value: &sandboxProfiles{
					value: &sandboxv1.Sandbox{Uid: uid, Attester: &sandboxv1.Sandbox_Attester{WorkloadUid: host}},
					profile: &securityprofile.Profile{
						Meta: securityprofile.Meta{Name: uid, SandboxUID: uid, Match: securityprofile.MatchSandbox},
						Spec: &agentsv1alpha1.SecurityProfileSpec{},
					},
				}}
				prepared = append(
					prepared,
					*source.snapshot.Resources[model.SandboxType][uid].Value.(*sandboxProfiles).profile,
				)
				if i < len(subjects) {
					subjects[i] = subject.Subject{
						Sandbox:  &subject.Sandbox{UID: uid},
						Workload: subject.Workload{UID: host, SecurityProfileReferences: []string{}},
					}
				}
			}
			for i := range shared {
				name := fmt.Sprintf("policy-%d", i)
				p := &securityprofile.Profile{Spec: &agentsv1alpha1.SecurityProfileSpec{}, Selector: labels.Nothing()}
				p.Meta.Name = name
				prepared = append(prepared, *p)
				key := "global/" + name
				source.snapshot.Resources[model.SecurityProfileType][key] = &xdsclient.Resource{Value: p}
				for j := range subjects {
					subjects[j].Workload.SecurityProfileReferences = append(
						subjects[j].Workload.SecurityProfileReferences,
						key,
					)
				}
			}
			s := New(source)
			var err error
			s.cache, err = demandcache.New[*xdsclient.Resource](
				source,
				demandcache.Config{MaxEntries: 120000, IdleTTL: 10 * time.Minute},
			)
			if err != nil {
				b.Fatal(err)
			}
			ctx, cancel := context.WithCancel(b.Context())
			done := make(chan error, 1)
			go func() { done <- s.cache.Run(ctx) }()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					b.Error(err)
				}
			}()
			raw := krt.NewStaticCollection(nil, prepared, krt.WithStop(b.Context().Done()))
			collection := profilestore.NewSourceCollection(raw, nil, krt.WithStop(b.Context().Done()))
			matcher := profilestore.NewXDSStore()
			reg := matcher.RegisterCollection(collection, s.AcquireProfileReferences)
			if !reg.WaitUntilSynced(b.Context().Done()) {
				b.Fatal("profile collection did not sync")
			}
			for _, subj := range subjects {
				if _, err := matcher.ResolveProfiles(b.Context(), subj); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					profiles, err := matcher.ResolveProfiles(b.Context(), subjects[i%len(subjects)])
					if err != nil || len(profiles) != shared+1 {
						b.Errorf("profiles: %v, %v", profiles, err)
						return
					}
					i++
				}
			})
		})
	}
}
