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
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/test"
	"k8s.io/apimachinery/pkg/labels"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	wds "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/profilestore"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	workloadpolicy "github.com/openkruise/agentio/extensions/epe/pkg/policy/workload"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/pkg/demandcache"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

// Immutable publications isolate request-side adaptation and cache maintenance
// from transport, decoding and policy compilation.
type profileBenchSource struct {
	*fakeSource
	done chan struct{}
}

func (s *profileBenchSource) LookupResource(typ, name string) (*xdsclient.Resource, <-chan struct{}, bool) {
	return s.snapshot.Resources[typ][name], s.snapshot.Changed, s.snapshot.Usable(typ)
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
	test.SetForTest(b, &features.SandboxMode, true)
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
					uid:         uid,
					workloadUID: host,
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

// Exercise Workload identity and ordered global/namespaced policy bindings with
// Sandbox discovery disabled. All workers share the normal retention and admission paths.
func BenchmarkWorkloadDeltaHot(b *testing.B) {
	test.SetForTest(b, &features.SandboxMode, false)
	for _, count := range []int{0, 1, 8} {
		b.Run(fmt.Sprintf("References%d", count), func(b *testing.B) {
			source := &profileBenchSource{fakeSource: testSource(), done: make(chan struct{})}
			source.snapshot.Synced[model.SecurityProfileType] = true
			source.snapshot.Resources[model.SecurityProfileType] = make(map[string]*xdsclient.Resource)
			binding := &ext.PolicyReference{TypeUrl: model.SecurityProfileType}
			prepared := make([]securityprofile.Profile, count)
			for i := range prepared {
				p := &prepared[i]
				p.Spec, p.Selector = &agentsv1alpha1.SecurityProfileSpec{}, labels.Nothing()
				p.Meta.Name = fmt.Sprintf("policy-%d", i)
				key := "global/" + p.Meta.Name
				if i%2 == 1 {
					p.Meta.Namespace = "ns"
					key = "namespaced/ns/" + p.Meta.Name
				}
				binding.Resources = append(binding.Resources, &ext.PolicyResourceReference{Name: key})
				source.snapshot.Resources[model.SecurityProfileType][key] = &xdsclient.Resource{Value: p}
			}
			payload, err := anypb.New(binding)
			if err != nil {
				b.Fatal(err)
			}
			requests := make([]filter.RequestContext, 128)
			for i := range requests {
				name := fmt.Sprintf("pod-%d", i)
				uid := "edge//Pod/ns/" + name
				requests[i].Caller.Subject.Workload.UID = uid
				source.snapshot.Resources[model.WorkloadType][uid] = &xdsclient.Resource{Value: &wds.Workload{
					Uid:        uid,
					Namespace:  "ns",
					Name:       name,
					Extensions: []*wds.Extension{{Name: "security-profile-reference", Config: payload}},
				}}
			}
			s := New(source)
			s.cache, err = demandcache.New[*xdsclient.Resource](source, demandcache.Config{IdleTTL: time.Hour})
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(s.cache.Close)
			aggregate := store.NewAggregate(s)
			workloadpolicy.RegisterQueries(aggregate, "edge")
			resolveBinding := workloadpolicy.NewContextResolver(aggregate)
			opts := krt.WithStop(b.Context().Done())
			raw := krt.NewStaticCollection(nil, prepared, opts)
			matcher := profilestore.NewXDSStore()
			reg := matcher.RegisterCollection(
				profilestore.NewSourceCollection(raw, nil, opts),
				s.AcquireProfileReferences,
			)
			b.Cleanup(reg.UnregisterHandler)
			if !reg.WaitUntilSynced(b.Context().Done()) {
				b.Fatal("policy collection did not sync")
			}
			for i, req := range requests {
				got, err := resolveBinding(b.Context(), req)
				if err != nil || got.Caller.Subject.Workload.UID != req.Caller.Subject.Workload.UID ||
					len(got.Caller.Subject.Workload.SecurityProfileReferences) != count {
					b.Fatalf("Workload %d: %v, %v", i, got.Caller.Subject.Workload, err)
				}
				profiles, err := matcher.ResolveProfiles(b.Context(), got.Caller.Subject)
				if err != nil || len(profiles) != count {
					b.Fatalf("profiles: %v, %v", profiles, err)
				}
				for j, p := range profiles {
					if p.Meta.Name != prepared[j].Meta.Name || p.Meta.Namespace != prepared[j].Meta.Namespace {
						b.Fatalf("out-of-order profile %d: %v", j, p.Meta)
					}
				}
				requests[i] = got
			}
			for _, stage := range []string{"Binding", "Profiles", "BindingAndProfiles"} {
				b.Run(stage, func(b *testing.B) {
					b.ReportAllocs()
					b.RunParallel(func(pb *testing.PB) {
						i := 0
						for pb.Next() {
							req := requests[i%len(requests)]
							i++
							if stage != "Profiles" {
								got, err := resolveBinding(b.Context(), req)
								if err != nil {
									b.Error(err)
									return
								}
								req = got
							}
							if stage != "Binding" {
								profiles, err := matcher.ResolveProfiles(b.Context(), req.Caller.Subject)
								if err != nil || len(profiles) != count {
									b.Errorf("profiles: %v, %v", profiles, err)
									return
								}
							}
						}
					})
				})
			}
		})
	}
}
