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
	"testing/synctest"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/pkg/krt"
)

func TestProfileRegistrationUnregistersPublicationsAndDeletes(t *testing.T) {
	for _, backend := range []string{"informer", "xds"} {
		t.Run(backend, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				profile := inlineProfile("sandbox", "ns", "1")
				source := krt.NewMutableCollection(
					nil,
					[]securityprofile.Profile{*profile},
					krt.WithStop(t.Context().Done()),
				)
				profiles := NewSourceCollection(source.AsCollection(), nil, krt.WithStop(t.Context().Done()))
				var reg krt.HandlerRegistration
				var snapshot func() any
				var installed func() *securityprofile.Profile
				if backend == "informer" {
					s := NewStore(0)
					reg = s.RegisterCollection(profiles)
					snapshot = func() any { return s.snapshot.Load() }
					installed = func() *securityprofile.Profile {
						p, _ := s.snapshot.Load().installed.get(keyFor(profile.Meta))
						return p
					}
				} else {
					s := NewXDSStore()
					reg = s.RegisterCollection(profiles, nil)
					snapshot = func() any { return s.snapshot.Load() }
					installed = func() *securityprofile.Profile { return s.snapshot.Load().get(profile.Meta) }
				}
				if !reg.WaitUntilSynced(t.Context().Done()) || !reg.HasSynced() {
					t.Fatal("registration did not sync")
				}
				synctest.Wait()
				if installed() == nil || installed().Meta.Version != "1" {
					t.Fatal("initial profile was not published")
				}
				reg.UnregisterHandler()
				before := snapshot()
				next := *profile
				next.Meta.Version = "2"
				source.UpdateObject(next)
				synctest.Wait()
				if snapshot() != before {
					t.Fatal("unregistered store received a publication")
				}
				source.DeleteObject(profile.ResourceName())
				synctest.Wait()
				if snapshot() != before {
					t.Fatal("unregistered store received a source deletion")
				}
			})
		})
	}
}
