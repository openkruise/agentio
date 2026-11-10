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
	"strconv"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube/controllers"
)

func TestXDSProfilePublicationPreservesPreviousSnapshot(t *testing.T) {
	s := NewXDSStore()
	events := sandboxPublicationFixtures(1000)
	for i := range events {
		if i%2 == 1 {
			events[i].New.Meta.Match = securityprofile.MatchSelector
		}
	}
	s.applyBatch(events)
	old := s.snapshot.Load()
	updated := *events[0].New
	updated.Meta.Version = "updated"
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Event: controllers.EventUpdate, Old: events[0].New, New: &updated},
		{Event: controllers.EventDelete, Old: events[1].New},
		{Event: controllers.EventUpdate, Old: events[2].New, New: events[2].New},
	})
	count := 0
	for _, shard := range s.snapshot.Load().shards {
		count += len(shard)
	}
	if count != 999 {
		t.Fatal("publication changed the previous snapshot's membership")
	}
	for i, event := range events {
		previous := old.get(event.New.Meta)
		if previous != event.New {
			t.Fatal("previous snapshot mutated", i)
		}
		current := s.snapshot.Load().get(event.New.Meta)
		switch i {
		case 0:
			if current == nil || current.Meta.Version != "updated" {
				t.Fatal("updated policy not published")
			}
		case 1:
			if current != nil {
				t.Fatal("deleted policy retained")
			}
		default:
			if current != previous {
				t.Fatal("unrelated policy changed", i)
			}
		}
	}
}

func BenchmarkXDSProfilePublication50K(b *testing.B) {
	s := NewXDSStore()
	events := sandboxPublicationFixtures(50_000)
	s.applyBatch(events)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.applyBatch(events[i%len(events) : i%len(events)+1])
	}
}

func sandboxPublicationFixtures(count int) []krt.Event[securityprofile.Profile] {
	events := make([]krt.Event[securityprofile.Profile], count)
	for i := range events {
		p := &securityprofile.Profile{Meta: securityprofile.Meta{
			Match:     securityprofile.MatchSandbox,
			Namespace: "ns",
			Name:      "sandbox-" + strconv.Itoa(i),
		}}
		events[i] = krt.Event[securityprofile.Profile]{Event: controllers.EventAdd, New: p}
	}
	return events
}
