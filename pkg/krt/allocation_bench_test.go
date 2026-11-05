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

package krt

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/openkruise/agentio/pkg/kube/controllers"
)

type allocationItem struct {
	Name  string
	Value int
}

func (i allocationItem) ResourceName() string { return i.Name }

func BenchmarkListenerAllocation(b *testing.B) {
	stop := b.Context().Done()
	b.ReportAllocs()
	for b.Loop() {
		listener := newProcessListener(func([]Event[allocationItem]) {}, alwaysSynced{}, stop)
		runtime.KeepAlive(listener)
	}
}

func BenchmarkFetchAllocation(b *testing.B) {
	values := make([]allocationItem, 128)
	for i := range values {
		values[i] = allocationItem{Name: fmt.Sprint(i), Value: i}
	}
	source := NewStaticCollection(nil, values, WithStop(b.Context().Done()))
	index := NewIndex(source, "all", func(allocationItem) []string { return []string{"all"} })
	for _, tc := range []struct {
		name    string
		options []FetchOption
	}{
		{name: "all"},
		{name: "index", options: []FetchOption{FilterIndex(index, "all")}},
		{name: "key", options: []FetchOption{FilterKey("0")}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				Fetch(TestingDummyContext{}, source, tc.options...)
			}
		})
	}
}

func BenchmarkCollectionEventAllocation(b *testing.B) {
	for _, count := range []int{1, 32} {
		for _, changed := range []bool{false, true} {
			b.Run(fmt.Sprintf("outputs=%d/changed=%v", count, changed), func(b *testing.B) {
				var values [2][]allocationItem
				for version := range values {
					for i := range count {
						values[version] = append(values[version], allocationItem{Name: fmt.Sprint(i), Value: version})
					}
				}
				parent := NewStaticCollection[allocationItem](nil, nil, WithStop(b.Context().Done()))
				collection := NewManyCollection(parent, func(_ HandlerContext, item allocationItem) []allocationItem {
					return values[item.Value]
				}, WithStop(b.Context().Done()))
				if !collection.WaitUntilSynced(b.Context().Done()) {
					b.Fatal("collection did not sync")
				}
				h := collection.internal().(*manyCollection[allocationItem, allocationItem])
				// No parent events are published; exercise the state transition synchronously.
				item := allocationItem{Name: "input"}
				events := []Event[allocationItem]{{New: &item, Event: controllers.EventUpdate}}
				h.handleChangedPrimaryInputEvents(events)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if changed {
						item.Value ^= 1
					}
					h.handleChangedPrimaryInputEvents(events)
				}
			})
		}
	}
}
