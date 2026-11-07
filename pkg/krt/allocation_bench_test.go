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
	"strconv"
	"testing"

	"github.com/openkruise/agentio/pkg/kube/controllers"
)

type allocationItem struct {
	Name  string
	Value int
}

func (i allocationItem) ResourceName() string { return i.Name }

type allocationIndexKey int

func (k allocationIndexKey) String() string { return strconv.Itoa(int(k)) }

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
	byValue := NewIndex(source, "value", func(i allocationItem) []allocationIndexKey { return []allocationIndexKey{allocationIndexKey(i.Value)} })
	for _, tc := range []struct {
		name    string
		options []FetchOption
	}{
		{name: "all"},
		{name: "index", options: []FetchOption{FilterIndex(index, "all")}},
		{name: "key", options: []FetchOption{FilterKey("0")}},
		{name: "index-stringer", options: []FetchOption{FilterIndex(byValue, allocationIndexKey(0))}},
		{name: "generic", options: []FetchOption{FilterGeneric(func(o any) bool { return o.(allocationItem).Value == 0 })}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				Fetch(TestingDummyContext{}, source, tc.options...)
			}
		})
	}
}

func BenchmarkFetchPointerAllocation(b *testing.B) {
	values := make([]*dependencyMatchObject, 128)
	for i := range values {
		values[i] = &dependencyMatchObject{
			Name: fmt.Sprint(i), Namespace: "ns", Labels: map[string]string{"app": "selected"},
		}
	}
	source := NewStaticCollection(nil, values, WithStop(b.Context().Done()))
	index := NewIndex(source, "namespace", func(o *dependencyMatchObject) []string { return []string{o.Namespace} })
	for _, tc := range []struct {
		name    string
		options []FetchOption
		want    int
	}{
		{name: "all", want: 128},
		{name: "key", options: []FetchOption{FilterKey("ns/0")}, want: 1},
		{name: "index", options: []FetchOption{FilterIndex(index, "ns")}, want: 128},
		{name: "label", options: []FetchOption{FilterLabel(map[string]string{"app": "selected"})}, want: 128},
	} {
		b.Run(tc.name, func(b *testing.B) {
			if got := len(Fetch(TestingDummyContext{}, source, tc.options...)); got != tc.want {
				b.Fatalf("got %d objects, want %d", got, tc.want)
			}
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
				h.handleChangedPrimaryInputEvents(events, 0, 0)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if changed {
						item.Value ^= 1
					}
					h.handleChangedPrimaryInputEvents(events, 0, 0)
				}
			})
		}
	}
}
