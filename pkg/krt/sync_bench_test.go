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
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/openkruise/agentio/pkg/kube/controllers"
)

func BenchmarkKRTSyncSelectiveFetch(b *testing.B) {
	for _, tc := range []struct {
		name       string
		size       int
		namespaces int
	}{{"128", 128, 1}, {"10000", 10000, 1}, {"10000-partial", 20000, 2}} {
		b.Run(tc.name, func(b *testing.B) {
			values := make([]*dependencyMatchObject, tc.size)
			for i := range values {
				values[i] = &dependencyMatchObject{
					Name:      strconv.Itoa(i),
					Namespace: "ns-" + strconv.Itoa(i%tc.namespaces),
					Labels:    map[string]string{"app": "other"},
				}
			}
			values[0].Labels["app"] = "selected"
			source := NewStaticCollection(nil, values, WithStop(b.Context().Done()))
			index := NewIndex(
				source,
				"namespace",
				func(o *dependencyMatchObject) []string { return []string{o.Namespace} },
			)
			opts := []FetchOption{FilterIndex(index, "ns-0"), FilterLabel(map[string]string{"app": "selected"})}
			b.ReportAllocs()
			for b.Loop() {
				if len(Fetch(TestingDummyContext{}, source, opts...)) != 1 {
					b.Fatal("expected one selected object")
				}
			}
		})
	}
}

func BenchmarkKRTSyncBurstRecompute(b *testing.B) {
	stop := b.Context().Done()
	values := make([]allocationItem, 128)
	for i := range values {
		values[i] = allocationItem{Name: fmt.Sprint(i)}
	}
	source := NewStaticCollection(nil, values, WithStop(stop))
	parent := NewStaticCollection(nil, []allocationItem{{Name: "input"}}, WithStop(stop))
	var runs atomic.Uint64
	collection := NewCollection(parent, func(ctx HandlerContext, item allocationItem) *allocationItem {
		runs.Add(1)
		item.Value = len(Fetch(ctx, source))
		return &item
	}, WithStop(stop))
	if !collection.WaitUntilSynced(stop) {
		b.Fatal("collection did not sync")
	}
	h := collection.internal().(*manyCollection[allocationItem, allocationItem])
	var value any = values[0]
	events := []Event[any]{{Old: &value, New: &value, Event: controllers.EventUpdate}}
	initial := runs.Load()
	iterations := 0
	b.ReportAllocs()
	for b.Loop() {
		blocked, release, drained := make(chan struct{}), make(chan struct{}), make(chan struct{})
		h.queue.Push(func() error {
			close(blocked)
			<-release
			return nil
		})
		<-blocked
		// All 128 events describe state already visible before the queue resumes.
		for range 128 {
			h.enqueueSecondaryEvents(source.uid(), events)
		}
		h.queue.Push(func() error {
			close(drained)
			return nil
		})
		close(release)
		<-drained
		iterations++
	}
	b.ReportMetric(float64(runs.Load()-initial)/float64(iterations), "transforms/op")
	if collection.GetKey("input").Value != len(values) {
		b.Fatal("incorrect final output")
	}
}
