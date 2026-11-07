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
	"strconv"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/test/util/assert"

	"github.com/openkruise/agentio/pkg/kube/controllers"
)

func TestCollectionQueryMethods(t *testing.T) {
	source := NewStaticCollection(
		nil,
		[]allocationItem{{Name: "b", Value: 1}, {Name: "a", Value: 2}},
		WithStop(t.Context().Done()),
	)
	ctx := TestingDummyContext{}
	assert.Equal(t, source.ListSorted(), []allocationItem{{Name: "a", Value: 2}, {Name: "b", Value: 1}})
	assert.Equal(t, source.FetchSorted(ctx), source.ListSorted())
	assert.Equal(
		t,
		ListSortedBy(source, func(o allocationItem) int { return o.Value }),
		[]allocationItem{{Name: "b", Value: 1}, {Name: "a", Value: 2}},
	)
	assert.Equal(t, source.FetchOne(ctx, FilterKey("a")), new(allocationItem{Name: "a", Value: 2}))
	assert.Equal(t, source.FetchOne(ctx, FilterKey("missing")), nil)
	assert.Equal(t, source.Fetch(ctx, FilterKey("b")), source.FetchOrList(nil, FilterKey("b")))
	assert.Equal(
		t,
		source.ListFiltered(func(o allocationItem) bool { return o.Value == 2 }),
		[]allocationItem{{Name: "a", Value: 2}},
	)
	var absent Collection[allocationItem]
	assert.Equal(t, absent == nil, true)
}

func TestPartialFetchPreservesMembershipChanges(t *testing.T) {
	for _, mode := range []string{"scan", "index", "key", "generic"} {
		t.Run(mode, func(t *testing.T) {
			f := newDependencyMatchFixture(t)
			options := []FetchOption{FilterLabel(map[string]string{"app": "selected"})}
			switch mode {
			case "index":
				options = append(options, FilterIndex(f.byNamespace, "ns"))
			case "key":
				options = append(options, FilterKey("ns/a"))
			case "generic":
				options = []FetchOption{
					FilterGeneric(func(o any) bool { return o.(dependencyMatchObject).Labels["app"] == "selected" }),
				}
			}
			ctx := &dependencyCaptureContext{}
			PartialFetchComparable(ctx, f.source, func(o dependencyMatchObject) string { return o.Name }, options...)
			f.state.update("consumer", ctx.dependencies, 0)
			for _, tc := range []struct {
				name string
				old  string
				next string
				want int
			}{
				{"unused field", "selected", "selected", 0},
				{"enters query", "other", "selected", 1},
				{"leaves query", "selected", "other", 1},
				{"outside query", "other", "other", 0},
			} {
				t.Run(tc.name, func(t *testing.T) {
					event := Event[any]{
						Old:   dependencyMatchValue("ns", "a", tc.old),
						New:   dependencyMatchValue("ns", "a", tc.next),
						Event: controllers.EventUpdate,
					}
					assert.Equal(t, len(f.state.changedInputKeys(f.sourceID, []Event[any]{event})), tc.want)
				})
			}
			for _, event := range []Event[any]{
				{New: dependencyMatchValue("ns", "a", "selected"), Event: controllers.EventAdd},
				{Old: dependencyMatchValue("ns", "a", "selected"), Event: controllers.EventDelete},
			} {
				assert.Equal(t, len(f.state.changedInputKeys(f.sourceID, []Event[any]{event})), 1)
			}
			// A full fetch of the same source must still invalidate when the projection is equal.
			Fetch(ctx, f.source)
			f.state.update("consumer", ctx.dependencies, 0)
			event := Event[any]{
				Old:   dependencyMatchValue("ns", "a", "selected"),
				New:   dependencyMatchValue("ns", "a", "selected"),
				Event: controllers.EventUpdate,
			}
			assert.Equal(t, len(f.state.changedInputKeys(f.sourceID, []Event[any]{event})), 1)
		})
	}
}

func TestPartialFetchAndResourceExists(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns"}}
	source := NewStaticCollection(nil, []*corev1.Pod{pod}, WithStop(t.Context().Done()))
	ctx := &dependencyCaptureContext{}
	assert.Equal(t, ResourceExists(ctx, source, "ns/a"), true)
	assert.Equal(t, ResourceExists(TestingDummyContext{}, source, "ns/missing"), false)
	old := any(pod)
	updated := pod.DeepCopy()
	updated.Labels = map[string]string{"changed": "true"}
	next := any(updated)
	assert.Equal(
		t,
		ctx.dependencies[0].filter.SuppressChange(Event[any]{Old: &old, New: &next, Event: controllers.EventUpdate}),
		true,
	)
	assert.Equal(
		t,
		ctx.dependencies[0].filter.SuppressChange(Event[any]{Old: &old, Event: controllers.EventDelete}),
		false,
	)
	assert.Equal(
		t,
		PartialFetchComparable(TestingDummyContext{}, source, func(p *corev1.Pod) string { return p.Name }),
		[]string{"a"},
	)
}

func TestIndexQueryMethods(t *testing.T) {
	source := NewMutableCollection(
		nil,
		[]allocationItem{{Name: "a", Value: 1}, {Name: "b", Value: 2}},
		WithStop(t.Context().Done()),
	)
	indexes := make([]Index[string, allocationItem], 0, 2)
	for _, offset := range []int{0, 10} {
		indexes = append(
			indexes,
			UnnamedIndex(
				source.AsCollection(),
				func(o allocationItem) []string { return []string{strconv.Itoa(o.Value + offset)} },
			),
		)
	}
	ctx := &dependencyCaptureContext{}
	assert.Equal(t, indexes[0].Fetch(ctx, "1"), []allocationItem{{Name: "a", Value: 1}})
	assert.Equal(t, len(ctx.dependencies), 1)
	assert.Equal(t, indexes[1].Fetch(TestingDummyContext{}, "11"), []allocationItem{{Name: "a", Value: 1}})
	assert.Equal(t, len(indexes[1].Lookup("1")), 0)
	buckets := indexes[0].AsCollection(WithStop(t.Context().Done()))
	assert.Equal(
		t,
		len(buckets.ListFiltered(func(o IndexObject[string, allocationItem]) bool { return o.Key == "1" })),
		1,
	)
	assert.Equal(t, FetchIndexObjects(TestingDummyContext{}, buckets, "2"), []allocationItem{{Name: "b", Value: 2}})
	source.DeleteObject("b")
	assert.Equal(t, FetchIndexObjects(TestingDummyContext{}, buckets, "2"), nil)
	assert.Equal(t, len(buckets.List()), 1)
}

func TestStringerIndexFetchTracksMembership(t *testing.T) {
	stop := t.Context().Done()
	source := NewMutableCollection(nil, []allocationItem{{Name: "a", Value: 1}}, WithStop(stop))
	byValue := NewIndex(source.AsCollection(), "value", func(o allocationItem) []allocationIndexKey {
		return []allocationIndexKey{allocationIndexKey(o.Value)}
	})
	selected := NewSingleton(func(ctx HandlerContext) *string {
		items := Fetch(ctx, source.AsCollection(), FilterIndex(byValue, allocationIndexKey(1)))
		result := ""
		for _, item := range items {
			result += item.Name
		}
		return &result
	}, WithStop(stop))
	assert.Equal(t, selected.AsCollection().WaitUntilSynced(stop), true)
	assert.Equal(t, selected.Get(), new("a"))
	source.UpdateObject(allocationItem{Name: "a", Value: 2})
	assert.EventuallyEqual(t, selected.Get, new(""))
	source.UpdateObject(allocationItem{Name: "b", Value: 1})
	assert.EventuallyEqual(t, selected.Get, new("b"))
	source.DeleteObject("b")
	assert.EventuallyEqual(t, selected.Get, new(""))
}

func TestJoinFilteredKeepsFirstWinner(t *testing.T) {
	opts := []CollectionOption{WithStop(t.Context().Done())}
	first := NewStaticCollection(nil, []allocationItem{{Name: "same", Value: 1}}, opts...)
	second := NewStaticCollection(nil, []allocationItem{{Name: "same", Value: 2}}, opts...)
	joined := JoinCollection([]Collection[allocationItem]{first, second}, opts...)
	assert.Equal(t, joined.WaitUntilSynced(t.Context().Done()), true)
	assert.Equal(t, len(joined.ListFiltered(func(o allocationItem) bool { return o.Value == 2 })), 0)
	assert.Equal(t, joined.GetKey("same"), new(allocationItem{Name: "same", Value: 1}))
}

type pointerKeyItem struct{ name string }

func (p *pointerKeyItem) ResourceName() string { return p.name }

func TestPointerCollectionRetainsOutput(t *testing.T) {
	stop := t.Context().Done()
	source := NewMutableCollection(nil, []allocationItem{{Name: "a", Value: 1}}, WithStop(stop))
	output := &pointerKeyItem{name: "a"}
	result := NewPointerCollection(source.AsCollection(), func(_ HandlerContext, item allocationItem) *pointerKeyItem {
		if item.Value == 0 {
			return nil
		}
		return output
	}, WithStop(stop))
	assert.Equal(t, result.WaitUntilSynced(stop), true)
	assert.Equal(t, *result.GetKey("a") == output, true)
	assert.Equal(t, GetKey(ObjectWithCluster[pointerKeyItem]{Object: output}), "a")
	source.UpdateObject(allocationItem{Name: "a"})
	assert.EventuallyEqual(t, func() int { return len(result.List()) }, 0)
}

func TestDelayedCollectionQueries(t *testing.T) {
	ready := make(chan struct{})
	stop := t.Context().Done()
	inner := NewStatic(new(allocationItem{Name: "a", Value: 1}), true, WithStop(stop))
	delayed := NewDelayedSingleton[allocationItem](
		channelSyncer{synced: ready},
		func() Singleton[allocationItem] { return inner },
		stop,
	)
	source := delayed.AsCollection()
	index := NewIndex(source, "value", func(o allocationItem) []string { return []string{strconv.Itoa(o.Value)} })
	assert.Equal(t, source.uid(), delayed.AsCollection().uid())
	assert.Equal(t, len(source.ListFiltered(nil)), 0)
	result := NewSingleton(func(ctx HandlerContext) *allocationItem { return source.FetchOne(ctx) }, WithStop(stop))
	close(ready)
	assert.Equal(t, result.AsCollection().WaitUntilSynced(stop), true)
	assert.Equal(t, result.Get(), new(allocationItem{Name: "a", Value: 1}))
	assert.Equal(t, index.Lookup("1"), []allocationItem{{Name: "a", Value: 1}})
	assert.Equal(t, len(index.LookupFiltered("1", func(o allocationItem) bool { return o.Value == 2 })), 0)
	inner.Set(new(allocationItem{Name: "a", Value: 2}))
	assert.EventuallyEqual(t, result.Get, new(allocationItem{Name: "a", Value: 2}))
	assert.Equal(t, len(index.Lookup("1")), 0)
}
