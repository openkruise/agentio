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

	"istio.io/istio/pkg/test/util/assert"
)

func TestJoinIndexKeepsFirstWinner(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values [][]allocationItem
	}{
		{"same bucket", [][]allocationItem{{{Name: "same", Value: 1}}, {{Name: "same", Value: 2}}}},
		{"winner has no index keys", [][]allocationItem{{{Name: "same"}}, {{Name: "same", Value: 2}}}},
		{"winner in middle collection", [][]allocationItem{nil, {{Name: "same", Value: 1}}, {{Name: "same", Value: 2}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := []CollectionOption{WithStop(t.Context().Done())}
			var sources []Collection[allocationItem]
			for _, values := range tc.values {
				sources = append(sources, NewStaticCollection(nil, values, opts...))
			}
			joined := JoinCollection(sources, opts...)
			assert.Equal(t, joined.WaitUntilSynced(t.Context().Done()), true)
			all := NewIndex(joined, "all", func(allocationItem) []string { return []string{"all"} })
			byValue := NewIndex(joined, "value", func(o allocationItem) []string {
				if o.Value == 0 {
					return nil
				}
				return []string{strconv.Itoa(o.Value)}
			})
			assert.Equal(t, all.Lookup("all"), joined.List())
			calls := 0
			all.LookupFiltered("all", func(allocationItem) bool {
				calls++
				return true
			})
			assert.Equal(t, calls, 1)
			assert.Equal(t, len(byValue.Lookup("2")), 0)
			assert.Equal(t, len(all.LookupFiltered("all", func(o allocationItem) bool { return o.Value == 2 })), 0)
			assert.Equal(t, all.Fetch(TestingDummyContext{}, "all"), joined.List())
			assert.Equal(t, len(byValue.Fetch(TestingDummyContext{}, "2")), 0)
			assert.Equal(t, len(all.Lookup("missing")), 0)
			buckets := all.AsCollection(opts...)
			assert.Equal(t, FetchIndexObjects(TestingDummyContext{}, buckets, "all"), joined.List())
		})
	}
}

func TestJoinIndexTracksWinnerChanges(t *testing.T) {
	opts := []CollectionOption{WithStop(t.Context().Done())}
	first := NewMutableCollection(nil, []allocationItem{{Name: "same", Value: 1}}, opts...)
	second := NewMutableCollection(nil, []allocationItem{{Name: "same", Value: 2}}, opts...)
	joined := JoinCollection([]Collection[allocationItem]{first.AsCollection(), second.AsCollection()}, opts...)
	byValue := NewIndex(joined, "value", func(o allocationItem) []string { return []string{strconv.Itoa(o.Value)} })
	all := NewIndex(joined, "all", func(allocationItem) []string { return []string{"all"} })
	selected := NewSingleton(func(ctx HandlerContext) *string {
		return new(strconv.Itoa(len(byValue.Fetch(ctx, "2"))))
	}, opts...)
	assert.Equal(t, selected.AsCollection().WaitUntilSynced(t.Context().Done()), true)
	assert.Equal(t, selected.Get(), new("0"))

	first.UpdateObject(allocationItem{Name: "same", Value: 3})
	assert.EventuallyEqual(t, func() int { return len(byValue.Lookup("3")) }, 1)
	assert.Equal(t, all.Lookup("all"), []allocationItem{{Name: "same", Value: 3}})
	assert.Equal(t, len(byValue.Lookup("2")), 0)
	assert.Equal(t, byValue.Lookup("3"), joined.List())
	first.DeleteObject("same")
	assert.EventuallyEqual(t, func() int { return len(byValue.Lookup("2")) }, 1)
	assert.Equal(t, all.Lookup("all"), []allocationItem{{Name: "same", Value: 2}})
	assert.Equal(t, byValue.Lookup("2"), joined.List())
	assert.EventuallyEqual(t, selected.Get, new("1"))
	first.UpdateObject(allocationItem{Name: "same", Value: 1})
	assert.EventuallyEqual(t, func() int { return len(byValue.Lookup("1")) }, 1)
	assert.Equal(t, all.Lookup("all"), []allocationItem{{Name: "same", Value: 1}})
	assert.Equal(t, len(byValue.Lookup("2")), 0)
	assert.EventuallyEqual(t, selected.Get, new("0"))
	second.UpdateObject(allocationItem{Name: "same", Value: 4})
	assert.Equal(t, len(byValue.Lookup("4")), 0)
	first.DeleteObject("same")
	assert.EventuallyEqual(t, func() int { return len(byValue.Lookup("4")) }, 1)
	assert.Equal(t, byValue.Lookup("4"), joined.List())
	second.DeleteObject("same")
	assert.EventuallyEqual(t, func() int { return len(byValue.Lookup("4")) }, 0)
	assert.Equal(t, len(all.Lookup("all")), 0)
}

func TestJoinIndexNestedOverlap(t *testing.T) {
	opts := []CollectionOption{WithStop(t.Context().Done())}
	first := NewStaticCollection(nil, []allocationItem{{Name: "same", Value: 1}}, opts...)
	second := NewStaticCollection(nil, []allocationItem{{Name: "same", Value: 2}}, opts...)
	inner := JoinCollection([]Collection[allocationItem]{first, second}, opts...)
	joined := JoinCollection([]Collection[allocationItem]{first, inner}, opts...)
	assert.Equal(t, joined.WaitUntilSynced(t.Context().Done()), true)
	all := NewIndex(joined, "all", func(allocationItem) []string { return []string{"all"} })
	assert.Equal(t, all.Lookup("all"), []allocationItem{{Name: "same", Value: 1}})
}
