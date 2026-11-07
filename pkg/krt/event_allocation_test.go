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
	"testing"

	"istio.io/istio/pkg/test/util/assert"

	"github.com/openkruise/agentio/pkg/kube/controllers"
)

func TestCollectionOutputMembershipChanges(t *testing.T) {
	parent := NewStaticCollection[allocationItem](nil, nil, WithStop(t.Context().Done()))
	var output []allocationItem
	collection := NewManyCollection(
		parent,
		func(HandlerContext, allocationItem) []allocationItem { return output },
		WithStop(t.Context().Done()),
	)
	assert.EventuallyEqual(t, collection.HasSynced, true)
	index := NewIndex(
		collection,
		"value",
		func(item allocationItem) []string { return []string{fmt.Sprint(item.Value)} },
	)
	h := collection.internal().(*manyCollection[allocationItem, allocationItem])
	events := assert.NewTracker[string](t)
	collection.Register(func(e Event[allocationItem]) { events.Record(fmt.Sprintf("%v/%s", e.Event, e.Latest().Name)) })
	previous := map[string]allocationItem{}
	for _, count := range []int{32, 32, 8, 16, 0, 1} {
		output = nil
		wantEvents := []string{}
		next := map[string]allocationItem{}
		for i := range count {
			value := allocationItem{Name: fmt.Sprint(i), Value: count}
			output = append(output, value)
			next[value.Name] = value
			if old, found := previous[value.Name]; !found {
				wantEvents = append(wantEvents, "add/"+value.Name)
			} else if old != value {
				wantEvents = append(wantEvents, "update/"+value.Name)
			}
		}
		for name := range previous {
			if _, found := next[name]; !found {
				wantEvents = append(wantEvents, "delete/"+name)
			}
		}
		item := allocationItem{Name: "input"}
		h.handleChangedPrimaryInputEvents([]Event[allocationItem]{{New: &item, Event: controllers.EventUpdate}}, 0, 0)
		if len(wantEvents) == 0 {
			events.Empty()
		} else {
			events.WaitUnordered(wantEvents...)
		}
		assert.Equal(t, len(collection.List()), count)
		assert.Equal(t, len(index.Lookup(fmt.Sprint(count))), count)
		for _, value := range output {
			assert.Equal(t, collection.GetKey(value.Name), &value)
		}
		for _, old := range previous {
			if old.Value != count {
				assert.Equal(t, len(index.Lookup(fmt.Sprint(old.Value))), 0)
			}
		}
		previous = next
	}
	item := allocationItem{Name: "input"}
	h.handleChangedPrimaryInputEvents([]Event[allocationItem]{{Old: &item, Event: controllers.EventDelete}}, 0, 0)
	events.WaitOrdered("delete/0")
	assert.Equal(t, len(collection.List()), 0)
	assert.Equal(t, len(index.Lookup("1")), 0)
}

func TestCollectionBatchKeepsDiscardContext(t *testing.T) {
	parent := NewStaticCollection[allocationItem](nil, nil, WithStop(t.Context().Done()))
	collection := NewCollection(parent, func(ctx HandlerContext, item allocationItem) *allocationItem {
		if item.Value == 0 {
			ctx.DiscardResult()
			return nil
		}
		return &item
	}, WithStop(t.Context().Done()))
	assert.EventuallyEqual(t, collection.HasSynced, true)
	h := collection.internal().(*manyCollection[allocationItem, allocationItem])
	initial := allocationItem{Name: "input", Value: 1}
	h.handleChangedPrimaryInputEvents([]Event[allocationItem]{{New: &initial, Event: controllers.EventAdd}}, 0, 0)
	events := assert.NewTracker[string](t)
	collection.RegisterBatch(func(batch []Event[allocationItem]) {
		for _, event := range batch {
			events.Record(fmt.Sprint(event.Event))
		}
	}, false)
	discarded := allocationItem{Name: "input"}
	updated := allocationItem{Name: "input", Value: 2}
	h.handleChangedPrimaryInputEvents([]Event[allocationItem]{
		{New: &discarded, Event: controllers.EventUpdate},
		{New: &updated, Event: controllers.EventUpdate},
	}, 0, 0)
	events.WaitOrdered("update")
	assert.Equal(t, collection.GetKey("input"), &updated)
}
