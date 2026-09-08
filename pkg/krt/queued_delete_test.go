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
	"sync"
	"testing"
	"time"

	"github.com/openkruise/agentio/pkg/kube/controllers"
)

type queuedDeleteItem struct{ Name, Value string }

func (x queuedDeleteItem) ResourceName() string { return x.Name }

// Exercise real parent events while a queue barrier models a busy consumer.
// Check intermediate deletions as well as convergence: a later Add can hide
// an obsolete Delete that temporarily withdrew the replacement's output.
func TestCollectionQueuedDelete(t *testing.T) {
	for _, tt := range []struct {
		name        string
		replacement string
		wantDeletes int
	}{
		{name: "same key recreated", replacement: "new", wantDeletes: 0},
		{name: "replacement no longer matches", replacement: "excluded", wantDeletes: 1},
		{name: "parent remains deleted", wantDeletes: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stop := make(chan struct{})
			defer close(stop)
			opts := NewOptionsBuilder(stop, "queued-delete", nil)
			parent := NewStaticCollection(nil, []queuedDeleteItem{{Name: "same-key", Value: "old"}}, opts.WithName("parent")...)
			out := NewCollection(parent, func(_ HandlerContext, x queuedDeleteItem) *queuedDeleteItem {
				if x.Value == "excluded" {
					return nil
				}
				return &x
			}, opts.WithName("output")...)
			if !out.WaitUntilSynced(stop) {
				t.Fatal("collection did not sync")
			}
			events := make(chan Event[queuedDeleteItem], 32)
			out.RegisterBatch(func(es []Event[queuedDeleteItem]) {
				for _, e := range es {
					events <- e
				}
			}, false)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			out.(*manyCollection[queuedDeleteItem, queuedDeleteItem]).queue.Push(func() error {
				close(entered)
				<-release
				return nil
			})
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("queue barrier timeout")
			}
			parent.UpdateObject(queuedDeleteItem{Name: "same-key", Value: "intermediate"})
			parent.DeleteObject("same-key")
			if tt.replacement != "" {
				parent.UpdateObject(queuedDeleteItem{Name: "same-key", Value: tt.replacement})
			}
			parent.UpdateObject(queuedDeleteItem{Name: "marker", Value: "queue drained"})
			unblock()
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			deletes := 0
			for {
				select {
				case ev := <-events:
					if ev.Latest().Name == "same-key" && ev.Event == controllers.EventDelete {
						deletes++
					}
					if ev.Latest().Name != "marker" {
						continue
					}
					if deletes != tt.wantDeletes {
						t.Fatalf("got %d downstream Deletes, want %d", deletes, tt.wantDeletes)
					}
					got := out.GetKey("same-key")
					if tt.replacement == "new" {
						if got == nil || got.Value != "new" {
							t.Fatalf("replacement output missing or outdated: %v", got)
						}
					} else if got != nil {
						t.Fatalf("unexpected retained output: %v", got)
					}
					return
				case <-timer.C:
					t.Fatal("event delivery timeout")
				}
			}
		})
	}
}

func TestIndexCollectionEmptyBucketIsAbsent(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	options := NewOptionsBuilder(stop, "empty-index", nil)
	parent := NewStaticCollection(nil, []queuedDeleteItem{{Name: "item", Value: "bucket"}}, options.WithName("parent")...)
	index := NewIndex(parent, "by-value", func(item queuedDeleteItem) []string { return []string{item.Value} }).AsCollection()
	if got := index.GetKey("bucket"); got == nil || len(got.Objects) != 1 {
		t.Fatalf("populated bucket = %v", got)
	}
	if got := index.GetKey("missing"); got != nil {
		t.Fatalf("missing bucket = %v", got)
	}
	parent.DeleteObject("item")
	if got := index.GetKey("bucket"); got != nil {
		t.Fatalf("deleted bucket = %v", got)
	}
}
