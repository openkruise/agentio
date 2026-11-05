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
	"testing/synctest"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/openkruise/agentio/pkg/kube/controllers"
)

type queuedDeleteItem struct {
	Name  string
	Value string
	UID   types.UID
}

func (x queuedDeleteItem) ResourceName() string { return x.Name }
func (x queuedDeleteItem) GetUID() types.UID    { return x.UID }

func TestCollectionDiscardUsesRetainedUID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		options := []CollectionOption{WithStop(t.Context().Done())}
		parent := NewMutableCollection[queuedDeleteItem](nil, nil, options...)
		out := NewCollection(parent.AsCollection(), func(ctx HandlerContext, item queuedDeleteItem) *queuedDeleteItem {
			if item.Value == "invalid" || item.Value == "invalid-again" {
				ctx.DiscardResult()
				return nil
			}
			return &item
		}, options...)
		for _, step := range []struct {
			uid   types.UID
			value string
			want  string
		}{
			{uid: "old", value: "valid", want: "valid"},
			{uid: "old", value: "invalid", want: "valid"},
			{uid: "old", value: "invalid-again", want: "valid"},
			{uid: "new", value: "invalid"},
			{uid: "new", value: "invalid-again"},
			{uid: "new", value: "recovered", want: "recovered"},
		} {
			parent.UpdateObject(queuedDeleteItem{Name: "same-key", UID: step.uid, Value: step.value})
			synctest.Wait()
			got := out.GetKey("same-key")
			if step.want == "" {
				if got != nil {
					t.Fatalf("%s/%s retained another object's result: %+v", step.uid, step.value, got)
				}
			} else if got == nil || got.UID != step.uid || got.Value != step.want {
				t.Fatalf("%s/%s: got %+v, want %s", step.uid, step.value, got, step.want)
			}
		}
	})
}

// Exercise real parent events while a queue barrier models a busy consumer.
// Check intermediate deletions as well as convergence: a later Add can hide
// an obsolete Delete that temporarily withdrew the replacement's output.
func TestCollectionQueuedDelete(t *testing.T) {
	for _, tc := range []struct {
		name        string
		replacement string
		uid         types.UID
		wantValue   string
		wantDeletes int
	}{
		{name: "same key recreated", replacement: "new", uid: "new", wantValue: "new", wantDeletes: 0},
		{name: "same object failed update", replacement: "invalid", uid: "old", wantValue: "old", wantDeletes: 0},
		{name: "recreated object failed compilation", replacement: "invalid", uid: "new", wantDeletes: 1},
		{name: "replacement no longer matches", replacement: "excluded", wantDeletes: 1},
		{name: "parent remains deleted", wantDeletes: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stop := make(chan struct{})
			defer close(stop)
			opts := NewOptionsBuilder(stop, "queued-delete", nil)
			parent := NewMutableCollection(
				nil,
				[]queuedDeleteItem{{Name: "same-key", Value: "old", UID: "old"}},
				opts.WithName("parent")...)
			out := NewCollection(parent.AsCollection(), func(ctx HandlerContext, x queuedDeleteItem) *queuedDeleteItem {
				if x.Value == "invalid" {
					ctx.DiscardResult()
					return nil
				}
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
			out.internal().(*manyCollection[queuedDeleteItem, queuedDeleteItem]).queue.Push(func() error {
				close(entered)
				<-release
				return nil
			})
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("queue barrier timeout")
			}
			parent.UpdateObject(queuedDeleteItem{Name: "same-key", Value: "intermediate", UID: "old"})
			if tc.uid != "old" {
				parent.DeleteObject("same-key")
			}
			if tc.replacement != "" {
				parent.UpdateObject(queuedDeleteItem{Name: "same-key", Value: tc.replacement, UID: tc.uid})
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
					if deletes != tc.wantDeletes {
						t.Fatalf("got %d downstream Deletes, want %d", deletes, tc.wantDeletes)
					}
					got := out.GetKey("same-key")
					if tc.wantValue != "" {
						if got == nil || got.Value != tc.wantValue {
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
	parent := NewMutableCollection(
		nil,
		[]queuedDeleteItem{{Name: "item", Value: "bucket"}},
		options.WithName("parent")...)
	index := NewIndex(
		parent.AsCollection(),
		"by-value",
		func(item queuedDeleteItem) []string { return []string{item.Value} },
	).AsCollection()
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
