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

package controller

import (
	"container/heap"
	"time"
)

const saturatedRetryDelay = 100 * time.Millisecond

type entryHeap []*entry

func (h entryHeap) Len() int { return len(h) }

func (h entryHeap) Less(i, j int) bool {
	if h[i].next.Equal(h[j].next) {
		return h[i].hostname < h[j].hostname
	}
	return h[i].next.Before(h[j].next)
}

func (h entryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *entryHeap) Push(value any) {
	item := value.(*entry)
	item.index = len(*h)
	item.inHeap = true
	*h = append(*h, item)
}

func (h *entryHeap) Pop() any {
	old := *h
	last := len(old) - 1
	item := old[last]
	old[last] = nil
	*h = old[:last]
	item.index = -1
	item.inHeap = false
	return item
}

func (r *Resolver) scheduleLocked(item *entry) {
	if item.inHeap {
		heap.Fix(&r.schedule, item.index)
		return
	}
	heap.Push(&r.schedule, item)
}

func (r *Resolver) removeScheduledLocked(item *entry) {
	if item.inHeap {
		heap.Remove(&r.schedule, item.index)
	}
}

func (r *Resolver) signalScheduler() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *Resolver) run() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		wait := r.dispatchDue()
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
		select {
		case <-r.ctx.Done():
			return
		case <-r.wake:
		case <-timer.C:
		}
	}
}

func (r *Resolver) dispatchDue() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for r.schedule.Len() > 0 {
		item := r.schedule[0]
		if item.next.After(now) {
			return item.next.Sub(now)
		}
		heap.Pop(&r.schedule)
		// A cold Resolve has no tracked owner. Keep its answer available for
		// one refresh period, then evict it instead of refreshing forever.
		if item.refs == 0 && item.published {
			delete(r.entries, item.hostname)
			r.results.DeleteObject(item.hostname)
			continue
		}
		if item.resolving {
			continue
		}
		item.resolving = true
		select {
		case r.jobs <- item.hostname:
		default:
			item.resolving = false
			item.next = now.Add(saturatedRetryDelay)
			r.scheduleLocked(item)
			return saturatedRetryDelay
		}
	}
	return time.Hour
}

func (r *Resolver) worker() {
	for {
		select {
		case <-r.ctx.Done():
			return
		case host := <-r.jobs:
			r.refresh(host)
		}
	}
}
