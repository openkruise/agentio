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

package demandcache

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type fakeLease struct {
	value    string
	ready    chan struct{}
	done     chan struct{}
	released atomic.Bool
}

func (l *fakeLease) Demand(ctx context.Context) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-l.done:
		return "", ErrClosed
	case <-l.ready:
		return l.value, nil
	}
}
func (l *fakeLease) Done() <-chan struct{} { return l.done }
func (l *fakeLease) Release()              { l.released.Store(true) }

type fakeSource struct {
	leases       map[key]*fakeLease
	acquisitions int
	pending      bool
}

func (s *fakeSource) Acquire(typ, name string) (Lease[string], error) {
	l := &fakeLease{value: name, ready: make(chan struct{}), done: make(chan struct{})}
	if !s.pending {
		close(l.ready)
	}
	if s.leases == nil {
		s.leases = map[key]*fakeLease{}
	}
	s.leases[key{typ, name}] = l
	s.acquisitions++
	return l, nil
}
func lookup(t *testing.T, c *Cache[string], typ, name string) string {
	t.Helper()
	value, err := c.Demand(t.Context(), typ, name)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestGlobalLRUAndLiveValues(t *testing.T) {
	source := &fakeSource{}
	cache, err := New(source, Config{MaxEntries: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	lookup(t, cache, "workload", "a")
	lookup(t, cache, "sandbox", "a")
	workload := source.leases[key{"workload", "a"}]
	sandbox := source.leases[key{"sandbox", "a"}]
	workload.value = "updated"
	if got := lookup(t, cache, "workload", "a"); got != "updated" {
		t.Fatal(got)
	}
	lookup(t, cache, "workload", "b")
	if !sandbox.released.Load() || workload.released.Load() {
		t.Fatal("global LRU did not evict least recently used type/name")
	}
	lookup(t, cache, "sandbox", "a")
	if source.acquisitions != 4 {
		t.Fatal("evicted entry was not reacquired")
	}
}

func TestIdleTTL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := &fakeSource{}
		cache, err := New(source, Config{IdleTTL: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		defer cache.Close()
		go func() {
			if err := cache.Run(t.Context()); err != nil {
				t.Error(err)
			}
		}()
		lookup(t, cache, "workload", "a")
		lease := source.leases[key{"workload", "a"}]
		if cache.Len() != 1 {
			t.Fatal("retained entry not counted")
		}
		time.Sleep(40 * time.Second)
		lookup(t, cache, "workload", "a")
		time.Sleep(40 * time.Second)
		synctest.Wait()
		if lease.released.Load() {
			t.Fatal("access did not refresh idle TTL")
		}
		lease.value = "control-plane update"
		time.Sleep(20 * time.Second)
		synctest.Wait()
		if !lease.released.Load() {
			t.Fatal("idle entry retained without traffic, or update refreshed TTL")
		}
		if cache.Len() != 0 {
			t.Fatal("expired entry still counted")
		}
		lookup(t, cache, "workload", "a")
		if source.acquisitions != 2 {
			t.Fatal("expired lease reused")
		}
	})
}

func TestPendingDemandsArePinnedAndShared(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := &fakeSource{pending: true}
		cache, err := New(source, Config{IdleTTL: time.Second, MaxEntries: 1})
		if err != nil {
			t.Fatal(err)
		}
		defer cache.Close()
		go func() {
			if err := cache.Run(t.Context()); err != nil {
				t.Error(err)
			}
		}()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		results := make(chan error, 3)
		for _, call := range []struct {
			ctx  context.Context
			name string
		}{{ctx, "a"}, {t.Context(), "a"}, {t.Context(), "b"}} {
			go func() {
				_, err := cache.Demand(call.ctx, "workload", call.name)
				results <- err
			}()
		}
		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		a, b := source.leases[key{"workload", "a"}], source.leases[key{"workload", "b"}]
		if a.released.Load() || b.released.Load() || source.acquisitions != 2 {
			t.Fatal("pending demands evicted or not shared")
		}
		cancel()
		if err := <-results; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if a.released.Load() {
			t.Fatal("one canceled waiter released another's demand")
		}
		close(a.ready)
		if err := <-results; err != nil {
			t.Fatal(err)
		}
		if !a.released.Load() || b.released.Load() {
			t.Fatal("soft capacity did not recover when demand completed")
		}
		close(b.ready)
		if err := <-results; err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if !b.released.Load() {
			t.Fatal("completed demand did not start idle TTL")
		}
	})
}

func TestFailedDemandAndEndedGeneration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := &fakeSource{pending: true}
		cache, err := New(source, Config{MaxEntries: 2})
		if err != nil {
			t.Fatal(err)
		}
		defer cache.Close()
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() {
			_, err := cache.Demand(ctx, "workload", "a")
			result <- err
		}()
		synctest.Wait()
		old := source.leases[key{"workload", "a"}]
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if !old.released.Load() {
			t.Fatal("abandoned pending lease retained")
		}
		source.pending = false
		lookup(t, cache, "workload", "a")
		old = source.leases[key{"workload", "a"}]
		close(old.done)
		lookup(t, cache, "workload", "a")
		if !old.released.Load() || source.acquisitions != 3 {
			t.Fatal("ended generation reused")
		}
		cache.Close()
		cache.Close()
		if _, err := cache.Demand(t.Context(), "workload", "a"); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if !source.leases[key{"workload", "a"}].released.Load() {
			t.Fatal("close retained lease")
		}
	})
}

func TestConfiguration(t *testing.T) {
	for _, config := range []Config{{IdleTTL: -time.Second}, {MaxEntries: -1}} {
		if _, err := New(&fakeSource{}, config); err == nil {
			t.Fatal("negative setting accepted")
		}
	}
	source := &fakeSource{}
	cache, err := New(source, Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	for _, name := range []string{"a", "b", "c"} {
		lookup(t, cache, "workload", name)
	}
	for _, lease := range source.leases {
		if lease.released.Load() {
			t.Fatal("zero configuration evicted entry")
		}
	}
}

func TestGetPinsResolvedDependencies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := &fakeSource{}
		cache, err := New(source, Config{IdleTTL: time.Second, MaxEntries: 1})
		if err != nil {
			t.Fatal(err)
		}
		defer cache.Close()
		_, releaseA, err := cache.Get(t.Context(), "workload", "a")
		if err != nil {
			t.Fatal(err)
		}
		_, releaseB, err := cache.Get(t.Context(), "policy", "b")
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		lookup(t, cache, "policy", "c")
		if cache.Len() != 2 || source.leases[key{"workload", "a"}].released.Load() ||
			source.leases[key{"policy", "b"}].released.Load() {
			t.Fatal("resolved dependencies were evicted while in use")
		}
		releaseA()
		if !source.leases[key{"workload", "a"}].released.Load() {
			t.Fatal("capacity did not recover after release")
		}
		releaseB()
		time.Sleep(500 * time.Millisecond)
		lookup(t, cache, "policy", "b")
		if source.acquisitions != 3 {
			t.Fatal("idle time started before consumer released the value")
		}
	})
}
