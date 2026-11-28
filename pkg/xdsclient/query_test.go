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

package xdsclient

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestQueryRefreshAliasesAndNegativeTTL(t *testing.T) {
	var calls, compiled int
	content := "before"
	var backendErr error
	query := func(_ context.Context, _ string) (string, *anypb.Any, time.Duration, error) {
		calls++
		if backendErr != nil || content == "" {
			return "", nil, time.Second, backendErr
		}
		v, err := anypb.New(wrapperspb.String(content))
		return "uid", v, time.Second, err
	}
	withSubscriptionClient(t, Watch{
		TypeURL: testType,
		Query:   query,
		Transform: func(v *anypb.Any) (any, error) {
			compiled++
			msg := new(wrapperspb.StringValue)
			return msg, v.UnmarshalTo(msg)
		},
	}, func(t *testing.T, c *Client) {
		uid, alias := acquire(t, c, "uid"), acquire(t, c, "ns/host")
		get := func(s *Subscription) string {
			r, err := s.Demand(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			return r.Value.(*wrapperspb.StringValue).Value
		}
		sent := map[string]map[string]*subscription{}
		if len(c.initialRequests(sent)) != 0 || len(c.pendingRequests(sent)) != 0 {
			t.Fatal("query created an ADS interest")
		}
		if get(uid) != "before" || get(uid) != "before" || get(alias) != "before" || calls != 2 || compiled != 1 {
			t.Fatal(calls, compiled)
		}
		uid.Release()
		c.reset()
		if get(alias) != "before" || !c.Snapshot().Usable(testType) {
			t.Fatal("alias lost canonical value")
		}
		time.Sleep(time.Second)
		if get(alias) != "before" || calls != 3 || compiled != 1 {
			t.Fatal("unchanged policy recompiled", calls, compiled)
		}
		content = "after"
		time.Sleep(time.Second)
		if get(alias) != "after" || compiled != 2 {
			t.Fatal(compiled)
		}
		content = ""
		time.Sleep(time.Second)
		for range 2 {
			if _, err := alias.Demand(t.Context()); !errors.Is(err, ErrNotFound) {
				t.Fatal(err)
			}
		}
		if calls != 5 || len(c.Snapshot().Resources[testType]) != 0 {
			t.Fatal("absence was not cached or old policy retained")
		}
		content = "next"
		backendErr = errors.New("read failed")
		time.Sleep(time.Second)
		if _, err := alias.Demand(t.Context()); !errors.Is(err, backendErr) {
			t.Fatal(err)
		}
		backendErr = nil
		if get(alias) != "next" || calls != 7 {
			t.Fatal("source error was cached")
		}
		alias.Release()
		if len(c.types[testType].queried) != 0 || len(c.types[testType].resources) != 0 {
			t.Fatal("final release retained policy")
		}
	})
}

func TestQueryCoalescesIndependentWaiters(t *testing.T) {
	var calls atomic.Int32
	var gate chan struct{}
	query := func(ctx context.Context, name string) (string, *anypb.Any, time.Duration, error) {
		calls.Add(1)
		select {
		case <-ctx.Done():
			return "", nil, 0, ctx.Err()
		case <-gate:
		}
		v, err := anypb.New(wrapperspb.String(name))
		return name, v, 0, err
	}
	withSubscriptionClient(t, Watch{TypeURL: testType, Query: query}, func(t *testing.T, c *Client) {
		gate = make(chan struct{})
		abandoned, retained := acquire(t, c, "uid"), acquire(t, c, "uid")
		wait := func(ctx context.Context, s *Subscription) <-chan error {
			ch := make(chan error, 1)
			go func() {
				_, err := s.Demand(ctx)
				ch <- err
			}()
			return ch
		}
		old := wait(t.Context(), abandoned)
		short, cancel := context.WithCancel(t.Context())
		shortWait := wait(short, retained)
		var shared []<-chan error
		for range 16 {
			shared = append(shared, wait(t.Context(), retained))
		}
		synctest.Wait()
		abandoned.Release()
		cancel()
		synctest.Wait()
		if err := <-old; !errors.Is(err, ErrReleased) {
			t.Fatal(err)
		}
		if err := <-shortWait; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		close(gate)
		for _, ch := range shared {
			if err := <-ch; err != nil {
				t.Fatal(err)
			}
		}
		if calls.Load() != 1 {
			t.Fatal(calls.Load())
		}
		if _, err := retained.Demand(t.Context()); err != nil || calls.Load() != 2 {
			t.Fatal("zero TTL must refetch", err, calls.Load())
		}
		retained.Release()
	})
}
