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

package server

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestCachingSandboxLookupMergesConcurrentReads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		var calls atomic.Int32
		row := &model.Sandbox{UID: "vm:one", SourceIdentity: model.SourceIdentity{UID: "source-v1"}}
		source := sandboxSourceFunc(func(context.Context, model.ClientScope, string) (*model.Sandbox, error) {
			calls.Add(1)
			<-gate
			return row, nil
		})
		lookup := applyOptions([]Option{WithCachingSandboxLookup(source, time.Minute)}).sandboxLookup
		scope := model.ClientScope{Class: model.ClientEPE}
		for range 32 {
			go func() {
				payload, version, err := lookup.LookupSandbox(t.Context(), scope, "vm:one")
				if err != nil || payload.GetUid() != "vm:one" || version != "source-v1" {
					t.Error(payload, version, err)
				}
			}()
		}
		// Every caller is parked: one inside the source, the rest in singleflight.
		synctest.Wait()
		close(gate)
		synctest.Wait()
		if got := calls.Load(); got != 1 {
			t.Fatalf("concurrent source reads = %d, want 1", got)
		}
	})
}

func TestCachingSandboxLookupFetchOutlivesInitiator(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		var calls atomic.Int32
		row := &model.Sandbox{UID: "vm:one", SourceIdentity: model.SourceIdentity{UID: "source-v1"}}
		source := sandboxSourceFunc(func(ctx context.Context, _ model.ClientScope, _ string) (*model.Sandbox, error) {
			calls.Add(1)
			select {
			case <-gate:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return row, nil
		})
		lookup := applyOptions([]Option{WithCachingSandboxLookup(source, time.Minute)}).sandboxLookup
		scope := model.ClientScope{Class: model.ClientEPE}
		initCtx, cancel := context.WithCancel(t.Context())
		go func() {
			_, _, _ = lookup.LookupSandbox(initCtx, scope, "vm:one")
		}()
		synctest.Wait()
		cancel()
		var payload *sandboxv1.Sandbox
		var version string
		var err error
		go func() {
			payload, version, err = lookup.LookupSandbox(t.Context(), scope, "vm:one")
		}()
		synctest.Wait()
		close(gate)
		synctest.Wait()
		if err != nil || payload.GetUid() != "vm:one" || version != "source-v1" {
			t.Fatalf("waiter after initiator cancel: %v %v %v", payload, version, err)
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("source reads = %d, want 1", got)
		}
	})
}

func TestCachingSandboxLookupRefreshesAfterTTL(t *testing.T) {
	calls := 0
	source := sandboxSourceFunc(func(context.Context, model.ClientScope, string) (*model.Sandbox, error) {
		calls++
		return &model.Sandbox{
			UID:            "vm:one",
			SourceIdentity: model.SourceIdentity{UID: fmt.Sprintf("v%d", calls)},
		}, nil
	})
	lookup := applyOptions([]Option{WithCachingSandboxLookup(source, 20*time.Millisecond)}).sandboxLookup
	scope := model.ClientScope{Class: model.ClientEPE}
	for range 2 {
		payload, version, err := lookup.LookupSandbox(t.Context(), scope, "vm:one")
		if err != nil || payload.GetUid() != "vm:one" || version != "v1" {
			t.Fatal(payload, version, err)
		}
	}
	if calls != 1 {
		t.Fatalf("fresh source reads = %d, want 1", calls)
	}
	time.Sleep(30 * time.Millisecond)
	_, version, err := lookup.LookupSandbox(t.Context(), scope, "vm:one")
	if err != nil || version != "v2" || calls != 2 {
		t.Fatal(version, calls, err)
	}
}

func TestCachingSandboxLookupCachesAbsence(t *testing.T) {
	calls := 0
	source := sandboxSourceFunc(func(context.Context, model.ClientScope, string) (*model.Sandbox, error) {
		calls++
		return nil, nil
	})
	lookup := applyOptions([]Option{WithCachingSandboxLookup(source, 20*time.Millisecond)}).sandboxLookup
	scope := model.ClientScope{Class: model.ClientEPE}
	for range 2 {
		payload, version, err := lookup.LookupSandbox(t.Context(), scope, "missing")
		if err != nil || payload != nil || version != "" {
			t.Fatal(payload, version, err)
		}
	}
	if calls != 1 {
		t.Fatalf("absent source reads = %d, want 1", calls)
	}
	time.Sleep(30 * time.Millisecond)
	if _, _, err := lookup.LookupSandbox(t.Context(), scope, "missing"); err != nil || calls != 2 {
		t.Fatal(calls, err)
	}
}

func TestCachingSandboxLookupIsolatesClientClasses(t *testing.T) {
	calls := 0
	source := sandboxSourceFunc(func(_ context.Context, scope model.ClientScope, _ string) (*model.Sandbox, error) {
		calls++
		return &model.Sandbox{UID: "vm:one", SourceIdentity: model.SourceIdentity{UID: string(scope.Class)}}, nil
	})
	lookup := applyOptions([]Option{WithCachingSandboxLookup(source, time.Minute)}).sandboxLookup
	for _, class := range []model.ClientClass{model.ClientEPE, model.ClientEgressGateway} {
		for range 2 {
			_, version, err := lookup.LookupSandbox(t.Context(), model.ClientScope{Class: class}, "vm:one")
			if err != nil || version != string(class) {
				t.Fatal(class, version, err)
			}
		}
	}
	if calls != 2 {
		t.Fatalf("cross-class source reads = %d, want 2", calls)
	}
}

func TestCachingSandboxLookupDoesNotCacheErrors(t *testing.T) {
	calls := 0
	sourceErr := errors.New("database connection lost")
	row := &model.Sandbox{
		UID:            "vm:one",
		SourceIdentity: model.SourceIdentity{UID: "source-v1"},
		Policies:       &model.SandboxPolicies{InputError: "invalid rule in database"},
	}
	source := sandboxSourceFunc(func(context.Context, model.ClientScope, string) (*model.Sandbox, error) {
		calls++
		if sourceErr != nil {
			return nil, sourceErr
		}
		return row, nil
	})
	lookup := applyOptions([]Option{WithCachingSandboxLookup(source, time.Minute)}).sandboxLookup
	scope := model.ClientScope{Class: model.ClientEPE}
	if _, _, err := lookup.LookupSandbox(t.Context(), scope, "vm:one"); !errors.Is(err, sourceErr) {
		t.Fatal(err)
	}
	sourceErr = nil
	if _, _, err := lookup.LookupSandbox(t.Context(), scope, "vm:one"); status.Code(err) != codes.FailedPrecondition {
		t.Fatal(err)
	}
	row.Policies = nil
	payload, version, err := lookup.LookupSandbox(t.Context(), scope, "vm:one")
	if err != nil || payload.GetUid() != "vm:one" || version != "source-v1" || calls != 3 {
		t.Fatal(payload, version, calls, err)
	}
}

func TestCachingSandboxLookupNonPositiveTTLReadsFresh(t *testing.T) {
	calls := 0
	source := sandboxSourceFunc(func(context.Context, model.ClientScope, string) (*model.Sandbox, error) {
		calls++
		return &model.Sandbox{UID: "vm:one"}, nil
	})
	for _, ttl := range []time.Duration{0, -time.Second} {
		lookup := applyOptions([]Option{WithCachingSandboxLookup(source, ttl)}).sandboxLookup
		for range 2 {
			if _, _, err := lookup.LookupSandbox(t.Context(), model.ClientScope{Class: model.ClientEPE}, "vm:one"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if calls != 4 {
		t.Fatalf("non-positive TTL source reads = %d, want 4", calls)
	}
}

func TestSandboxLookupOptionsLastWriterWins(t *testing.T) {
	source := sandboxSourceFunc(func(context.Context, model.ClientScope, string) (*model.Sandbox, error) {
		return nil, nil
	})
	caching := applyOptions([]Option{WithSandboxLookup(source), WithCachingSandboxLookup(source, time.Minute)}).sandboxLookup
	if _, ok := caching.(*cachingSandboxLookup); !ok {
		t.Fatalf("WithCachingSandboxLookup did not replace WithSandboxLookup: %T", caching)
	}
	compiled := applyOptions([]Option{WithCachingSandboxLookup(source, time.Minute), WithSandboxLookup(source)}).sandboxLookup
	if _, ok := compiled.(compiledSandboxLookup); !ok {
		t.Fatalf("WithSandboxLookup did not replace WithCachingSandboxLookup: %T", compiled)
	}
}
