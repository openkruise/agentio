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
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/pkg/model"
)

func benchSandboxRow() *model.Sandbox {
	return &model.Sandbox{
		UID:            "vm:one",
		Name:           "one",
		Namespace:      "bench",
		SourceIdentity: model.SourceIdentity{UID: "src-v1"},
		Attester:       &model.Attester{WorkloadUID: "host"},
		Policies: &model.SandboxPolicies{SecurityProfile: &agents.SecurityProfileSpec{
			Rules: []agents.SecurityRule{{
				Name:  "http-0",
				Match: []agents.RuleMatch{{Domains: []string{"api.example.com"}, Ports: []int32{443}, Schemes: []string{"https"}}},
			}},
		}},
	}
}

// Hit path only: mutex, map probe, expiry check. The source is read once.
func BenchmarkCachingSandboxLookupHit(b *testing.B) {
	for _, keys := range []int{1, 1000} {
		b.Run(fmt.Sprintf("Keys%d", keys), func(b *testing.B) {
			var calls atomic.Int64
			source := sandboxSourceFunc(func(context.Context, model.ClientScope, string) (*model.Sandbox, error) {
				calls.Add(1)
				return benchSandboxRow(), nil
			})
			l := applyOptions([]Option{WithCachingSandboxLookup(source, time.Minute)}).sandboxLookup
			scope := model.ClientScope{Class: model.ClientEPE}
			names := make([]string, keys)
			for i := range names {
				names[i] = fmt.Sprintf("vm:%06d", i)
				if _, _, err := l.LookupSandbox(b.Context(), scope, names[i]); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					if _, _, err := l.LookupSandbox(b.Context(), scope, names[i%keys]); err != nil {
						b.Fatal(err)
					}
					i++
				}
			})
			if got := calls.Load(); got != int64(keys) {
				b.Fatalf("source reads = %d, want %d", got, keys)
			}
		})
	}
}

// What the cache saves: one source read plus CompileSandboxPayload per call.
func BenchmarkSandboxLookupCompile(b *testing.B) {
	source := sandboxSourceFunc(func(context.Context, model.ClientScope, string) (*model.Sandbox, error) {
		return benchSandboxRow(), nil
	})
	l := applyOptions([]Option{WithSandboxLookup(source)}).sandboxLookup
	scope := model.ClientScope{Class: model.ClientEPE}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, _, err := l.LookupSandbox(b.Context(), scope, "vm:one"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Refresh path: expired entry, source read, compile, and cache insert.
func BenchmarkCachingSandboxLookupRefresh(b *testing.B) {
	source := sandboxSourceFunc(func(context.Context, model.ClientScope, string) (*model.Sandbox, error) {
		return benchSandboxRow(), nil
	})
	l := applyOptions([]Option{WithCachingSandboxLookup(source, time.Minute)}).sandboxLookup.(*cachingSandboxLookup)
	scope := model.ClientScope{Class: model.ClientEPE}
	key := sandboxCacheKey{class: scope.Class, name: "vm:one"}
	if _, _, err := l.LookupSandbox(b.Context(), scope, key.name); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		l.mu.Lock()
		entry := l.entries[key]
		entry.expires = time.Now().Add(-time.Second)
		l.entries[key] = entry
		l.mu.Unlock()
		if _, _, err := l.LookupSandbox(b.Context(), scope, key.name); err != nil {
			b.Fatal(err)
		}
	}
}