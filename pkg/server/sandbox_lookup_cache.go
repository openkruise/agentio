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
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/pkg/model"
)

// WithCachingSandboxLookup compiles each Sandbox once per TTL instead of once
// per GetSandbox RPC. It sets the same seam as WithSandboxLookup, so the last
// option applied wins. A non-positive TTL reads fresh on every call.
func WithCachingSandboxLookup(source SandboxSource, ttl time.Duration) Option {
	return func(cmp *composition) {
		cmp.sandboxLookup = &cachingSandboxLookup{
			compiled: compiledSandboxLookup{source: source},
			ttl:      ttl,
			entries:  make(map[sandboxCacheKey]sandboxCacheEntry),
		}
	}
}

type sandboxCacheKey struct {
	class model.ClientClass
	name  string
}

type sandboxCacheEntry struct {
	payload *sandboxv1.Sandbox
	version string
	expires time.Time
}

type cachingSandboxLookup struct {
	compiled compiledSandboxLookup
	ttl      time.Duration
	flights  singleflight.Group

	mu      sync.Mutex
	entries map[sandboxCacheKey]sandboxCacheEntry
}

func (l *cachingSandboxLookup) LookupSandbox(
	ctx context.Context,
	scope model.ClientScope,
	name string,
) (*sandboxv1.Sandbox, string, error) {
	if l.ttl <= 0 {
		return l.compiled.LookupSandbox(ctx, scope, name)
	}
	// Every class allowed to query (gateway/EPE) shares cluster-wide Sandbox
	// visibility today; if that ever diverges the key must grow to match.
	key := sandboxCacheKey{class: scope.Class, name: name}
	l.mu.Lock()
	entry, found := l.entries[key]
	l.mu.Unlock()
	if found && time.Now().Before(entry.expires) {
		return entry.payload, entry.version, nil
	}
	// Class values are a closed set without '/', so this pairing is injective.
	result, err, _ := l.flights.Do(string(key.class)+"/"+key.name, func() (any, error) {
		// The shared fetch outlives the initiating RPC: a canceled caller must not
		// abort the lookup every other waiter shares. The bound replaces the RPC
		// deadline so a hung remote source cannot occupy the flight forever.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		payload, version, err := l.compiled.LookupSandbox(ctx, scope, name)
		if err != nil {
			// Source and compile failures stay uncached so the next RPC retries.
			return nil, err
		}
		// A nil payload is authoritative absence and earns the same TTL.
		entry := sandboxCacheEntry{payload: payload, version: version, expires: time.Now().Add(l.ttl)}
		l.mu.Lock()
		l.entries[key] = entry
		l.mu.Unlock()
		return entry, nil
	})
	if err != nil {
		return nil, "", err
	}
	cached := result.(sandboxCacheEntry)
	return cached.payload, cached.version, nil
}
