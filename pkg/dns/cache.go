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

package dns

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

type cacheKey struct {
	host   string
	family Family
}

// One lock protects compound LRU operations and configuration revisions.
// Lookups never hold this lock.
type resolutionCache struct {
	mu       sync.Mutex
	dns      *lru.Cache[cacheKey, Result]
	records  map[string][]netip.Addr
	revision uint64
	now      func() time.Time
}

func newResolutionCache(capacity int) *resolutionCache {
	c := &resolutionCache{records: make(map[string][]netip.Addr), now: time.Now}
	if capacity > 0 {
		c.dns, _ = lru.New[cacheKey, Result](capacity)
	}
	return c
}

func (c *resolutionCache) get(key cacheKey) (Result, bool, uint64, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if addresses, ok := c.records[key.host]; ok {
		return customResult(addresses, key.family), true, c.revision, now
	}
	if c.dns != nil {
		if result, ok := c.dns.Get(key); ok {
			if now.Before(result.ExpiresAt) {
				result.Addresses = slices.Clone(result.Addresses)
				return result, true, c.revision, now
			}
			c.dns.Remove(key)
		}
	}
	return Result{}, false, c.revision, now
}

func (c *resolutionCache) store(key cacheKey, result Result, revision uint64) Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	if addresses, ok := c.records[key.host]; ok {
		return customResult(addresses, key.family)
	}
	if c.dns != nil && c.revision == revision && len(result.Addresses) > 0 && c.now().Before(result.ExpiresAt) {
		cached := result
		cached.Addresses = slices.Clone(result.Addresses)
		c.dns.Add(key, cached)
	}
	return result
}

func (c *resolutionCache) update(host string, addresses []netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A global revision also prevents an older query from resurrecting an entry
	// after a record was installed and then removed while the query was running.
	c.revision++
	if len(addresses) == 0 {
		delete(c.records, host)
	} else {
		c.records[host] = addresses
	}
	if c.dns != nil {
		for _, family := range []Family{DualStack, IPv4Only, IPv6Only} {
			c.dns.Remove(cacheKey{host: host, family: family})
		}
	}
}

func customResult(addresses []netip.Addr, family Family) Result {
	return Result{Addresses: selectAddresses(addresses, family), Source: SourceCustom}
}
