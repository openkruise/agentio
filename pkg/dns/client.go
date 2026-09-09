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
	"context"
	"fmt"
	"time"
)

// Client resolves hostnames using custom records, a TTL cache, and DNS.
// Share one instance between request handlers and configuration writers.
type Client struct {
	lookup  Lookup
	timeout time.Duration
	cache   *resolutionCache
}

type Option func(*Client)

// WithCache sets the capacity in (hostname, family) entries. Non-positive
// capacity disables DNS caching; custom records are unaffected.
func WithCache(capacity int) Option {
	return func(c *Client) { c.cache = newResolutionCache(capacity) }
}

// NewClient uses a system-configured DNS transport when lookup is nil.
func NewClient(lookup Lookup, timeout time.Duration, options ...Option) *Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if lookup == nil {
		lookup = NewTransport(nil, timeout)
	}
	c := &Client{lookup: lookup, timeout: timeout, cache: newResolutionCache(DefaultCacheCapacity)}
	for _, option := range options {
		option(c)
	}
	return c
}

// Resolve returns custom records or fresh DNS answers. Expired answers are
// never served after a lookup failure. Literal IP handling belongs to callers.
func (c *Client) Resolve(ctx context.Context, host string, family Family) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if family > IPv6Only {
		return Result{}, ErrInvalidFamily
	}
	host, err := normalizeHost(host)
	if err != nil {
		return Result{}, err
	}
	key := cacheKey{host: host, family: family}
	result, ok, revision, started := c.cache.get(key)
	if ok {
		return requireAddresses(result)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	answer, err := c.lookup.Lookup(ctx, host, family)
	if err != nil {
		return Result{}, fmt.Errorf("resolve DNS host: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	// Count query time against TTL conservatively; a slow lookup must not
	// increase the lifetime of an early answer in a multi-query response.
	result = Result{Addresses: selectAddresses(answer.Addresses, family), ExpiresAt: started.Add(max(0, answer.TTL))}
	result = c.cache.store(key, result, revision)
	return requireAddresses(result)
}

func requireAddresses(result Result) (Result, error) {
	if len(result.Addresses) == 0 {
		return Result{}, ErrNoAddresses
	}
	return result, nil
}
