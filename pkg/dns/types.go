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

// Package dns provides protocol lookups, a bounded TTL cache, and custom
// records. Control-plane refresh and KRT integration live in dns/controller.
package dns

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// DefaultTimeout bounds a protocol lookup when no timeout is configured.
const DefaultTimeout = 250 * time.Millisecond

// DefaultCacheCapacity limits the number of cached DNS results.
const DefaultCacheCapacity = 1024

// Family selects the IP address families returned by a lookup.
type Family uint8

const (
	// DualStack requests both IPv4 and IPv6 addresses.
	DualStack Family = iota
	// IPv4Only requests IPv4 addresses.
	IPv4Only
	// IPv6Only requests IPv6 addresses.
	IPv6Only
)

// ErrInvalidHost, ErrInvalidFamily, and ErrNoAddresses describe invalid queries or empty results.
var (
	ErrInvalidHost   = errors.New("invalid DNS hostname")
	ErrInvalidFamily = errors.New("invalid DNS address family")
	ErrNoAddresses   = errors.New("DNS result has no addresses for requested family")
)

// Lookup is the protocol query capability used by Client. Transport implements
// it; callers may inject another implementation without changing cache behavior.
type Lookup interface {
	Lookup(context.Context, string, Family) (LookupResult, error)
}

// LookupFunc adapts a function to the Lookup interface.
type LookupFunc func(context.Context, string, Family) (LookupResult, error)

// Lookup implements the Lookup interface.
func (f LookupFunc) Lookup(ctx context.Context, host string, family Family) (LookupResult, error) {
	return f(ctx, host, family)
}

// Source identifies whether addresses came from DNS or custom records.
type Source uint8

const (
	// SourceDNS identifies a protocol DNS result.
	SourceDNS Source = iota
	// SourceCustom identifies an explicitly configured record.
	SourceCustom
)

// Result owns its address slice. ExpiresAt is an absolute deadline, not a fresh
// TTL on each cache hit. Custom records have SourceCustom and no expiration.
type Result struct {
	Addresses []netip.Addr
	ExpiresAt time.Time
	Source    Source
}
