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

const DefaultTimeout = 250 * time.Millisecond
const DefaultCacheCapacity = 1024

type Family uint8

const (
	DualStack Family = iota
	IPv4Only
	IPv6Only
)

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

type Source uint8

const (
	SourceDNS Source = iota
	SourceCustom
)

// Result owns its address slice. ExpiresAt is an absolute deadline, not a fresh
// TTL on each cache hit. Custom records have SourceCustom and no expiration.
type Result struct {
	Addresses []netip.Addr
	ExpiresAt time.Time
	Source    Source
}
