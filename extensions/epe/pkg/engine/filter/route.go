// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package filter

import (
	"fmt"
	"net/netip"
)

// RouteMutation describes request routing changes. It and all nested values
// must remain immutable after the filter returns them.
type RouteMutation struct {
	// Upstream is nil when the upstream target is unchanged.
	Upstream *UpstreamTarget
	// ClearCache requests route re-evaluation. Requests from multiple mutations
	// are combined with OR. Setting Upstream does not imply ClearCache.
	ClearCache bool
}

// UpstreamTarget identifies the actual connection destination without rewriting
// HTTP Host/authority. Further target forms may be added here in the future.
type UpstreamTarget struct {
	// Address must be present, valid, unscoped, and have a non-zero port.
	Address *netip.AddrPort
}

// Validate checks the routing data contract. A nil or empty RouteMutation is a
// no-op; a non-nil Upstream must contain a valid destination.
func (r *RouteMutation) Validate() error {
	if r == nil || r.Upstream == nil {
		return nil
	}
	address := r.Upstream.Address
	if address == nil {
		return fmt.Errorf("upstream address is required")
	}
	if !address.IsValid() || address.Port() == 0 || address.Addr().Zone() != "" {
		return fmt.Errorf("invalid upstream address: %s", address)
	}
	return nil
}

func (r *RouteMutation) equal(other *RouteMutation) bool {
	if r == nil || other == nil {
		return r == other
	}
	if r.ClearCache != other.ClearCache {
		return false
	}
	if r.Upstream == nil || other.Upstream == nil {
		return r.Upstream == other.Upstream
	}
	a, b := r.Upstream.Address, other.Upstream.Address
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
