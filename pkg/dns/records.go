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
	"fmt"
	"net/netip"
	"strings"
)

// SetRecord atomically replaces an exact-host record, copying its addresses.
// Records support both IP families and do not expire or participate in LRU
// eviction. A record without the requested family returns ErrNoAddresses;
// it never falls through to public DNS.
func (c *Client) SetRecord(host string, addresses []netip.Addr) error {
	host, err := normalizeHost(host)
	if err != nil {
		return err
	}
	if len(addresses) == 0 {
		return ErrNoAddresses
	}
	for _, ip := range addresses {
		if !ip.IsValid() || ip.Zone() != "" {
			return fmt.Errorf("invalid custom DNS address: %v", ip)
		}
	}
	c.cache.update(host, selectAddresses(addresses, DualStack))
	return nil
}

// DeleteRecord removes a configured record and invalidates all cached families.
// Requests already holding a result are unchanged.
func (c *Client) DeleteRecord(host string) error {
	host, err := normalizeHost(host)
	if err != nil {
		return err
	}
	c.cache.update(host, nil)
	return nil
}

// normalizeHost accepts exact ASCII DNS names, without ports or wildcards.
func normalizeHost(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if len(host) == 0 || len(host) > 253 || strings.Trim(host, "0123456789.") == "" {
		return "", ErrInvalidHost
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidHost
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", ErrInvalidHost
			}
		}
	}
	return host, nil
}

// Preserve response order; choosing an upstream is the caller's decision.
func selectAddresses(addresses []netip.Addr, family Family) []netip.Addr {
	result := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, ip := range addresses {
		ip = ip.Unmap()
		if !ip.IsValid() || ip.Zone() != "" || family == IPv4Only && !ip.Is4() || family == IPv6Only && !ip.Is6() {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		result = append(result, ip)
	}
	return result
}
