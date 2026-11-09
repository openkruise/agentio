// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

package config

import (
	"fmt"
	"net/netip"
	"strconv"
)

// ValidateNATOutputPriority keeps destination NAT after conntrack lookup at -200.
func ValidateNATOutputPriority(value string) error {
	priority, err := strconv.ParseInt(value, 10, 32)
	if err != nil || priority <= -200 {
		return fmt.Errorf("NAT OUTPUT priority must be a signed 32-bit integer greater than -200, got %q", value)
	}
	return nil
}

const (
	// Due to implementation constraints, we have to impose a limit on the
	// number of owner groups whose outgoing traffic should be redirected
	// to Envoy.
	//
	// Since all included groups will be translated into a single Iptables
	// rule that combines N match expressions `-m owner ! --gid-owner <GID>`,
	// we need to be sure it won't be too long.
	//
	// Most common Linux distributions allow no more than 128-1200
	// match expressions per rule.
	maxOwnerGroupsInclude = 64
)

func ValidateOwnerGroups(include, exclude string) error {
	filter := ParseInterceptFilter(include, exclude)
	if !filter.Except && len(filter.Values) > maxOwnerGroupsInclude {
		return fmt.Errorf("number of owner groups whose outgoing traffic "+
			"should be redirected to Envoy cannot exceed %d, got %d: %v",
			maxOwnerGroupsInclude, len(filter.Values), filter.Values)
	}
	return nil
}

//nolint:errorlint // Preserve upstream configuration error identity.
func ValidateIPv4LoopbackCidr(cidr string) error {
	ipp, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("failed to parse CIDR %s: %v", cidr, err)
	}

	if !ipp.Addr().Is4() || !ipp.Addr().IsLoopback() {
		return fmt.Errorf("expected valid IPv4 loopback address in CIDR %s; found %v", cidr, ipp.Addr())
	}

	ones := ipp.Bits()
	if ones < 8 || ones > 32 {
		return fmt.Errorf("expected CIDR %s to have mask in range [8, 32]; found %v", cidr, ones)
	}
	return nil
}

// copied over from the dependency implementation package to avoid circular imports
const (
	legacy = "legacy"
	nft    = "nft"
)

func ValidateIptablesBinary(iptb string) error {
	switch iptb {
	case "", legacy, nft:
		return nil
	default:
		return fmt.Errorf("invalid AGENTIO_FORCE_IPTABLES_BINARY value %q", iptb)

	}
}
