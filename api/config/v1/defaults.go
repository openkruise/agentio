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

package configv1

import (
	"fmt"
	"net/netip"
	"slices"
)

// Validate checks operator-supplied destination CIDRs.
func (x *EgressAuthorization) Validate() error {
	for _, raw := range x.GetDeniedCidrs() {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Addr().Is4In6() {
			return fmt.Errorf("egressAuthorization.deniedCIDRs: invalid or IPv4-mapped CIDR %q", raw)
		}
	}
	return nil
}

// EffectiveDeniedCIDRs requires validated configuration and retains mandatory restrictions.
func (x *EgressAuthorization) EffectiveDeniedCIDRs() []string {
	denied := MandatoryEgressDeniedCIDRs()
	var additional []string
	for _, raw := range x.GetDeniedCidrs() {
		cidr := netip.MustParsePrefix(raw).Masked().String()
		if !slices.Contains(denied, cidr) {
			additional = append(additional, cidr)
		}
	}
	slices.Sort(additional)
	return append(denied, slices.Compact(additional)...)
}

// MandatoryEgressDeniedCIDRs returns the destination restrictions shared by EPE
// and native gateway forwarding. Private service networks remain
// operator-owned. Each caller receives its own slice.
func MandatoryEgressDeniedCIDRs() []string {
	return []string{
		"127.0.0.0/8", "::1/128", // Loopback.
		"0.0.0.0/32", "::/128", // Unspecified.
		"169.254.0.0/16", "fe80::/10", // Link-local.
	}
}
