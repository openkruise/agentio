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

package egressauthz

import (
	"fmt"
	"net/netip"
)

// Config is an immutable snapshot of platform destination restrictions.
// DeniedCIDRs must not be mutated after publication.
type Config struct {
	DeniedCIDRs []netip.Prefix
}

// Action is a platform destination decision.
type Action string

const (
	// Allow permits the destination.
	Allow Action = "Allow"
	// Deny rejects the destination.
	Deny Action = "Deny"
)

// Decision attributes a denial to its configured CIDR. Default decisions have
// no policy name and a RuleIndex of -1.
type Decision struct {
	Action     Action
	PolicyName string
	RuleIndex  int
}

func (c Config) Validate() error {
	for _, prefix := range c.DeniedCIDRs {
		if !prefix.IsValid() || prefix.Addr().Is4In6() {
			return fmt.Errorf("invalid or IPv4-mapped denied CIDR: %s", prefix)
		}
	}
	return nil
}

// Evaluate denies invalid targets and configured CIDRs; all other targets pass.
func (c Config) Evaluate(address netip.AddrPort) Decision {
	if !address.IsValid() || address.Port() == 0 || address.Addr().Zone() != "" {
		return Decision{Action: Deny, RuleIndex: -1}
	}
	for i, prefix := range c.DeniedCIDRs {
		if prefix.Contains(address.Addr().Unmap()) {
			return Decision{Action: Deny, PolicyName: "EPEConfig/egressAuthorization", RuleIndex: i}
		}
	}
	return Decision{Action: Allow, RuleIndex: -1}
}
