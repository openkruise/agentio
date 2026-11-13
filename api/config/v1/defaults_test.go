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
	"slices"
	"testing"
)

func TestEgressAuthorization(t *testing.T) {
	for _, raw := range []string{"192.0.2.1", "invalid", "192.0.2.0/33", "::ffff:192.0.2.0/120", "fe80::1%eth0/128"} {
		if err := (&EgressAuthorization{DeniedCidrs: []string{raw}}).Validate(); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	config := &EgressAuthorization{DeniedCidrs: []string{
		"2001:db8::1/64", "192.0.2.9/24", "192.0.2.0/24", "127.0.0.1/8",
	}}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	want := append(MandatoryEgressDeniedCIDRs(), "192.0.2.0/24", "2001:db8::/64")
	if got := config.EffectiveDeniedCIDRs(); !slices.Equal(got, want) {
		t.Fatalf("effective CIDRs = %v, want %v", got, want)
	}
	if config.DeniedCidrs[0] != "2001:db8::1/64" {
		t.Fatal("normalization mutated input")
	}
	for _, config := range []*EgressAuthorization{nil, {}} {
		if err := config.Validate(); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(config.EffectiveDeniedCIDRs(), MandatoryEgressDeniedCIDRs()) {
			t.Fatal("empty configuration removed mandatory restrictions")
		}
	}
}
