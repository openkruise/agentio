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

package network

import "testing"

func TestPrefixCIDRUsesLiteralNetworkBoundaries(t *testing.T) {
	tests := []struct {
		bits int
		want string
	}{
		{bits: 32, want: "10.20.30.40/32"},
		{bits: 24, want: "10.20.30.0/24"},
		{bits: 16, want: "10.20.0.0/16"},
	}
	for _, tc := range tests {
		got, err := PrefixCIDR("10.20.30.40", tc.bits)
		if err != nil || got != tc.want {
			t.Fatalf("prefix /%d = %q, %v; want %q", tc.bits, got, err, tc.want)
		}
	}
	if _, err := PrefixCIDR("not-an-ip", 24); err == nil {
		t.Fatal("invalid IP was accepted")
	}
}

func TestHostCIDRUsesAddressFamilyWidth(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		wantError         bool
	}{
		{name: "IPv4", input: "10.0.0.8", want: "10.0.0.8/32"},
		{name: "IPv6", input: "2001:db8::8", want: "2001:db8::8/128"},
		{name: "headless", input: "None", wantError: true},
		{name: "invalid", input: "service.invalid", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := HostCIDR(tc.input)
			if tc.wantError {
				if err == nil {
					t.Fatalf("HostCIDR(%q) = %q, want error", tc.input, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("HostCIDR(%q) = %q, %v; want %q", tc.input, got, err, tc.want)
			}
		})
	}
}
