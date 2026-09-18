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

package config

import "testing"

func TestValidateUDPTProxy(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Config)
		valid  bool
	}{
		{"defaults", func(c *Config) {}, true},
		{"tcp-redirect", func(c *Config) { c.InboundInterceptionMode = "REDIRECT"; c.InboundPortsInclude = "*" }, true},
		{"tcp-tproxy", func(c *Config) { c.InboundInterceptionMode = "TPROXY"; c.InboundPortsInclude = "*" }, false},
		{"custom", func(c *Config) {
			c.UDPProxyPort = "15012"
			c.UDPProxyMark = "2000"
			c.UDPTProxyMark = "2001"
			c.UDPTProxyRouteTable = "200"
		}, true},
		{"iptables-nft", func(c *Config) { c.ForceIptablesBinary = "nft" }, true},
		{"native-nft", func(c *Config) { c.NativeNftables = true }, false},
		{"cni", func(c *Config) { c.HostFilesystemPodNetwork = true }, false},
		{"validation-only", func(c *Config) { c.SkipRuleApply = true }, false},
		{"zero-port", func(c *Config) { c.UDPProxyPort = "0" }, false},
		{"overflow-port", func(c *Config) { c.UDPProxyPort = "65536" }, false},
		{"zero-mark", func(c *Config) { c.UDPTProxyMark = "0" }, false},
		{"invalid-mark", func(c *Config) { c.UDPTProxyMark = "invalid" }, false},
		{"overflow-mark", func(c *Config) { c.UDPTProxyMark = "4294967296" }, false},
		{"proxy-mark-collision", func(c *Config) { c.UDPTProxyMark = "01337" }, false},
		{"tcp-mark-collision", func(c *Config) { c.UDPTProxyMark = "1338" }, false},
		{"custom-proxy-mark-collision", func(c *Config) { c.UDPProxyMark = c.UDPTProxyMark }, false},
		{"reserved-table", func(c *Config) { c.UDPTProxyRouteTable = "254" }, false},
		{"tcp-table-collision", func(c *Config) { c.UDPTProxyRouteTable = "133" }, false},
		{"disabled", func(c *Config) { c.EnableUDPTProxy = false; c.NativeNftables = true; c.UDPProxyPort = "invalid" }, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultConfig()
			c.EnableUDPTProxy = true
			tt.change(c)
			if err := c.Validate(); (err == nil) != tt.valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, tt.valid)
			}
		})
	}
}
