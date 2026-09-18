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

import (
	"fmt"
	"strconv"

	"istio.io/istio/tools/istio-iptables/pkg/constants"
)

func (c *Config) validateUDPTProxy() error {
	if !c.EnableUDPTProxy {
		return nil
	}
	if c.InboundInterceptionMode != "" && c.InboundInterceptionMode != "REDIRECT" {
		return fmt.Errorf("outbound UDP TPROXY requires TCP REDIRECT interception")
	}
	if c.NativeNftables {
		return fmt.Errorf("UDP TPROXY requires iptables (legacy or nft), not native nftables")
	}
	if c.SkipRuleApply || c.HostFilesystemPodNetwork {
		return fmt.Errorf("UDP TPROXY requires the pod init container; CNI rule programming is not supported")
	}
	for name, value := range map[string]string{
		"udp-proxy-port": c.UDPProxyPort, "udp-tproxy-mark": c.UDPTProxyMark,
		"udp-proxy-mark": c.UDPProxyMark, "udp-tproxy-route-table": c.UDPTProxyRouteTable,
	} {
		bits := 32
		if name == "udp-proxy-port" {
			bits = 16
		} else if name == "udp-tproxy-route-table" {
			bits = 31
		}
		n, err := strconv.ParseUint(value, 10, bits)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != value {
			return fmt.Errorf("%s must be a nonzero %d-bit decimal integer, got %q", name, bits, value)
		}
	}
	mark, _ := strconv.ParseUint(c.UDPTProxyMark, 10, 32)
	proxyMark, _ := strconv.ParseUint(c.UDPProxyMark, 10, 32)
	inboundMark, _ := strconv.ParseUint(c.InboundTProxyMark, 10, 32)
	outboundMark, _ := strconv.ParseUint(constants.OutboundMark, 10, 32)
	if mark == proxyMark || mark == inboundMark || mark == outboundMark {
		return fmt.Errorf("udp-tproxy-mark must differ from the proxy socket mark and TCP interception marks")
	}
	table, _ := strconv.ParseUint(c.UDPTProxyRouteTable, 10, 31)
	inboundTable, _ := strconv.ParseUint(c.InboundTProxyRouteTable, 10, 31)
	if table == 253 || table == 254 || table == 255 || table == inboundTable {
		return fmt.Errorf("udp-tproxy-route-table must not use a built-in or TCP interception routing table")
	}
	return nil
}
