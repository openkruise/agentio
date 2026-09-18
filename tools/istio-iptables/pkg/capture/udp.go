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

package capture

import (
	"istio.io/istio/tools/common/config"
	"istio.io/istio/tools/istio-iptables/pkg/constants"
)

const (
	udpOutput = constants.AgentioUDPOutput
	udpTProxy = "ISTIO_UDP_TPROXY"
)

// setupOutboundUDPTProxy preserves the original destination for recvmsg/IP_RECVORIGDSTADDR.
// NAT REDIRECT would replace it with the proxy listener address. Each datagram is
// marked in OUTPUT, routed to lo, then delivered to the transparent UDP listener.
func (cfg *IptablesConfigurator) setupOutboundUDPTProxy(
	v4Include, v6Include, v4Exclude, v6Exclude config.NetworkRange,
) {
	b := cfg.ruleBuilder
	b.AppendRule("PREROUTING", "mangle", "-i", "lo", "-p", "udp",
		"-m", "mark", "--mark", cfg.cfg.UDPTProxyMark, "-j", udpTProxy)
	b.AppendRule(udpTProxy, "mangle", "-p", "udp", "-j", "TPROXY",
		"--tproxy-mark", cfg.cfg.UDPTProxyMark+"/0xffffffff", "--on-port", cfg.cfg.UDPProxyPort)
	b.AppendRule("OUTPUT", "mangle", "-p", "udp", "-j", udpOutput)

	// Leave local traffic to the app.
	b.AppendRule(udpOutput, "mangle", "-o", "lo", "-j", "RETURN")
	b.AppendVersionedRule("LOCAL,BROADCAST,MULTICAST", "LOCAL,MULTICAST", udpOutput, "mangle",
		"-m", "addrtype", "--dst-type", constants.IPVersionSpecific, "-j", "RETURN")
	// Replies from an inbound UDP server must not become new outbound sessions.
	// Do not bypass all ESTABLISHED packets: later client datagrams still need capture.
	b.AppendRule(udpOutput, "mangle", "-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN")
	b.AppendRule(udpOutput, "mangle", "-m", "mark", "--mark", cfg.cfg.UDPProxyMark, "-j", "RETURN")
	for _, uid := range config.Split(cfg.cfg.ProxyUID) {
		b.AppendRule(udpOutput, "mangle", "-m", "owner", "--uid-owner", uid, "-j", "RETURN")
	}
	for _, gid := range config.Split(cfg.cfg.ProxyGID) {
		b.AppendRule(udpOutput, "mangle", "-m", "owner", "--gid-owner", gid, "-j", "RETURN")
	}
	for _, iface := range config.Split(cfg.cfg.ExcludeInterfaces) {
		b.AppendRule(udpOutput, "mangle", "-o", iface, "-j", "RETURN")
	}
	filter := config.ParseInterceptFilter(cfg.cfg.OwnerGroupsInclude, cfg.cfg.OwnerGroupsExclude)
	if filter.Except {
		for _, group := range filter.Values {
			b.AppendRule(udpOutput, "mangle", "-m", "owner", "--gid-owner", group, "-j", "RETURN")
		}
	} else {
		matchers := CombineMatchers(filter.Values, func(group string) []string {
			return []string{"-m", "owner", "!", "--gid-owner", group}
		})
		b.AppendRule(udpOutput, "mangle", append(matchers, "-j", "RETURN")...)
	}
	for _, port := range config.Split(cfg.cfg.OutboundPortsExclude) {
		b.AppendRule(udpOutput, "mangle", "-p", "udp", "--dport", port, "-j", "RETURN")
	}
	for _, cidr := range v4Exclude.CIDRs {
		b.AppendRuleV4(udpOutput, "mangle", "-d", cidr.String(), "-j", "RETURN")
	}
	for _, cidr := range v6Exclude.CIDRs {
		b.AppendRuleV6(udpOutput, "mangle", "-d", cidr.String(), "-j", "RETURN")
	}
	for _, port := range config.Split(cfg.cfg.OutboundPortsInclude) {
		b.AppendRule(udpOutput, "mangle", "-p", "udp", "--dport", port, "-j", "MARK", "--set-mark", cfg.cfg.UDPTProxyMark)
	}
	if v4Include.IsWildcard {
		b.AppendRuleV4(udpOutput, "mangle", "-j", "MARK", "--set-mark", cfg.cfg.UDPTProxyMark)
	} else {
		for _, cidr := range v4Include.CIDRs {
			b.AppendRuleV4(udpOutput, "mangle", "-d", cidr.String(), "-j", "MARK", "--set-mark", cfg.cfg.UDPTProxyMark)
		}
	}
	if v6Include.IsWildcard {
		b.AppendRuleV6(udpOutput, "mangle", "-j", "MARK", "--set-mark", cfg.cfg.UDPTProxyMark)
	} else {
		for _, cidr := range v6Include.CIDRs {
			b.AppendRuleV6(udpOutput, "mangle", "-d", cidr.String(), "-j", "MARK", "--set-mark", cfg.cfg.UDPTProxyMark)
		}
	}
}
