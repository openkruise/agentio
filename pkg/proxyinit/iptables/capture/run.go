// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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
package capture

import (
	"fmt"
	"strings"

	agentlog "github.com/openkruise/agentio/pkg/log"

	"github.com/openkruise/agentio/pkg/proxyinit/config"
	"github.com/openkruise/agentio/pkg/proxyinit/iptables/builder"
	"github.com/openkruise/agentio/pkg/proxyinit/iptables/constants"
	dep "github.com/openkruise/agentio/pkg/proxyinit/iptables/dependencies"
)

var log = agentlog.New("proxy-init.iptables.capture")

type Ops int

const (
	// AppendOps performs append operations of rules
	AppendOps Ops = iota
	// DeleteOps performs delete operations of rules
	DeleteOps
)

type IptablesConfigurator struct {
	ruleBuilder *builder.IptablesRuleBuilder
	// TODO(abhide): Fix dep.Dependencies with better interface
	ext   dep.Dependencies
	cfg   *config.Config
	iptV  dep.IptablesVersion
	ipt6V dep.IptablesVersion
}

func NewIptablesConfigurator(cfg *config.Config, ext dep.Dependencies) (*IptablesConfigurator, error) {
	iptVer, err := ext.DetectIptablesVersion(false)
	if err != nil {
		return nil, err
	}

	ipt6Ver, err := ext.DetectIptablesVersion(true)
	if err != nil {
		if cfg.EnableIPv6 {
			return nil, err
		}
		log.Warn(
			fmt.Sprintf(
				"Failed to detect a working ip6tables binary; continuing because IPv6 support is disabled (ENABLE_INBOUND_IPV6=false): %v",
				err,
			),
		)
		ipt6Ver = dep.IptablesVersion{}
	}

	return &IptablesConfigurator{
		ruleBuilder: builder.NewIptablesRuleBuilder(cfg),
		ext:         ext,
		cfg:         cfg,
		iptV:        iptVer,
		ipt6V:       ipt6Ver,
	}, nil
}

func (cfg *IptablesConfigurator) logConfig() {
	cfg.cfg.Print()
}

func (cfg *IptablesConfigurator) handleInboundPortsInclude() {
	// Handling of inbound ports. Traffic will be redirected to Envoy, which will process and forward
	// to the local service. If InboundPortsInclude is not set, no inbound ports will be intercepted by Agentio iptables.
	var table string
	if cfg.cfg.InboundPortsInclude != "" {
		table = "nat"
		cfg.ruleBuilder.AppendRule("PREROUTING", table, "-p", "tcp",
			"-j", constants.AGENTIOINBOUND)

		if cfg.cfg.InboundPortsInclude == "*" {
			// Apply any user-specified port exclusions.
			if cfg.cfg.InboundPortsExclude != "" {
				for _, port := range config.Split(cfg.cfg.InboundPortsExclude) {
					cfg.ruleBuilder.AppendRule(constants.AGENTIOINBOUND, table, "-p", "tcp",
						"--dport", port, "-j", "RETURN")
				}
			}
			// Redirect remaining inbound traffic to Envoy.
			cfg.ruleBuilder.AppendRule(constants.AGENTIOINBOUND, "nat", "-p", "tcp",
				"-j", constants.AGENTIOINREDIRECT)
		} else {
			// User has specified a non-empty list of ports to be redirected to Envoy.
			for _, port := range config.Split(cfg.cfg.InboundPortsInclude) {
				cfg.ruleBuilder.AppendRule(
					constants.AGENTIOINBOUND, "nat", "-p", "tcp", "--dport", port, "-j", constants.AGENTIOINREDIRECT)
			}
		}
	}
}

func (cfg *IptablesConfigurator) handleOutboundIncludeRules(
	rangeInclude config.NetworkRange,
	appendRule func(chain string, table string, params ...string) *builder.IptablesRuleBuilder,
	insert func(chain string, table string, position int, params ...string) *builder.IptablesRuleBuilder,
) {
	// Apply outbound IP inclusions.
	if rangeInclude.IsWildcard {
		// Wildcard specified. Redirect all remaining outbound traffic to Envoy.
		appendRule(constants.AGENTIOOUTPUT, "nat", "-j", constants.AGENTIOREDIRECT)
		for _, internalInterface := range config.Split(cfg.cfg.RerouteVirtualInterfaces) {
			insert(
				"PREROUTING", "nat", 1, "-i", internalInterface, "-j", constants.AGENTIOREDIRECT)
		}
	} else if len(rangeInclude.CIDRs) > 0 {
		// User has specified a non-empty list of cidrs to be redirected to Envoy.
		for _, cidr := range rangeInclude.CIDRs {
			for _, internalInterface := range config.Split(cfg.cfg.RerouteVirtualInterfaces) {
				insert("PREROUTING", "nat", 1, "-i", internalInterface,
					"-d", cidr.String(), "-j", constants.AGENTIOREDIRECT)
			}
			appendRule(
				constants.AGENTIOOUTPUT, "nat", "-d", cidr.String(), "-j", constants.AGENTIOREDIRECT)
		}
	}
}

func (cfg *IptablesConfigurator) shortCircuitKubeInternalInterface() {
	for _, internalInterface := range config.Split(cfg.cfg.RerouteVirtualInterfaces) {
		cfg.ruleBuilder.InsertRule("PREROUTING", "nat", 1, "-i", internalInterface, "-j", "RETURN")
	}
}

func (cfg *IptablesConfigurator) shortCircuitExcludeInterfaces() {
	for _, excludeInterface := range config.Split(cfg.cfg.ExcludeInterfaces) {
		cfg.ruleBuilder.AppendRule(
			"PREROUTING", "nat", "-i", excludeInterface, "-j", "RETURN")
		cfg.ruleBuilder.AppendRule("OUTPUT", "nat", "-o", excludeInterface, "-j", "RETURN")
	}
}

func (cfg *IptablesConfigurator) Run() error {
	defer func() {
		// Best effort since we don't know if the commands exist
		if state, err := cfg.ext.Run(log.With(), true, constants.IPTablesSave, &cfg.iptV, nil); err == nil {
			log.Info(fmt.Sprintf("Final iptables state (IPv4):\n%s", state))
		}
		if cfg.cfg.EnableIPv6 {
			if state, err := cfg.ext.Run(log.With(), true, constants.IPTablesSave, &cfg.ipt6V, nil); err == nil {
				log.Info(fmt.Sprintf("Final iptables state (IPv6):\n%s", state))
			}
		}
	}()

	// Since OUTBOUND_IP_RANGES_EXCLUDE could carry ipv4 and ipv6 ranges
	// need to split them in different arrays one for ipv4 and one for ipv6
	// in order to not to fail
	ipv4RangesExclude, ipv6RangesExclude, err := config.SeparateV4V6(cfg.cfg.OutboundIPRangesExclude)
	if err != nil {
		return err
	}
	if ipv4RangesExclude.IsWildcard {
		return fmt.Errorf("invalid value for OUTBOUND_IP_RANGES_EXCLUDE")
	}
	// FixMe: Do we need similar check for ipv6RangesExclude as well ??

	ipv4RangesInclude, ipv6RangesInclude, err := config.SeparateV4V6(cfg.cfg.OutboundIPRangesInclude)
	if err != nil {
		return err
	}

	redirectDNS := cfg.cfg.RedirectDNS || cfg.cfg.RejectNonTCP
	captureAllDNS := cfg.cfg.CaptureAllDNS || cfg.cfg.RejectNonTCP
	// How many DNS flags do we have? Three DNS flags! AH AH AH AH
	if redirectDNS && !captureAllDNS && len(cfg.cfg.DNSServersV4) == 0 && len(cfg.cfg.DNSServersV6) == 0 {
		log.Warn(
			"AGENTIO_REDIRECT_DNS is set, but AGENTIO_CAPTURE_ALL_DNS is false, and no DNS servers provided. DNS capture disabled.",
		)
		redirectDNS = false
	}

	cfg.logConfig()

	cfg.shortCircuitExcludeInterfaces()

	// Do not capture internal interface.
	cfg.shortCircuitKubeInternalInterface()

	// Create a rule for invalid drop in PREROUTING chain in mangle table, so the iptables will drop the out of window packets instead of reset connection .
	dropInvalid := cfg.cfg.DropInvalid
	if dropInvalid {
		cfg.ruleBuilder.AppendRule("PREROUTING", "mangle", "-m", "conntrack", "--ctstate",
			"INVALID", "-j", constants.AGENTIODROP)
		cfg.ruleBuilder.AppendRule(constants.AGENTIODROP, "mangle", "-j", "DROP")
	}

	// Create a new chain for to hit tunnel port directly. Envoy will be listening on port acting as VPN tunnel.
	cfg.ruleBuilder.AppendRule(constants.AGENTIOINBOUND, "nat", "-p", "tcp", "--dport",
		cfg.cfg.InboundTunnelPort, "-j", "RETURN")

	// Create a new chain for redirecting outbound traffic to the common Envoy port.
	// In both chains, '-j RETURN' bypasses Envoy and '-j AGENTIOREDIRECT'
	// redirects to Envoy.
	cfg.ruleBuilder.AppendRule(
		constants.AGENTIOREDIRECT, "nat", "-p", "tcp", "-j", "REDIRECT", "--to-ports", cfg.cfg.ProxyPort)

	// Use this chain also for redirecting inbound traffic to the common Envoy port

	cfg.ruleBuilder.AppendRule(constants.AGENTIOINREDIRECT, "nat", "-p", "tcp", "-j", "REDIRECT",
		"--to-ports", cfg.cfg.InboundCapturePort)

	cfg.handleInboundPortsInclude()

	// TODO: change the default behavior to not intercept any output - user may use http_proxy or another
	// iptablesOrFail wrapper (like ufw). Current default is similar with 0.1
	// Jump to the AGENTIOOUTPUT chain from OUTPUT chain for all traffic
	// NOTE: udp traffic will be optionally shunted (or no-op'd) within the AGENTIOOUTPUT chain, we don't need a conditional jump here.
	cfg.ruleBuilder.AppendRule("OUTPUT", "nat", "-j", constants.AGENTIOOUTPUT)

	// Apply port based exclusions. Must be applied before connections back to self are redirected.
	if cfg.cfg.OutboundPortsExclude != "" {
		for _, port := range config.Split(cfg.cfg.OutboundPortsExclude) {
			cfg.ruleBuilder.AppendRule(constants.AGENTIOOUTPUT, "nat", "-p", "tcp", "--dport", port, "-j", "RETURN")
			cfg.ruleBuilder.AppendRule(constants.AGENTIOOUTPUT, "nat", "-p", "udp", "--dport", port, "-j", "RETURN")
		}
	}

	// 127.0.0.6/::6 is bind connect from inbound passthrough cluster
	cfg.ruleBuilder.AppendVersionedRule("127.0.0.6/32", "::6/128", constants.AGENTIOOUTPUT, "nat",
		"-o", "lo", "-s", constants.IPVersionSpecific, "-j", "RETURN")

	for _, uid := range config.Split(cfg.cfg.ProxyUID) {
		// Redirect app calls back to itself via Envoy when using the service VIP
		// e.g. appN => Envoy (client) => Envoy (server) => appN.
		// nolint: lll
		if redirectDNS {
			// When DNS is enabled, we skip this for port 53. This ensures we do not have:
			// app => agentio-agent => Envoy inbound => dns server
			// Instead, we just have:
			// app => agentio-agent => dns server
			cfg.ruleBuilder.AppendVersionedRule(cfg.cfg.HostIPv4LoopbackCidr, "::1/128", constants.AGENTIOOUTPUT, "nat",
				"-o", "lo",
				"!", "-d", constants.IPVersionSpecific,
				"-p", "tcp",
				"-m", "multiport",
				"!", "--dports", "53,"+cfg.cfg.InboundTunnelPort,
				"-m", "owner", "--uid-owner", uid, "-j", constants.AGENTIOINREDIRECT)
		} else {
			cfg.ruleBuilder.AppendVersionedRule(cfg.cfg.HostIPv4LoopbackCidr, "::1/128", constants.AGENTIOOUTPUT, "nat",
				"-o", "lo",
				"!", "-d", constants.IPVersionSpecific,
				"-p", "tcp",
				"!", "--dport", cfg.cfg.InboundTunnelPort,
				"-m", "owner", "--uid-owner", uid, "-j", constants.AGENTIOINREDIRECT)
		}
		// Do not redirect app calls to back itself via Envoy when using the endpoint address
		// e.g. appN => appN by lo
		// If loopback explicitly set via OutboundIPRangesInclude, then don't return.
		if !ipv4RangesInclude.HasLoopBackIP && !ipv6RangesInclude.HasLoopBackIP {
			if redirectDNS {
				// Users may have a DNS server that is on localhost. In these cases, applications may
				// send TCP traffic to the DNS server that we actually *do* want to intercept. To
				// handle this case, we exclude port 53 from this rule. Note: We cannot just move the
				// port 53 redirection rule further up the list, as we will want to avoid capturing
				// DNS requests from the proxy UID/GID
				cfg.ruleBuilder.AppendRule(constants.AGENTIOOUTPUT, "nat", "-o", "lo", "-p", "tcp",
					"!", "--dport", "53",
					"-m", "owner", "!", "--uid-owner", uid, "-j", "RETURN")
			} else {
				cfg.ruleBuilder.AppendRule(constants.AGENTIOOUTPUT, "nat",
					"-o", "lo", "-m", "owner", "!", "--uid-owner", uid, "-j", "RETURN")
			}
		}

		// Avoid infinite loops. Don't redirect Envoy traffic directly back to
		// Envoy for non-loopback traffic.
		// Note that this rule is, unlike the others, protocol-independent - we want to unconditionally skip
		// all UDP/TCP packets from Envoy, regardless of dest.
		cfg.ruleBuilder.AppendRule(constants.AGENTIOOUTPUT, "nat",
			"-m", "owner", "--uid-owner", uid, "-j", "RETURN")
	}

	for _, gid := range config.Split(cfg.cfg.ProxyGID) {
		// Redirect app calls back to itself via Envoy when using the service VIP
		// e.g. appN => Envoy (client) => Envoy (server) => appN.
		cfg.ruleBuilder.AppendVersionedRule(cfg.cfg.HostIPv4LoopbackCidr, "::1/128", constants.AGENTIOOUTPUT, "nat",
			"-o", "lo",
			"!", "-d", constants.IPVersionSpecific,
			"-p", "tcp",
			"!", "--dport", cfg.cfg.InboundTunnelPort,
			"-m", "owner", "--gid-owner", gid, "-j", constants.AGENTIOINREDIRECT)

		// Do not redirect app calls to back itself via Envoy when using the endpoint address
		// e.g. appN => appN by lo
		// If loopback explicitly set via OutboundIPRangesInclude, then don't return.
		if !ipv4RangesInclude.HasLoopBackIP && !ipv6RangesInclude.HasLoopBackIP {
			if redirectDNS {
				// Users may have a DNS server that is on localhost. In these cases, applications may
				// send TCP traffic to the DNS server that we actually *do* want to intercept. To
				// handle this case, we exclude port 53 from this rule. Note: We cannot just move the
				// port 53 redirection rule further up the list, as we will want to avoid capturing
				// DNS requests from the proxy UID/GID
				cfg.ruleBuilder.AppendRule(constants.AGENTIOOUTPUT, "nat",
					"-o", "lo", "-p", "tcp",
					"!", "--dport", "53",
					"-m", "owner", "!", "--gid-owner", gid, "-j", "RETURN")
			} else {
				cfg.ruleBuilder.AppendRule(constants.AGENTIOOUTPUT, "nat",
					"-o", "lo", "-m", "owner", "!", "--gid-owner", gid, "-j", "RETURN")
			}
		}

		// Avoid infinite loops. Don't redirect Envoy traffic directly back to
		// Envoy for non-loopback traffic.
		// Note that this rule is, unlike the others, protocol-independent - we want to unconditionally skip
		// all UDP/TCP packets from Envoy, regardless of dest.
		cfg.ruleBuilder.AppendRule(constants.AGENTIOOUTPUT, "nat", "-m", "owner", "--gid-owner", gid, "-j", "RETURN")
	}

	ownerGroupsFilter := config.ParseInterceptFilter(cfg.cfg.OwnerGroupsInclude, cfg.cfg.OwnerGroupsExclude)

	cfg.handleCaptureByOwnerGroup(ownerGroupsFilter)

	if redirectDNS {
		SetupDNSRedir(
			cfg.ruleBuilder, cfg.cfg.ProxyUID, cfg.cfg.ProxyGID,
			cfg.cfg.DNSServersV4, cfg.cfg.DNSServersV6, captureAllDNS,
			ownerGroupsFilter, cfg.cfg.RejectNonTCP)
	}
	if cfg.cfg.RejectNonTCP {
		cfg.ruleBuilder.InsertRule("OUTPUT", "filter", 1, "!", "-p", "tcp", "-j", constants.AGENTIOOUTPUT)
		// IPv6 TCP still needs error reporting, neighbor discovery, and multicast membership.
		for _, icmpType := range []string{"1", "2", "3", "4", "130", "131", "132", "133", "134", "135", "136", "143"} {
			cfg.ruleBuilder.AppendRuleV6(
				constants.AGENTIOOUTPUT,
				"filter",
				"-p",
				"ipv6-icmp",
				"--icmpv6-type",
				icmpType,
				"-j",
				"RETURN",
			)
		}
		// Only DNS that actually reached the local redirect may leave application sockets.
		// OUTPUT rerouting can occur after filtering; match the translated address rather than oif.
		cfg.ruleBuilder.AppendVersionedRule(
			"127.0.0.1/32",
			"::1/128",
			constants.AGENTIOOUTPUT,
			"filter",
			"-d",
			constants.IPVersionSpecific,
			"-p",
			"udp",
			"--dport",
			constants.AgentioAgentDNSListenerPort,
			"-m",
			"conntrack",
			"--ctstate",
			"DNAT",
			"-j",
			"RETURN",
		)
		for _, uid := range config.Split(cfg.cfg.ProxyUID) {
			cfg.ruleBuilder.AppendRule(constants.AGENTIOOUTPUT, "filter", "-p", "udp", "--dport", "53",
				"-m", "owner", "--uid-owner", uid, "-j", "RETURN")
			cfg.ruleBuilder.AppendRule(
				constants.AGENTIOOUTPUT,
				"filter",
				"-p",
				"udp",
				"--sport",
				constants.AgentioAgentDNSListenerPort,
				"-m",
				"owner",
				"--uid-owner",
				uid,
				"-j",
				"RETURN",
			)
		}
		for _, gid := range config.Split(cfg.cfg.ProxyGID) {
			cfg.ruleBuilder.AppendRule(constants.AGENTIOOUTPUT, "filter", "-p", "udp", "--dport", "53",
				"-m", "owner", "--gid-owner", gid, "-j", "RETURN")
			cfg.ruleBuilder.AppendRule(
				constants.AGENTIOOUTPUT,
				"filter",
				"-p",
				"udp",
				"--sport",
				constants.AgentioAgentDNSListenerPort,
				"-m",
				"owner",
				"--gid-owner",
				gid,
				"-j",
				"RETURN",
			)
		}
		cfg.ruleBuilder.AppendRule(constants.AGENTIOOUTPUT, "filter", "-j", "REJECT")
	}

	// Skip redirection for Envoy-aware applications and
	// container-to-container traffic both of which explicitly use
	// localhost.
	cfg.ruleBuilder.AppendVersionedRule(cfg.cfg.HostIPv4LoopbackCidr, "::1/128", constants.AGENTIOOUTPUT, "nat",
		"-d", constants.IPVersionSpecific, "-j", "RETURN")
	// Apply outbound IPv4 exclusions. Must be applied before inclusions.
	for _, cidr := range ipv4RangesExclude.CIDRs {
		cfg.ruleBuilder.AppendRuleV4(constants.AGENTIOOUTPUT, "nat", "-d", cidr.String(), "-j", "RETURN")
	}
	for _, cidr := range ipv6RangesExclude.CIDRs {
		cfg.ruleBuilder.AppendRuleV6(constants.AGENTIOOUTPUT, "nat", "-d", cidr.String(), "-j", "RETURN")
	}

	cfg.handleOutboundPortsInclude()

	cfg.handleOutboundIncludeRules(ipv4RangesInclude, cfg.ruleBuilder.AppendRuleV4, cfg.ruleBuilder.InsertRuleV4)
	cfg.handleOutboundIncludeRules(ipv6RangesInclude, cfg.ruleBuilder.AppendRuleV6, cfg.ruleBuilder.InsertRuleV6)

	return cfg.executeCommands(&cfg.iptV, &cfg.ipt6V)
}

// SetupDNSRedir is a helper function to tackle with DNS UDP specific operations.
// This helps the creation logic of DNS UDP rules in sync with the deletion.
func SetupDNSRedir(
	iptables *builder.IptablesRuleBuilder,
	proxyUID, proxyGID string,
	dnsServersV4 []string,
	dnsServersV6 []string,
	captureAllDNS bool,
	ownerGroupsFilter config.InterceptFilter,
	forceCapture bool,
) {
	// Uniquely for DNS (at this time) we need a jump in "raw:OUTPUT", so this jump is conditional on that setting.
	// And, unlike nat/OUTPUT, we have no shared rules, so no need to do a 2-level jump at this time
	iptables.AppendRule("OUTPUT", "raw", "-j", constants.AGENTIOOUTPUTDNS)

	// Conditionally insert jumps for V6 and V4 - we may have DNS capture enabled for V4 servers but not V6, or vice versa.
	// This avoids creating no-op jumps in v6 if we only need them in v4.
	//
	// TODO we should probably *conditionally* create jumps if and only if rules exist in the jumped-to table,
	// in a more automatic fashion.
	if forceCapture {
		// DNS capture must precede interface, port, and owner-group exclusions.
		iptables.InsertRule("OUTPUT", "nat", 1, "-j", constants.AGENTIOOUTPUTDNS)
		for _, uid := range config.Split(proxyUID) {
			iptables.AppendRule(constants.AGENTIOOUTPUTDNS, "nat", "-m", "owner", "--uid-owner", uid, "-j", "RETURN")
		}
		for _, gid := range config.Split(proxyGID) {
			iptables.AppendRule(constants.AGENTIOOUTPUTDNS, "nat", "-m", "owner", "--gid-owner", gid, "-j", "RETURN")
		}
	} else {
		if captureAllDNS || len(dnsServersV4) > 0 {
			iptables.AppendRuleV4(constants.AGENTIOOUTPUT, "nat", "-j", constants.AGENTIOOUTPUTDNS)
		}

		if captureAllDNS || len(dnsServersV6) > 0 {
			iptables.AppendRuleV6(constants.AGENTIOOUTPUT, "nat", "-j", constants.AGENTIOOUTPUTDNS)
		}
	}

	if captureAllDNS {
		// Redirect all TCP dns traffic on port 53 to the agent on port 15053
		// This will be useful for the CNI case where pod DNS server address cannot be decided.
		iptables.AppendRule(
			constants.AGENTIOOUTPUTDNS, "nat",
			"-p", "tcp",
			"--dport", "53",
			"-j", "REDIRECT",
			"--to-ports", constants.AgentioAgentDNSListenerPort)
	} else {
		for _, s := range dnsServersV4 {
			// redirect all TCP dns traffic on port 53 to the agent on port 15053 for all servers
			// in etc/resolv.conf
			// We avoid redirecting all IP ranges to avoid infinite loops when there are local DNS proxies
			// such as: app -> proxy dns server -> dnsmasq -> upstream
			// This ensures that we do not get requests from dnsmasq sent back to the agent dns server in a loop.
			// Note: If a user somehow configured etc/resolv.conf to point to dnsmasq and server X, and dnsmasq also
			// pointed to server X, this would not work. However, the assumption is that is not a common case.
			iptables.AppendRuleV4(
				constants.AGENTIOOUTPUTDNS, "nat",
				"-p", "tcp",
				"--dport", "53",
				"-d", s+"/32",
				"-j", "REDIRECT",
				"--to-ports", constants.AgentioAgentDNSListenerPort)
		}
		for _, s := range dnsServersV6 {
			iptables.AppendRuleV6(
				constants.AGENTIOOUTPUTDNS, "nat",
				"-p", "tcp",
				"--dport", "53",
				"-d", s+"/128",
				"-j", "REDIRECT",
				"--to-ports", constants.AgentioAgentDNSListenerPort)
		}
	}

	if captureAllDNS {
		// Redirect all UDP dns traffic on port 53 to the agent on port 15053
		// This will be useful for the CNI case where pod DNS server address cannot be decided.
		iptables.AppendRule(
			constants.AGENTIOOUTPUTDNS,
			"nat",
			"-p",
			"udp",
			"--dport",
			"53",
			"-j",
			"REDIRECT",
			"--to-port",
			constants.AgentioAgentDNSListenerPort,
		)
	} else {
		// redirect all UDP dns traffic on port 53 to the agent on port 15053 for all servers
		// in etc/resolv.conf
		// We avoid redirecting all IP ranges to avoid infinite loops when there are local DNS proxies
		// such as: app -> proxy dns server -> dnsmasq -> upstream
		// This ensures that we do not get requests from dnsmasq sent back to the agent dns server in a loop.
		// Note: If a user somehow configured etc/resolv.conf to point to dnsmasq and server X, and dnsmasq also
		// pointed to server X, this would not work. However, the assumption is that is not a common case.
		for _, s := range dnsServersV4 {
			iptables.AppendRuleV4(constants.AGENTIOOUTPUTDNS, "nat", "-p", "udp", "--dport", "53", "-d", s+"/32",
				"-j", "REDIRECT", "--to-port", constants.AgentioAgentDNSListenerPort)
		}
		for _, s := range dnsServersV6 {
			iptables.AppendRuleV6(constants.AGENTIOOUTPUTDNS, "nat", "-p", "udp", "--dport", "53", "-d", s+"/128",
				"-j", "REDIRECT", "--to-port", constants.AgentioAgentDNSListenerPort)
		}
	}
	// Split UDP DNS traffic to separate conntrack zones
	addDNSConntrackZones(iptables, proxyUID, proxyGID, dnsServersV4, dnsServersV6, captureAllDNS)
}

// addDNSConntrackZones is a helper function to add iptables rules to split DNS traffic
// in two separate conntrack zones to avoid issues with UDP conntrack race conditions.
// Traffic that goes from proxy to DNS servers and vice versa are zone 1 and traffic from
// DNS client to proxy and vice versa goes to zone 2
func addDNSConntrackZones(
	iptables *builder.IptablesRuleBuilder,
	proxyUID, proxyGID string,
	dnsServersV4 []string,
	dnsServersV6 []string,
	captureAllDNS bool,
) {
	for _, uid := range config.Split(proxyUID) {
		// Packets with dst port 53 from proxy to zone 1. These are Agentio calls to upstream resolvers
		iptables.AppendRule(
			constants.AGENTIOOUTPUTDNS,
			"raw",
			"-p",
			"udp",
			"--dport",
			"53",
			"-m",
			"owner",
			"--uid-owner",
			uid,
			"-j",
			"CT",
			"--zone",
			"1",
		)
		// Packets with src port 15053 from proxy to zone 2. These are Agentio response packets to application clients
		iptables.AppendRule(
			constants.AGENTIOOUTPUTDNS,
			"raw",
			"-p",
			"udp",
			"--sport",
			"15053",
			"-m",
			"owner",
			"--uid-owner",
			uid,
			"-j",
			"CT",
			"--zone",
			"2",
		)
	}
	for _, gid := range config.Split(proxyGID) {
		// Packets with dst port 53 from proxy to zone 1. These are Agentio calls to upstream resolvers
		iptables.AppendRule(
			constants.AGENTIOOUTPUTDNS,
			"raw",
			"-p",
			"udp",
			"--dport",
			"53",
			"-m",
			"owner",
			"--gid-owner",
			gid,
			"-j",
			"CT",
			"--zone",
			"1",
		)
		// Packets with src port 15053 from proxy to zone 2. These are Agentio response packets to application clients
		iptables.AppendRule(
			constants.AGENTIOOUTPUTDNS,
			"raw",
			"-p",
			"udp",
			"--sport",
			"15053",
			"-m",
			"owner",
			"--gid-owner",
			gid,
			"-j",
			"CT",
			"--zone",
			"2",
		)
	}

	// For DNS conntrack, we need (at least one) inbound rule in raw/PREROUTING, so make a chain
	// and jump to it. NOTE that we are conditionally creating the jump from the nat/PREROUTING chain
	// to the AGENTIO_INBOUND chain here, because otherwise it is possible to create a jump to an empty chain,
	// which the reconciliation logic currently ignores/won't clean up.
	//
	// TODO in practice this is harmless - a jump to an empty chain is a no-op - but it borks tests.
	if captureAllDNS {
		iptables.AppendRule("PREROUTING", "raw", "-j", constants.AGENTIOINBOUND)
		// Not specifying destination address is useful for the CNI case where pod DNS server address cannot be decided.

		// Mark all UDP dns traffic with dst port 53 as zone 2. These are application client packets towards DNS resolvers.
		iptables.AppendRule(constants.AGENTIOOUTPUTDNS, "raw", "-p", "udp", "--dport", "53",
			"-j", "CT", "--zone", "2")
		// Mark all UDP dns traffic with src port 53 as zone 1. These are response packets from the DNS resolvers.
		iptables.AppendRule(constants.AGENTIOINBOUND, "raw", "-p", "udp", "--sport", "53", "-j", "CT", "--zone", "1")

	} else {

		if len(dnsServersV4) != 0 {
			iptables.AppendRuleV4("PREROUTING", "raw", "-j", constants.AGENTIOINBOUND)
		}
		// Go through all DNS servers in etc/resolv.conf and mark the packets based on these destination addresses.
		for _, s := range dnsServersV4 {
			// Mark all UDP dns traffic with dst port 53 as zone 2. These are application client packets towards DNS resolvers.
			iptables.AppendRuleV4(constants.AGENTIOOUTPUTDNS, "raw", "-p", "udp", "--dport", "53", "-d", s+"/32",
				"-j", "CT", "--zone", "2")
			// Mark all UDP dns traffic with src port 53 as zone 1. These are response packets from the DNS resolvers.
			iptables.AppendRuleV4(constants.AGENTIOINBOUND, "raw", "-p", "udp", "--sport", "53", "-s", s+"/32",
				"-j", "CT", "--zone", "1")
		}

		if len(dnsServersV6) != 0 {
			iptables.AppendRuleV6("PREROUTING", "raw", "-j", constants.AGENTIOINBOUND)
		}
		for _, s := range dnsServersV6 {
			// Mark all UDP dns traffic with dst port 53 as zone 2. These are application client packets towards DNS resolvers.
			iptables.AppendRuleV6(constants.AGENTIOOUTPUTDNS, "raw", "-p", "udp", "--dport", "53", "-d", s+"/128",
				"-j", "CT", "--zone", "2")
			// Mark all UDP dns traffic with src port 53 as zone 1. These are response packets from the DNS resolvers.
			iptables.AppendRuleV6(constants.AGENTIOINBOUND, "raw", "-p", "udp", "--sport", "53", "-s", s+"/128",
				"-j", "CT", "--zone", "1")
		}
	}
}

func (cfg *IptablesConfigurator) handleOutboundPortsInclude() {
	if cfg.cfg.OutboundPortsInclude != "" {
		for _, port := range config.Split(cfg.cfg.OutboundPortsInclude) {
			cfg.ruleBuilder.AppendRule(
				constants.AGENTIOOUTPUT, "nat", "-p", "tcp", "--dport", port, "-j", constants.AGENTIOREDIRECT)
		}
	}
}

func (cfg *IptablesConfigurator) handleCaptureByOwnerGroup(filter config.InterceptFilter) {
	if filter.Except {
		for _, group := range filter.Values {
			cfg.ruleBuilder.AppendRule(constants.AGENTIOOUTPUT, "nat",
				"-m", "owner", "--gid-owner", group, "-j", "RETURN")
		}
	} else {
		groupIsNoneOf := CombineMatchers(filter.Values, func(group string) []string {
			return []string{"-m", "owner", "!", "--gid-owner", group}
		})
		cfg.ruleBuilder.AppendRule(constants.AGENTIOOUTPUT, "nat",
			append(groupIsNoneOf, "-j", "RETURN")...)
	}
}

func (cfg *IptablesConfigurator) executeIptablesCommands(iptVer *dep.IptablesVersion, commands [][]string) error {
	for _, cmd := range commands {
		if _, err := cfg.ext.Run(log.With(), false, constants.IPTables, iptVer, nil, cmd...); err != nil {
			return err
		}
	}
	return nil
}

//nolint:errcheck // Upstream intentionally treats these cleanup commands as best effort.
func (cfg *IptablesConfigurator) tryExecuteIptablesCommands(iptVer *dep.IptablesVersion, commands [][]string) {
	for _, cmd := range commands {
		_, _ = cfg.ext.Run(log.With(), true, constants.IPTables, iptVer, nil, cmd...)
	}
}

func (cfg *IptablesConfigurator) executeIptablesRestoreCommand(iptVer *dep.IptablesVersion, data string) error {
	log.Info(
		fmt.Sprintf(
			"Running iptables restore with: %s and the following input:\n%v",
			iptVer.CmdToString(constants.IPTablesRestore),
			strings.TrimSpace(data),
		),
	)
	// --noflush to prevent flushing/deleting previous contents from table
	_, err := cfg.ext.Run(log.With(), false, constants.IPTablesRestore, iptVer, strings.NewReader(data), "--noflush")
	return err
}

//nolint:errcheck // Guardrail cleanup must not change the install result, matching upstream.
func (cfg *IptablesConfigurator) executeCommands(iptVer, ipt6Ver *dep.IptablesVersion) error {
	guardrails := false
	defer func() {
		if guardrails {
			log.Info("Removing guardrails")
			guardrailsCleanup := cfg.ruleBuilder.BuildCleanupGuardrails()
			_ = cfg.executeIptablesCommands(iptVer, guardrailsCleanup)
			if cfg.cfg.EnableIPv6 {
				_ = cfg.executeIptablesCommands(ipt6Ver, guardrailsCleanup)
			}
		}
	}()

	residueExists, deltaExists := VerifyIptablesState(log.With(), cfg.ext, cfg.ruleBuilder, iptVer, ipt6Ver)
	if residueExists && deltaExists && !cfg.cfg.Reconcile {
		log.Info(
			"reconcile is recommended but no-reconcile flag is set. Unexpected behavior may occur due to preexisting iptables rules",
		)
	}
	// Cleanup Step
	if (residueExists && deltaExists && cfg.cfg.Reconcile) || cfg.cfg.CleanupOnly {
		// Apply safety guardrails
		if !cfg.cfg.CleanupOnly {
			log.Info("Setting up guardrails")
			guardrailsCleanup := cfg.ruleBuilder.BuildCleanupGuardrails()
			guardrailsRules := cfg.ruleBuilder.BuildGuardrails()
			iptVersions := []*dep.IptablesVersion{iptVer}
			if cfg.cfg.EnableIPv6 {
				iptVersions = append(iptVersions, ipt6Ver)
			}
			for _, ver := range iptVersions {
				cfg.tryExecuteIptablesCommands(ver, guardrailsCleanup)
				if err := cfg.executeIptablesCommands(ver, guardrailsRules); err != nil {
					return err
				}
				guardrails = true
			}
		}
		// Remove old iptables
		log.Info("Performing cleanup of existing iptables")
		cfg.tryExecuteIptablesCommands(iptVer, cfg.ruleBuilder.BuildCleanupV4())
		if cfg.cfg.EnableIPv6 {
			cfg.tryExecuteIptablesCommands(ipt6Ver, cfg.ruleBuilder.BuildCleanupV6())
		}
	}

	// Apply Step
	if (deltaExists || cfg.cfg.ForceApply) && !cfg.cfg.CleanupOnly {
		log.Info("Applying iptables chains and rules")
		// Execute iptables-restore
		if err := cfg.executeIptablesRestoreCommand(iptVer, cfg.ruleBuilder.BuildV4Restore()); err != nil {
			return err
		}
		// Execute ip6tables-restore
		if cfg.cfg.EnableIPv6 {
			if err := cfg.executeIptablesRestoreCommand(ipt6Ver, cfg.ruleBuilder.BuildV6Restore()); err != nil {
				return err
			}
		}
	}

	if !deltaExists && cfg.cfg.ForceApply {
		log.Warn(
			"The forced apply of iptables changes succeeded despite the presence of conflicting rules or chains. " +
				"If you encounter this message, please consider reporting it as an issue.",
		)
	}

	return nil
}
