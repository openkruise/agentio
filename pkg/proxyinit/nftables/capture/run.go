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
	"context"
	"errors"
	"fmt"
	"os/exec"

	agentlog "github.com/openkruise/agentio/pkg/log"

	"sigs.k8s.io/knftables"

	"github.com/openkruise/agentio/pkg/proxyinit/config"
	"github.com/openkruise/agentio/pkg/proxyinit/nftables/builder"
	"github.com/openkruise/agentio/pkg/proxyinit/nftables/constants"
)

var log = agentlog.New("proxy-init.nftables.capture")

// NftProviderFunc is a type for the function signature of the nftProvider function.
type NftProviderFunc func(family knftables.Family, table string) (builder.NftablesAPI, error)

// NftablesConfigurator is the main struct used to create nftables rules based on Agentio configuration.
// It builds the necessary rules and applies them using a provided nftProvider function.
type NftablesConfigurator struct {
	cfg              *config.Config
	NetworkNamespace string
	ruleBuilder      *builder.NftablesRuleBuilder // Helper to construct nftables rules
	nftProvider      NftProviderFunc
}

// NewNftablesConfigurator initializes a new configurator instance.
// If nftProvider is not supplied, it uses the real system provider with the default inet family.
func NewNftablesConfigurator(cfg *config.Config, nftProvider NftProviderFunc) (*NftablesConfigurator, error) {
	if cfg == nil {
		cfg = &config.Config{}
	}

	if nftProvider == nil {
		nftProvider = func(family knftables.Family, table string) (builder.NftablesAPI, error) {
			nftImpl, err := builder.NewNftImpl(family, table)
			if err != nil {
				if errors.Is(err, exec.ErrNotFound) {
					if cfg.HostFilesystemPodNetwork {
						return nil, fmt.Errorf(
							"nativeNftables is enabled, but the nft binary is missing on the host filesystem: %w",
							err,
						)
					}
					return nil, fmt.Errorf(
						"nativeNftables is enabled, but the nft binary is missing in the sidecar container image: %w",
						err,
					)
				}
				return nil, err
			}
			return nftImpl, nil
		}
	}

	return &NftablesConfigurator{
		cfg:              cfg,
		NetworkNamespace: cfg.NetworkNamespace,
		ruleBuilder:      builder.NewNftablesRuleBuilder(cfg),
		nftProvider:      nftProvider,
	}, nil
}

// logConfig prints the effective configuration after applying environment and CLI overrides.
func (cfg *NftablesConfigurator) logConfig() {
	cfg.cfg.Print()
}

func (cfg *NftablesConfigurator) handleInboundPortsInclude() {
	// Handling of inbound ports. Traffic will be redirected to Envoy, which will process and forward
	// to the local service. If InboundPortsInclude is not set, no inbound ports will be intercepted by Agentio nftables.
	if cfg.cfg.InboundPortsInclude == "" {
		return
	}

	// Handle NAT table redirection
	cfg.ruleBuilder.AppendRule(constants.PreroutingChain, constants.AgentioProxyNatTable,
		"meta l4proto tcp", constants.Counter,
		"jump", constants.AgentioInboundChain)

	if cfg.cfg.InboundPortsInclude == "*" {
		// Apply any user-specified port exclusions.
		if cfg.cfg.InboundPortsExclude != "" {
			for _, port := range config.Split(cfg.cfg.InboundPortsExclude) {
				cfg.ruleBuilder.AppendRule(constants.AgentioInboundChain, constants.AgentioProxyNatTable,
					"meta l4proto tcp",
					"tcp dport", port, constants.Counter, "return")
			}
		}
		// Redirect remaining inbound traffic to Envoy.
		cfg.ruleBuilder.AppendRule(constants.AgentioInboundChain, constants.AgentioProxyNatTable,
			"meta l4proto tcp", constants.Counter,
			"jump", constants.AgentioInRedirectChain)
	} else {
		// User has specified a non-empty list of ports to be redirected to Envoy.
		for _, port := range config.Split(cfg.cfg.InboundPortsInclude) {
			cfg.ruleBuilder.AppendRule(
				constants.AgentioInboundChain, constants.AgentioProxyNatTable,
				"meta l4proto tcp", "tcp dport", port, constants.Counter, "jump", constants.AgentioInRedirectChain)
		}
	}
}

// handleOutboundIncludeRules sets up redirection for outbound traffic to Envoy based on the IP ranges included in the config.
// If the config contains "*", it means all outbound traffic should be captured.
// Otherwise, only the specified IPv4 and IPv6 CIDRs will be captured and redirected.
func (cfg *NftablesConfigurator) handleOutboundIncludeRules(
	ipv4NwRange config.NetworkRange,
	ipv6NwRange config.NetworkRange,
) {
	// Apply outbound IP inclusions.
	if ipv4NwRange.IsWildcard || ipv6NwRange.IsWildcard {
		cfg.ruleBuilder.AppendRule(
			constants.AgentioOutputChain,
			constants.AgentioProxyNatTable,
			constants.Counter,
			"jump",
			constants.AgentioRedirectChain,
		)
		// Wildcard specified. Redirect all remaining outbound traffic to Envoy.
		for _, internalInterface := range config.Split(cfg.cfg.RerouteVirtualInterfaces) {
			cfg.ruleBuilder.InsertRule(
				constants.PreroutingChain,
				constants.AgentioProxyNatTable,
				0,
				"iifname",
				internalInterface,
				constants.Counter,
				"jump",
				constants.AgentioRedirectChain,
			)
		}
	} else if len(ipv4NwRange.CIDRs) > 0 || len(ipv6NwRange.CIDRs) > 0 {
		// User has specified a non-empty list of cidrs to be redirected to Envoy.
		for _, cidr := range ipv4NwRange.CIDRs {
			for _, internalInterface := range config.Split(cfg.cfg.RerouteVirtualInterfaces) {
				cfg.ruleBuilder.InsertRule(
					constants.PreroutingChain,
					constants.AgentioProxyNatTable,
					0,
					"iifname",
					internalInterface,
					"ip daddr",
					cidr.String(),
					constants.Counter,
					"jump",
					constants.AgentioRedirectChain,
				)
			}
			cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyNatTable, "ip daddr",
				cidr.String(), constants.Counter, "jump", constants.AgentioRedirectChain)
		}

		for _, cidr := range ipv6NwRange.CIDRs {
			for _, internalInterface := range config.Split(cfg.cfg.RerouteVirtualInterfaces) {
				cfg.ruleBuilder.InsertV6RuleIfSupported(
					constants.PreroutingChain,
					constants.AgentioProxyNatTable,
					0,
					"iifname",
					internalInterface,
					"ip6 daddr",
					cidr.String(),
					constants.Counter,
					"jump",
					constants.AgentioRedirectChain,
				)
			}
			cfg.ruleBuilder.AppendV6RuleIfSupported(
				constants.AgentioOutputChain,
				constants.AgentioProxyNatTable,
				"ip6 daddr",
				cidr.String(),
				constants.Counter,
				"jump",
				constants.AgentioRedirectChain,
			)
		}
	}
}

// shortCircuitKubeInternalInterface adds a rule to skip traffic redirection for configured interfaces.
func (cfg *NftablesConfigurator) shortCircuitKubeInternalInterface() {
	for _, internalInterface := range config.Split(cfg.cfg.RerouteVirtualInterfaces) {
		cfg.ruleBuilder.InsertRule(
			constants.PreroutingChain,
			constants.AgentioProxyNatTable,
			0,
			"iifname",
			internalInterface,
			constants.Counter,
			"return",
		)
	}
}

// shortCircuitExcludeInterfaces adds return rules to skip both NAT and mangle table processing
// for the interfaces listed in ExcludeInterfaces. This is useful when you want to avoid capturing
// traffic from specific network interfaces.
func (cfg *NftablesConfigurator) shortCircuitExcludeInterfaces() {
	for _, excludeInterface := range config.Split(cfg.cfg.ExcludeInterfaces) {
		cfg.ruleBuilder.AppendRule(
			constants.PreroutingChain,
			constants.AgentioProxyNatTable,
			"iifname",
			excludeInterface,
			constants.Counter,
			"return",
		)
		cfg.ruleBuilder.AppendRule(
			constants.OutputChain,
			constants.AgentioProxyNatTable,
			"oifname",
			excludeInterface,
			constants.Counter,
			"return",
		)
	}
}

// Run is the main function that builds and applies nftables rules based on the provided configuration.
// It handles exclusion and inclusion logic for inbound and outbound traffic, DNS redirection,
// owner-based filtering, and finally applies all the rules.
func (cfg *NftablesConfigurator) Run() (*knftables.Transaction, error) {
	// Since OUTBOUND_IP_RANGES_EXCLUDE could carry ipv4 and ipv6 ranges
	// need to split them in different arrays one for ipv4 and one for ipv6
	// in order to not to fail
	ipv4RangesExclude, ipv6RangesExclude, err := config.SeparateV4V6(cfg.cfg.OutboundIPRangesExclude)
	if err != nil {
		return nil, err
	}
	if ipv4RangesExclude.IsWildcard {
		return nil, fmt.Errorf("invalid value for OUTBOUND_IP_RANGES_EXCLUDE")
	}

	ipv4RangesInclude, ipv6RangesInclude, err := config.SeparateV4V6(cfg.cfg.OutboundIPRangesInclude)
	if err != nil {
		return nil, err
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

	// Add rules to skip specific interfaces from redirection.
	cfg.shortCircuitExcludeInterfaces()
	cfg.shortCircuitKubeInternalInterface()

	// Create a rule for invalid drop in PREROUTING chain in mangle table, so the nftables will drop the out of window packets instead of reset connection .
	dropInvalid := cfg.cfg.DropInvalid
	if dropInvalid {
		cfg.ruleBuilder.AppendRule(constants.PreroutingChain, constants.AgentioProxyMangleTable,
			"meta l4proto tcp",
			"ct state", "invalid", constants.Counter,
			"jump", constants.AgentioDropChain)
		cfg.ruleBuilder.AppendRule(
			constants.AgentioDropChain,
			constants.AgentioProxyMangleTable,
			constants.Counter,
			"drop",
		)
	}

	// Create a rule to directly route traffic to the tunnel port. Envoy will listen on port 15008, serving
	// as an HBONE tunnel for Ambient traffic.
	cfg.ruleBuilder.AppendRule(constants.AgentioInboundChain, constants.AgentioProxyNatTable,
		"meta l4proto tcp",
		"tcp dport", cfg.cfg.InboundTunnelPort, constants.Counter,
		"return")

	// Create a new chain for redirecting outbound traffic to the common Envoy port.
	// In both chains, 'counter RETURN' bypasses Envoy and 'counter jump AgentioRedirectChain'
	// redirects to Envoy.
	cfg.ruleBuilder.AppendRule(
		constants.AgentioRedirectChain, constants.AgentioProxyNatTable,
		"meta l4proto tcp", constants.Counter,
		"redirect to", ":"+cfg.cfg.ProxyPort)

	// Use this chain also for redirecting inbound traffic to the common Envoy port

	cfg.ruleBuilder.AppendRule(constants.AgentioInRedirectChain, constants.AgentioProxyNatTable,
		"meta l4proto tcp", constants.Counter,
		"redirect to", ":"+cfg.cfg.InboundCapturePort)

	// Setup rules to intercept inbound traffic.
	cfg.handleInboundPortsInclude()

	// Send all output traffic to the output chain
	cfg.ruleBuilder.AppendRule(
		constants.OutputChain,
		constants.AgentioProxyNatTable,
		constants.Counter,
		"jump",
		constants.AgentioOutputChain,
	)

	// Apply port based exclusions. Must be applied before connections back to self are redirected.
	if cfg.cfg.OutboundPortsExclude != "" {
		for _, port := range config.Split(cfg.cfg.OutboundPortsExclude) {
			cfg.ruleBuilder.AppendRule(
				constants.AgentioOutputChain,
				constants.AgentioProxyNatTable,
				"tcp dport",
				port,
				constants.Counter,
				"return",
			)
			cfg.ruleBuilder.AppendRule(
				constants.AgentioOutputChain,
				constants.AgentioProxyNatTable,
				"udp dport",
				port,
				constants.Counter,
				"return",
			)
		}
	}

	// 127.0.0.6 and ::6 is bind connect from inbound passthrough cluster
	cfg.ruleBuilder.AppendRule(
		constants.AgentioOutputChain,
		constants.AgentioProxyNatTable,
		"oifname",
		"lo",
		"ip saddr",
		"127.0.0.6/32",
		constants.Counter,
		"return",
	)
	cfg.ruleBuilder.AppendV6RuleIfSupported(
		constants.AgentioOutputChain,
		constants.AgentioProxyNatTable,
		"oifname",
		"lo",
		"ip6 saddr",
		"::6/128",
		constants.Counter,
		"return",
	)

	for _, uid := range config.Split(cfg.cfg.ProxyUID) {
		// Redirect app calls back to itself via Envoy when using the service VIP
		// e.g. appN => Envoy (client) => Envoy (server) => appN.
		// nolint: lll
		if redirectDNS {
			// When DNS is enabled, we skip this for port 53. This ensures we do not have:
			// app => agentio-agent => Envoy inbound => dns server
			// Instead, we just have:
			// app => agentio-agent => dns server

			cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
				"oifname", "lo",
				"meta l4proto tcp",
				"ip daddr", "!=", cfg.cfg.HostIPv4LoopbackCidr,
				"tcp dport", "!=", "{ "+"53, "+cfg.cfg.InboundTunnelPort+" }",
				"skuid", uid,
				constants.Counter,
				"jump", constants.AgentioInRedirectChain)

			cfg.ruleBuilder.AppendV6RuleIfSupported(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
				"oifname", "lo",
				"meta l4proto tcp",
				"ip6 daddr", "!=", "::1/128",
				"tcp dport", "!=", "{ "+"53, "+cfg.cfg.InboundTunnelPort+" }",
				"skuid", uid,
				constants.Counter,
				"jump", constants.AgentioInRedirectChain)

		} else {
			cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
				"oifname", "lo",
				"meta l4proto tcp",
				"ip daddr", "!=", cfg.cfg.HostIPv4LoopbackCidr,
				"tcp dport", "!=", cfg.cfg.InboundTunnelPort,
				"skuid", uid,
				constants.Counter,
				"jump", constants.AgentioInRedirectChain)

			cfg.ruleBuilder.AppendV6RuleIfSupported(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
				"oifname", "lo",
				"meta l4proto tcp",
				"ip6 daddr", "!=", "::1/128",
				"tcp dport", "!=", cfg.cfg.InboundTunnelPort,
				"skuid", uid,
				constants.Counter,
				"jump", constants.AgentioInRedirectChain)
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
				cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
					"oifname", "lo",
					"meta l4proto tcp",
					"tcp dport", "!=", "53",
					"skuid", "!=", uid,
					constants.Counter,
					"return")
			} else {
				cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
					"oifname", "lo",
					"skuid", "!=", uid,
					constants.Counter, "return")
			}
		}

		// Avoid infinite loops. Don't redirect Envoy traffic directly back to
		// Envoy for non-loopback traffic.
		// Note that this rule is, unlike the others, protocol-independent - we want to unconditionally skip
		// all UDP/TCP packets from Envoy, regardless of dest.
		cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
			"skuid", uid,
			constants.Counter, "return")
	}

	for _, gid := range config.Split(cfg.cfg.ProxyGID) {
		// Redirect app calls back to itself via Envoy when using the service VIP
		// e.g. appN => Envoy (client) => Envoy (server) => appN.
		cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
			"oifname", "lo",
			"meta l4proto tcp",
			"ip daddr", "!=", cfg.cfg.HostIPv4LoopbackCidr,
			"tcp dport", "!=", cfg.cfg.InboundTunnelPort,
			"skgid", gid,
			constants.Counter,
			"jump", constants.AgentioInRedirectChain)

		cfg.ruleBuilder.AppendV6RuleIfSupported(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
			"oifname", "lo",
			"meta l4proto tcp",
			"ip6 daddr", "!=", "::1/128",
			"tcp dport", "!=", cfg.cfg.InboundTunnelPort,
			"skgid", gid,
			constants.Counter,
			"jump", constants.AgentioInRedirectChain)

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
				cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
					"oifname", "lo",
					"meta l4proto tcp",
					"tcp dport", "!=", "53",
					"skgid", "!=", gid,
					constants.Counter,
					"return")
			} else {
				cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
					"oifname", "lo",
					"skgid", "!=", gid,
					constants.Counter,
					"return")
			}
		}

		// Avoid infinite loops. Don't redirect Envoy traffic directly back to
		// Envoy for non-loopback traffic.
		// Note that this rule is, unlike the others, protocol-independent - we want to unconditionally skip
		// all UDP/TCP packets from Envoy, regardless of dest.
		cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
			"skgid", gid,
			constants.Counter,
			"return")
	}

	ownerGroupsFilter := config.ParseInterceptFilter(cfg.cfg.OwnerGroupsInclude, cfg.cfg.OwnerGroupsExclude)

	cfg.handleCaptureByOwnerGroup(ownerGroupsFilter)

	if redirectDNS {
		cfg.SetupDNSRedir(
			cfg.ruleBuilder, cfg.cfg.ProxyUID, cfg.cfg.ProxyGID,
			cfg.cfg.DNSServersV4, cfg.cfg.DNSServersV6, captureAllDNS,
			ownerGroupsFilter, cfg.cfg.RejectNonTCP)
	}
	if cfg.cfg.RejectNonTCP {
		cfg.ruleBuilder.AppendRule(constants.OutputChain, constants.AgentioProxyFilterTable,
			"meta l4proto != tcp", constants.Counter, "jump", constants.AgentioOutputChain)
		// IPv6 TCP still needs error reporting, neighbor discovery, and multicast membership.
		cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyFilterTable,
			"icmpv6 type { 1, 2, 3, 4, 130, 131, 132, 133, 134, 135, 136, 143 }", constants.Counter, "return")
		// Only DNS that actually reached the local redirect may leave application sockets.
		// OUTPUT still carries the original oif until rerouting.
		cfg.ruleBuilder.AppendRule(
			constants.AgentioOutputChain,
			constants.AgentioProxyFilterTable,
			"ip daddr 127.0.0.1",
			"udp dport",
			constants.AgentioAgentDNSListenerPort,
			"ct status dnat",
			constants.Counter,
			"return",
		)
		cfg.ruleBuilder.AppendV6RuleIfSupported(
			constants.AgentioOutputChain,
			constants.AgentioProxyFilterTable,
			"ip6 daddr ::1",
			"udp dport",
			constants.AgentioAgentDNSListenerPort,
			"ct status dnat",
			constants.Counter,
			"return",
		)
		for _, uid := range config.Split(cfg.cfg.ProxyUID) {
			cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyFilterTable,
				"udp dport 53", "meta skuid", uid, constants.Counter, "return")
			cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyFilterTable,
				"udp sport", constants.AgentioAgentDNSListenerPort, "meta skuid", uid, constants.Counter, "return")
		}
		for _, gid := range config.Split(cfg.cfg.ProxyGID) {
			cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyFilterTable,
				"udp dport 53", "meta skgid", gid, constants.Counter, "return")
			cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyFilterTable,
				"udp sport", constants.AgentioAgentDNSListenerPort, "meta skgid", gid, constants.Counter, "return")
		}
		cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyFilterTable,
			constants.Counter, "reject with icmpx type admin-prohibited")
	}

	// Skip redirection for Envoy-aware applications and
	// container-to-container traffic both of which explicitly use
	// localhost.
	cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
		"ip daddr", cfg.cfg.HostIPv4LoopbackCidr, constants.Counter, "return")

	cfg.ruleBuilder.AppendV6RuleIfSupported(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
		"ip6 daddr", "::1/128", constants.Counter, "return")

	// Apply outbound IPv4 exclusions. Must be applied before inclusions.
	for _, cidr := range ipv4RangesExclude.CIDRs {
		cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
			"ip daddr", cidr.String(),
			constants.Counter,
			"return")
	}
	for _, cidr := range ipv6RangesExclude.CIDRs {
		cfg.ruleBuilder.AppendV6RuleIfSupported(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
			"ip6 daddr", cidr.String(),
			constants.Counter,
			"return")
	}

	cfg.handleOutboundPortsInclude()

	cfg.handleOutboundIncludeRules(ipv4RangesInclude, ipv6RangesInclude)

	return cfg.executeCommands()
}

// SetupDNSRedir is a helper function for supporting DNS redirection use-cases.
func (cfg *NftablesConfigurator) SetupDNSRedir(
	nft *builder.NftablesRuleBuilder,
	proxyUID, proxyGID string,
	dnsServersV4 []string,
	dnsServersV6 []string,
	captureAllDNS bool,
	ownerGroupsFilter config.InterceptFilter,
	forceCapture bool,
) {
	// Uniquely for DNS (at this time) we need a jump in "raw:OUTPUT", so this jump is conditional on that setting.
	// And, unlike nat/OUTPUT, we have no shared rules, so no need to do a 2-level jump at this time
	nft.AppendRule(
		constants.OutputChain,
		constants.AgentioProxyRawTable,
		constants.Counter,
		"jump",
		constants.AgentioOutputDNSChain,
	)

	// Conditionally insert jumps for V6 and V4 - we may have DNS capture enabled for V4 servers but not V6, or vice versa.
	// This avoids creating no-op jumps in v6 if we only need them in v4.
	//
	// TODO we should probably *conditionally* create jumps if and only if rules exist in the jumped-to table,
	// in a more automatic fashion.
	if forceCapture {
		// DNS capture must precede interface, port, and owner-group exclusions.
		nft.InsertRule(
			constants.OutputChain,
			constants.AgentioProxyNatTable,
			0,
			constants.Counter,
			"jump",
			constants.AgentioOutputDNSChain,
		)
		for _, uid := range config.Split(proxyUID) {
			nft.AppendRule(constants.AgentioOutputDNSChain, constants.AgentioProxyNatTable,
				"meta skuid", uid, constants.Counter, "return")
		}
		for _, gid := range config.Split(proxyGID) {
			nft.AppendRule(constants.AgentioOutputDNSChain, constants.AgentioProxyNatTable,
				"meta skgid", gid, constants.Counter, "return")
		}
	} else if captureAllDNS || len(dnsServersV4) > 0 || len(dnsServersV6) > 0 {
		nft.AppendRule(
			constants.AgentioOutputChain,
			constants.AgentioProxyNatTable,
			constants.Counter,
			"jump",
			constants.AgentioOutputDNSChain,
		)
	}

	if captureAllDNS {
		// Redirect all TCP dns traffic on port 53 to the agent on port 15053
		// This will be useful for the CNI case where pod DNS server address cannot be decided.
		nft.AppendRule(
			constants.AgentioOutputDNSChain, constants.AgentioProxyNatTable,
			"meta l4proto tcp",
			"tcp dport", "53",
			constants.Counter,
			"redirect",
			"to", ":"+constants.AgentioAgentDNSListenerPort)
	} else {
		for _, s := range dnsServersV4 {
			// redirect all TCP dns traffic on port 53 to the agent on port 15053 for all servers
			// in etc/resolv.conf
			// We avoid redirecting all IP ranges to avoid infinite loops when there are local DNS proxies
			// such as: app -> proxy dns server -> dnsmasq -> upstream
			// This ensures that we do not get requests from dnsmasq sent back to the agent dns server in a loop.
			// Note: If a user somehow configured etc/resolv.conf to point to dnsmasq and server X, and dnsmasq also
			// pointed to server X, this would not work. However, the assumption is that is not a common case.
			nft.AppendRule(
				constants.AgentioOutputDNSChain, constants.AgentioProxyNatTable,
				"ip daddr", s+"/32",
				"tcp dport", "53",
				constants.Counter,
				"redirect",
				"to", ":"+constants.AgentioAgentDNSListenerPort)
		}
		for _, s := range dnsServersV6 {
			nft.AppendV6RuleIfSupported(
				constants.AgentioOutputDNSChain, constants.AgentioProxyNatTable,
				"ip6 daddr", s+"/128",
				"tcp dport", "53",
				constants.Counter,
				"redirect",
				"to", ":"+constants.AgentioAgentDNSListenerPort)
		}
	}

	if captureAllDNS {
		// Redirect all UDP dns traffic on port 53 to the agent on port 15053
		// This will be useful for the CNI case where pod DNS server address cannot be decided.
		nft.AppendRule(constants.AgentioOutputDNSChain, constants.AgentioProxyNatTable,
			"udp dport", "53",
			constants.Counter,
			"redirect",
			"to", ":"+constants.AgentioAgentDNSListenerPort)
	} else {
		// redirect all UDP dns traffic on port 53 to the agent on port 15053 for all servers
		// in etc/resolv.conf
		// We avoid redirecting all IP ranges to avoid infinite loops when there are local DNS proxies
		// such as: app -> proxy dns server -> dnsmasq -> upstream
		// This ensures that we do not get requests from dnsmasq sent back to the agent dns server in a loop.
		// Note: If a user somehow configured etc/resolv.conf to point to dnsmasq and server X, and dnsmasq also
		// pointed to server X, this would not work. However, the assumption is that is not a common case.
		for _, s := range dnsServersV4 {
			nft.AppendRule(constants.AgentioOutputDNSChain, constants.AgentioProxyNatTable,
				"ip daddr", s+"/32",
				"udp dport", "53",
				constants.Counter,
				"redirect",
				"to", ":"+constants.AgentioAgentDNSListenerPort)
		}
		for _, s := range dnsServersV6 {
			nft.AppendV6RuleIfSupported(constants.AgentioOutputDNSChain, constants.AgentioProxyNatTable,
				"ip6 daddr", s+"/128",
				"udp dport", "53",
				constants.Counter,
				"redirect",
				"to", ":"+constants.AgentioAgentDNSListenerPort)
		}
	}
	// Split UDP DNS traffic to separate conntrack zones
	cfg.addDNSConntrackZones(nft, proxyUID, proxyGID, dnsServersV4, dnsServersV6, captureAllDNS)
}

// addDNSConntrackZones is a helper function to add nftables rules to split DNS traffic
// in two separate conntrack zones to avoid issues with UDP conntrack race conditions.
// Traffic that goes from proxy to DNS servers and vice versa are zone 1 and traffic from
// DNS client to proxy and vice versa goes to zone 2
func (cfg *NftablesConfigurator) addDNSConntrackZones(
	nft *builder.NftablesRuleBuilder,
	proxyUID, proxyGID string,
	dnsServersV4 []string,
	dnsServersV6 []string,
	captureAllDNS bool,
) {
	for _, uid := range config.Split(proxyUID) {
		// Packets with dst port 53 from proxy to zone 1. These are Agentio calls to upstream resolvers
		nft.AppendRule(constants.AgentioOutputDNSChain, constants.AgentioProxyRawTable,
			"udp dport", "53",
			"meta",
			"skuid", uid, constants.Counter,
			"ct", "zone", "set", "1")
		// Packets with src port 15053 from proxy to zone 2. These are Agentio response packets to application clients
		nft.AppendRule(constants.AgentioOutputDNSChain, constants.AgentioProxyRawTable,
			"udp sport", "15053",
			"meta",
			"skuid", uid, constants.Counter,
			"ct", "zone", "set", "2")
	}
	for _, gid := range config.Split(proxyGID) {
		// Packets with dst port 53 from proxy to zone 1. These are Agentio calls to upstream resolvers
		nft.AppendRule(constants.AgentioOutputDNSChain, constants.AgentioProxyRawTable,
			"udp dport", "53",
			"meta",
			"skgid", gid, constants.Counter,
			"ct", "zone", "set", "1")
		// Packets with src port 15053 from proxy to zone 2. These are Agentio response packets to application clients
		nft.AppendRule(constants.AgentioOutputDNSChain, constants.AgentioProxyRawTable,
			"udp sport", "15053",
			"meta",
			"skgid", gid, constants.Counter,
			"ct", "zone", "set", "2")
	}

	// For DNS conntrack, we need (at least one) inbound rule in raw/PREROUTING, so make a chain
	// and jump to it. NOTE that we are conditionally creating the jump from the nat/PREROUTING chain
	// to the AGENTIO_INBOUND chain here, because otherwise it is possible to create a jump to an empty chain,
	// which the reconciliation logic currently ignores/won't clean up.
	//
	if captureAllDNS {
		nft.AppendRule(
			constants.PreroutingChain,
			constants.AgentioProxyRawTable,
			constants.Counter,
			"jump",
			constants.AgentioInboundChain,
		)
		// Not specifying destination address is useful for the CNI case where pod DNS server address cannot be decided.

		// Mark all UDP dns traffic with dst port 53 as zone 2. These are application client packets towards DNS resolvers.
		nft.AppendRule(constants.AgentioOutputDNSChain, constants.AgentioProxyRawTable,
			"udp dport", "53", constants.Counter,
			"ct", "zone", "set", "2")
		// Mark all UDP dns traffic with src port 53 as zone 1. These are response packets from the DNS resolvers.
		nft.AppendRule(constants.AgentioInboundChain, constants.AgentioProxyRawTable,
			"udp sport", "53", constants.Counter,
			"ct", "zone", "set", "1")
	} else {

		if len(dnsServersV4) != 0 || len(dnsServersV6) != 0 {
			nft.AppendRule(
				constants.PreroutingChain,
				constants.AgentioProxyRawTable,
				constants.Counter,
				"jump",
				constants.AgentioInboundChain,
			)
		}
		// Go through all DNS servers in etc/resolv.conf and mark the packets based on these destination addresses.
		for _, s := range dnsServersV4 {
			// Mark all UDP dns traffic with dst port 53 as zone 2. These are application client packets towards DNS resolvers.
			nft.AppendRule(constants.AgentioOutputDNSChain, constants.AgentioProxyRawTable,
				"udp dport", "53",
				"ip daddr", s+"/32", constants.Counter,
				"ct", "zone", "set", "2")
			// Mark all UDP dns traffic with src port 53 as zone 1. These are response packets from the DNS resolvers.
			nft.AppendRule(constants.AgentioInboundChain, constants.AgentioProxyRawTable,
				"udp sport", "53",
				"ip saddr", s+"/32", constants.Counter,
				"ct", "zone", "set", "1")
		}

		for _, s := range dnsServersV6 {
			// Mark all UDP dns traffic with dst port 53 as zone 2. These are application client packets towards DNS resolvers.
			nft.AppendV6RuleIfSupported(constants.AgentioOutputDNSChain, constants.AgentioProxyRawTable,
				"udp dport", "53",
				"ip6 daddr", s+"/128", constants.Counter,
				"ct", "zone", "set", "2")
			// Mark all UDP dns traffic with src port 53 as zone 1. These are response packets from the DNS resolvers.
			nft.AppendV6RuleIfSupported(constants.AgentioInboundChain, constants.AgentioProxyRawTable,
				"udp sport", "53",
				"ip6 saddr", s+"/128", constants.Counter,
				"ct", "zone", "set", "1")
		}
	}
}

// handleOutboundPortsInclude checks if there are any outbound ports to include for redirection.
// If yes, it splits the list of ports and adds a rule for each port to redirect TCP traffic.
// This makes sure traffic to these ports gets redirected properly in the AgentioProxyNatTable table.
func (cfg *NftablesConfigurator) handleOutboundPortsInclude() {
	if cfg.cfg.OutboundPortsInclude != "" {
		for _, port := range config.Split(cfg.cfg.OutboundPortsInclude) {
			// For each port, add a rule to redirect TCP traffic on that port from the OUTPUT chain in the NAT table to the redirect chain
			cfg.ruleBuilder.AppendRule(
				constants.AgentioOutputChain,
				constants.AgentioProxyNatTable,
				"tcp dport",
				port,
				constants.Counter,
				"jump",
				constants.AgentioRedirectChain,
			)
		}
	}
}

// handleCaptureByOwnerGroup adds rules based on the socket owner group ID (skgid).
func (cfg *NftablesConfigurator) handleCaptureByOwnerGroup(filter config.InterceptFilter) {
	if filter.Except {
		for _, group := range filter.Values {
			cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
				"skgid", group,
				constants.Counter,
				"return")
		}
	} else {
		groupIsNoneOf := CombineMatchers(filter.Values, func(group string) []string {
			return []string{"skgid", "!=", group}
		})
		cfg.ruleBuilder.AppendRule(constants.AgentioOutputChain, constants.AgentioProxyNatTable,
			append(groupIsNoneOf, constants.Counter, "return")...)
	}
}

func (cfg *NftablesConfigurator) addAgentioTableRules(
	tx *knftables.Transaction,
	tableName string,
	chains []knftables.Chain,
	rules []knftables.Rule,
) *knftables.Transaction {
	// Track how many rules have been added to each chain
	chainRuleCount := make(map[string]int)

	// Count the number of rules present in each of the chains
	for _, rule := range rules {
		chainRuleCount[rule.Chain]++
	}

	// Let's filter out the chains that have rules
	chainsWithRules := []knftables.Chain{}
	for _, chain := range chains {
		if chainRuleCount[chain.Name] > 0 {
			chainsWithRules = append(chainsWithRules, chain)
		}
	}

	// Skip creating the table itself if none of the chains have any rules
	if len(chainsWithRules) == 0 {
		return tx
	}

	// Ensure that the table exists
	tx.Add(&knftables.Table{Name: tableName, Family: knftables.InetFamily})

	// Flush the table to remove all existing rules before applying new ones
	tx.Flush(&knftables.Table{Name: tableName, Family: knftables.InetFamily})

	// Add the chains that have rules
	for _, chain := range chainsWithRules {
		tx.Add(&chain)
	}

	// Reset chainRuleCount to handle the use-case mentioned below.
	chainRuleCount = make(map[string]int)

	// Add the rules to the transaction
	for _, rule := range rules {
		chain := rule.Chain

		// In IPtables, inserting a rule at position 1 means it gets placed at the head of the chain. In contrast,
		// nftables starts rule indexing at 0. However, nftables does not allow inserting a rule at index 0 when
		// the chain is empty, nor does it allow inserting a rule at position N if the chain already contains N rules.
		// To handle these cases, we check if the chain is empty and convert it to an append operation.
		if rule.Index != nil && (chainRuleCount[chain] == 0 || *rule.Index >= chainRuleCount[chain]) {
			rule.Index = nil
		}

		// When a rule includes the Index, its considered as an Insert request.
		if rule.Index != nil {
			tx.Insert(&rule)
		} else {
			tx.Add(&rule)
		}
		chainRuleCount[chain]++
	}

	return tx
}

// cleanupTable deletes all the chains and rules from the specific table.
func (cfg *NftablesConfigurator) cleanupTable(tableName string, tx *knftables.Transaction) *knftables.Transaction {
	tx.Add(&knftables.Table{Name: tableName, Family: knftables.InetFamily})
	tx.Delete(&knftables.Table{Name: tableName, Family: knftables.InetFamily})
	return tx
}

// addAgentioNatTableRules updates a transaction to include the nftables rules for the AgentioProxyNat table.
// It makes sure the table and the necessary chains exist, then adds rules from the rule builder.
func (cfg *NftablesConfigurator) addAgentioNatTableRules(tx *knftables.Transaction) *knftables.Transaction {
	if cfg.cfg.CleanupOnly {
		return cfg.cleanupTable(constants.AgentioProxyNatTable, tx)
	}

	if len(cfg.ruleBuilder.Rules[constants.AgentioProxyNatTable]) == 0 {
		return tx
	}

	chains := []knftables.Chain{
		{
			Name:     constants.PreroutingChain,
			Table:    constants.AgentioProxyNatTable,
			Family:   knftables.InetFamily,
			Type:     knftables.PtrTo(knftables.NATType),
			Hook:     knftables.PtrTo(knftables.PreroutingHook),
			Priority: knftables.PtrTo(knftables.DNATPriority),
		},
		{
			Name:     constants.OutputChain,
			Table:    constants.AgentioProxyNatTable,
			Family:   knftables.InetFamily,
			Type:     knftables.PtrTo(knftables.NATType),
			Hook:     knftables.PtrTo(knftables.OutputHook),
			Priority: new(knftables.BaseChainPriority(cfg.cfg.NativeNftablesOutputPriority)),
		},
		{Name: constants.AgentioInboundChain, Table: constants.AgentioProxyNatTable, Family: knftables.InetFamily},
		{Name: constants.AgentioRedirectChain, Table: constants.AgentioProxyNatTable, Family: knftables.InetFamily},
		{Name: constants.AgentioInRedirectChain, Table: constants.AgentioProxyNatTable, Family: knftables.InetFamily},
		{Name: constants.AgentioOutputChain, Table: constants.AgentioProxyNatTable, Family: knftables.InetFamily},
		{Name: constants.AgentioOutputDNSChain, Table: constants.AgentioProxyNatTable, Family: knftables.InetFamily},
	}

	rules := cfg.ruleBuilder.Rules[constants.AgentioProxyNatTable]

	return cfg.addAgentioTableRules(tx, constants.AgentioProxyNatTable, chains, rules)
}

// addAgentioMangleTableRules updates a transaction to include the nftables rules for the AgentioProxyMangle table.
// It makes sure the table and the necessary chains exist, then adds rules from the rule builder.
func (cfg *NftablesConfigurator) addAgentioMangleTableRules(tx *knftables.Transaction) *knftables.Transaction {
	if cfg.cfg.CleanupOnly {
		return cfg.cleanupTable(constants.AgentioProxyMangleTable, tx)
	}

	if len(cfg.ruleBuilder.Rules[constants.AgentioProxyMangleTable]) == 0 {
		return tx
	}

	chains := []knftables.Chain{
		{
			Name:     constants.PreroutingChain,
			Table:    constants.AgentioProxyMangleTable,
			Family:   knftables.InetFamily,
			Type:     knftables.PtrTo(knftables.FilterType),
			Hook:     knftables.PtrTo(knftables.PreroutingHook),
			Priority: knftables.PtrTo(knftables.ManglePriority),
		},
		{
			Name:     constants.OutputChain,
			Table:    constants.AgentioProxyMangleTable,
			Family:   knftables.InetFamily,
			Type:     knftables.PtrTo(knftables.RouteType),
			Hook:     knftables.PtrTo(knftables.OutputHook),
			Priority: knftables.PtrTo(knftables.ManglePriority),
		},
		{Name: constants.AgentioInboundChain, Table: constants.AgentioProxyMangleTable, Family: knftables.InetFamily},
		{Name: constants.AgentioDropChain, Table: constants.AgentioProxyMangleTable, Family: knftables.InetFamily},
	}

	rules := cfg.ruleBuilder.Rules[constants.AgentioProxyMangleTable]

	return cfg.addAgentioTableRules(tx, constants.AgentioProxyMangleTable, chains, rules)
}

// addAgentioRawTableRules updates a transaction to include the nftables rules for the AgentioProxyRaw table.
// It makes sure the table and the necessary chains exist, then adds rules from the rule builder.
func (cfg *NftablesConfigurator) addAgentioRawTableRules(tx *knftables.Transaction) *knftables.Transaction {
	if cfg.cfg.CleanupOnly {
		return cfg.cleanupTable(constants.AgentioProxyRawTable, tx)
	}

	if len(cfg.ruleBuilder.Rules[constants.AgentioProxyRawTable]) == 0 {
		return tx
	}

	chains := []knftables.Chain{
		{
			Name:     constants.PreroutingChain,
			Table:    constants.AgentioProxyRawTable,
			Family:   knftables.InetFamily,
			Type:     knftables.PtrTo(knftables.FilterType),
			Hook:     knftables.PtrTo(knftables.PreroutingHook),
			Priority: knftables.PtrTo(knftables.RawPriority),
		},
		{
			Name:     constants.OutputChain,
			Table:    constants.AgentioProxyRawTable,
			Family:   knftables.InetFamily,
			Type:     knftables.PtrTo(knftables.FilterType),
			Hook:     knftables.PtrTo(knftables.OutputHook),
			Priority: knftables.PtrTo(knftables.RawPriority),
		},
		{Name: constants.AgentioInboundChain, Table: constants.AgentioProxyRawTable, Family: knftables.InetFamily},
		{Name: constants.AgentioOutputDNSChain, Table: constants.AgentioProxyRawTable, Family: knftables.InetFamily},
	}

	rules := cfg.ruleBuilder.Rules[constants.AgentioProxyRawTable]

	return cfg.addAgentioTableRules(tx, constants.AgentioProxyRawTable, chains, rules)
}

// addAgentioFilterTableRules installs the optional non-TCP outbound policy.
func (cfg *NftablesConfigurator) addAgentioFilterTableRules(tx *knftables.Transaction) *knftables.Transaction {
	if cfg.cfg.CleanupOnly {
		return cfg.cleanupTable(constants.AgentioProxyFilterTable, tx)
	}
	chains := []knftables.Chain{
		{
			Name:     constants.OutputChain,
			Table:    constants.AgentioProxyFilterTable,
			Family:   knftables.InetFamily,
			Type:     knftables.PtrTo(knftables.FilterType),
			Hook:     knftables.PtrTo(knftables.OutputHook),
			Priority: knftables.PtrTo(knftables.FilterPriority),
		},
		{Name: constants.AgentioOutputChain, Table: constants.AgentioProxyFilterTable, Family: knftables.InetFamily},
	}
	return cfg.addAgentioTableRules(
		tx,
		constants.AgentioProxyFilterTable,
		chains,
		cfg.ruleBuilder.Rules[constants.AgentioProxyFilterTable],
	)
}

// executeCommands creates a transaction including all needed modifications and runs it.
func (cfg *NftablesConfigurator) executeCommands() (*knftables.Transaction, error) {
	nft, err := cfg.nftProvider("", "")
	if err != nil {
		return nil, err
	}
	tx := nft.NewTransaction()
	tx = cfg.addAgentioNatTableRules(tx)
	tx = cfg.addAgentioMangleTableRules(tx)
	tx = cfg.addAgentioRawTableRules(tx)
	tx = cfg.addAgentioFilterTableRules(tx)

	// If there are any transactions to apply, run them in a batch.
	if tx.NumOperations() > 0 {
		if err := nft.Run(context.TODO(), tx); err != nil {
			return tx, fmt.Errorf("nftables run failed: %w", err)
		}
	}
	return tx, nil
}

// CombineMatchers takes a list of values and a matcher function.
// For each value, it calls the matcher function to get a list of conditions,
// then it combines all those lists into one big list using Flatten.
func CombineMatchers(values []string, matcher func(value string) []string) []string {
	matchers := make([][]string, 0, len(values))
	for _, value := range values {
		matchers = append(matchers, matcher(value))
	}
	return Flatten(matchers...)
}

// Flatten takes many lists of strings and joins them into a single list and appends all the elements
// from each list one after another.
func Flatten(lists ...[]string) []string {
	var result []string
	for _, list := range lists {
		result = append(result, list...)
	}
	return result
}
