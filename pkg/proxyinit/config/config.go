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
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	agentlog "github.com/openkruise/agentio/pkg/log"

	"github.com/miekg/dns"

	"github.com/openkruise/agentio/pkg/proxyinit/iptables/constants"
)

var log = agentlog.New("proxy-init.config")

func DefaultConfig() *Config {
	return &Config{
		ProxyPort:            "15001",
		InboundCapturePort:   "15006",
		InboundTunnelPort:    "15008",
		IptablesProbePort:    constants.DefaultIptablesProbePortUint,
		ProbeTimeout:         constants.DefaultProbeTimeout,
		OwnerGroupsInclude:   constants.OwnerGroupsInclude,
		OwnerGroupsExclude:   constants.OwnerGroupsExclude,
		HostIPv4LoopbackCidr: constants.HostIPv4LoopbackCidr,

		NativeNftablesOutputPriority: "-100",
	}
}

// Command line options
type Config struct {
	ProxyPort                string        `json:"OUTBOUND_CAPTURE_PORT"`
	InboundCapturePort       string        `json:"AGENTIO_INBOUND_CAPTURE_PORT"`
	InboundTunnelPort        string        `json:"AGENTIO_INBOUND_TUNNEL_PORT"`
	ProxyUID                 string        `json:"AGENTIO_PROXY_UID"`
	ProxyGID                 string        `json:"AGENTIO_PROXY_GID"`
	InboundInterceptionMode  string        `json:"AGENTIO_INTERCEPTION_MODE"`
	InboundPortsInclude      string        `json:"AGENTIO_INCLUDE_INBOUND_PORTS"`
	InboundPortsExclude      string        `json:"AGENTIO_EXCLUDE_INBOUND_PORTS"`
	OwnerGroupsInclude       string        `json:"AGENTIO_INCLUDE_OUTBOUND_OWNER_GROUPS"`
	OwnerGroupsExclude       string        `json:"AGENTIO_EXCLUDE_OUTBOUND_OWNER_GROUPS"`
	OutboundPortsInclude     string        `json:"AGENTIO_INCLUDE_OUTBOUND_PORTS"`
	OutboundPortsExclude     string        `json:"AGENTIO_EXCLUDE_OUTBOUND_PORTS"`
	OutboundIPRangesInclude  string        `json:"AGENTIO_INCLUDE_OUTBOUND_IP_RANGES"`
	OutboundIPRangesExclude  string        `json:"AGENTIO_EXCLUDE_OUTBOUND_IP_RANGES"`
	RerouteVirtualInterfaces string        `json:"AGENTIO_REROUTE_VIRTUAL_INTERFACES"`
	ExcludeInterfaces        string        `json:"AGENTIO_EXCLUDE_INTERFACES"`
	IptablesProbePort        uint16        `json:"AGENTIO_IPTABLES_PROBE_PORT"`
	ProbeTimeout             time.Duration `json:"AGENTIO_PROBE_TIMEOUT"`
	DryRun                   bool          `json:"AGENTIO_DRY_RUN"`
	SkipRuleApply            bool          `json:"AGENTIO_SKIP_RULE_APPLY"`
	RunValidation            bool          `json:"AGENTIO_RUN_VALIDATION"`
	RedirectDNS              bool          `json:"AGENTIO_REDIRECT_DNS"`
	DropInvalid              bool          `json:"AGENTIO_DROP_INVALID"`
	RejectNonTCP             bool          `json:"AGENTIO_REJECT_NON_TCP"`
	CaptureAllDNS            bool          `json:"AGENTIO_CAPTURE_ALL_DNS"`
	EnableIPv6               bool          `json:"DETECTED_IPV6"`
	DNSServersV4             []string      `json:"RESOLVER_SERVERS_V4"`
	DNSServersV6             []string      `json:"RESOLVER_SERVERS_V6"`
	NetworkNamespace         string        `json:"AGENTIO_NETWORK_NAMESPACE"`
	// When running in host filesystem, we have different semantics around the environment.
	// For instance, we would have a node-shared IPTables lock, despite not needing it.
	// HostFilesystemPodNetwork indicates we are in this mode, typically from the CNI.
	HostFilesystemPodNetwork bool       `json:"AGENTIO_CNI_MODE"`
	DualStack                bool       `json:"AGENTIO_DUAL_STACK"`
	HostIP                   netip.Addr `json:"DETECTED_HOST_IP"`
	HostIPv4LoopbackCidr     string     `json:"AGENTIO_OUTBOUND_IPV4_LOOPBACK_CIDR"`
	Reconcile                bool       `json:"AGENTIO_RECONCILE"`
	CleanupOnly              bool       `json:"AGENTIO_CLEANUP_ONLY"`
	ForceApply               bool       `json:"AGENTIO_FORCE_APPLY"`
	NativeNftables           bool       `json:"AGENTIO_NATIVE_NFTABLES"`
	ForceIptablesBinary      string     `json:"AGENTIO_FORCE_IPTABLES_BINARY"`

	NativeNftablesOutputPriority string `json:"AGENTIO_NATIVE_NFTABLES_OUTPUT_PRIORITY"`
}

type NetworkRange struct {
	IsWildcard    bool
	CIDRs         []netip.Prefix
	HasLoopBackIP bool
}

func (c *Config) String() string {
	output, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		log.Error(fmt.Sprintf("Unable to marshal config object: %v", err))
	}
	return string(output)
}

func (c *Config) Print() {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("OUTBOUND_CAPTURE_PORT=%s\n", c.ProxyPort))
	b.WriteString(fmt.Sprintf("AGENTIO_INBOUND_CAPTURE_PORT=%s\n", c.InboundCapturePort))
	b.WriteString(fmt.Sprintf("AGENTIO_INBOUND_TUNNEL_PORT=%s\n", c.InboundTunnelPort))
	b.WriteString(fmt.Sprintf("AGENTIO_PROXY_UID=%s\n", c.ProxyUID))
	b.WriteString(fmt.Sprintf("AGENTIO_PROXY_GID=%s\n", c.ProxyGID))
	b.WriteString(fmt.Sprintf("AGENTIO_INTERCEPTION_MODE=%s\n", c.InboundInterceptionMode))
	b.WriteString(fmt.Sprintf("AGENTIO_INCLUDE_INBOUND_PORTS=%s\n", c.InboundPortsInclude))
	b.WriteString(fmt.Sprintf("AGENTIO_EXCLUDE_INBOUND_PORTS=%s\n", c.InboundPortsExclude))
	b.WriteString(fmt.Sprintf("AGENTIO_INCLUDE_OUTBOUND_OWNER_GROUPS=%s\n", c.OwnerGroupsInclude))
	b.WriteString(fmt.Sprintf("AGENTIO_EXCLUDE_OUTBOUND_OWNER_GROUPS=%s\n", c.OwnerGroupsExclude))
	b.WriteString(fmt.Sprintf("AGENTIO_INCLUDE_OUTBOUND_IP_RANGES=%s\n", c.OutboundIPRangesInclude))
	b.WriteString(fmt.Sprintf("AGENTIO_EXCLUDE_OUTBOUND_IP_RANGES=%s\n", c.OutboundIPRangesExclude))
	b.WriteString(fmt.Sprintf("AGENTIO_INCLUDE_OUTBOUND_PORTS=%s\n", c.OutboundPortsInclude))
	b.WriteString(fmt.Sprintf("AGENTIO_EXCLUDE_OUTBOUND_PORTS=%s\n", c.OutboundPortsExclude))
	b.WriteString(fmt.Sprintf("AGENTIO_REROUTE_VIRTUAL_INTERFACES=%s\n", c.RerouteVirtualInterfaces))
	b.WriteString(fmt.Sprintf("DETECTED_IPV6=%t\n", c.EnableIPv6))
	// TODO remove this flag - "dual stack" should just mean
	// - supports IPv6
	// - supports pods with more than one podIP
	// The former already has a flag, the latter is something we should do by default and is a bug where we do not
	b.WriteString(fmt.Sprintf("AGENTIO_DUAL_STACK=%t\n", c.DualStack))
	b.WriteString(fmt.Sprintf("AGENTIO_REDIRECT_DNS=%t\n", c.RedirectDNS))
	b.WriteString(fmt.Sprintf("AGENTIO_DROP_INVALID=%t\n", c.DropInvalid))
	b.WriteString(fmt.Sprintf("AGENTIO_REJECT_NON_TCP=%t\n", c.RejectNonTCP))
	b.WriteString(fmt.Sprintf("AGENTIO_CAPTURE_ALL_DNS=%t\n", c.CaptureAllDNS))
	b.WriteString(fmt.Sprintf("RESOLVER_SERVERS=%s,%s\n", c.DNSServersV4, c.DNSServersV6))
	b.WriteString(fmt.Sprintf("AGENTIO_NETWORK_NAMESPACE=%s\n", c.NetworkNamespace))
	b.WriteString(fmt.Sprintf("AGENTIO_CNI_MODE=%s\n", strconv.FormatBool(c.HostFilesystemPodNetwork)))
	b.WriteString(fmt.Sprintf("AGENTIO_EXCLUDE_INTERFACES=%s\n", c.ExcludeInterfaces))
	b.WriteString(fmt.Sprintf("AGENTIO_RECONCILE=%t\n", c.Reconcile))
	b.WriteString(fmt.Sprintf("AGENTIO_CLEANUP_ONLY=%t\n", c.CleanupOnly))
	b.WriteString(fmt.Sprintf("AGENTIO_FORCE_APPLY=%t\n", c.ForceApply))
	b.WriteString(fmt.Sprintf("AGENTIO_NATIVE_NFTABLES=%t\n", c.NativeNftables))
	b.WriteString(fmt.Sprintf("AGENTIO_NATIVE_NFTABLES_OUTPUT_PRIORITY=%s\n", c.NativeNftablesOutputPriority))
	b.WriteString(fmt.Sprintf("AGENTIO_FORCE_IPTABLES_BINARY=%s\n", c.ForceIptablesBinary))
	log.Info(fmt.Sprintf("Agentio effective config:\n%s", b.String()))
}

func (c *Config) Validate() error {
	if c.InboundInterceptionMode != "" && c.InboundInterceptionMode != "REDIRECT" {
		return fmt.Errorf("unsupported interception mode %q: only REDIRECT is supported", c.InboundInterceptionMode)
	}
	if !c.NativeNftables && c.NativeNftablesOutputPriority != "-100" {
		return fmt.Errorf("custom NAT OUTPUT priority requires AGENTIO_NATIVE_NFTABLES=true")
	}
	if c.NativeNftables {
		if err := ValidateNATOutputPriority(c.NativeNftablesOutputPriority); err != nil {
			return err
		}
	}
	if err := ValidateOwnerGroups(c.OwnerGroupsInclude, c.OwnerGroupsExclude); err != nil {
		return err
	}

	if err := ValidateIptablesBinary(c.ForceIptablesBinary); err != nil {
		return err
	}
	return ValidateIPv4LoopbackCidr(c.HostIPv4LoopbackCidr)
}

//nolint:errorlint // Preserve upstream resolver error identity.
func (c *Config) FillConfigFromEnvironment() error {
	// Fill in env-var only options
	if v, ok := os.LookupEnv("AGENTIO_INCLUDE_OUTBOUND_OWNER_GROUPS"); ok {
		c.OwnerGroupsInclude = v
	}
	if v, ok := os.LookupEnv("AGENTIO_EXCLUDE_OUTBOUND_OWNER_GROUPS"); ok {
		c.OwnerGroupsExclude = v
	}

	if v, ok := os.LookupEnv("AGENTIO_OUTBOUND_IPV4_LOOPBACK_CIDR"); ok {
		c.HostIPv4LoopbackCidr = v
	}
	proxyUser := "agentio-proxy"
	if v, ok := os.LookupEnv(constants.ProxyUser); ok {
		proxyUser = v
	}

	// TODO: Make this more configurable, maybe with an allowlist of users to be captured for output instead of a denylist.
	if c.ProxyUID == "" {
		usr, err := user.Lookup(proxyUser)
		var userID string
		// Default to the UID of AGENTIO_PROXY_USER.
		if err != nil {
			userID = constants.DefaultProxyUID
		} else {
			userID = usr.Uid
		}
		c.ProxyUID = userID
	}

	// Default the proxy group to the proxy user ID.
	if c.ProxyGID == "" {
		c.ProxyGID = c.ProxyUID
	}
	// Detect whether IPv6 is enabled by checking if the pod's IP address is IPv4 or IPv6.
	// TODO remove this check, it will break with more than one pod IP
	hostIP, isIPv6, err := getLocalIP(c.DualStack)
	if err != nil {
		return err
	}

	c.HostIP = hostIP
	c.EnableIPv6 = isIPv6

	// Lookup DNS nameservers. We only do this if DNS is enabled in case of some obscure theoretical
	// case where reading /etc/resolv.conf could fail.
	// If capture all DNS option is enabled, we don't need to read from the dns resolve conf. All
	// traffic to port 53 will be captured.
	if c.RedirectDNS && !c.CaptureAllDNS && !c.RejectNonTCP {
		dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return fmt.Errorf("failed to load /etc/resolv.conf: %v", err)
		}
		c.DNSServersV4, c.DNSServersV6 = nil, nil
		for _, server := range dnsConfig.Servers {
			ip, err := netip.ParseAddr(server)
			if err != nil {
				log.Debug(fmt.Sprintf("ignoring un-parsable IP address: %v", err))
				continue
			}
			if ip.Is4() {
				c.DNSServersV4 = append(c.DNSServersV4, ip.String())
			} else if ip.Is6() {
				c.DNSServersV6 = append(c.DNSServersV6, ip.String())
			}
		}
	}

	return nil
}

// mock net.InterfaceAddrs to make its unit test become available
var (
	LocalIPAddrs = net.InterfaceAddrs
)

// getLocalIP returns one of the local IP address and it should support IPv6 or not
func getLocalIP(dualStack bool) (netip.Addr, bool, error) {
	var isIPv6 bool
	var ipAddrs []netip.Addr
	addrs, err := LocalIPAddrs()
	if err != nil {
		return netip.Addr{}, isIPv6, err
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			ip := ipnet.IP
			ipAddr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			// unwrap the IPv4-mapped IPv6 address
			unwrapAddr := ipAddr.Unmap()
			if !unwrapAddr.IsLoopback() && !unwrapAddr.IsLinkLocalUnicast() && !unwrapAddr.IsLinkLocalMulticast() {
				isIPv6 = unwrapAddr.Is6()
				ipAddrs = append(ipAddrs, unwrapAddr)
				if !dualStack {
					return unwrapAddr, isIPv6, nil
				}
				if isIPv6 {
					break
				}
			}
		}
	}

	if len(ipAddrs) > 0 {
		return ipAddrs[0], isIPv6, nil
	}

	return netip.Addr{}, isIPv6, fmt.Errorf("no valid local IP address found")
}

func SeparateV4V6(cidrList string) (NetworkRange, NetworkRange, error) {
	if cidrList == "*" {
		return NetworkRange{IsWildcard: true}, NetworkRange{IsWildcard: true}, nil
	}
	ipv6Ranges := NetworkRange{}
	ipv4Ranges := NetworkRange{}
	for _, ipRange := range Split(cidrList) {
		ipp, err := netip.ParsePrefix(ipRange)
		if err != nil {
			return ipv4Ranges, ipv6Ranges, err
		}
		if ipp.Addr().Is4() {
			ipv4Ranges.CIDRs = append(ipv4Ranges.CIDRs, ipp)
			if ipp.Addr().IsLoopback() {
				ipv4Ranges.HasLoopBackIP = true
			}
		} else {
			ipv6Ranges.CIDRs = append(ipv6Ranges.CIDRs, ipp)
			if ipp.Addr().IsLoopback() {
				ipv6Ranges.HasLoopBackIP = true
			}
		}
	}
	return ipv4Ranges, ipv6Ranges, nil
}
