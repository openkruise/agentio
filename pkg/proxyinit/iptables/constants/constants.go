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

package constants

import (
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
)

var BuiltInChainsAndTargetsMap = sets.New(
	"INPUT",
	"OUTPUT",
	"FORWARD",
	"PREROUTING",
	"POSTROUTING",
	"ACCEPT",
	"RETURN",
	"DROP",
	"REJECT",
)

const (
	// IPVersionSpecific is used as an input to rules that will be replaced with an ip version (v4/v6)
	// specific value
	IPVersionSpecific = "PLACEHOLDER_IP_VERSION_SPECIFIC"
)

// iptables chains
const (
	AGENTIOOUTPUT     = "AGENTIO_OUTPUT"
	AGENTIOOUTPUTDNS  = "AGENTIO_OUTPUT_DNS"
	AGENTIOINBOUND    = "AGENTIO_INBOUND"
	AGENTIOREDIRECT   = "AGENTIO_REDIRECT"
	AGENTIOINREDIRECT = "AGENTIO_IN_REDIRECT"
	AGENTIODROP       = "AGENTIO_DROP"
)

// Command-line option names.
const (
	InterceptionMode         = "interception-mode"
	IncludeInboundPorts      = "include-inbound-ports"
	ExcludeInboundPorts      = "exclude-inbound-ports"
	ExcludeInterfaces        = "exclude-interfaces"
	IncludeOutboundIPRanges  = "include-outbound-ip-ranges"
	ExcludeOutboundIPRanges  = "exclude-outbound-ip-ranges"
	IncludeOutboundPorts     = "include-outbound-ports"
	ExcludeOutboundPorts     = "exclude-outbound-ports"
	OutboundCapturePort      = "outbound-capture-port"
	InboundCapturePort       = "inbound-capture-port"
	InboundTunnelPort        = "inbound-tunnel-port"
	ProxyUID                 = "proxy-uid"
	ProxyGID                 = "proxy-gid"
	RerouteVirtualInterfaces = "reroute-virtual-interfaces"
	DryRun                   = "dry-run"
	TraceLogging             = "iptables-trace-logging"
	SkipRuleApply            = "skip-rule-apply"
	RunValidation            = "run-validation"
	IptablesProbePort        = "iptables-probe-port"
	ProbeTimeout             = "probe-timeout"
	RedirectDNS              = "redirect-dns"
	DropInvalid              = "drop-invalid"
	RejectNonTCP             = "reject-non-tcp"
	DualStack                = "dual-stack"
	CaptureAllDNS            = "capture-all-dns"
	NetworkNamespace         = "network-namespace"
	CNIMode                  = "cni-mode"
	Reconcile                = "reconcile"
	CleanupOnly              = "cleanup-only"
	ForceApply               = "force-apply"
	NativeNftables           = "native-nftables"
	ForceIptablesBinary      = "force-iptables-binary"

	NativeNftablesOutputPriority = "native-nftables-output-priority"
)

// Defaults for environment-only settings.
const (
	HostIPv4LoopbackCidr = "127.0.0.1/32"
	OwnerGroupsInclude   = "*"
	OwnerGroupsExclude   = ""
)

const (
	DefaultProxyUID    = "1337"
	DefaultProxyUIDInt = int64(1337)
)

// Constants used in environment variables
const (
	ProxyUser = "AGENTIO_PROXY_USER"
)

// Constants for syscall
const (
	// sys/socket.h
	SoOriginalDst = 80
)

const (
	DefaultIptablesProbePortUint = 15002
	DefaultProbeTimeout          = 5 * time.Second
)

const (
	ValidationContainerName = "agentio-validation"
	ValidationErrorCode     = 126
)

// DNS ports
const (
	AgentioAgentDNSListenerPort = "15053"
)

// type of iptables operation/command to run, as an enum
// the implementation will choose the correct underlying binary,
// so callers should just use these enums to indicate what they want to do.
type IptablesCmd int

const (
	IPTables        IptablesCmd = iota
	IPTablesSave    IptablesCmd = iota
	IPTablesRestore IptablesCmd = iota
)
