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

const (
	// Table names used in sideCar mode when applying native nftables rules
	AgentioProxyNatTable    = "agentio-proxy-nat"
	AgentioProxyMangleTable = "agentio-proxy-mangle"
	AgentioProxyRawTable    = "agentio-proxy-raw"
	AgentioProxyFilterTable = "agentio-proxy-filter"

	// Base chains.
	PreroutingChain = "prerouting"
	OutputChain     = "output"

	// Regular chains prefixed with "agentio" to distinguish them from base chains
	AgentioInboundChain    = "agentio-inbound"
	AgentioOutputChain     = "agentio-output"
	AgentioOutputDNSChain  = "agentio-output-dns"
	AgentioRedirectChain   = "agentio-redirect"
	AgentioInRedirectChain = "agentio-in-redirect"
	AgentioPreroutingChain = "agentio-prerouting"
	AgentioDropChain       = "agentio-drop"
)

// A counter statement helps us in tracking the number of packets that match the rule.
const Counter = "counter"

// DNS ports
const (
	AgentioAgentDNSListenerPort = "15053"
)
