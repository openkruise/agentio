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

package model

// Local SDS resource names used by the gateway and its credential provider.
const (
	GatewayIdentitySecret = "default"
	GatewayRootSecret     = "ROOTCA"
)

// Filter-state keys shared by gateway configuration and CONNECT processing.
const (
	FilterStateOuterSNI          = "agentio.tls.outer_sni"
	FilterStateDenialReason      = "agentio.egress.denial_reason"
	FilterStateWorkloadUID       = "agentio.workload.uid"
	FilterStateWorkloadName      = "agentio.workload.name"
	FilterStateWorkloadNamespace = "agentio.workload.namespace"
	FilterStateSandboxID         = "agentio.sandbox.id"
	FilterStateConnectAuthority  = "agentio.connect.authority"
	FilterStatePeerCertificate   = "agentio.peer.certificate"
	FilterStatePeerIP            = "agentio.downstream.ip"
	FilterStatePeerPrincipal     = "agentio.peer.principal"
	FilterStateLocalPrincipal    = "agentio.local.principal"
	// FilterStateConnectionPolicyHash must match HASH_KEY in extensions/envoy/connection-policy.
	FilterStateConnectionPolicyHash = "agentio.connection.policy_hash"
	// FilterStatePolicyStart identifies the matched profile for SNI destination authorization.
	FilterStatePolicyStart = "agentio.policy.start"
	// FilterStateRouteUpstream holds the gateway-selected IP:port for this request.
	FilterStateRouteUpstream = "agentio.route.upstream"
)

// ExtProc attributes requested by Envoy and consumed by Porter and EPE.
const (
	ExtProcAttributesKey       = "envoy.filters.http.ext_proc"
	AttributeWorkloadUID       = "filter_state['" + FilterStateWorkloadUID + "']"
	AttributeWorkloadName      = "filter_state['" + FilterStateWorkloadName + "']"
	AttributeWorkloadNamespace = "filter_state['" + FilterStateWorkloadNamespace + "']"
	AttributeRouteUpstream     = "filter_state['" + FilterStateRouteUpstream + "']"
	AttributeSandboxID         = "filter_state['" + FilterStateSandboxID + "']"
	AttributePeerCertificate   = "filter_state['" + FilterStatePeerCertificate + "']"
	AttributePeerIP            = "filter_state['" + FilterStatePeerIP + "']"
	AttributePeerPrincipal     = "filter_state['" + FilterStatePeerPrincipal + "']"
	GatewayMetadataNamespace   = "agentio"
)
