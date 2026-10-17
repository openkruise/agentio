// Copyright 2026 The Kruise Authors
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
package filter

import (
	"k8s.io/apimachinery/pkg/types"
)

// Peer is the downstream caller: the Sandbox pod and its agent credential,
// resolved from filter_state and source.address. Mirrors the source/Peer
// half of Envoy's AttributeContext. Never expression-visible; the
// expression vocabulary lives in the inputs package.
//
// Peer and SandboxToken live in the contract package itself because Stream
// embeds Peer, so anything imported here lands in every filter's dependency
// closure (see the arch guards).
type Peer struct {
	// Pod identifies the source pod from filter_state['agentio.workload.name'] and
	// filter_state['agentio.workload.namespace'], falling back per field to
	// filter_state['downstream_peer']. Either half may be empty; see Valid.
	Pod types.NamespacedName
	// IP is the source pod IP, extracted from Envoy's source.address
	// attribute. Empty string when the attribute is absent (E2E test
	// fallback).
	IP string
	// Labels is the source workload's label map, parsed from
	// filter_state['agentio.workload.labels'] (or legacy sandbox.labels). Nil when pod identity is missing.
	Labels map[string]string
	// Token is the parsed filter_state['sandbox.token'], parsed eagerly by
	// Extract. Nil when the filter state value is absent or malformed.
	Token *SandboxToken
}

// Valid reports whether filter_state carried a usable pod identity.
// The predicate mirrors the fail-open condition in the request handler: both
// the pod namespace AND the pod name must be non-empty.
func (p Peer) Valid() bool {
	return p.Pod.Namespace != "" && p.Pod.Name != ""
}

// SandboxToken is the parsed filter_state['sandbox.token'] payload. It is
// pure data (agent identity), deliberately not an interface, and must
// never be exposed to the evaluation Scope.
type SandboxToken struct {
	RequestID       string `json:"requestId"`
	AccessToken     string `json:"accessToken"`
	SandboxClientID string `json:"sandboxClientId"`
}
