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

package egressauthz

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
	"github.com/openkruise/agentio/pkg/dns"
)

// Authorizer filters a request's candidates once, returning only allowed entries
// in their original order. It must not add or change destination addresses.
// Implementations load their configuration once for the entire candidate set.
type Authorizer = filter.DestinationAuthorizer

// StaticAuthorizer publishes immutable configurations for global authorization.
// Construct with NewStaticAuthorizer before serving requests.
type StaticAuthorizer struct {
	current atomic.Pointer[Config]
}

// NewStaticAuthorizer creates an authorizer with an initial configuration.
func NewStaticAuthorizer(cfg Config) *StaticAuthorizer {
	a := &StaticAuthorizer{}
	a.Update(cfg)
	return a
}

// Update publishes a caller-validated configuration. Its slices must not be
// mutated afterward; an authorization already in progress keeps the old version.
func (a *StaticAuthorizer) Update(cfg Config) {
	a.current.Store(&cfg)
}

// Authorize filters all candidates against the current immutable configuration.
func (a *StaticAuthorizer) Authorize(
	ctx context.Context,
	stream *filter.Stream,
	candidates []netip.AddrPort,
) ([]netip.AddrPort, error) {
	return a.current.Load().Authorize(ctx, stream, candidates)
}

// Authorize filters candidates against this validated configuration and records
// matching allow rules in StreamInfo for audit. If every candidate is denied,
// the denial is recorded instead.
func (c Config) Authorize(
	ctx context.Context,
	stream *filter.Stream,
	candidates []netip.AddrPort,
) ([]netip.AddrPort, error) {
	logger := log.FromContext(ctx).V(logging.DEBUG)
	allowed := make([]netip.AddrPort, 0, len(candidates))
	// DNS evidence describes the original HBONE destination, not a rewritten route.
	original := stream.Request.OriginalDestination.Addr()
	if strings.EqualFold(stream.Request.Method, "CONNECT") {
		original, _ = netip.ParseAddr(stream.Request.Host)
	}
	var last Decision
	for _, candidate := range candidates {
		var names []string
		if original.IsValid() && candidate.Addr().Unmap() == original.Unmap() {
			names = stream.Request.DNSCandidates
		}
		decision := c.Evaluate(candidate, names...)
		if logger.Enabled() {
			logger.Info("egress destination evaluated",
				"address", candidate.String(), "action", string(decision.Action),
				"policy", decision.PolicyName, "ruleIndex", decision.RuleIndex)
		}
		last = decision
		if decision.Action != Allow {
			continue
		}
		if decision.PolicyName != "" {
			stream.Info.RecordAuthorizationMatch(candidate, decision.PolicyName, decision.RuleIndex)
		}
		allowed = append(allowed, candidate)
	}
	if len(allowed) == 0 {
		if len(candidates) == 1 {
			recordDenial(stream, candidates[0], last)
		} else {
			stream.Info.RecordAuthorization(filter.AuthorizationDecision{
				Action: "deny",
				Reason: filter.AuthorizationReasonPolicyDenied,
			})
		}
	}
	return allowed, nil
}

// Aggregate intersects an ordered list of authorizers. It owns DNS resolution
// and target selection, so children filter the same addresses without resolving
// or pinning targets independently.
type Aggregate struct {
	client      *dns.Client
	authorizers []Authorizer
}

// NewAggregate evaluates authorizers in the supplied order. An empty list
// imposes no restrictions but still resolves and pins the target.
func NewAggregate(client *dns.Client, authorizers ...Authorizer) *Aggregate {
	return &Aggregate{client: client, authorizers: slices.Clone(authorizers)}
}
