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

// Authorize applies platform CIDR restrictions and records rejected destinations.
func (c Config) Authorize(
	ctx context.Context,
	stream *filter.Stream,
	candidates []netip.AddrPort,
) ([]netip.AddrPort, error) {
	logger := log.FromContext(ctx).V(logging.DEBUG)
	allowed := make([]netip.AddrPort, 0, len(candidates))
	var last Decision
	for _, candidate := range candidates {
		decision := c.Evaluate(candidate)
		if logger.Enabled() {
			logger.Info("egress destination evaluated",
				"address", candidate.String(), "action", string(decision.Action),
				"policy", decision.PolicyName, "ruleIndex", decision.RuleIndex)
		}
		last = decision
		if decision.Action != Allow {
			continue
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

// Aggregate resolves targets and intersects common authorizers before the
// request-bound policy. Children filter the same addresses without resolving
// or pinning targets independently.
type Aggregate struct {
	client      *dns.Client
	authorizers []Authorizer
}

// NewAggregate evaluates common authorizers in the supplied order, followed
// by the request-bound policy when authorizing the final destination.
func NewAggregate(client *dns.Client, authorizers ...Authorizer) *Aggregate {
	return &Aggregate{client: client, authorizers: slices.Clone(authorizers)}
}
