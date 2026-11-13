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

// Package egressauthz authorizes resolved destinations and pins the selected
// upstream address so the proxy can connect to the address that was authorized.
package egressauthz

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/pkg/dns"
)

// Authorize applies common restrictions, then the request-bound policy, and
// pins a surviving address. Selection is random within the first
// surviving candidate's address family; explicit and original targets stay fixed.
func (a *Aggregate) Authorize(
	ctx context.Context,
	stream *filter.Stream,
) (*filter.UpstreamTarget, *filter.Reply, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if stream == nil {
		return nil, nil, fmt.Errorf("request stream is required")
	}
	candidates, err := a.Candidates(ctx, stream)
	if err != nil {
		return nil, nil, err
	}
	if len(candidates) == 0 {
		return denied()
	}
	if authorizer := stream.Policies.DestinationAuthorizer; authorizer != nil {
		candidates, err = authorizer.Authorize(ctx, stream, candidates)
		if err != nil {
			stream.Info.RecordAuthorization(
				filter.AuthorizationDecision{Action: "error", Reason: filter.AuthorizationReasonPolicyLoadFailed},
			)
			return nil, nil, err
		}
		if len(candidates) == 0 {
			return denied()
		}
	}
	selected := selectRandomCandidate(candidates)
	stream.Info.RecordAuthorizedDestination(selected)
	if stream.Upstream != nil {
		return stream.Upstream, nil, nil
	}
	return &filter.UpstreamTarget{Address: &selected}, nil, nil
}

// Candidates resolves the current target and applies common restrictions.
// It neither invokes the request-bound policy nor pins an address.
func (a *Aggregate) Candidates(ctx context.Context, stream *filter.Stream) ([]netip.AddrPort, error) {
	candidates, err := resolveCandidates(ctx, a.client, stream)
	if err != nil {
		return nil, err
	}
	for _, authorizer := range a.authorizers {
		candidates, err = authorizer.Authorize(ctx, stream, candidates)
		if err != nil {
			stream.Info.RecordAuthorization(
				filter.AuthorizationDecision{Action: "error", Reason: filter.AuthorizationReasonPolicyLoadFailed},
			)
			return nil, err
		}
		if len(candidates) == 0 {
			break
		}
	}
	return candidates, nil
}

// SelectCandidate selects an address after authorization has removed denied candidates.
func SelectCandidate(candidates []netip.AddrPort) netip.AddrPort {
	return selectRandomCandidate(candidates)
}

// selectRandomCandidate selects uniformly within the first candidate's address
// family. The caller supplies a non-empty list of authorized candidates.
func selectRandomCandidate(candidates []netip.AddrPort) netip.AddrPort {
	selected := candidates[0]
	// Reservoir sampling gives each allowed candidate in the preferred family
	// equal probability without reordering or copying the candidate list.
	count := 1
	for _, candidate := range candidates[1:] {
		if candidate.Addr().Is4() != selected.Addr().Is4() {
			continue
		}
		count++
		if rand.IntN(count) == 0 {
			selected = candidate
		}
	}
	return selected
}

// Explicit routes and an original destination found in DNS are fixed targets:
// expose only that candidate so denial cannot fall back to another address.
func resolveCandidates(
	ctx context.Context,
	client *dns.Client,
	stream *filter.Stream,
) ([]netip.AddrPort, error) {
	if stream.Upstream != nil {
		if err := (&filter.RouteMutation{Upstream: stream.Upstream}).Validate(); err != nil {
			return nil, fmt.Errorf("egressauthz upstream: %w", err)
		}
		return []netip.AddrPort{*stream.Upstream.Address}, nil
	}
	addresses, err := resolveDNS(ctx, client, stream)
	if err != nil {
		stream.Info.RecordAuthorization(filter.AuthorizationDecision{
			Action: "error",
			Reason: filter.AuthorizationReasonResolutionFailed,
		})
		return nil, fmt.Errorf("egressauthz: %w", err)
	}
	original := stream.Request.OriginalDestination
	if original.IsValid() && slices.Contains(addresses, original.Addr().Unmap()) {
		return []netip.AddrPort{netip.AddrPortFrom(original.Addr().Unmap(), uint16(stream.Request.Port))}, nil
	}
	candidates := make([]netip.AddrPort, 0, len(addresses))
	for _, ip := range addresses {
		candidates = append(candidates, netip.AddrPortFrom(ip, uint16(stream.Request.Port)))
	}
	return candidates, nil
}

func recordDenial(stream *filter.Stream, address netip.AddrPort, decision Decision) {
	record := filter.AuthorizationDecision{
		Action:      "deny",
		Destination: address.String(),
		Reason:      filter.AuthorizationReasonPolicyDenied,
	}
	if decision.PolicyName != "" {
		record.Policy, record.RuleIndex = decision.PolicyName, &decision.RuleIndex
	}
	stream.Info.RecordAuthorization(record)
}

func denied() (*filter.UpstreamTarget, *filter.Reply, error) {
	return nil, &egressDeniedReply, nil
}
