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

package securityprofile

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/pkg/policy"
)

// tcpAuthorizer remembers the TCP checkpoints already reached by this request.
// Final authorization rechecks those restrictions if a later rule changes the target.
type tcpAuthorizer struct {
	profiles []*Profile
	visited  int
}

type tcpDecision struct {
	allow     bool
	profile   *Profile
	ruleIndex int
}

func matchTCPProfiles(profiles []*Profile, target netip.AddrPort) tcpDecision {
	for _, profile := range profiles {
		allow, index := policy.MatchTCPRules(profile.TCPPolicy.GetRules(), target)
		if index >= 0 {
			return tcpDecision{allow: allow, profile: profile, ruleIndex: index}
		}
	}
	return tcpDecision{allow: true}
}

func (d tcpDecision) record(info *filter.StreamInfo, target netip.AddrPort) {
	if d.profile == nil {
		return
	}
	if d.allow {
		info.RecordAuthorizationMatch(target, d.profile.ResourceName(), d.ruleIndex)
	} else {
		info.RecordAuthorization(filter.AuthorizationDecision{
			Action:      "deny",
			Destination: target.String(),
			Policy:      d.profile.ResourceName(),
			RuleIndex:   &d.ruleIndex,
			Reason:      filter.AuthorizationReasonPolicyDenied,
		})
	}
}

func (a *tcpAuthorizer) checkpoint(
	index int,
	targets *egressauthz.Aggregate,
) func(context.Context, *filter.Stream) (filter.Action, error) {
	return func(ctx context.Context, stream *filter.Stream) (filter.Action, error) {
		if targets == nil {
			return filter.Action{}, fmt.Errorf("TCP authorization requires a destination resolver")
		}
		candidates, err := targets.Candidates(ctx, stream)
		if err != nil {
			return filter.Action{}, err
		}
		a.visited = index + 1
		var allowed []netip.AddrPort
		unmatched := 0
		for _, target := range candidates {
			decision := matchTCPProfiles(a.profiles[:index+1], target)
			if decision.profile == nil {
				unmatched++
				continue
			}
			decision.record(stream.Info, target)
			if decision.allow {
				allowed = append(allowed, target)
			}
		}
		if len(allowed) > 0 {
			selected := egressauthz.SelectCandidate(allowed)
			return filter.Bypass(
				filter.Mutation{Route: &filter.RouteMutation{Upstream: &filter.UpstreamTarget{Address: &selected}}},
			), nil
		}
		if unmatched > 0 {
			return filter.Continue(), nil
		}
		return filter.Stop(filter.Reply{Status: 403, Details: "epe_egress_denied"}), nil
	}
}

func (a *tcpAuthorizer) Authorize(
	_ context.Context,
	stream *filter.Stream,
	candidates []netip.AddrPort,
) ([]netip.AddrPort, error) {
	allowed := make([]netip.AddrPort, 0, len(candidates))
	for _, target := range candidates {
		decision := matchTCPProfiles(a.profiles[:a.visited], target)
		decision.record(stream.Info, target)
		if decision.allow {
			allowed = append(allowed, target)
		}
	}
	return allowed, nil
}
