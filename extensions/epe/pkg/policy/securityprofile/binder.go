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

// Package securityprofile binds compiled SecurityProfile objects to the
// filter framework: it projects each profile version's rules into per-filter
// configs when the profile is compiled, matches rules at request time, and
// emits the ordered unit list the ordered engine evaluates. It is the only
// place on the request path that touches the policy model.
package securityprofile

import (
	"fmt"

	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// unit is one matched (profile, rule) pair in evaluation order. It embeds
// the engine-facing engine.Unit (identity, scope, projected configs) and
// adds the audit-attribution fields only the audit stream logger reads.
//
// It is unexported because nothing outside this package needs to name it:
// the engine receives the embedded engine.Unit, and the audit stream logger
// that reads the attribution lives here too.
type unit struct {
	engine.Unit
	// MatchIndex is the RuleMatch index that fired, for audit's
	// MatchedCriteria reconstruction.
	MatchIndex int
	// Profile and Rule are consumed only by the audit stream logger; the
	// engine itself never reads them.
	Profile *Profile
	Rule    *Rule
	// HasAudits reports whether the rule or profile carries compiled audit
	// entries; the audit stream logger skips units without any.
	HasAudits bool
}

// binder reads the projections a profile was compiled with and emits the
// ordered unit list for one request. It holds the registration set only to
// check that a profile was projected against the same chain and to name a
// filter in an error; projecting itself happens once, in the compiler.
type binder struct {
	regs    []filter.Registration
	chain   string
	targets *egressauthz.Aggregate
}

// binding keeps the executable plan separate from HTTP audit attribution.
type binding struct {
	units      []engine.Unit
	rules      []unit
	authorizer *tcpAuthorizer
}

func newBinder(regs []filter.Registration, targets *egressauthz.Aggregate) *binder {
	frozen := append([]filter.Registration(nil), regs...)
	return &binder{regs: frozen, chain: chainFingerprint(frozen), targets: targets}
}

// bind matches profiles (already sorted by the store) against req and
// builds the ordered execution plan, reading the projection each profile was
// compiled with. A matched rule whose payloads or projection failed fails the
// request closed.
//
// On failure, rules includes the failing rule for audit attribution.
// The caller must discard the execution plan when err != nil.
func (b *binder) bind(profiles []*Profile, req *httpreq.HTTPRequest, workload inputs.Workload) (binding, error) {
	request := inputs.RequestFrom(*req)

	type checkpoint struct {
		profileIndex int
		ordinal      int
	}
	var checkpoints []checkpoint
	ordinal := 0
	bound := binding{authorizer: &tcpAuthorizer{profiles: profiles}}
	for index, profile := range profiles {
		// A profile whose declared inputs failed to resolve still installs and
		// enforces; the scope poisons only the inputs slot, so a Block rule
		// keeps blocking while an inputs-reading evaluation fails through the
		// consuming action's failure strategy.
		var scopeOpts []inputs.ScopeOption
		if profile.InputsError != "" {
			scopeOpts = []inputs.ScopeOption{inputs.WithInputsError(profile.InputsError)}
		}
		for i := range profile.Rules {
			rule := &profile.Rules[i]
			matchIdx := rule.MatchingIndex(req)
			if matchIdx < 0 {
				continue
			}
			p, projErr := profile.projection(i, b.chain)
			// Appended before the projection verdict: the rule matched, so its
			// attribution is valid even when its config is not, and that is
			// what lets a failed resolution still be audited.
			bound.rules = append(bound.rules, unit{
				Unit: engine.Unit{
					ID: filter.UnitID{
						Scope:   profile.Meta.Namespace + "/" + profile.Meta.Name,
						Name:    rule.Name,
						Ordinal: ordinal,
					},
					Scope: inputs.NewScope(
						request, workload,
						inputs.Profile{Name: profile.Meta.Name, Namespace: profile.Meta.Namespace},
						inputs.Rule{Name: rule.Name},
						profile.Inputs,
						scopeOpts...,
					),
					Cfgs: p.Cfgs,
				},
				MatchIndex: matchIdx,
				Profile:    profile,
				Rule:       rule,
				HasAudits:  len(rule.Audits) > 0 || len(profile.Audits) > 0,
			})

			if projErr != nil {
				return bound, projErr
			}
			if p.Err != nil {
				return bound, fmt.Errorf("build payloads for rule %q of profile %q: %w",
					rule.Name, profile.Meta.Name, p.Err)
			}
			for regIdx, err := range p.Errs {
				if err != nil {
					return bound, fmt.Errorf("project rule %q of profile %q for filter %q: %w",
						rule.Name, profile.Meta.Name, b.regs[regIdx].Name, err)
				}
			}
			ordinal++
		}
		if len(profile.TCPPolicy.GetRules()) > 0 {
			checkpoints = append(checkpoints, checkpoint{profileIndex: index, ordinal: ordinal})
			ordinal++
		}
	}
	bound.units = make([]engine.Unit, ordinal)
	for _, rule := range bound.rules {
		bound.units[rule.ID.Ordinal] = rule.Unit
	}
	for _, point := range checkpoints {
		profile := profiles[point.profileIndex]
		bound.units[point.ordinal] = engine.Unit{
			ID: filter.UnitID{
				Scope:   profile.Meta.Namespace + "/" + profile.Meta.Name,
				Name:    "tcpRules",
				Ordinal: point.ordinal,
			},
			Cfgs:         make([]any, len(b.regs)),
			CheckRequest: bound.authorizer.checkpoint(point.profileIndex, b.targets),
		}
	}
	return bound, nil
}
