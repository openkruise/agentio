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
// filter framework: it matches rules, projects them into per-filter
// configs (cached per profile version), and emits the ordered unit list
// the ordered engine evaluates. It is the only place on the request
// path that touches the policy model.
package securityprofile

import (
	"fmt"
	"sync"

	"istio.io/istio/extensions/epe/pkg/httpreq"

	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/extensions/epe/pkg/engine"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/inputs"
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

// binder projects profiles against a fixed registration set.
type binder struct {
	regs []filter.Registration

	mu    sync.Mutex
	cache map[cacheKey]*cacheEntry
}

// cacheKey identifies a projection cache slot. Meta.Source is part of the
// key because an inline per-Sandbox profile and a SecurityProfile CR in the
// same namespace can share a name and even a resourceVersion; keying on
// namespace/name alone would let them cross-return each other's projections.
type cacheKey struct {
	source string
	types.NamespacedName
}

type cacheEntry struct {
	version string
	rules   []ruleProjection
}

// ruleProjection is one rule's projection result. cfgs/errs are parallel
// to the registration slice; err is a failure to build the rule's payloads
// at all, which fails the rule closed regardless of which filters it
// mounts.
type ruleProjection struct {
	cfgs []any
	errs []error
	err  error
}

func newBinder(regs []filter.Registration) *binder {
	frozen := append([]filter.Registration(nil), regs...)
	return &binder{
		regs:  frozen,
		cache: map[cacheKey]*cacheEntry{},
	}
}

// bind matches profiles (already sorted by the store) against req and
// returns the ordered unit list. Projection results are cached per
// (profile identity, ProfileMeta.Version). A matched rule whose payloads
// or projection failed fails the request closed.
//
// On failure the units matched up to and including the failing rule are
// returned alongside the error. They are NOT safe to evaluate — the failing
// one has no usable Cfgs — but they carry the profile/rule attribution the
// audit stream logger needs, so a stream that fails to resolve can still be
// recorded. Callers that evaluate must discard the list when err != nil.
func (b *binder) bind(profiles []*Profile, req *httpreq.HTTPRequest, pod inputs.Pod) ([]unit, error) {
	request := inputs.RequestFrom(*req)

	var units []unit
	for _, profile := range profiles {
		var entry *cacheEntry
		for i := range profile.Rules {
			rule := &profile.Rules[i]
			matchIdx := rule.MatchingIndex(req)
			if matchIdx < 0 {
				continue
			}
			if entry == nil {
				entry = b.projections(profile)
			}
			p := &entry.rules[i]
			// Appended before the projection verdict: the rule matched, so its
			// attribution is valid even when its config is not, and that is
			// what lets a failed resolution still be audited.
			units = append(units, unit{
				Unit: engine.Unit{
					ID: filter.UnitID{
						Scope:   profile.Meta.Namespace + "/" + profile.Meta.Name,
						Name:    rule.Name,
						Ordinal: len(units),
					},
					Scope: inputs.NewScope(
						request, pod,
						inputs.Profile{Name: profile.Meta.Name, Namespace: profile.Meta.Namespace},
						inputs.Rule{Name: rule.Name},
						profile.Inputs,
					),
					Cfgs: p.cfgs,
				},
				MatchIndex: matchIdx,
				Profile:    profile,
				Rule:       rule,
				HasAudits:  len(rule.Audits) > 0 || len(profile.Audits) > 0,
			})

			if p.err != nil {
				return units, fmt.Errorf("build payloads for rule %q of profile %q: %w",
					rule.Name, profile.Meta.Name, p.err)
			}
			for regIdx, err := range p.errs {
				if err != nil {
					return units, fmt.Errorf("project rule %q of profile %q for filter %q: %w",
						rule.Name, profile.Meta.Name, b.regs[regIdx].Name, err)
				}
			}
		}
	}
	return units, nil
}

// projections returns the cached per-rule projections for the profile,
// recomputing when the profile version changed. Entries are keyed by
// source and identity and replaced in place, so cache size is bounded by
// the number of live profiles (plus deleted ones until process restart).
//
// The cache key is Meta.Version (the CR's resourceVersion), which does NOT
// change when a referenced ConfigMap re-resolves Profile.Inputs. Projection
// therefore must only read the rule spec (payloadsFor), never Profile.Inputs;
// Inputs are read at bind time from the live profile pointer instead.
func (b *binder) projections(profile *Profile) *cacheEntry {
	key := cacheKey{
		source: profile.Meta.Source,
		NamespacedName: types.NamespacedName{
			Namespace: profile.Meta.Namespace,
			Name:      profile.Meta.Name,
		},
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if e, ok := b.cache[key]; ok && e.version == profile.Meta.Version {
		return e
	}
	e := &cacheEntry{
		version: profile.Meta.Version,
		rules:   make([]ruleProjection, len(profile.Rules)),
	}
	for i := range profile.Rules {
		rule := &profile.Rules[i]
		payloads, err := payloadsFor(rule)
		if err != nil {
			e.rules[i] = ruleProjection{err: err}
			continue
		}
		cfgs, errs := filter.Project(b.regs, payloads)
		e.rules[i] = ruleProjection{cfgs: cfgs, errs: errs}
	}
	b.cache[key] = e
	return e
}
