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

// metrics.go publishes what the store did with each compiled-profile event.
// Rejecting a version is not a data-plane error — the store keeps serving the
// previous one — so nothing on the request path notices. These series are the
// only signal an operator gets that a published profile never took effect.
package profilestore

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/openkruise/agentio/extensions/epe/pkg/metrics"
)

// Label values for the scope dimension. Bounded on purpose: the reason a
// profile failed to compile is an unbounded error string and belongs in the
// log line, never in a label.
const (
	scopeNamespaced = "namespaced"
	scopeGlobal     = "global"
	scopeSandbox    = "pod" // Preserve the published metric label.
)

var (
	// profileCompileFailuresTotal counts source objects rejected at the
	// collection boundary. Every increment means a published profile version
	// did not take effect.
	profileCompileFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "epe_profile_compile_failures_total",
			Help: "Profile versions rejected because they failed to compile.",
		},
		[]string{"scope"}, // namespaced | global | pod
	)

	// profileStale counts sources whose newest published version failed to
	// compile while an earlier version stays installed. Alert on
	// `epe_profile_stale > 0`.
	profileStale = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "epe_profile_stale",
			Help: "Policy sources whose newest version was rejected and whose previous version is still being served.",
		},
		[]string{"scope"},
	)

	// profileUnenforced counts sources that exist in the API but have no
	// version installed at all, because the first version published for them
	// failed to compile. Nothing of that policy is in effect, so the workloads it
	// targets are unprotected — the severe half of a compile failure, and the
	// one profileStale deliberately does not cover. Alert on
	// `epe_profile_unenforced > 0`.
	profileUnenforced = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "epe_profile_unenforced",
			Help: "Policy sources that failed to compile with no previous version installed, so none of their rules are in effect.",
		},
		[]string{"scope"},
	)

	// profileInputsUnavailable counts installed profiles whose declared inputs
	// could not be resolved — typically a referenced ConfigMap that does not
	// exist (or no longer exists). Their rules stay in effect; only evaluations
	// that read inputs fail, resolved through the consuming action's failure
	// policy. Alert on `epe_profile_inputs_unavailable > 0`.
	profileInputsUnavailable = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "epe_profile_inputs_unavailable",
			Help: "Installed profiles whose declared inputs are unresolved, so inputs-dependent evaluations fail per the consuming action's failure policy.",
		},
		[]string{"scope"},
	)
)

func init() {
	metrics.Registry.MustRegister(
		profileCompileFailuresTotal,
		profileStale,
		profileUnenforced,
		profileInputsUnavailable,
	)
}

// profileScope maps a profile's namespace onto the bounded scope label.
// Cluster-scoped GlobalSecurityProfiles carry an empty namespace.
func profileScope(namespace string) string {
	if namespace == "" {
		return scopeGlobal
	}
	return scopeNamespaced
}

// degradedSets records which policy sources are currently in each degraded
// state, keyed exactly like the snapshot, so the gauges can publish a count per
// scope instead of one series per object.
//
// The identity deliberately does not reach the metric. A cluster can hold tens
// of thousands of SecurityProfiles and Sandboxes, and the failures these gauges
// describe are the systematic kind — one bad chart render, one Sandbox Manager
// schema change — so a per-identity label would mint a time series for every
// object in the cluster at exactly the moment the signal matters, multiplying
// scrape size and TSDB churn on a data-plane process. The counts answer "is
// anything degraded, and is it tenant or operator policy"; the log lines that
// accompany every transition name the object and the error.
//
// Memory is bounded by the number of degraded sources, not by the number of
// profiles; scope counters have only three entries per state.
type degradedSets struct {
	stale             degradedSet
	unenforced        degradedSet
	inputsUnavailable degradedSet
}

type degradedSet struct {
	keys   map[profileKey]struct{}
	counts map[string]int
}

func newDegradedSets() degradedSets {
	return degradedSets{
		stale:             degradedSet{keys: map[profileKey]struct{}{}, counts: map[string]int{}},
		unenforced:        degradedSet{keys: map[profileKey]struct{}{}, counts: map[string]int{}},
		inputsUnavailable: degradedSet{keys: map[profileKey]struct{}{}, counts: map[string]int{}},
	}
}

func (d degradedSet) set(k profileKey, present bool) {
	_, found := d.keys[k]
	if found == present {
		return
	}
	if present {
		d.keys[k] = struct{}{}
		d.counts[k.scope()]++
	} else {
		delete(d.keys, k)
		d.counts[k.scope()]--
	}
}

// rejected preserves the installed profile's inputs status.
func (d degradedSets) rejected(k profileKey, installed bool) {
	d.stale.set(k, installed)
	d.unenforced.set(k, !installed)
}

func (d degradedSets) clearRejection(k profileKey) {
	d.stale.set(k, false)
	d.unenforced.set(k, false)
}

// installed clears rejection states and refreshes inputs availability.
func (d degradedSets) installed(k profileKey, inputsUnavailable bool) {
	d.clearRejection(k)
	d.inputsUnavailable.set(k, inputsUnavailable)
}

func (d degradedSets) removed(k profileKey) {
	d.clearRejection(k)
	d.inputsUnavailable.set(k, false)
}

// publish uses incrementally maintained counts so admission callbacks never scan profiles.
func (d degradedSets) publish() {
	publishDegraded(profileStale, d.stale)
	publishDegraded(profileUnenforced, d.unenforced)
	publishDegraded(profileInputsUnavailable, d.inputsUnavailable)
}

func publishDegraded(g *prometheus.GaugeVec, set degradedSet) {
	for _, scope := range []string{scopeNamespaced, scopeGlobal, scopeSandbox} {
		g.WithLabelValues(scope).Set(float64(set.counts[scope]))
	}
}
