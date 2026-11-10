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
package profilestore

import (
	"errors"
	"strconv"
	"testing"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/metrics"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube/controllers"
)

// invalidItem builds the identity-bearing CompileError item the collection
// transform produces for a source object that failed to compile. It takes the
// object and spec separately so both CRD scopes can use it: the namespaced
// newTestProfile and the cluster-scoped newTestGlobalProfile.
func invalidItem(obj metav1.Object, spec *v1alpha1.SecurityProfileSpec) *securityprofile.Profile {
	return securityprofile.InvalidProfile(obj, spec, errors.New("invalid selector"))
}

// invalidNamespaced is the namespaced shorthand used by most tests here.
func invalidNamespaced(name, namespace string) *securityprofile.Profile {
	obj := newTestProfile(name, namespace, map[string]string{"app": "x"})
	return invalidItem(obj, &obj.Spec)
}

func TestApplyBatch_CountsRejectedNamespacedVersion(t *testing.T) {
	s := NewStore(0)
	before := testutil.ToFloat64(profileCompileFailuresTotal.WithLabelValues(scopeNamespaced))

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: invalidNamespaced("p", "default"), Event: controllers.EventAdd},
	})

	if got := testutil.ToFloat64(profileCompileFailuresTotal.WithLabelValues(scopeNamespaced)) - before; got != 1 {
		t.Fatalf("compile failures delta for scope %q = %v, want 1", scopeNamespaced, got)
	}
}

// The cluster-scoped CRD is a distinct Go type whose namespace is always empty,
// which is what selects the global label. Use the real type rather than a
// namespaced profile with a blank namespace.
func TestApplyBatch_CountsRejectedGlobalVersion(t *testing.T) {
	s := NewStore(0)
	before := testutil.ToFloat64(profileCompileFailuresTotal.WithLabelValues(scopeGlobal))

	g := newTestGlobalProfile("g", map[string]string{"app": "x"})
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: invalidItem(g, &g.Spec), Event: controllers.EventAdd},
	})

	if got := testutil.ToFloat64(profileCompileFailuresTotal.WithLabelValues(scopeGlobal)) - before; got != 1 {
		t.Fatalf("compile failures delta for scope %q = %v, want 1", scopeGlobal, got)
	}
}

func TestApplyBatch_ValidItemCountsNothing(t *testing.T) {
	s := NewStore(0)
	before := testutil.ToFloat64(profileCompileFailuresTotal.WithLabelValues(scopeNamespaced))

	good := newTestProfile("p", "default", map[string]string{"app": "x"})
	compiled, err := securityprofile.NewProfile(good, &good.Spec)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: compiled, Event: controllers.EventAdd},
	})

	if got := testutil.ToFloat64(profileCompileFailuresTotal.WithLabelValues(scopeNamespaced)) - before; got != 0 {
		t.Fatalf("compile failures delta = %v, want 0 for a valid profile", got)
	}
}

// staleCount reports how many sources in one scope are serving an older
// version. The gauges carry no identity, so a test asserts the count for its
// scope; attribution is the log line's job.
func staleCount(t testing.TB, scope string) float64 {
	t.Helper()
	return gaugeValue(t, "epe_profile_stale", scope)
}

// unenforcedCount reports how many sources in one scope have nothing installed.
func unenforcedCount(t testing.TB, scope string) float64 {
	t.Helper()
	return gaugeValue(t, "epe_profile_unenforced", scope)
}

// inputsUnavailableCount reports how many installed profiles in one scope are
// serving with unresolved inputs.
func inputsUnavailableCount(t testing.TB, scope string) float64 {
	t.Helper()
	return gaugeValue(t, "epe_profile_inputs_unavailable", scope)
}

// gaugeValue reads one scope's series. Every scope is always published, so a
// missing series is a failure rather than an implicit zero.
func gaugeValue(t testing.TB, metricName, scope string) float64 {
	t.Helper()
	families, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, f := range families {
		if f.GetName() != metricName {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "scope" && l.GetValue() == scope {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("gauge %s has no series for scope %q", metricName, scope)
	return 0
}

func installGood(t testing.TB, s *store, name, namespace string) *securityprofile.Profile {
	t.Helper()
	obj := newTestProfile(name, namespace, map[string]string{"app": "x"})
	compiled, err := securityprofile.NewProfile(obj, &obj.Spec)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: compiled, Event: controllers.EventAdd},
	})
	return compiled
}

func TestApplyBatch_InvalidUpdateMarksProfileStale(t *testing.T) {
	s := NewStore(0)
	good := installGood(t, s, "stale-me", "default")

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: good, New: invalidNamespaced("stale-me", "default"), Event: controllers.EventUpdate},
	})

	if got := staleCount(t, scopeNamespaced); got != 1 {
		t.Fatalf("stale count for scope %q = %v, want 1", scopeNamespaced, got)
	}
}

func TestApplyBatch_ValidVersionClearsStale(t *testing.T) {
	s := NewStore(0)
	good := installGood(t, s, "recover-me", "default")
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: good, New: invalidNamespaced("recover-me", "default"), Event: controllers.EventUpdate},
	})
	if got := staleCount(t, scopeNamespaced); got != 1 {
		t.Fatalf("precondition: stale count = %v, want 1", got)
	}

	installGood(t, s, "recover-me", "default")

	if got := staleCount(t, scopeNamespaced); got != 0 {
		t.Fatalf("stale count = %v after a valid version landed, want 0", got)
	}
}

func TestApplyBatch_DeleteClearsStale(t *testing.T) {
	s := NewStore(0)
	good := installGood(t, s, "delete-me", "default")
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: good, New: invalidNamespaced("delete-me", "default"), Event: controllers.EventUpdate},
	})
	if got := staleCount(t, scopeNamespaced); got != 1 {
		t.Fatalf("precondition: stale count = %v, want 1", got)
	}

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: good, Event: controllers.EventDelete},
	})

	if got := staleCount(t, scopeNamespaced); got != 0 {
		t.Fatalf("stale count = %v after the profile was deleted, want 0", got)
	}
}

func TestApplyBatch_RejectedWithNoPriorVersionIsNotStale(t *testing.T) {
	s := NewStore(0)

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: invalidNamespaced("never-installed", "default"), Event: controllers.EventAdd},
	})

	if got := staleCount(t, scopeNamespaced); got != 0 {
		t.Fatalf("stale count = %v, want 0: nothing is being served, so it is unenforced, not stale", got)
	}
}

// The dangerous case: a profile whose first published version was rejected.
// Nothing is installed, so no rule of it is enforced — the pods it targets are
// unprotected. `stale` deliberately stays zero here (nothing is being served),
// which is what separates "still protected by an older version" from "not
// protected at all" without either gauge naming an object.
func TestApplyBatch_RejectedWithNoPriorVersionIsUnenforced(t *testing.T) {
	s := NewStore(0)

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: invalidNamespaced("never-installed", "default"), Event: controllers.EventAdd},
	})

	if got := unenforcedCount(t, scopeNamespaced); got != 1 {
		t.Fatalf("unenforced count for scope %q = %v, want 1", scopeNamespaced, got)
	}
}

// A rejected update over an installed version is stale, not unenforced: the
// previous version keeps enforcing. Conflating the two would page someone at
// 3am for a profile that is still protecting its pods.
func TestApplyBatch_StaleProfileIsNotUnenforced(t *testing.T) {
	s := NewStore(0)
	good := installGood(t, s, "still-serving", "default")

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: good, New: invalidNamespaced("still-serving", "default"), Event: controllers.EventUpdate},
	})

	if got := unenforcedCount(t, scopeNamespaced); got != 0 {
		t.Fatalf("unenforced count = %v; an installed previous version is still enforcing, so this is stale", got)
	}
}

func TestApplyBatch_ValidVersionClearsUnenforced(t *testing.T) {
	s := NewStore(0)
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: invalidNamespaced("recovers", "default"), Event: controllers.EventAdd},
	})
	if got := unenforcedCount(t, scopeNamespaced); got != 1 {
		t.Fatalf("precondition: unenforced count = %v, want 1", got)
	}

	installGood(t, s, "recovers", "default")

	if got := unenforcedCount(t, scopeNamespaced); got != 0 {
		t.Fatalf("unenforced count = %v after a valid version landed, want 0", got)
	}
}

func TestApplyBatch_DeleteClearsUnenforced(t *testing.T) {
	s := NewStore(0)
	bad := invalidNamespaced("delete-unenforced", "default")
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: bad, Event: controllers.EventAdd},
	})
	if got := unenforcedCount(t, scopeNamespaced); got != 1 {
		t.Fatalf("precondition: unenforced count = %v, want 1", got)
	}

	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: bad, Event: controllers.EventDelete},
	})

	if got := unenforcedCount(t, scopeNamespaced); got != 0 {
		t.Fatalf("unenforced count = %v after the profile was deleted, want 0", got)
	}
}

// invalidInline is the identity-bearing item the inline collection transform
// produces for an annotation that failed to compile or project.
func invalidInline(name, namespace, version string) *securityprofile.Profile {
	return securityprofile.InvalidSandboxProfile(&metav1.PartialObjectMetadata{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, ResourceVersion: version},
	}, errors.New("invalid inline action"))
}

// Inline rules obey the same last-known-good contract as CRD profiles, and they
// report through the same two gauges under scope="inline" — which is what keeps
// a Sandbox-scale object from minting a time series per identity. The scope is
// the part that matters operationally: it separates a tenant's own annotation
// mistake from an operator's profile being unenforced.
func TestApplyBatch_InlineRulesMetrics(t *testing.T) {
	const ns, name = "sandboxes", "sbx-metrics"
	s := NewStore(0)

	// A bad first version installs nothing: unenforced, not stale.
	before := testutil.ToFloat64(profileCompileFailuresTotal.WithLabelValues(scopeSandbox))
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: invalidInline(name, ns, "1"), Event: controllers.EventAdd},
	})
	if got := testutil.ToFloat64(profileCompileFailuresTotal.WithLabelValues(scopeSandbox)) - before; got != 1 {
		t.Errorf("compile failures delta for scope %q = %v, want 1", scopeSandbox, got)
	}
	if got := unenforcedCount(t, scopeSandbox); got != 1 {
		t.Errorf("inline unenforced count = %v, want 1", got)
	}
	if got := staleCount(t, scopeSandbox); got != 0 {
		t.Errorf("inline stale count = %v for a Sandbox with nothing installed, want 0", got)
	}
	// The CRD scopes must not move: the scope label is what keeps tenant and
	// operator failures apart in one gauge.
	if got := unenforcedCount(t, scopeNamespaced); got != 0 {
		t.Errorf("namespaced unenforced count = %v, want 0: an inline failure must not read as a profile failure", got)
	}

	// A good version clears it.
	good := inlineProfile(name, ns, "2")
	s.applyBatch([]krt.Event[securityprofile.Profile]{{New: good, Event: controllers.EventAdd}})
	if got := unenforcedCount(t, scopeSandbox); got != 0 {
		t.Errorf("inline unenforced count = %v after a good version, want 0", got)
	}

	// A bad update is stale, not unenforced: the good version still serves.
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: good, New: invalidInline(name, ns, "3"), Event: controllers.EventUpdate},
	})
	if got := staleCount(t, scopeSandbox); got != 1 {
		t.Errorf("inline stale count = %v, want 1", got)
	}
	if got := unenforcedCount(t, scopeSandbox); got != 0 {
		t.Errorf("inline unenforced count = %v while the previous version still serves, want 0", got)
	}

	// Deleting the Sandbox leaves no series behind.
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: good, Event: controllers.EventDelete},
	})
	if got := staleCount(t, scopeSandbox); got != 0 {
		t.Errorf("inline stale count = %v after the Sandbox was deleted, want 0", got)
	}
	if got := unenforcedCount(t, scopeSandbox); got != 0 {
		t.Errorf("inline unenforced count = %v after the Sandbox was deleted, want 0", got)
	}
}

// gaugeSeriesCount reports how many time series one gauge family publishes.
func gaugeSeriesCount(t testing.TB, metricName string) int {
	t.Helper()
	families, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, f := range families {
		if f.GetName() == metricName {
			return len(f.GetMetric())
		}
	}
	t.Fatalf("gauge %s is not registered", metricName)
	return 0
}

// TestDegradedGaugesAreBoundedByScope is the cardinality contract. These gauges
// describe failures that arrive in bulk — one bad chart render, one Sandbox
// Manager schema change — so labelling them by object identity would mint a
// time series per object in the cluster at exactly the moment the signal
// matters, on a data-plane process. Whatever the store holds, the metric
// surface stays one series per scope.
func TestDegradedGaugesAreBoundedByScope(t *testing.T) {
	const n = 200
	s := NewStore(0)

	events := make([]krt.Event[securityprofile.Profile], 0, 2*n)
	for i := 0; i < n; i++ {
		id := strconv.Itoa(i)
		events = append(events,
			krt.Event[securityprofile.Profile]{
				New:   invalidNamespaced("p-"+id, "ns-"+id),
				Event: controllers.EventAdd,
			},
			krt.Event[securityprofile.Profile]{
				New:   invalidInline("sbx-"+id, "ns-"+id, "1"),
				Event: controllers.EventAdd,
			},
		)
	}
	s.applyBatch(events)

	for _, name := range []string{
		"epe_profile_stale", "epe_profile_unenforced", "epe_profile_inputs_unavailable",
	} {
		if got := gaugeSeriesCount(t, name); got != 3 {
			t.Errorf("%s publishes %d series for %d degraded sources, want 3 (one per scope)", name, got, 2*n)
		}
	}
	// The counts still carry the whole story, split by who has to act on it.
	if got := unenforcedCount(t, scopeNamespaced); got != n {
		t.Errorf("namespaced unenforced count = %v, want %d", got, n)
	}
	if got := unenforcedCount(t, scopeSandbox); got != n {
		t.Errorf("inline unenforced count = %v, want %d", got, n)
	}

	// Deleting every source drains the sets, so nothing is retained per object.
	deletes := make([]krt.Event[securityprofile.Profile], 0, 2*n)
	for _, ev := range events {
		deletes = append(deletes, krt.Event[securityprofile.Profile]{
			Old:   ev.New,
			Event: controllers.EventDelete,
		})
	}
	s.applyBatch(deletes)
	if got := unenforcedCount(t, scopeNamespaced) + unenforcedCount(t, scopeSandbox); got != 0 {
		t.Errorf("unenforced counts total = %v after deleting every source, want 0", got)
	}
	if got := len(s.degraded.unenforced.keys); got != 0 {
		t.Errorf("degraded set retains %d entries after every source was deleted, want 0", got)
	}
}

// An installed profile whose declared inputs did not resolve keeps enforcing,
// so it is neither stale nor unenforced — it needs its own signal.
func TestApplyBatch_InputsUnavailableCounted(t *testing.T) {
	s := NewStore(0)
	obj := newTestProfile("degraded-inputs", "default", map[string]string{"app": "x"})
	compiled, err := securityprofile.NewProfile(obj, &obj.Spec)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	compiled.InputsError = `input "routing" from ConfigMap default/missing: not found`
	s.applyBatch([]krt.Event[securityprofile.Profile]{{New: compiled, Event: controllers.EventAdd}})

	if got := inputsUnavailableCount(t, scopeNamespaced); got != 1 {
		t.Errorf("inputs-unavailable count = %v, want 1", got)
	}
	if got := staleCount(t, scopeNamespaced) + unenforcedCount(t, scopeNamespaced); got != 0 {
		t.Errorf("stale+unenforced = %v for an installed profile, want 0", got)
	}

	// The ConfigMap appearing recompiles the same version with inputs resolved.
	healed, err := securityprofile.NewProfile(obj, &obj.Spec)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: compiled, New: healed, Event: controllers.EventUpdate},
	})
	if got := inputsUnavailableCount(t, scopeNamespaced); got != 0 {
		t.Errorf("inputs-unavailable count = %v after the inputs resolved, want 0", got)
	}
}
