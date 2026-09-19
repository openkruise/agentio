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
// Package profilestore provides an in-memory store for SecurityProfiles.
// Profile matching uses an immutable label index to select candidates from Pod
// labels extracted from Envoy filter_state, then evaluates each candidate's
// complete Kubernetes selector at request time.
//
// The store is a materialized view of a krt compiled-profile collection: it
// uses a copy-on-write strategy with atomic.Pointer for lock-free reads, and
// each collection event batch is folded into a fresh snapshot under a mutex.
package profilestore

import (
	"context"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube/controllers"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	GlobalProfileNamespace      = ""
	defaultGlobalSandboxWaiters = 1024
	defaultPerSandboxWaiters    = 64
)

var ErrSandboxPolicyWaitOverloaded = securityprofile.ErrSandboxPolicyWaitOverloaded

type StoreOption func(*store)

func WithWaitLimits(global, perSandbox int) StoreOption {
	return func(s *store) {
		s.maxWaiters = global
		s.maxWaitersPerSandbox = perSandbox
	}
}

// Store is a thread-safe in-memory store for SecurityProfiles and
// GlobalSecurityProfiles. It maintains a simple profile index and performs
// dynamic label-based matching at request time via ProfilesFor.
//
// Cluster-scoped GlobalSecurityProfiles are stored under an empty-namespace
// key and, unlike namespace-scoped SecurityProfiles, match pods in every
// namespace.
//
// Store is the read-only production surface consumed by the ext-proc data plane
// and admin endpoints. Writes are driven exclusively by RegisterCollection,
// which replays and then tails a krt compiled-profile collection in batches.
type Store interface {
	// List returns all installed profiles: selector-matched ones (both
	// namespace- and cluster-scoped) and per-Sandbox pod-matched profiles.
	List() []*securityprofile.Profile

	// ProfilesFor returns the complete, ordered policy chain for one pod:
	// profiles whose selectors match pod.Labels (cluster-scoped
	// GlobalSecurityProfiles and namespace-scoped SecurityProfiles in
	// pod.Namespace, sorted by priority, creation time, name, namespace),
	// followed by the pod's own profile when one exists. Pod-matched
	// profiles are keyed by exact identity — the Sandbox name is the
	// Pod name — and always evaluate after the selector-matched
	// administrator profiles. A zero pod.Name skips the identity lookup
	// (admin and debug paths that match by labels only).
	ProfilesFor(pod inputs.Pod) []*securityprofile.Profile

	AwaitSnapshot(ctx context.Context, pod inputs.Pod, wait time.Duration) (securityprofile.PolicySnapshot, error)
}

// profileKey identifies one installed profile. The match mode belongs in the
// key for two reasons: a Sandbox and a SecurityProfile in one namespace may
// share a name, and the mode is what decides how the profile is found — by
// exact Pod identity, or through the label index. It is a uint8 rather than a
// string because this key is copied for every entry on every write.
type profileKey struct {
	match     securityprofile.MatchMode
	namespace string
	name      string
}

func keyFor(m securityprofile.Meta) profileKey {
	return profileKey{match: m.Match, namespace: m.Namespace, name: m.Name}
}

// name2 is the identity half of the key, which is what each per-mode map is
// keyed by. The mode selects the map, so it must not also sit in the key.
func (k profileKey) name2() types.NamespacedName {
	return types.NamespacedName{Namespace: k.namespace, Name: k.name}
}

// scope maps the key onto the bounded metric scope label.
func (k profileKey) scope() string {
	if k.match == securityprofile.MatchPod {
		return scopePod
	}
	return profileScope(k.namespace)
}

// installedSet holds every installed profile, in one identity-keyed map per
// match mode. Callers address it by profileKey and never choose a map, so the
// write path treats every policy source identically; the split is what keeps
// the two lookups apart.
//
// Two maps rather than one keyed by (mode, namespace, name): the whole set is
// copied on every write, and folding the mode into the key grew it from two
// words to three, which measured ~17% slower and ~16% more allocation per batch
// at ten thousand profiles.
type installedSet struct {
	selector map[types.NamespacedName]*securityprofile.Profile
	pod      map[types.NamespacedName]*securityprofile.Profile
}

func newInstalledSet(selectorCap, podCap int) installedSet {
	return installedSet{
		selector: make(map[types.NamespacedName]*securityprofile.Profile, selectorCap),
		pod:      make(map[types.NamespacedName]*securityprofile.Profile, podCap),
	}
}

// clone is the copy-on-write step: the caller mutates the copy and publishes it.
func (set installedSet) clone() installedSet {
	next := newInstalledSet(len(set.selector), len(set.pod))
	maps.Copy(next.selector, set.selector)
	maps.Copy(next.pod, set.pod)
	return next
}

func (set installedSet) mapFor(match securityprofile.MatchMode) map[types.NamespacedName]*securityprofile.Profile {
	if match == securityprofile.MatchPod {
		return set.pod
	}
	return set.selector
}

func (set installedSet) get(k profileKey) (*securityprofile.Profile, bool) {
	p, ok := set.mapFor(k.match)[k.name2()]
	return p, ok
}

func (set installedSet) put(k profileKey, sp *securityprofile.Profile) {
	set.mapFor(k.match)[k.name2()] = sp
}

// remove reports whether anything was installed under the key.
func (set installedSet) remove(k profileKey) bool {
	m := set.mapFor(k.match)
	key := k.name2()
	if _, ok := m[key]; !ok {
		return false
	}
	delete(m, key)
	return true
}

func (set installedSet) len() int { return len(set.selector) + len(set.pod) }

// profileSnapshot is an immutable point-in-time view of all profiles.
// It is replaced atomically on every write operation (copy-on-write).
//
// installed is the storage. A pod-matched profile needs no index of its own,
// because its key *is* its lookup — exact Pod identity. Selector profiles do,
// so selectorIndex is the label index derived from installed.selector, keyed by
// namespace with cluster-scoped GlobalSecurityProfiles under the empty string.
//
// Keeping the two lookups apart is a security property, not an optimization: an
// identity match must never be reachable through a label, which a workload can
// influence.
//
// selectorIndex is immutable once built and may be shared with the preceding
// snapshot when a batch changed no selector profile: nothing may mutate a
// profileIndex after buildSnapshot returns it.
type sandboxPolicy struct {
	state   securityprofile.SandboxPolicyState
	version string
}

type profileSnapshot struct {
	installed       installedSet
	selectorIndex   map[string]profileIndex
	sandboxPolicies map[types.NamespacedName]sandboxPolicy
}

func newEmptySnapshot() *profileSnapshot {
	return &profileSnapshot{
		installed:       newInstalledSet(0, 0),
		selectorIndex:   make(map[string]profileIndex),
		sandboxPolicies: make(map[types.NamespacedName]sandboxPolicy),
	}
}

// NewStore creates a new in-memory configuration store. Wire it to a
// compiled-profile collection with RegisterCollection.
func NewStore(options ...StoreOption) *store {
	s := &store{
		degraded:             newDegradedSets(),
		maxWaiters:           defaultGlobalSandboxWaiters,
		maxWaitersPerSandbox: defaultPerSandboxWaiters,
		waitersBySandbox:     make(map[types.NamespacedName]int),
		notifiers:            make(map[types.NamespacedName]chan struct{}),
	}
	for _, option := range options {
		option(s)
	}
	s.snapshot.Store(newEmptySnapshot())
	return s
}

type store struct {
	snapshot             atomic.Pointer[profileSnapshot]
	mu                   sync.Mutex
	maxWaiters           int
	maxWaitersPerSandbox int
	waiters              int
	waitersBySandbox     map[types.NamespacedName]int
	notifiers            map[types.NamespacedName]chan struct{}
	// degraded is write-path state, guarded by mu: which sources are currently
	// stale, unenforced, or serving unresolved inputs. The gauges publish counts
	// from it, so the metric surface stays three series per gauge no matter how
	// many profiles the cluster holds.
	degraded degradedSets
}

// RegisterCollection materializes the compiled-profile collection into the
// store's snapshot. It registers a batch handler with initial-state replay,
// so the current collection contents are applied immediately and every
// subsequent krt event batch triggers one copy-on-write snapshot rebuild.
// The returned registration's WaitUntilSynced gates readiness on the initial
// replay having been delivered.
func (s *store) RegisterCollection(profiles krt.Collection[securityprofile.Profile]) krt.HandlerRegistration {
	return profiles.RegisterBatch(s.applyBatch, true)
}

// applyBatch folds one krt event batch into a new snapshot. Every source is
// handled the same way — an invalid item carries identity plus CompileError and
// leaves the prior effective entry untouched, and only a real source delete
// removes an installed profile. The source affects one thing here: whether the
// derived label index has to be rebuilt.
func (s *store) applyBatch(events []krt.Event[securityprofile.Profile]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Once per batch, not once per event: the gauges are counts, so only the
	// state after the whole batch is meaningful.
	defer s.degraded.publish()

	log := ctrllog.Log.WithName("profile")

	old := s.snapshot.Load()
	installed := old.installed.clone()
	sandboxPolicies := maps.Clone(old.sandboxPolicies)
	selectorsChanged := false
	touchedSandboxes := make(map[types.NamespacedName]struct{})

	for _, ev := range events {
		if ev.Event == controllers.EventDelete {
			key := keyFor(ev.Latest().Meta)
			s.degraded.removed(key)
			if installed.remove(key) {
				selectorsChanged = selectorsChanged || key.match == securityprofile.MatchSelector
			}
			if key.match == securityprofile.MatchPod {
				delete(sandboxPolicies, key.name2())
				touchedSandboxes[key.name2()] = struct{}{}
			}
			continue
		}
		sp := ev.New
		key := keyFor(sp.Meta)
		if key.match == securityprofile.MatchPod {
			sandboxPolicies[key.name2()] = sandboxPolicy{state: sp.SandboxState, version: sp.Meta.Version}
			touchedSandboxes[key.name2()] = struct{}{}
			if sp.SandboxState == securityprofile.SandboxPolicyUnknown || sp.SandboxState == securityprofile.SandboxPolicyReadyEmpty {
				s.degraded.removed(key)
				installed.remove(key)
				continue
			}
		}
		if sp.CompileError != "" {
			profileCompileFailuresTotal.WithLabelValues(key.scope()).Inc()
			_, wasInstalled := installed.get(key)
			s.degraded.rejected(key, wasInstalled)
			if wasInstalled {
				log.Error(nil, "policy version rejected; retaining last-known-good version",
					"profile", sp.ResourceName(), "scope", key.scope(), "error", sp.CompileError)
			} else {
				log.Error(nil, "policy version rejected with no previous version installed; "+
					"none of its rules are in effect",
					"profile", sp.ResourceName(), "scope", key.scope(), "error", sp.CompileError)
			}
			continue
		}
		s.degraded.installed(key, sp.InputsError != "")
		if sp.InputsError != "" {
			log.Error(nil, "profile installed with unavailable inputs; rules enforce but "+
				"inputs-dependent evaluations fail per each action's failure strategy",
				"profile", sp.ResourceName(), "error", sp.InputsError)
		}
		installed.put(key, sp)
		selectorsChanged = selectorsChanged || key.match == securityprofile.MatchSelector
	}

	var next *profileSnapshot
	if selectorsChanged {
		next = buildSnapshot(installed, sandboxPolicies)
	} else {
		next = reuseSnapshot(old, installed, sandboxPolicies)
	}
	s.snapshot.Store(next)
	for key := range touchedSandboxes {
		policy := next.sandboxPolicies[key]
		log.Info("sandbox policy state published",
			"sandbox", key.String(), "state", policy.state.String(), "resourceVersion", policy.version)
		s.notifySandboxLocked(key)
	}
}

// --- Read path (lock-free) ---

func (s *store) List() []*securityprofile.Profile {
	snap := s.snapshot.Load()
	result := make([]*securityprofile.Profile, 0, snap.installed.len())
	for _, p := range snap.installed.selector {
		result = append(result, p)
	}
	for _, p := range snap.installed.pod {
		result = append(result, p)
	}
	return result
}

func (s *store) ProfilesFor(pod inputs.Pod) []*securityprofile.Profile {
	return profilesFromSnapshot(s.snapshot.Load(), pod)
}

func profilesFromSnapshot(snap *profileSnapshot, pod inputs.Pod) []*securityprofile.Profile {
	ls := labels.Set(pod.Labels)
	matched := snap.selectorIndex[GlobalProfileNamespace].appendMatches(ls, nil)
	if pod.Namespace != GlobalProfileNamespace {
		matched = snap.selectorIndex[pod.Namespace].appendMatches(ls, matched)
	}
	if len(matched) > 1 {
		securityprofile.SortProfiles(matched)
	}
	return appendPodProfile(matched, snap, pod)
}

func policySnapshot(snap *profileSnapshot, pod inputs.Pod) securityprofile.PolicySnapshot {
	policy, exists := snap.sandboxPolicies[types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}]
	return securityprofile.PolicySnapshot{
		Profiles:       profilesFromSnapshot(snap, pod),
		SandboxExists:  exists,
		SandboxState:   policy.state,
		SandboxVersion: policy.version,
	}
}

// AwaitSnapshot reads the current policy snapshot and, when the store knows
// the caller as a Sandbox whose policy is still Unknown, holds the request
// until a later publish resolves it or the bounded wait expires. The wait is
// keyed on the store and nothing else: propagated identity is not consulted
// (ztunnel never emits sandbox.id, and the pod's claimed label is frozen at
// creation), so a caller the store has not observed is an ordinary Pod and
// returns immediately.
//
// wait is a courtesy window, not a convergence bound: watch latency has no
// upper bound, so a request that arrives while convergence is slower than
// wait fails closed with an Unknown snapshot, and the resolver turns that
// into a 503. Callers size the window for availability and configure it
// independently of the collection debounce.
func (s *store) AwaitSnapshot(ctx context.Context, pod inputs.Pod, wait time.Duration) (securityprofile.PolicySnapshot, error) {
	key := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}

	s.mu.Lock()
	current := policySnapshot(s.snapshot.Load(), pod)
	if !current.SandboxExists || current.SandboxState != securityprofile.SandboxPolicyUnknown || wait <= 0 {
		s.mu.Unlock()
		return current, nil
	}
	if s.waiters >= s.maxWaiters || s.waitersBySandbox[key] >= s.maxWaitersPerSandbox {
		s.mu.Unlock()
		sandboxPolicyWaitsTotal.WithLabelValues(waitOutcomeOverloaded).Inc()
		return current, ErrSandboxPolicyWaitOverloaded
	}
	s.waiters++
	s.waitersBySandbox[key]++
	updates := s.notifierLocked(key)
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.waiters--
		s.waitersBySandbox[key]--
		if s.waitersBySandbox[key] == 0 {
			delete(s.waitersBySandbox, key)
			if s.notifiers[key] == updates {
				delete(s.notifiers, key)
			}
		}
		s.mu.Unlock()
	}()

	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return securityprofile.PolicySnapshot{}, ctx.Err()
		case <-timer.C:
			s.mu.Lock()
			current = policySnapshot(s.snapshot.Load(), pod)
			s.mu.Unlock()
			outcome := waitOutcomeTimeout
			if current.SandboxState != securityprofile.SandboxPolicyUnknown {
				outcome = waitOutcomeReady
			}
			sandboxPolicyWaitsTotal.WithLabelValues(outcome).Inc()
			return current, nil
		case <-updates:
			s.mu.Lock()
			current = policySnapshot(s.snapshot.Load(), pod)
			if !current.SandboxExists {
				// The Sandbox left the store while the request waited — a
				// delete is a resolution, not a countdown: the caller is an
				// ordinary Pod now and the request must proceed instead of
				// being held to the deadline. Not counted as a wait outcome:
				// nothing about policy convergence was learned.
				s.mu.Unlock()
				return current, nil
			}
			if current.SandboxState != securityprofile.SandboxPolicyUnknown {
				s.mu.Unlock()
				sandboxPolicyWaitsTotal.WithLabelValues(waitOutcomeReady).Inc()
				return current, nil
			}
			// The publish did not resolve this Sandbox (its version moved but
			// stayed Unknown, or the notification belonged to another batch);
			// re-arm on the current notifier and keep waiting.
			updates = s.notifierLocked(key)
			s.mu.Unlock()
		}
	}
}

func (s *store) notifierLocked(key types.NamespacedName) chan struct{} {
	updates := s.notifiers[key]
	if updates == nil {
		updates = make(chan struct{})
		s.notifiers[key] = updates
	}
	return updates
}

func (s *store) notifySandboxLocked(key types.NamespacedName) {
	if updates := s.notifiers[key]; updates != nil {
		close(updates)
		delete(s.notifiers, key)
	}
}

// appendPodProfile adds the pod's own profile after the selector-matched
// administrator profiles: tenant rules must never evaluate ahead of them. It is
// one map lookup, because identity is the storage key. A zero pod.Name (e.g.
// the admin listing endpoint) skips the lookup.
func appendPodProfile(matched []*securityprofile.Profile, snap *profileSnapshot, pod inputs.Pod) []*securityprofile.Profile {
	if pod.Name == "" {
		return matched
	}
	if p, ok := snap.installed.pod[types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}]; ok {
		return append(matched, p)
	}
	return matched
}

// reuseSnapshot builds the next snapshot from a batch that changed no selector
// profile, carrying the label index forward instead of rebuilding an identical
// one. It exists so buildSnapshot stays the only place that decides what a
// snapshot is made of: a field added there must be handled here too, and a
// compiler error is easier to notice than a silently zero field.
func reuseSnapshot(old *profileSnapshot, installed installedSet, sandboxPolicies map[types.NamespacedName]sandboxPolicy) *profileSnapshot {
	return &profileSnapshot{installed: installed, selectorIndex: old.selectorIndex, sandboxPolicies: sandboxPolicies}
}

// buildSnapshot takes ownership of installed and derives the label index from
// its selector half. Pod-matched profiles are not in it: they are found by
// identity, and letting them into the label index is exactly the confusion the
// two lookups exist to prevent.
func buildSnapshot(installed installedSet, sandboxPolicies map[types.NamespacedName]sandboxPolicy) *profileSnapshot {
	profilesByNamespace := make(map[string][]*securityprofile.Profile)
	for nn, sp := range installed.selector {
		profilesByNamespace[nn.Namespace] = append(profilesByNamespace[nn.Namespace], sp)
	}

	selectorIndex := make(map[string]profileIndex, len(profilesByNamespace))
	for namespace, profiles := range profilesByNamespace {
		securityprofile.SortProfiles(profiles)
		selectorIndex[namespace] = buildProfileIndex(profiles)
	}

	return &profileSnapshot{installed: installed, selectorIndex: selectorIndex, sandboxPolicies: sandboxPolicies}
}
