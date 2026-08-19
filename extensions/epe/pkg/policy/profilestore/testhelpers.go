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
	"istio.io/istio/extensions/epe/pkg/policy/securityprofile"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
)

// FakeStore embeds the production *store and adds synchronous
// direct-insertion helpers for tests. It exists so the real store type
// (*store) carries no test-only surface: production code uses NewStore,
// tests use MakeFakeStore. All read methods (List, Matches)
// and the production write path (RegisterCollection/applyBatch) are inherited
// unchanged via embedding.
//
// Seeding compiles the object exactly as NewCollection does and then folds the
// result through applyBatch — the same batch handler the krt collection drives
// in production — so tests exercise real selector/regex/audit compilation,
// CompileError/LKG retention, and snapshot building. Only the krt collection
// layer itself is bypassed, and because applyBatch is synchronous the write is
// visible the moment the helper returns.
//
// This is a regular (non _test.go) file on purpose: external test packages
// (admin, handlers) import these helpers, and _test.go symbols are not visible
// across packages, while a separate package could not reach the unexported
// applyBatch.
type FakeStore struct {
	*store
}

// MakeFakeStore returns an empty store that supports synchronous test seeding.
func MakeFakeStore() *FakeStore {
	return &FakeStore{store: NewStore()}
}

// ProfileSet adds or updates a namespace-scoped profile synchronously.
func (s *FakeStore) ProfileSet(profile *v1alpha1.SecurityProfile) {
	if profile == nil {
		return
	}
	s.apply(profile, &profile.Spec)
}

// GlobalProfileSet adds or updates a cluster-scoped profile synchronously.
func (s *FakeStore) GlobalProfileSet(profile *v1alpha1.GlobalSecurityProfile) {
	if profile == nil {
		return
	}
	s.apply(profile, &profile.Spec)
}

// InlineProfileSet compiles a Sandbox's inline security-rules annotation and
// installs the resulting profile synchronously. Objects without the
// annotation or with an invalid chain are ignored, mirroring the inline
// collection, which emits nothing for them.
func (s *FakeStore) InlineProfileSet(sandbox metav1.Object) {
	p, err := securityprofile.NewInlineProfile(sandbox)
	if err != nil || p == nil {
		return
	}
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: p, Event: controllers.EventAdd},
	})
}

// apply compiles obj/spec and folds the outcome through applyBatch. A
// compilation failure is folded as an identity-bearing CompileError item
// rather than dropped, so — exactly as in NewCollection — an invalid update
// leaves any prior effective profile installed instead of removing it.
//
// The nil krt context and nil ConfigMap collection mean ConfigMap-sourced
// inputs cannot resolve here and fail compilation; inline inputs resolve
// normally. Tests that need ConfigMap inputs must drive NewCollection.
func (s *FakeStore) apply(obj metav1.Object, spec *v1alpha1.SecurityProfileSpec) {
	log := ctrllog.Log.WithName("profile")
	sp, err := compileProfile(obj, spec, nil, nil)
	if err != nil {
		log.Error(err, "profile is invalid; retaining last-known-good version",
			"profile", obj.GetNamespace()+"/"+obj.GetName())
		sp = securityprofile.InvalidProfile(obj, spec, err)
	}
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{New: sp, Event: controllers.EventAdd},
	})
}

// ProfileGet retrieves a profile by its NamespacedName; cluster-scoped profiles
// use an empty Namespace.
func (s *FakeStore) ProfileGet(namespacedName types.NamespacedName) (*securityprofile.Profile, bool) {
	snap := s.snapshot.Load()
	p, ok := snap.byKey[namespacedName]
	return p, ok
}

// ProfileDelete removes a namespace-scoped profile synchronously.
func (s *FakeStore) ProfileDelete(namespace, name string) {
	s.remove(types.NamespacedName{Namespace: namespace, Name: name})
}

// GlobalProfileDelete removes a cluster-scoped profile synchronously.
func (s *FakeStore) GlobalProfileDelete(name string) {
	s.remove(types.NamespacedName{Name: name})
}

// remove folds a delete event for nn through applyBatch. Only the identity is
// needed: applyBatch's delete branch reads nothing but ev.Latest().Meta, and
// Latest falls back to Old when New is nil. applyBatch takes s.mu itself, so
// the caller must not hold it.
func (s *FakeStore) remove(nn types.NamespacedName) {
	tombstone := &securityprofile.Profile{
		Meta: securityprofile.Meta{Namespace: nn.Namespace, Name: nn.Name},
	}
	s.applyBatch([]krt.Event[securityprofile.Profile]{
		{Old: tombstone, Event: controllers.EventDelete},
	})
}
