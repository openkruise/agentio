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
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube/controllers"
	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
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
	regs []filter.Registration
}

// MakeFakeStore returns an empty store that supports synchronous test seeding.
//
// Seeded profiles are projected against regs, exactly as NewCollection does,
// so a malformed action fails the same way it would in production. Pass the
// same registration set the resolver under test was built with. Called with
// none, the store still works for matching tests, and the binder reports the
// mismatch rather than evaluating a profile projected against a different
// chain.
func MakeFakeStore(regs ...filter.Registration) *FakeStore {
	return &FakeStore{store: NewStore(0), regs: regs}
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

// SandboxProfileSet compiles a Sandbox's security-rules annotation and
// installs the resulting profile synchronously. Objects without the
// annotation are ignored, mirroring the sandbox collection, which emits
// nothing for them.
//
// A compile or projection failure is folded as an identity-bearing
// CompileError item, again mirroring the sandbox collection: the store
// retains any last-known-good sandbox version instead of installing or
// removing anything.
func (s *FakeStore) SandboxProfileSet(sandbox metav1.Object) {
	if sandbox.GetAnnotations()[securityprofile.AnnotationSecurityRules] == "" {
		return
	}
	p, err := securityprofile.NewSandboxProfile(sandbox)
	if err == nil {
		err = p.Project(s.regs)
	}
	if err != nil {
		p = securityprofile.InvalidSandboxProfile(sandbox, err)
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
	sp, err := compileProfile(obj, spec, s.regs, nil, nil)
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
	p, ok := snap.installed.selector[namespacedName]
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
