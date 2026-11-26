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

package kclient

import (
	"testing"
	"testing/synctest"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func TestRegistrationCompletesWithoutCRD(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		watcherSynced := make(chan struct{})
		r := &delayedHandlerRegistration{
			watcherSynced: watcherSynced,
			attached:      make(chan struct{}),
			lifetime:      &delayedInformerLifetime{started: make(chan struct{})},
		}
		checker := r.HasSyncedChecker()
		done := checker.Done()
		if cache.IsDone(checker) {
			t.Fatal("registration completed before the watcher synced")
		}
		close(watcherSynced)
		synctest.Wait()
		if !r.HasSynced() || !cache.IsDone(checker) {
			t.Fatal("watcher sync did not complete the registration")
		}
		// Installation after completion changes the bool, while Done is one-shot.
		handlerSynced := make(chan struct{})
		r.attach(testSyncedRegistration{synced: handlerSynced})
		if r.HasSynced() || checker.Done() != done || !cache.IsDone(checker) {
			t.Fatal("unexpected completion state after late CRD installation")
		}
		attached := r.HasSyncedChecker()
		if cache.IsDone(attached) {
			t.Fatal("new checker reported completion before the attached handler synced")
		}
		close(handlerSynced)
		if !r.HasSynced() || !cache.IsDone(attached) {
			t.Fatal("new checker did not report the attached handler's completion")
		}
	})
	if cache.IsDone((neverSynced{}).HasSyncedChecker()) {
		t.Fatal("stopped informer reported success")
	}
}

func TestRegistrationWaitsForAttachedHandler(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		watcherSynced := make(chan struct{})
		handlerSynced := make(chan struct{})
		r := &delayedHandlerRegistration{
			watcherSynced: watcherSynced,
			attached:      make(chan struct{}),
			lifetime:      &delayedInformerLifetime{started: make(chan struct{})},
		}
		checker := r.HasSyncedChecker()
		checker.Done()
		r.attach(testSyncedRegistration{synced: handlerSynced})
		close(watcherSynced)
		synctest.Wait()
		if r.HasSynced() || cache.IsDone(checker) {
			t.Fatal("watcher sync bypassed the attached handler")
		}
		close(handlerSynced)
		synctest.Wait()
		if !r.HasSynced() || !cache.IsDone(checker) {
			t.Fatal("attached handler sync did not complete the registration")
		}
	})
}

func TestStoppedRegistrationDoesNotComplete(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stop := make(chan struct{})
		watcherSynced := make(chan struct{})
		d := &delayedInformer[*metav1.PartialObjectMetadata]{
			lifetime: delayedInformerLifetime{started: make(chan struct{})},
		}
		r := &delayedHandlerRegistration{watcherSynced: watcherSynced, lifetime: &d.lifetime}
		checker := r.HasSyncedChecker()
		checker.Done()
		d.Start(stop)
		close(stop)
		synctest.Wait()
		close(watcherSynced)
		if cache.IsDone(checker) {
			t.Fatal("shutdown reported successful synchronization")
		}
	})
}

type testSyncedRegistration struct{ synced <-chan struct{} }

func (r testSyncedRegistration) HasSynced() bool                     { return cache.IsDone(r) }
func (r testSyncedRegistration) HasSyncedChecker() cache.DoneChecker { return r }
func (r testSyncedRegistration) Name() string                        { return "test registration" }
func (r testSyncedRegistration) Done() <-chan struct{}               { return r.synced }
