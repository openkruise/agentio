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

package spstatus

import (
	"net/http"
	"sync"
	"testing"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apitypes "k8s.io/apimachinery/pkg/types"

	"istio.io/istio/pilot/pkg/status"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/revisions"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"
)

// fakePatcher records ApplyStatus calls and can be told to fail.
type fakePatcher struct {
	mu    sync.Mutex
	calls []applyCall
	err   error
}

type applyCall struct {
	Name         string
	Namespace    string
	Data         []byte
	FieldManager string
}

func (f *fakePatcher) Patch(name, namespace string, pt apitypes.PatchType, data []byte) error {
	return nil
}

func (f *fakePatcher) PatchStatus(name, namespace string, pt apitypes.PatchType, data []byte) error {
	return nil
}

func (f *fakePatcher) ApplyStatus(name, namespace string, pt apitypes.PatchType, data []byte, fieldManager string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, applyCall{name, namespace, data, fieldManager})
	return f.err
}

func (f *fakePatcher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakePatcher) last() applyCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func statusErr(code int32, reason metav1.StatusReason) error {
	return &kerrors.StatusError{ErrStatus: metav1.Status{Code: code, Reason: reason}}
}

func newTestQueue(t *testing.T, fp *fakePatcher, entries ...ProfileStatus) (*Queue, <-chan struct{}) {
	t.Helper()
	stop := test.NewStop(t)
	col := krt.NewStaticCollection(nil, entries, krt.WithStop(stop))
	q := NewQueue(fp, col)
	go q.Run(stop)
	return q, stop
}

func entry(ns, name string, gen int64) ProfileStatus {
	sp := &agentsv1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Generation: gen},
	}
	return ProfileStatus{Obj: sp, Status: BuildStatus(sp, nil, nil)}
}

func resourceFor(ns, name string) status.Resource {
	return status.Resource{
		GroupVersionResource: schema.GroupVersionResource{
			Group: "agents.kruise.io", Version: "v1alpha1", Resource: "securityprofiles",
		},
		Namespace: ns,
		Name:      name,
	}
}

func TestQueueAppliesStatus(t *testing.T) {
	fp := &fakePatcher{}
	q, _ := newTestQueue(t, fp, entry("ns-a", "sp", 4))

	q.EnqueueStatusUpdateResource(nil, resourceFor("ns-a", "sp"))

	assert.EventuallyEqual(t, fp.count, 1)
	got := fp.last()
	assert.Equal(t, got.Name, "sp")
	assert.Equal(t, got.Namespace, "ns-a")
	assert.Equal(t, got.FieldManager, FieldManager)

	// The body must be the apply patch for this object. Timestamps are
	// generated per call so the bytes cannot be compared to a fresh
	// BuildPatch; assert the identifying fields instead.
	body := decodePatch(t, got.Data)
	assert.Equal(t, body["kind"], "SecurityProfile")
	assert.Equal(t, body["metadata"].(map[string]any)["name"], "sp")
	status := body["status"].(map[string]any)
	assert.Equal[any](t, status["observedGeneration"], float64(4))
	assert.Equal(t, len(status["conditions"].([]any)), 3)
}

// An object that vanished from the collection needs no write.
func TestQueueSkipsMissingObject(t *testing.T) {
	fp := &fakePatcher{}
	q, _ := newTestQueue(t, fp)

	q.EnqueueStatusUpdateResource(nil, resourceFor("ns-a", "gone"))

	assert.EventuallyEqual(t, fp.count, 0)
}

// 404 means the object is gone; that is success, not a retry.
func TestQueueTreats404AsSuccess(t *testing.T) {
	fp := &fakePatcher{err: statusErr(http.StatusNotFound, metav1.StatusReasonNotFound)}
	q, _ := newTestQueue(t, fp, entry("ns-a", "sp", 1))

	q.EnqueueStatusUpdateResource(nil, resourceFor("ns-a", "sp"))

	// Exactly one attempt; no retries.
	assert.EventuallyEqual(t, fp.count, 1)
	assert.Consistently(t, fp.count, 1, 100*time.Millisecond)
}

// 403 will not heal on its own; retrying five times only spams the log.
func TestQueueDoesNotRetryForbidden(t *testing.T) {
	fp := &fakePatcher{err: statusErr(http.StatusForbidden, metav1.StatusReasonForbidden)}
	q, _ := newTestQueue(t, fp, entry("ns-a", "sp", 1))

	q.EnqueueStatusUpdateResource(nil, resourceFor("ns-a", "sp"))

	assert.EventuallyEqual(t, fp.count, 1)
	assert.Consistently(t, fp.count, 1, 100*time.Millisecond)
}

// A conflict is transient and must be retried.
func TestQueueRetriesConflict(t *testing.T) {
	fp := &fakePatcher{err: statusErr(http.StatusConflict, metav1.StatusReasonConflict)}
	q, _ := newTestQueue(t, fp, entry("ns-a", "sp", 1))

	q.EnqueueStatusUpdateResource(nil, resourceFor("ns-a", "sp"))

	// WithMaxAttempts(5) means at least a second attempt shows up.
	assert.EventuallyEqual(t, func() bool { return fp.count() >= 2 }, true)
}

// Register must suppress writes when the live status already equals the
// desired status; otherwise every resync rewrites every object.
func TestRegisterSuppressesNoOpWrites(t *testing.T) {
	stop := test.NewStop(t)
	fp := &fakePatcher{}

	sp := &agentsv1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns-a", Name: "sp", Generation: 1},
	}
	desired := BuildStatus(sp, nil, nil)
	// Live status already matches desired.
	sp.Status = desired

	col := krt.NewStaticCollection(nil, []ProfileStatus{{Obj: sp, Status: desired}}, krt.WithStop(stop))
	q := NewQueue(fp, col)
	go q.Run(stop)

	sc := &status.StatusCollections{}
	Register(sc, col, revisions.NewTagWatcher(kube.NewFakeClient(), "", "istio-system"))
	sc.SetQueue(q)

	// Nothing to do: live == desired.
	assert.EventuallyEqual(t, fp.count, 0)
}

// A foreign condition on the live object (written by another fieldManager)
// must not defeat suppression: only the conditions this controller owns decide
// whether a write is needed.
func TestRegisterSuppressesWithForeignCondition(t *testing.T) {
	stop := test.NewStop(t)
	fp := &fakePatcher{}

	sp := &agentsv1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns-a", Name: "sp", Generation: 1},
	}
	desired := BuildStatus(sp, nil, nil)
	live := *desired.DeepCopy()
	live.Conditions = append(live.Conditions, metav1.Condition{
		Type:               "SomeOtherController",
		Status:             metav1.ConditionTrue,
		Reason:             "External",
		Message:            "written by someone else",
		ObservedGeneration: 1,
		LastTransitionTime: metav1.Now(),
	})
	sp.Status = live

	col := krt.NewStaticCollection(nil, []ProfileStatus{{Obj: sp, Status: desired}}, krt.WithStop(stop))
	q := NewQueue(fp, col)
	go q.Run(stop)

	sc := &status.StatusCollections{}
	Register(sc, col, revisions.NewTagWatcher(kube.NewFakeClient(), "", "istio-system"))
	sc.SetQueue(q)

	// Everything we own already matches; the foreign condition is not ours to
	// reconcile, so no write may happen.
	assert.Consistently(t, fp.count, 0, 100*time.Millisecond)
}

func TestRegisterWritesWhenStatusDiffers(t *testing.T) {
	stop := test.NewStop(t)
	fp := &fakePatcher{}

	sp := &agentsv1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns-a", Name: "sp", Generation: 2},
	}
	// Live status is stale (empty), desired is not.
	col := krt.NewStaticCollection(nil, []ProfileStatus{{Obj: sp, Status: BuildStatus(sp, nil, nil)}},
		krt.WithStop(stop))
	q := NewQueue(fp, col)
	go q.Run(stop)

	sc := &status.StatusCollections{}
	Register(sc, col, revisions.NewTagWatcher(kube.NewFakeClient(), "", "istio-system"))
	sc.SetQueue(q)

	assert.EventuallyEqual(t, func() bool { return fp.count() >= 1 }, true)
}

// UnsetQueue unregisters the krt handler, so nothing is computed or written
// while this instance is not the leader.
func TestUnsetQueueStopsWrites(t *testing.T) {
	stop := test.NewStop(t)
	fp := &fakePatcher{}

	sp := &agentsv1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns-a", Name: "sp", Generation: 2},
	}
	col := krt.NewStaticCollection(nil, []ProfileStatus{{Obj: sp, Status: BuildStatus(sp, nil, nil)}},
		krt.WithStop(stop))
	q := NewQueue(fp, col)
	go q.Run(stop)

	sc := &status.StatusCollections{}
	Register(sc, col, revisions.NewTagWatcher(kube.NewFakeClient(), "", "istio-system"))
	sc.SetQueue(q)
	assert.EventuallyEqual(t, func() bool { return fp.count() >= 1 }, true)

	before := fp.count()
	sc.UnsetQueue()

	sp2 := sp.DeepCopy()
	sp2.Generation = 3
	col.UpdateObject(ProfileStatus{Obj: sp2, Status: BuildStatus(sp2, nil, nil)})

	// No further writes after the handler was unregistered.
	assert.Consistently(t, fp.count, before, 100*time.Millisecond)
}
