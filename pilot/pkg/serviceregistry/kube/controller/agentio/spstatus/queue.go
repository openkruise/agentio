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
	"strconv"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apitypes "k8s.io/apimachinery/pkg/types"

	"istio.io/istio/pilot/pkg/model/kstatus"
	"istio.io/istio/pilot/pkg/status"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	istiolog "istio.io/istio/pkg/log"
	"istio.io/istio/pkg/revisions"
)

var log = istiolog.RegisterScope("securityprofile-status", "SecurityProfile status controller")

// securityProfileGVR mirrors the GVR registered in the parent agentio package.
// It is hardcoded rather than resolved through istio's schema because
// agents.kruise.io types are not registered there.
var securityProfileGVR = schema.GroupVersionResource{
	Group: "agents.kruise.io", Version: "v1alpha1", Resource: "securityprofiles",
}

// FieldManager identifies this controller's server-side-apply ownership. It
// must be stable across releases: changing it orphans the fields written under
// the old name.
const FieldManager = "agentio-securityprofile-status"

// queueItem is what sits on the workqueue. It carries only the object key, not
// the status: workqueue deduplicates on item equality, so embedding the status
// would prevent two pending updates for the same object from coalescing.
// reconcile re-reads the desired status from the collection, which therefore
// always writes the latest value.
type queueItem struct {
	apitypes.NamespacedName
}

// Queue satisfies status.Queue and writes SecurityProfile status via
// server-side apply.
type Queue struct {
	queue   controllers.Queue
	patcher kclient.Patcher
	col     krt.Collection[ProfileStatus]
}

func NewQueue(patcher kclient.Patcher, col krt.Collection[ProfileStatus]) *Queue {
	q := &Queue{patcher: patcher, col: col}
	q.queue = controllers.NewQueue("securityprofile status",
		controllers.WithGenericReconciler(q.reconcile),
		controllers.WithMaxAttempts(5))
	return q
}

func (q *Queue) Run(stop <-chan struct{}) {
	q.queue.Run(stop)
}

// EnqueueStatusUpdateResource implements status.Queue.
//
// The context argument is intentionally ignored. The interface exists for
// istio's status.Manager, whose controllers pass the desired status through it;
// here the desired status is read from the collection at reconcile time so
// that coalesced workqueue entries always write the newest value.
func (q *Queue) EnqueueStatusUpdateResource(_ any, target status.Resource) {
	q.queue.Add(queueItem{apitypes.NamespacedName{
		Namespace: target.Namespace,
		Name:      target.Name,
	}})
}

func (q *Queue) reconcile(raw any) error {
	item := raw.(queueItem)
	log := log.WithLabels("securityprofile", item.String())

	entry := q.col.GetKey(item.String())
	if entry == nil {
		log.Debugf("object no longer present, nothing to write")
		return nil
	}

	data, err := BuildPatch(item.Name, entry.Status)
	if err != nil {
		// A marshalling failure is deterministic; retrying cannot help.
		log.Errorf("failed to build status patch: %v", err)
		return nil
	}

	err = q.patcher.ApplyStatus(item.Name, item.Namespace, apitypes.ApplyPatchType, data, FieldManager)
	switch {
	case err == nil:
		log.Debugf("wrote status")
		return nil
	case kerrors.IsNotFound(err):
		// Deleted between the collection read and the write.
		log.Debugf("object deleted before status could be written")
		return nil
	case kerrors.IsForbidden(err), kerrors.IsUnauthorized(err):
		// RBAC will not fix itself; retrying five times only spams the log.
		log.Errorf("not permitted to write status, check the securityprofiles/status RBAC rule: %v", err)
		return nil
	default:
		return err
	}
}

var _ status.Queue = &Queue{}

// ownedConditionTypes are the only condition types this controller declares
// and reconciles.
var ownedConditionTypes = []string{
	agentsv1alpha1.SecurityProfileConditionAccepted,
	agentsv1alpha1.SecurityProfileConditionProgrammed,
	ConditionResolvedRefs,
}

// ownedStatusEqual reports whether a status write is needed. A wholesale
// krt.Equal over the two statuses would be wrong: the live status may
// legitimately carry conditions written by other fieldManagers that the
// desired (owned-only) status never contains, so wholesale comparison would
// never suppress and every resync would enqueue a redundant PATCH. Compare
// only what this controller owns: observedGeneration plus the three owned
// condition types. LastTransitionTime is excluded because it is redundant:
// BuildStatus carries the live timestamp forward whenever Status matches, and
// when Status differs the Status comparison already forces a write.
func ownedStatusEqual(live, desired agentsv1alpha1.SecurityProfileStatus) bool {
	if live.ObservedGeneration != desired.ObservedGeneration {
		return false
	}
	for _, typ := range ownedConditionTypes {
		l := kstatus.GetCondition(live.Conditions, typ)
		d := kstatus.GetCondition(desired.Conditions, typ)
		if l.Status != d.Status || l.Reason != d.Reason ||
			l.Message != d.Message || l.ObservedGeneration != d.ObservedGeneration {
			return false
		}
	}
	return true
}

// Register wires the status collection into the StatusCollections container so
// leader election can turn writing on and off.
//
// This mirrors status.RegisterStatus (pilot/pkg/status/collections.go:78-112)
// but cannot call it: that function's enqueueStatus resolves the GVR via
// schematypes.GvrFromObject, which panics for any GVK absent from the
// generated istio schema switch (pkg/config/schema/kubetypes/common.go:43-49),
// and agents.kruise.io types are not in that schema.
//
// SetQueue registers the handler with runExistingState, so becoming the leader
// replays the full current state (pkg/kube/krt/collection.go:743-746).
// UnsetQueue unregisters it, so a non-leader neither computes nor writes.
func Register(sc *status.StatusCollections, col krt.Collection[ProfileStatus], tagWatcher revisions.TagWatcher) {
	sc.Register(func(writer status.Queue) krt.HandlerRegistration {
		return col.Register(func(o krt.Event[ProfileStatus]) {
			l := o.Latest()
			if o.Event == controllers.EventDelete {
				// The object is gone; do not resurrect its status.
				return
			}
			if ownedStatusEqual(l.Obj.Status, l.Status) {
				// Already what we want. Skipping avoids rewriting every object
				// on every resync, which matters because LastTransitionTime
				// would otherwise make each write look like a change.
				log.Debugf("suppress no-op status write for %v", l.ResourceName())
				return
			}
			if !tagWatcher.IsMine(metav1.ObjectMeta{
				Namespace: l.Obj.GetNamespace(),
				Name:      l.Obj.GetName(),
				Labels:    l.Obj.GetLabels(),
			}) {
				log.Debugf("suppress status write for %v: not my revision", l.ResourceName())
				return
			}
			writer.EnqueueStatusUpdateResource(nil, status.Resource{
				GroupVersionResource: securityProfileGVR,
				Namespace:            l.Obj.GetNamespace(),
				Name:                 l.Obj.GetName(),
				Generation:           strconv.FormatInt(l.Obj.GetGeneration(), 10),
			})
		})
	})
}
