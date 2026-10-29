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

package policystatus

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkruise/agentio/pkg/krt"

	"istio.io/istio/pkg/test/util/assert"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"
)

func livePolicy(s source) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "agents.kruise.io/v1alpha1",
		"kind":       s.Kind,
	}}
	obj.SetName(s.Metadata.Name)
	obj.SetNamespace(s.Metadata.Namespace)
	obj.SetUID(s.Metadata.UID)
	obj.SetGeneration(s.Metadata.Generation)
	obj.SetResourceVersion("42")
	return obj
}

func TestStatusPatchOwnershipAndTransitions(t *testing.T) {
	s := profileSource(t, `{}`, "demo")
	oldTime := metav1.NewTime(time.Unix(1, 0))
	accepted := condition("Accepted", metav1.ConditionTrue, "Accepted", "valid", s.Metadata.Generation)
	accepted.LastTransitionTime = oldTime
	resolved := condition("ResolvedRefs", metav1.ConditionTrue, "ResolvedRefs", "found", s.Metadata.Generation)
	resolved.LastTransitionTime = oldTime
	foreign := condition("Programmed", metav1.ConditionTrue, "Loaded", "owned by another controller", 2)
	foreign.LastTransitionTime = oldTime
	status, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&statusBody{
		ObservedGeneration: &s.Metadata.Generation,
		Conditions:         []metav1.Condition{accepted, resolved, foreign},
	})
	assert.NoError(t, err)
	live := livePolicy(s)
	live.Object["status"] = status
	desired := result{
		Source:     s,
		Conditions: []metav1.Condition{accepted, resolved},
	}
	data, err := buildPatch(live, desired)
	assert.NoError(t, err)
	assert.Equal(t, len(data), 0)
	desired.Conditions[0].Message = "new details"
	desired.Conditions[1].Status = metav1.ConditionFalse
	data, err = buildPatch(live, desired)
	assert.NoError(t, err)
	var patch statusPatch
	assert.NoError(t, json.Unmarshal(data, &patch))
	assert.Equal(t, len(patch.Status.Conditions), 2)
	assert.Equal(t, patch.Status.Conditions[0].LastTransitionTime, oldTime)
	assert.Equal(t, patch.Status.Conditions[1].LastTransitionTime.After(oldTime.Time), true)
	assert.Equal(t, patch.Metadata.ResourceVersion, "42")
	assert.Equal(t, patch.Metadata.UID, s.Metadata.UID)
	assert.Equal(t, *patch.Status.ObservedGeneration, s.Metadata.Generation)
	// TrafficPolicy's existing schema has observedGeneration on conditions only.
	desired.Source.Profile = nil
	data, err = buildPatch(live, desired)
	assert.NoError(t, err)
	var raw map[string]any
	assert.NoError(t, json.Unmarshal(data, &raw))
	_, found := raw["status"].(map[string]any)["observedGeneration"]
	assert.Equal(t, found, false)
}

func TestWriterRejectsStaleResultsAndReturnsErrors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		uid        types.UID
		generation int64
		failure    error
		patches    int
	}{
		{"current", "original", 3, nil, 1},
		{"new generation", "original", 4, nil, 0},
		{"recreated", "replacement", 3, nil, 0},
		{"conflict", "original", 3, apierrors.NewConflict(profileSource(t, `{}`, "demo").gvr().GroupResource(), "test", fmt.Errorf("resource version changed")), 1},
		{"forbidden", "original", 3, apierrors.NewForbidden(profileSource(t, `{}`, "demo").gvr().GroupResource(), "test", fmt.Errorf("denied")), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := testController(t, false)
			s := profileSource(t, `{}`, "demo")
			live := livePolicy(s)
			live.SetUID(tc.uid)
			live.SetGeneration(tc.generation)
			client := c.client.Dynamic().(*dynamicfake.FakeDynamicClient)
			assert.NoError(t, client.Tracker().Add(live))
			patches := 0
			client.PrependReactor("patch", "*", func(action ktesting.Action) (bool, runtime.Object, error) {
				patches++
				patch := action.(ktesting.PatchAction)
				assert.Equal(t, patch.GetSubresource(), "status")
				assert.Equal(t, patch.GetPatchType(), types.ApplyPatchType)
				options := action.(ktesting.PatchActionImpl).GetPatchOptions()
				assert.Equal(t, options.FieldManager, fieldManager)
				assert.Equal(t, options.Force == nil, true)
				return true, live, tc.failure
			})
			err := c.write(t.Context(), result{
				Source:     s,
				Conditions: []metav1.Condition{condition("Accepted", metav1.ConditionTrue, "Accepted", "valid", 3)},
			})
			assert.Equal(t, err != nil, tc.failure != nil)
			assert.Equal(t, patches, tc.patches)
		})
	}
}

func TestWriterRetriesConflicts(t *testing.T) {
	c, _ := testController(t, false)
	s := profileSource(t, `{}`, "demo")
	live := livePolicy(s)
	client := c.client.Dynamic().(*dynamicfake.FakeDynamicClient)
	assert.NoError(t, client.Tracker().Add(live))
	var attempts atomic.Int32
	client.PrependReactor("patch", "*", func(ktesting.Action) (bool, runtime.Object, error) {
		if attempts.Add(1) <= 6 {
			return true, nil, apierrors.NewConflict(s.gvr().GroupResource(), s.Metadata.Name, fmt.Errorf("changed"))
		}
		return true, live, nil
	})
	c.results = krt.NewStaticCollection(nil, []result{{
		Source:     s,
		Conditions: []metav1.Condition{condition("Accepted", metav1.ConditionTrue, "Accepted", "valid", 3)},
	}}, krt.WithStop(t.Context().Done()))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		c.runWriter(ctx)
		close(done)
	}()
	assert.EventuallyEqual(t, attempts.Load, int32(7))
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("writer did not stop")
	}
}

func TestLongCompilerErrorFitsStatusSchema(t *testing.T) {
	s := profileSource(t, `{}`, "demo")
	desired := result{
		Source: s,
		Conditions: []metav1.Condition{
			condition("Accepted", metav1.ConditionFalse, "InvalidConfiguration", strings.Repeat("界", 32769), 3),
		},
	}
	data, err := buildPatch(livePolicy(s), desired)
	assert.NoError(t, err)
	var patch statusPatch
	assert.NoError(t, json.Unmarshal(data, &patch))
	assert.Equal(t, len([]rune(patch.Status.Conditions[0].Message)), 32768)
	assert.Equal(t, strings.HasSuffix(patch.Status.Conditions[0].Message, "..."), true)
	assert.Equal(t, len([]rune(desired.Conditions[0].Message)), 32769)
}
