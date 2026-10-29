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
	"reflect"
	"slices"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// Preserve the original SecurityProfile controller's SSA ownership on upgrade.
const fieldManager = "agentio-securityprofile-status"

type statusBody struct {
	ObservedGeneration *int64             `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions"`
}

type statusPatch struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   metav1.ObjectMeta `json:"metadata"`
	Status     statusBody        `json:"status"`
}

func buildPatch(live *unstructured.Unstructured, desired result) ([]byte, error) {
	var existing statusBody
	raw, found, err := unstructured.NestedMap(live.Object, "status")
	if err != nil {
		return nil, err
	}
	if found {
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &existing); err != nil {
			return nil, fmt.Errorf("decode policy status: %w", err)
		}
	}
	conditions := slices.Clone(desired.Conditions)
	changed := false
	for i := range conditions {
		c := &conditions[i]
		// Compiler errors may quote expressions longer than Condition's schema limit.
		if message := []rune(c.Message); len(message) > 32768 {
			c.Message = string(message[:32765]) + "..."
		}
		previous := apiMeta.FindStatusCondition(existing.Conditions, c.Type)
		c.LastTransitionTime = metav1.Now()
		if previous != nil && previous.Status == c.Status {
			c.LastTransitionTime = previous.LastTransitionTime
		}
		if previous == nil || !reflect.DeepEqual(*previous, *c) {
			changed = true
		}
	}
	status := statusBody{Conditions: conditions}
	if desired.Source.Profile != nil {
		generation := desired.Source.Metadata.Generation
		status.ObservedGeneration = &generation
		changed = changed || existing.ObservedGeneration == nil || *existing.ObservedGeneration != generation
	}
	if !changed {
		return nil, nil
	}
	return json.Marshal(statusPatch{
		APIVersion: "agents.kruise.io/v1alpha1",
		Kind:       desired.Source.Kind,
		Metadata: metav1.ObjectMeta{Name: live.GetName(),
			Namespace:       live.GetNamespace(),
			UID:             live.GetUID(),
			ResourceVersion: live.GetResourceVersion()},
		Status: status,
	})
}

func (c *Controller) write(ctx context.Context, desired result) error {
	s := desired.Source
	client := c.client.Dynamic().Resource(s.gvr()).Namespace(s.Metadata.Namespace)
	live, err := client.Get(ctx, s.Metadata.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	// A queued result must not attach to a replacement object or newer spec.
	if live.GetUID() != s.Metadata.UID || live.GetGeneration() != s.Metadata.Generation {
		return nil
	}
	patch, err := buildPatch(live, desired)
	if err != nil {
		return err
	}
	if patch == nil {
		return nil
	}
	_, err = client.Patch(ctx, s.Metadata.Name, types.ApplyPatchType, patch,
		metav1.PatchOptions{FieldManager: fieldManager}, "status")
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
