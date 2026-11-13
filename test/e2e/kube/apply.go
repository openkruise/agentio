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

package kube

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/util/retry"
)

type Mode string

const (
	CreateOnly     Mode = "create-only"
	ReconcileOwned Mode = "reconcile-owned"
)

func (c *Client) Apply(ctx context.Context, desired *unstructured.Unstructured, mode Mode) (ResourceRecord, error) {
	return c.apply(ctx, "", desired, mode)
}

// ApplyInNamespace applies desired and assigns namespace only when the mapped
// resource is namespaced and desired does not already name a namespace.
func (c *Client) ApplyInNamespace(
	ctx context.Context,
	namespace string,
	desired *unstructured.Unstructured,
	mode Mode,
) (ResourceRecord, error) {
	return c.apply(ctx, namespace, desired, mode)
}

func (c *Client) apply(
	ctx context.Context,
	defaultNamespace string,
	desired *unstructured.Unstructured,
	mode Mode,
) (ResourceRecord, error) {
	if desired == nil {
		return ResourceRecord{}, errors.New("apply object is required")
	}
	object := desired.DeepCopy()
	gvk := object.GroupVersionKind()
	if gvk.Empty() || object.GetName() == "" {
		return ResourceRecord{}, fmt.Errorf(
			"apply object requires apiVersion, kind, and metadata.name: %s",
			object.GetName(),
		)
	}
	mapping, err := c.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return ResourceRecord{}, fmt.Errorf("map %s: %w", gvk.String(), err)
	}
	namespaced := mapping.Scope.Name() == meta.RESTScopeNameNamespace
	if namespaced && object.GetNamespace() == "" {
		object.SetNamespace(defaultNamespace)
	} else if !namespaced {
		object.SetNamespace("")
	}
	labels := object.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}
	labels[RunLabel] = c.runID
	if namespaced && c.testID != "" {
		labels[TestLabel] = c.testID
	}
	object.SetLabels(labels)
	resource := c.resource(mapping.Resource, object.GetNamespace(), namespaced)
	manifest, err := json.Marshal(object.Object)
	if err != nil {
		return ResourceRecord{}, fmt.Errorf(
			"marshal %s %s/%s: %w",
			gvk.Kind,
			object.GetNamespace(),
			object.GetName(),
			err,
		)
	}

	applied, err := c.applyObject(ctx, resource, mapping.Resource, object, mode)
	if err != nil {
		return ResourceRecord{}, err
	}

	hash := sha256.Sum256(manifest)
	record := ResourceRecord{
		GVR:          mapping.Resource,
		Namespace:    applied.GetNamespace(),
		Name:         applied.GetName(),
		UID:          applied.GetUID(),
		RunID:        c.runID,
		Labels:       cloneLabels(applied.GetLabels()),
		ManifestHash: hex.EncodeToString(hash[:]),
		Namespaced:   namespaced,
	}
	c.ledger.Record(record)
	if gvk.Group == "apiextensions.k8s.io" && gvk.Kind == "CustomResourceDefinition" {
		if err := c.Wait(ctx, record.GVR, "", record.Name, customResourceDefinitionEstablished); err != nil {
			return ResourceRecord{}, fmt.Errorf("wait for applied CustomResourceDefinition %s: %w", record.Name, err)
		}
		if c.discovery != nil {
			c.discovery.Invalidate()
		}
		if resettable, ok := c.mapper.(interface{ Reset() }); ok {
			resettable.Reset()
		}
	}
	return record, nil
}

func (c *Client) applyObject(
	ctx context.Context,
	resource dynamic.ResourceInterface,
	gvr schema.GroupVersionResource,
	object *unstructured.Unstructured,
	mode Mode,
) (*unstructured.Unstructured, error) {
	gvk := object.GroupVersionKind()
	var applied *unstructured.Unstructured
	var err error
	switch mode {
	case CreateOnly:
		applied, err = resource.Create(ctx, object, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf(
				"%s %s/%s already exists: %w",
				gvk.Kind,
				object.GetNamespace(),
				object.GetName(),
				err,
			)
		}
		if err != nil {
			return nil, fmt.Errorf(
				"create %s %s/%s: %w",
				gvk.Kind,
				object.GetNamespace(),
				object.GetName(),
				err,
			)
		}
	case ReconcileOwned:
		record, found := c.ledger.Find(gvr, object.GetNamespace(), object.GetName())
		if !found {
			return nil, fmt.Errorf(
				"reconcile %s %s/%s: object has no ownership ledger entry",
				gvk.Kind,
				object.GetNamespace(),
				object.GetName(),
			)
		}
		// CreateOnly deliberately uses an atomic create so it cannot mutate a
		// pre-existing object. Once ownership is verified, use a full update so
		// fields omitted by the desired manifest (notably policy list entries)
		// are removed instead of remaining under the create field manager.
		err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			live, getErr := resource.Get(ctx, object.GetName(), metav1.GetOptions{})
			if getErr != nil {
				return getErr
			}
			if err := c.validateOwnership(live, record); err != nil {
				return err
			}
			if live.GetResourceVersion() == "" {
				return fmt.Errorf("live object has no resourceVersion")
			}
			object.SetResourceVersion(live.GetResourceVersion())
			applied, err = resource.Update(ctx, object, metav1.UpdateOptions{FieldManager: c.fieldManager})
			return err
		})
		if err != nil {
			return nil, fmt.Errorf(
				"update owned %s %s/%s: %w",
				gvk.Kind,
				object.GetNamespace(),
				object.GetName(),
				err,
			)
		}
	default:
		return nil, fmt.Errorf("unsupported apply mode %q", mode)
	}

	return applied, nil
}

func customResourceDefinitionEstablished(object *unstructured.Unstructured) (bool, error) {
	rawConditions, found, err := unstructured.NestedFieldNoCopy(object.Object, "status", "conditions")
	if err != nil || !found || rawConditions == nil {
		return false, err
	}
	conditions, ok := rawConditions.([]any)
	if !ok {
		return false, fmt.Errorf("CRD status.conditions has type %T, want array", rawConditions)
	}
	for _, raw := range conditions {
		condition, ok := raw.(map[string]any)
		if !ok || condition["type"] != "Established" {
			continue
		}
		return condition["status"] == "True", nil
	}
	return false, nil
}

func (c *Client) resource(
	gvr schema.GroupVersionResource,
	namespace string,
	namespaced bool,
) dynamic.ResourceInterface {
	resource := c.dynamic.Resource(gvr)
	if namespaced || namespace != "" {
		return resource.Namespace(namespace)
	}
	return resource
}
