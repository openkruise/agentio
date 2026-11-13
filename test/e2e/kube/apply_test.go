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
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/openkruise/agentio/test/e2e/cluster"
)

func TestCreateOnlyRejectsForeignObject(t *testing.T) {
	foreign := configMap("sandbox", "settings")
	foreign.SetUID(types.UID("foreign"))
	client, _ := newFakeClient(t, foreign)

	_, err := client.Apply(context.Background(), configMap("sandbox", "settings"), CreateOnly)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Apply() error = %v", err)
	}
}

func TestCreateOnlyUsesAtomicCreate(t *testing.T) {
	client, _ := newFakeClient(t)
	installApplyReactor(t, client, "uid-1")

	if _, err := client.Apply(context.Background(), configMap("sandbox", "settings"), CreateOnly); err != nil {
		t.Fatal(err)
	}
	for _, action := range client.dynamic.(*dynamicfake.FakeDynamicClient).Actions() {
		if action.GetVerb() == "get" || action.GetVerb() == "patch" || action.GetVerb() == "update" {
			t.Fatalf(
				"CreateOnly issued %q; want one atomic create without a preflight read or mutation",
				action.GetVerb(),
			)
		}
	}
}

func TestApplyRecordsLiveIdentityLabelsAndManifestHash(t *testing.T) {
	client, ledger := newFakeClient(t)
	installApplyReactor(t, client, "uid-1")

	record, err := client.WithTestID("TestPolicy/allow").Apply(
		context.Background(), configMap("sandbox", "settings"), CreateOnly,
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.UID != "uid-1" || record.RunID != "run-1" || len(record.ManifestHash) != 64 {
		t.Fatalf("record = %+v", record)
	}
	if record.Labels[RunLabel] != "run-1" || record.Labels[TestLabel] != "TestPolicy-allow" {
		t.Fatalf("labels = %#v", record.Labels)
	}
	snapshot := ledger.Snapshot()
	if len(snapshot) != 1 || snapshot[0].UID != record.UID {
		t.Fatalf("ledger = %#v", snapshot)
	}
}

func TestApplyInNamespaceDefaultsOnlyNamespacedResources(t *testing.T) {
	t.Run("empty namespaced object", func(t *testing.T) {
		client, _ := newFakeClient(t)
		installApplyReactor(t, client, "uid-defaulted")
		object := configMap("", "settings")

		record, err := client.ApplyInNamespace(context.Background(), "sandbox", object, CreateOnly)
		if err != nil {
			t.Fatal(err)
		}
		if record.Namespace != "sandbox" || !record.Namespaced {
			t.Fatalf("record = %+v", record)
		}
		if object.GetNamespace() != "" {
			t.Fatalf("ApplyInNamespace mutated input namespace to %q", object.GetNamespace())
		}
	})

	t.Run("explicit namespace", func(t *testing.T) {
		client, _ := newFakeClient(t)
		installApplyReactor(t, client, "uid-explicit")

		record, err := client.ApplyInNamespace(
			context.Background(),
			"default",
			configMap("explicit", "settings"),
			CreateOnly,
		)
		if err != nil {
			t.Fatal(err)
		}
		if record.Namespace != "explicit" {
			t.Fatalf("record namespace = %q, want explicit", record.Namespace)
		}
	})

	t.Run("cluster scoped object", func(t *testing.T) {
		dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
		mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{{Group: "", Version: "v1"}})
		mapper.Add(namespaceGVK, meta.RESTScopeRoot)
		client := NewClient("run-1", &cluster.Cluster{Dynamic: dynamicClient, Mapper: mapper}, NewLedger())
		installResourceApplyReactor(t, client, "namespaces", namespaceGVR, "uid-cluster")
		object := namespaceObject("incorrect", "sandbox")

		record, err := client.ApplyInNamespace(context.Background(), "default", object, CreateOnly)
		if err != nil {
			t.Fatal(err)
		}
		if record.Namespace != "" || record.Namespaced {
			t.Fatalf("record = %+v", record)
		}
		if object.GetNamespace() != "incorrect" {
			t.Fatalf("ApplyInNamespace mutated input namespace to %q", object.GetNamespace())
		}
	})
}

func TestReconcileOwnedRejectsMissingLedgerIdentity(t *testing.T) {
	live := configMap("sandbox", "settings")
	live.SetUID("uid-1")
	live.SetLabels(map[string]string{RunLabel: "run-1"})
	client, _ := newFakeClient(t, live)

	_, err := client.Apply(context.Background(), configMap("sandbox", "settings"), ReconcileOwned)
	if err == nil || !strings.Contains(err.Error(), "ledger") {
		t.Fatalf("Apply() error = %v", err)
	}
}

func TestReconcileOwnedRejectsRecreatedLiveObject(t *testing.T) {
	live := configMap("sandbox", "settings")
	live.SetUID("new-uid")
	live.SetLabels(map[string]string{RunLabel: "run-1"})
	client, ledger := newFakeClient(t, live)
	ledger.Record(ResourceRecord{
		GVR:       configMapGVR,
		Namespace: "sandbox",
		Name:      "settings",
		UID:       "old-uid",
		RunID:     "run-1",
	})

	_, err := client.Apply(context.Background(), configMap("sandbox", "settings"), ReconcileOwned)
	if err == nil || !strings.Contains(err.Error(), "UID") {
		t.Fatalf("Apply() error = %v", err)
	}
}

func TestReconcileOwnedUsesResourceVersionAndUpdateResponse(t *testing.T) {
	live := configMap("sandbox", "settings")
	live.SetUID("uid-1")
	live.SetResourceVersion("17")
	live.SetLabels(map[string]string{RunLabel: "run-1"})
	live.Object["data"] = map[string]any{"key": "old", "stale": "remove-me"}
	client, ledger := newFakeClient(t, live)
	ledger.Record(ResourceRecord{
		GVR:       configMapGVR,
		Namespace: "sandbox",
		Name:      "settings",
		UID:       "uid-1",
		RunID:     "run-1",
	})
	fakeClient := client.dynamic.(*dynamicfake.FakeDynamicClient)
	var updated *unstructured.Unstructured
	var updateOptions metav1.UpdateOptions
	fakeClient.PrependReactor("update", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		update := action.(ktesting.UpdateAction)
		updated = update.GetObject().(*unstructured.Unstructured).DeepCopy()
		updateOptions = action.(interface{ GetUpdateOptions() metav1.UpdateOptions }).GetUpdateOptions()
		response := updated.DeepCopy()
		response.SetUID("uid-1")
		response.SetResourceVersion("18")
		labels := response.GetLabels()
		labels["server-defaulted"] = "true"
		response.SetLabels(labels)
		return true, response, nil
	})

	record, err := client.Apply(context.Background(), configMap("sandbox", "settings"), ReconcileOwned)
	if err != nil {
		t.Fatal(err)
	}
	if updated.GetResourceVersion() != "17" {
		t.Fatalf("Update resourceVersion = %q, want 17", updated.GetResourceVersion())
	}
	if updateOptions.FieldManager != "agentio-e2e" {
		t.Fatalf("Update options = %+v, want field manager agentio-e2e", updateOptions)
	}
	data, _, err := unstructured.NestedStringMap(updated.Object, "data")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 1 || data["key"] != "value" {
		t.Fatalf("updated data = %#v, want the desired object without stale fields", data)
	}
	if record.Labels["server-defaulted"] != "true" {
		t.Fatalf("record labels = %#v, want fields from the Update response", record.Labels)
	}
	gets, updates, patches := 0, 0, 0
	for _, action := range fakeClient.Actions() {
		switch action.GetVerb() {
		case "get":
			gets++
		case "update":
			updates++
		case "patch":
			patches++
		}
	}
	if gets != 1 || updates != 1 || patches != 0 {
		t.Fatalf("GET/UPDATE/PATCH actions = %d/%d/%d, want 1/1/0", gets, updates, patches)
	}
}

func TestReconcileOwnedRetriesConflictsAndRechecksOwnership(t *testing.T) {
	for _, recreated := range []bool{false, true} {
		t.Run(fmt.Sprintf("recreated=%v", recreated), func(t *testing.T) {
			live := configMap("sandbox", "settings")
			live.SetUID("uid-1")
			live.SetResourceVersion("17")
			live.SetLabels(map[string]string{RunLabel: "run-1"})
			client, ledger := newFakeClient(t, live)
			ledger.Record(
				ResourceRecord{GVR: configMapGVR, Namespace: "sandbox", Name: "settings", UID: "uid-1", RunID: "run-1"},
			)
			fakeClient := client.dynamic.(*dynamicfake.FakeDynamicClient)
			var versions []string
			fakeClient.PrependReactor(
				"update",
				"configmaps",
				func(action ktesting.Action) (bool, runtime.Object, error) {
					updated := action.(ktesting.UpdateAction).GetObject().(*unstructured.Unstructured).DeepCopy()
					versions = append(versions, updated.GetResourceVersion())
					if len(versions) == 1 {
						live.SetResourceVersion("18")
						if recreated {
							live.SetUID("uid-2")
						}
						if err := fakeClient.Tracker().Update(configMapGVR, live, "sandbox"); err != nil {
							t.Fatal(err)
						}
						return true, nil, apierrors.NewConflict(
							configMapGVR.GroupResource(),
							live.GetName(),
							errors.New("status changed"),
						)
					}
					updated.SetUID("uid-1")
					return true, updated, nil
				},
			)
			_, err := client.Apply(t.Context(), configMap("sandbox", "settings"), ReconcileOwned)
			if recreated {
				if err == nil || !strings.Contains(err.Error(), "UID") || len(versions) != 1 {
					t.Fatalf("recreated resource: versions=%v error=%v", versions, err)
				}
			} else if err != nil || !slices.Equal(versions, []string{"17", "18"}) {
				t.Fatalf("status conflict: versions=%v error=%v", versions, err)
			}
		})
	}
}

func TestApplyWaitsForCRDEstablishedBeforeReturning(t *testing.T) {
	dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{{Group: "apiextensions.k8s.io", Version: "v1"}})
	mapper.Add(customResourceDefinitionGVK, meta.RESTScopeRoot)
	client := NewClient("run-1", &cluster.Cluster{Dynamic: dynamicClient, Mapper: mapper}, NewLedger())
	watchStarted := make(chan struct{})
	dynamicClient.PrependWatchReactor(
		"customresourcedefinitions",
		func(ktesting.Action) (bool, watch.Interface, error) {
			close(watchStarted)
			return false, nil, nil
		},
	)
	dynamicClient.PrependReactor(
		"create",
		"customresourcedefinitions",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			object := action.(ktesting.CreateAction).GetObject().(*unstructured.Unstructured).DeepCopy()
			object.SetUID("uid-crd")
			object.Object["status"] = map[string]any{"conditions": nil}
			if err := dynamicClient.Tracker().Create(customResourceDefinitionGVR, object, ""); err != nil {
				return true, nil, err
			}
			return true, object, nil
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := client.Apply(ctx, trafficPolicyCRD(), CreateOnly)
		result <- err
	}()

	select {
	case err := <-result:
		t.Fatalf("Apply() returned before the CRD was established: %v", err)
	case <-watchStarted:
	case <-ctx.Done():
		t.Fatalf("Apply() did not start waiting for the CRD: %v", ctx.Err())
	}
	live, err := dynamicClient.Resource(customResourceDefinitionGVR).
		Get(ctx, "trafficpolicies.agents.kruise.io", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := unstructured.SetNestedSlice(live.Object, []any{
		map[string]any{"type": "Established", "status": "True"},
	}, "status", "conditions"); err != nil {
		t.Fatal(err)
	}
	if _, err := dynamicClient.Resource(customResourceDefinitionGVR).
		Update(ctx, live, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatalf("Apply() did not observe the established CRD: %v", ctx.Err())
	}
}

func newFakeClient(t *testing.T, objects ...runtime.Object) (*Client, *Ledger) {
	t.Helper()
	dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), objects...)
	mapper := newTestMapper()
	ledger := NewLedger()
	return NewClient("run-1", &cluster.Cluster{Dynamic: dynamicClient, Mapper: mapper}, ledger), ledger
}

func installApplyReactor(t *testing.T, client *Client, uid types.UID) {
	t.Helper()
	installResourceApplyReactor(t, client, "configmaps", configMapGVR, uid)
}

func installResourceApplyReactor(
	t *testing.T,
	client *Client,
	resource string,
	gvr schema.GroupVersionResource,
	uid types.UID,
) {
	t.Helper()
	fakeClient := client.dynamic.(*dynamicfake.FakeDynamicClient)
	fakeClient.PrependReactor("create", resource, func(action ktesting.Action) (bool, runtime.Object, error) {
		object := action.(ktesting.CreateAction).GetObject().(*unstructured.Unstructured).DeepCopy()
		object.SetUID(uid)
		if err := fakeClient.Tracker().Create(gvr, object, object.GetNamespace()); err != nil {
			t.Fatal(err)
		}
		return true, object, nil
	})
}

var (
	configMapGVK                = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"}
	configMapGVR                = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}
	namespaceGVK                = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}
	namespaceGVR                = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	customResourceDefinitionGVK = schema.GroupVersionKind{
		Group:   "apiextensions.k8s.io",
		Version: "v1",
		Kind:    "CustomResourceDefinition",
	}
	customResourceDefinitionGVR = schema.GroupVersionResource{
		Group:    "apiextensions.k8s.io",
		Version:  "v1",
		Resource: "customresourcedefinitions",
	}
)

func configMap(namespace, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"namespace": namespace,
			"name":      name,
		},
		"data": map[string]any{"key": "value"},
	}}
}

func namespaceObject(namespace, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"namespace": namespace,
			"name":      name,
		},
	}}
}

func trafficPolicyCRD() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1",
		"kind":       "CustomResourceDefinition",
		"metadata":   map[string]any{"name": "trafficpolicies.agents.kruise.io"},
		"spec": map[string]any{
			"group": "agents.kruise.io",
			"names": map[string]any{
				"kind": "TrafficPolicy", "plural": "trafficpolicies", "singular": "trafficpolicy",
			},
			"scope": "Namespaced",
			"versions": []any{map[string]any{
				"name": "v1alpha1", "served": true, "storage": true,
				"schema": map[string]any{"openAPIV3Schema": map[string]any{"type": "object"}},
			}},
		},
	}}
}
