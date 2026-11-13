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

package model

import (
	"testing"
)

func TestResourceSetVersionIgnoresInsertionOrder(t *testing.T) {
	a, err := NewResourceSet([]Resource{
		testResource(t, "b", "two"),
		testResource(t, "a", "one"),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewResourceSet([]Resource{
		testResource(t, "a", "one"),
		testResource(t, "b", "two"),
	})
	if err != nil {
		t.Fatal(err)
	}

	if a.Version() != b.Version() {
		t.Fatalf("versions differ: %s != %s", a.Version(), b.Version())
	}
}

// The set takes ownership of what it is given: a caller that keeps mutating the
// resource it passed in cannot reach inside the snapshot.
func TestResourceSetOwnsItsInput(t *testing.T) {
	resource := testWorkloadResource(t, "a", "one", "sandbox-a", "", nil, nil)
	set, err := NewResourceSet([]Resource{resource})
	if err != nil {
		t.Fatal(err)
	}
	version := set.Version()

	resource.Facts.Workload.WorkloadUID = "mutated"
	resource.Value.Value[0] ^= 0xff

	stored, found := set.Get(resource.Key)
	if !found {
		t.Fatal("resource not found")
	}
	if stored.Facts.Workload.WorkloadUID != "sandbox-a" {
		t.Fatalf("input mutation changed facts: %#v", stored.Facts)
	}
	if set.Version() != version {
		t.Fatalf("input mutation changed version: %s != %s", set.Version(), version)
	}
}

// Reads share storage with the set; do not reintroduce a per-read copy.
func TestResourceSetReadsShareStorage(t *testing.T) {
	resource := testWorkloadResource(t, "a", "one", "sandbox-a", "", nil, nil)
	set, err := NewResourceSet([]Resource{resource})
	if err != nil {
		t.Fatal(err)
	}

	first, found := set.Get(resource.Key)
	if !found {
		t.Fatal("resource not found")
	}
	second, found := set.Get(resource.Key)
	if !found {
		t.Fatal("resource not found on second read")
	}
	if first.Value != second.Value {
		t.Fatal("Get returned a copied value; reads must share the set's storage")
	}

	listed := set.List(resource.Key.TypeURL)
	if len(listed) != 1 {
		t.Fatalf("List returned %d resources, want 1", len(listed))
	}
	if listed[0].Value != first.Value {
		t.Fatal("List returned a copied value; reads must share the set's storage")
	}
}

func TestResourceSetRejectsDuplicateKeys(t *testing.T) {
	_, err := NewResourceSet([]Resource{
		testResource(t, "a", "one"),
		testResource(t, "a", "two"),
	})
	if err == nil {
		t.Fatal("duplicate resource key accepted")
	}
}

func TestResourceSetPreservesScopedWireName(t *testing.T) {
	resource := testResource(t, "gateway-a/main_internal", "value")
	resource.XDSName = "main_internal"
	set, err := NewResourceSet([]Resource{resource})
	if err != nil {
		t.Fatalf("NewResourceSet: %v", err)
	}
	got, found := set.Get(resource.Key)
	if !found {
		t.Fatal("resource not found")
	}
	if got.XDSName != "main_internal" {
		t.Fatalf("wire name = %q", got.XDSName)
	}
}

// Applying one compiled KRT event must update only that key without rebuilding
// the set from a full List. The original snapshot remains a valid immutable
// view for readers that were already serving it.
func TestResourceSetApplyChangesIncrementally(t *testing.T) {
	original, err := NewResourceSet([]Resource{
		testResource(t, "a", "one"),
		testResource(t, "b", "two"),
	})
	if err != nil {
		t.Fatal(err)
	}
	beforeB, _ := original.Get(ResourceKey{TypeURL: "type.googleapis.com/google.protobuf.StringValue", Name: "b"})
	updatedB := testResource(t, "b", "updated")
	addedC := testResource(t, "c", "three")

	next, changed, err := original.Apply([]ResourceChange{
		{Key: updatedB.Key, New: &updatedB},
		{Key: addedC.Key, New: &addedC},
		{Key: ResourceKey{TypeURL: updatedB.Key.TypeURL, Name: "a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("incremental update reported no change")
	}
	if next.Len() != 2 {
		t.Fatalf("next length = %d, want 2", next.Len())
	}
	if _, found := next.Get(ResourceKey{TypeURL: updatedB.Key.TypeURL, Name: "a"}); found {
		t.Fatal("deleted resource a is still present")
	}
	afterB, found := next.Get(updatedB.Key)
	if !found || afterB.Hash == beforeB.Hash {
		t.Fatal("resource b was not updated")
	}
	if _, found := next.Get(addedC.Key); !found {
		t.Fatal("resource c was not added")
	}
	if original.Len() != 2 {
		t.Fatalf("applying changes mutated the original snapshot: len=%d", original.Len())
	}
}

func TestResourceSetApplyIgnoresNoOpChanges(t *testing.T) {
	resource, err := NewResource(
		testResource(t, "a", "one").Key,
		"",
		Prebuilt(testResource(t, "a", "one").Value),
		nil,
		ResourceFacts{},
	)
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewResourceSet([]Resource{resource})
	if err != nil {
		t.Fatal(err)
	}

	next, changed, err := set.Apply([]ResourceChange{{Key: resource.Key, New: &resource}})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("identical resource was treated as changed")
	}
	if next.Version() != set.Version() {
		t.Fatalf("no-op changed version: %s != %s", next.Version(), set.Version())
	}
}

func TestResourceSetApplyCanReplaceLastResourceOfType(t *testing.T) {
	oldResource := testResource(t, "old", "one")
	newResource := testResource(t, "new", "two")
	set, err := NewResourceSet([]Resource{oldResource})
	if err != nil {
		t.Fatal(err)
	}

	next, changed, err := set.Apply([]ResourceChange{
		{Key: oldResource.Key},
		{Key: newResource.Key, New: &newResource},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed || next.Len() != 1 {
		t.Fatalf("replacement result changed=%t len=%d", changed, next.Len())
	}
	if _, found := next.Get(newResource.Key); !found {
		t.Fatal("replacement resource is missing")
	}
}
