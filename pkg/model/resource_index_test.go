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
	"fmt"
	"testing"
)

func TestResourceSetLookupIndexesRemainImmutableAcrossApply(t *testing.T) {
	raw := testWorkloadResource(t, "canonical", "old", "sandbox-a", "", nil, nil)
	oldResource, err := NewResource(
		raw.Key, "wire-old", Prebuilt(raw.Value), []string{"alias-old"}, raw.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := NewResourceSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	original, changed, err := empty.Apply([]ResourceChange{{Key: oldResource.Key, New: &oldResource}})
	if err != nil || !changed {
		t.Fatalf("Apply(add) changed=%t err=%v", changed, err)
	}
	assertLookupNames(t, empty.Lookup(oldResource.Key.TypeURL, "wire-old"))
	assertLookupNames(t, empty.ListWorkloads(oldResource.Key.TypeURL,
		WorkloadQuery{WorkloadUID: "sandbox-a"}))
	assertLookupNames(t, original.Lookup(oldResource.Key.TypeURL, "wire-old"), "wire-old")
	assertLookupNames(t, original.Lookup(oldResource.Key.TypeURL, "alias-old"), "wire-old")
	assertLookupNames(t, original.ListWorkloads(oldResource.Key.TypeURL,
		WorkloadQuery{WorkloadUID: "sandbox-a"}), "wire-old")

	updatedRaw := testWorkloadResource(t, "canonical", "new", "sandbox-b", "", nil, nil)
	newResource, err := NewResource(
		oldResource.Key, "wire-new", Prebuilt(updatedRaw.Value), []string{"alias-new"}, updatedRaw.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	updated, changed, err := original.Apply([]ResourceChange{{Key: oldResource.Key, New: &newResource}})
	if err != nil || !changed {
		t.Fatalf("Apply(update) changed=%t err=%v", changed, err)
	}

	assertLookupNames(t, original.Lookup(oldResource.Key.TypeURL, "wire-new"))
	assertLookupNames(t, original.ListWorkloads(oldResource.Key.TypeURL,
		WorkloadQuery{WorkloadUID: "sandbox-b"}))

	assertLookupNames(t, updated.Lookup(newResource.Key.TypeURL, "wire-old"))
	assertLookupNames(t, updated.Lookup(newResource.Key.TypeURL, "alias-old"))
	assertLookupNames(t, updated.ListWorkloads(newResource.Key.TypeURL,
		WorkloadQuery{WorkloadUID: "sandbox-a"}))
	assertLookupNames(t, updated.Lookup(newResource.Key.TypeURL, "wire-new"), "wire-new")
	assertLookupNames(t, updated.Lookup(newResource.Key.TypeURL, "alias-new"), "wire-new")
	assertLookupNames(t, updated.ListWorkloads(newResource.Key.TypeURL,
		WorkloadQuery{WorkloadUID: "sandbox-b"}), "wire-new")

	deleted, changed, err := updated.Apply([]ResourceChange{{Key: newResource.Key}})
	if err != nil || !changed {
		t.Fatalf("Apply(delete) changed=%t err=%v", changed, err)
	}
	assertLookupNames(t, deleted.Lookup(newResource.Key.TypeURL, "wire-new"))
	assertLookupNames(t, deleted.Lookup(newResource.Key.TypeURL, "alias-new"))
	assertLookupNames(t, deleted.ListWorkloads(newResource.Key.TypeURL,
		WorkloadQuery{WorkloadUID: "sandbox-b"}))
	assertLookupNames(t, updated.Lookup(newResource.Key.TypeURL, "alias-new"), "wire-new")
}

func TestResourceSetHasWorkloadUsesExactIntersection(t *testing.T) {
	typeURL := AddressType
	resources := []Resource{
		testWorkloadResource(t, "node-a-gateway-a", "one", "sandbox-a", "node-a", nil, []string{"gateway-a"}),
		testWorkloadResource(t, "node-a-gateway-b", "two", "sandbox-b", "node-a", nil, []string{"gateway-b"}),
		testWorkloadResource(t, "node-b-gateway-a", "three", "sandbox-c", "node-b", nil, []string{"gateway-a"}),
	}
	set, err := NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}

	if !set.HasWorkload(typeURL, WorkloadQuery{NodeName: "node-a", GatewayReference: "gateway-a"}) {
		t.Fatal("node-a/gateway-a intersection was not found")
	}
	if !set.HasWorkload(typeURL, WorkloadQuery{
		WorkloadUID:      "sandbox-a",
		NodeName:         "node-a",
		GatewayReference: "gateway-a",
	}) {
		t.Fatal("sandbox-a/node-a/gateway-a intersection was not found")
	}
	if set.HasWorkload(typeURL, WorkloadQuery{NodeName: "node-a", GatewayReference: "gateway-c"}) {
		t.Fatal("nonexistent node-a/gateway-c intersection was found")
	}
	if set.HasWorkload("unknown", WorkloadQuery{NodeName: "node-a"}) {
		t.Fatal("unknown type reported a Workload match")
	}
	if set.HasWorkload(typeURL, WorkloadQuery{}) {
		t.Fatal("empty Workload query reported a match")
	}
}

func TestResourceSetPayloadUpdateReusesUnchangedLookupMemberships(t *testing.T) {
	raw := testWorkloadResource(t, "canonical", "old", "sandbox-a", "", []string{"demo/service"}, nil)
	oldResource, err := NewResource(
		raw.Key, "wire-name", Prebuilt(raw.Value), []string{"alias"}, raw.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	original, err := NewResourceSet([]Resource{oldResource})
	if err != nil {
		t.Fatal(err)
	}
	lookupBefore := lookupNames(&original.resources[oldResource.Key.TypeURL].lookup, "alias")
	factBefore := lookupNames(&original.resources[oldResource.Key.TypeURL].facts,
		resourceFactIndexKey(resourceFactService, "demo/service"))

	newRaw := testWorkloadResource(t, "canonical", "new", "sandbox-a", "", []string{"demo/service"}, nil)
	newResource, err := NewResource(
		oldResource.Key, oldResource.XDSName, Prebuilt(newRaw.Value), oldResource.Aliases, oldResource.Facts,
	)
	if err != nil {
		t.Fatal(err)
	}
	updated, changed, err := original.Apply([]ResourceChange{{Key: newResource.Key, New: &newResource}})
	if err != nil || !changed {
		t.Fatalf("Apply(payload update) changed=%t err=%v", changed, err)
	}
	lookupAfter := lookupNames(&updated.resources[newResource.Key.TypeURL].lookup, "alias")
	factAfter := lookupNames(&updated.resources[newResource.Key.TypeURL].facts,
		resourceFactIndexKey(resourceFactService, "demo/service"))
	if len(lookupBefore) != 1 || len(lookupAfter) != 1 || &lookupBefore[0] != &lookupAfter[0] {
		t.Fatal("payload-only update copied unchanged alias membership")
	}
	if len(factBefore) != 1 || len(factAfter) != 1 || &factBefore[0] != &factAfter[0] {
		t.Fatal("payload-only update copied unchanged fact membership")
	}
}

func assertLookupNames(t *testing.T, resources []Resource, want ...string) {
	t.Helper()
	got := make([]string, 0, len(resources))
	for _, resource := range resources {
		got = append(got, resource.XDSName)
	}
	if len(got) != len(want) {
		t.Fatalf("lookup names = %v, want %v", got, want)
	}
	for index := range got {
		if got[index] != want[index] {
			t.Fatalf("lookup names = %v, want %v", got, want)
		}
	}
}

// A singleton posting is only a candidate: every remaining predicate, including
// invalid predicates after the UID, must still be checked before returning it.
func TestWorkloadQuerySingletonPreservesAllPredicates(t *testing.T) {
	raw := testWorkloadResource(
		t,
		"canonical",
		"value",
		"uid-a",
		"node-a",
		[]string{"demo/service"},
		[]string{"demo/gateway"},
	)
	raw.Facts.Workload.Source = SourceRef{Registry: "kubernetes/test", Key: "source-a"}
	raw.Facts.Workload.AuthorizationRefs = []string{"demo/policy"}
	snapshot, err := NewResourceSet([]Resource{raw})
	if err != nil {
		t.Fatal(err)
	}
	principal := testPrincipal()
	matching := WorkloadQuery{WorkloadUID: "uid-a",
		Source:                 SourceRef{Registry: "kubernetes/test", Key: "source-a"},
		NodeName:               "node-a",
		Principal:              &principal,
		Namespace:              "demo",
		ServiceKey:             "demo/service",
		GatewayReference:       "demo/gateway",
		AuthorizationReference: "demo/policy",
		AuthorizationRefsOnly:  true}
	check := func(t *testing.T, query WorkloadQuery, want bool) {
		t.Helper()
		if got := query.Matches(raw.Facts.Workload); got != want {
			t.Fatalf("Matches = %v, want %v", got, want)
		}
		if got := snapshot.HasWorkload(AddressType, query); got != want {
			t.Fatalf("HasWorkload = %v, want %v", got, want)
		}
		results := snapshot.ListWorkloads(AddressType, query)
		if (len(results) > 0) != want || (want && (len(results) != 1 || results[0].Key.Name != "canonical")) {
			t.Fatalf("ListWorkloads = %#v, want match=%v", results, want)
		}
	}
	check(t, matching, true)
	for _, field := range []string{"source", "source registry", "node", "namespace", "service", "gateway", "authorization", "principal"} {
		for _, invalid := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/invalid=%v", field, invalid), func(t *testing.T) {
				query := matching
				value := "unrelated"
				if invalid {
					value = " \t "
				}
				switch field {
				case "source":
					query.Source.Key = value
				case "source registry":
					query.Source.Registry = value
				case "node":
					query.NodeName = value
				case "namespace":
					query.Namespace = value
				case "service":
					query.ServiceKey = value
				case "gateway":
					query.GatewayReference = value
				case "authorization":
					query.AuthorizationReference = value
				case "principal":
					other, err := NewPrincipal("cluster.local", "workload/test/"+value)
					if (err != nil) != invalid {
						t.Fatalf("NewPrincipal() error = %v, invalid = %v", err, invalid)
					}
					query.Principal = &other
				}
				check(t, query, false)
			})
		}
	}
	raw.Facts.Workload.AuthorizationRefs = nil
	snapshot, err = NewResourceSet([]Resource{raw})
	if err != nil {
		t.Fatal(err)
	}
	matching.AuthorizationReference = ""
	check(t, matching, false)
	matching.AuthorizationRefsOnly = false
	check(t, matching, true)
}

func TestOpaquePrincipalNamespaceComesFromSourceMetadata(t *testing.T) {
	resource := testWorkloadResource(t, "opaque", "value", "uid", "node", nil, nil)
	resource.Facts.Workload.Principal = MustPrincipal("cluster.local", "workload/app")
	resource.Facts.Workload.Namespace = "source-namespace"
	snapshot, err := NewResourceSet([]Resource{resource})
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.HasWorkload(AddressType, WorkloadQuery{Namespace: "source-namespace"}) ||
		snapshot.HasWorkload(AddressType, WorkloadQuery{Namespace: "demo"}) {
		t.Fatal("namespace lookup depended on certificate naming")
	}
}
