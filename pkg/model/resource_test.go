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
	"slices"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
)

func TestResourceReferencesAreImmutableAndIndexed(t *testing.T) {
	profile := ResourceKey{TypeURL: SecurityProfileType, Name: "same"}
	sni := ResourceKey{TypeURL: SniTrafficPolicyType, Name: "same"}
	tp := ResourceKey{TypeURL: TrafficPolicyType, Name: "same"}
	keys := []ResourceKey{sni, profile, tp, profile}
	raw := testWorkloadResource(t, "a", "one", "", "", nil, nil)
	raw.Facts.References = &ResourceReferences{Keys: keys}
	r, err := NewResource(raw.Key, raw.XDSName, Prebuilt(raw.Value), raw.Aliases, raw.Facts)
	if err != nil {
		t.Fatal(err)
	}
	keys[0] = ResourceKey{TypeURL: SecurityProfileType, Name: "mutated"}
	if len(r.Facts.References.Keys) != 3 || slices.Contains(r.Facts.References.Keys, keys[0]) {
		t.Fatal("reference facts were not copied and deduplicated")
	}
	before, err := NewResourceSet([]Resource{r})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []ResourceKey{profile, sni, tp} {
		if !before.HasReference(key) {
			t.Fatalf("reference not indexed: %v", key)
		}
	}
	facts := r.Facts
	facts.References = &ResourceReferences{Keys: []ResourceKey{tp, sni}}
	rebound, err := NewResource(r.Key, r.XDSName, Prebuilt(r.Value), r.Aliases, facts)
	if err != nil {
		t.Fatal(err)
	}
	if rebound.Hash == r.Hash || rebound.Facts.Equal(r.Facts) {
		t.Fatal("changed references were ignored by equality or hashing")
	}
	after, _, err := before.Apply([]ResourceChange{{Key: r.Key, New: &rebound}})
	if err != nil {
		t.Fatal(err)
	}
	if after.HasReference(profile) || !before.HasReference(profile) || !after.HasReference(sni) {
		t.Fatal("reference update corrupted the current or previous index")
	}
	permuted := facts
	permuted.References = &ResourceReferences{Keys: []ResourceKey{sni, tp, tp}}
	same, err := NewResource(r.Key, r.XDSName, Prebuilt(r.Value), r.Aliases, permuted)
	if err != nil {
		t.Fatal(err)
	}
	if same.Hash != rebound.Hash || !same.Facts.Equal(rebound.Facts) {
		t.Fatal("reference order affected resource identity")
	}
	for _, invalid := range []ResourceKey{{Name: "missing-type"}, {TypeURL: SecurityProfileType}} {
		facts.References = &ResourceReferences{Keys: []ResourceKey{invalid}}
		if _, err := NewResource(r.Key, r.XDSName, Prebuilt(r.Value), r.Aliases, facts); err == nil {
			t.Fatal("empty reference key was accepted")
		}
	}
}

func TestReferenceCountsTrackLastReferrerAcrossBatchUpdates(t *testing.T) {
	profile := ResourceKey{TypeURL: SecurityProfileType, Name: "shared"}
	makeReferrer := func(name string, references []ResourceKey) Resource {
		t.Helper()
		raw := testWorkloadResource(t, name, "value", "", "", nil, nil)
		raw.Facts.References = &ResourceReferences{Keys: references}
		resource, err := NewResource(raw.Key, raw.XDSName, Prebuilt(raw.Value), raw.Aliases, raw.Facts)
		if err != nil {
			t.Fatal(err)
		}
		return resource
	}
	a := makeReferrer("a", []ResourceKey{profile})
	b := makeReferrer("b", []ResourceKey{profile})
	before, err := NewResourceSet([]Resource{a, b})
	if err != nil {
		t.Fatal(err)
	}
	unbound := makeReferrer("a", nil)
	after, _, err := before.Apply([]ResourceChange{
		{Key: a.Key, New: &unbound},
		{Key: a.Key, New: &a},
		{Key: b.Key},
	})
	if err != nil || !after.HasReference(profile) || !before.HasReference(profile) {
		t.Fatalf("remaining or previous reference lost: %v", err)
	}
	empty, _, err := after.Apply([]ResourceChange{{Key: a.Key, New: &unbound}})
	if err != nil || empty.HasReference(profile) || !after.HasReference(profile) {
		t.Fatalf("last reference removal corrupted a snapshot: %v", err)
	}
}

func TestReferenceCountsSurviveContentUpdatesInMixedBatch(t *testing.T) {
	profile := ResourceKey{TypeURL: SecurityProfileType, Name: "shared"}
	a := testWorkloadResource(t, "a", "old", "", "", nil, nil)
	a.Facts.References = &ResourceReferences{Keys: []ResourceKey{profile}}
	b := testWorkloadResource(t, "b", "old", "", "", nil, nil)
	b.Facts.References = a.Facts.References
	updated, err := NewResource(a.Key, a.XDSName,
		Prebuilt(&anypb.Any{TypeUrl: a.Key.TypeURL, Value: []byte("new")}), a.Aliases, a.Facts)
	if err != nil {
		t.Fatal(err)
	}
	for _, contentFirst := range []bool{true, false} {
		before, err := NewResourceSet([]Resource{a, b})
		if err != nil {
			t.Fatal(err)
		}
		changes := []ResourceChange{{Key: a.Key, New: &updated}, {Key: b.Key}}
		if !contentFirst {
			slices.Reverse(changes)
		}
		after, _, err := before.Apply(changes)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := after.Get(a.Key)
		if !ok || got.Hash != updated.Hash || !after.HasReference(profile) {
			t.Fatal("content update or remaining reference lost")
		}
		empty, _, err := after.Apply([]ResourceChange{{Key: a.Key}})
		if err != nil || empty.HasReference(profile) || !after.HasReference(profile) || !before.HasReference(profile) {
			t.Fatalf("reference counts corrupted across content update and deletion: %v", err)
		}
	}
}

// Hash is computed once at construction, so a resource built by NewResource
// carries a hash that NewResourceSet accepts without re-encoding it.
func TestNewResourceHashesOnceAndMatchesSetNormalization(t *testing.T) {
	raw := testWorkloadResource(t, "a", "one", "sandbox-a", "", nil, nil)

	prehashed, err := NewResource(raw.Key, raw.XDSName, Prebuilt(raw.Value), raw.Aliases, raw.Facts)
	if err != nil {
		t.Fatal(err)
	}
	if prehashed.Hash == "" {
		t.Fatal("NewResource did not compute a hash")
	}

	// A set built from the raw resource normalizes it itself; both paths must
	// agree or a pre-hashed snapshot would get a different version.
	fromRaw, err := NewResourceSet([]Resource{raw})
	if err != nil {
		t.Fatal(err)
	}
	fromPrehashed, err := NewResourceSet([]Resource{prehashed})
	if err != nil {
		t.Fatal(err)
	}
	if fromRaw.Version() != fromPrehashed.Version() {
		t.Fatalf("version differs between normalization paths: %s != %s", fromRaw.Version(), fromPrehashed.Version())
	}

	stored, _ := fromRaw.Get(raw.Key)
	if stored.Hash != prehashed.Hash {
		t.Fatalf("hash differs between normalization paths: %s != %s", stored.Hash, prehashed.Hash)
	}
}

// Equals is what krt uses to suppress no-op events, so it must track every field
// the hash covers.
func TestResourceEqualsTracksContent(t *testing.T) {
	base := testWorkloadResource(t, "a", "one", "sandbox-a", "", nil, nil)
	same := testWorkloadResource(t, "a", "one", "sandbox-a", "", nil, nil)
	differentValue := testWorkloadResource(t, "a", "two", "sandbox-a", "", nil, nil)
	differentFacts := testWorkloadResource(t, "a", "one", "sandbox-b", "", nil, nil)

	normalize := func(r Resource) Resource {
		out, err := NewResource(r.Key, r.XDSName, Prebuilt(r.Value), r.Aliases, r.Facts)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	if !normalize(base).Equals(normalize(same)) {
		t.Fatal("identical resources are not Equal")
	}
	if normalize(base).Equals(normalize(differentValue)) {
		t.Fatal("resources with different values are Equal")
	}
	if normalize(base).Equals(normalize(differentFacts)) {
		t.Fatal("resources with different facts are Equal")
	}
}

// ResourceName must distinguish resources that share a name across types, since
// krt keys collection members by it.
func TestResourceNameSeparatesTypes(t *testing.T) {
	address := Resource{Key: ResourceKey{TypeURL: AddressType, Name: "same"}}
	workload := Resource{Key: ResourceKey{TypeURL: WorkloadType, Name: "same"}}
	if address.ResourceName() == workload.ResourceName() {
		t.Fatalf("ResourceName collides across types: %s", address.ResourceName())
	}
}

func TestNewResourceRejectsInvalidFacts(t *testing.T) {
	base := testResource(t, "one", "value")
	tests := []struct {
		name  string
		key   ResourceKey
		value *anypb.Any
		facts ResourceFacts
	}{
		{
			name:  "generic resource with Workload facts",
			key:   base.Key,
			value: base.Value,
			facts: ResourceFacts{Workload: &WorkloadResourceFacts{WorkloadUID: "sandbox-a", Principal: testPrincipal()}},
		},
		{
			name:  "Address without family",
			key:   ResourceKey{TypeURL: AddressType, Name: "uid-a"},
			value: &anypb.Any{TypeUrl: AddressType},
		},
		{
			name:  "namespace Authorization without namespace",
			key:   ResourceKey{TypeURL: WorkloadAuthorizationType, Name: "demo/policy"},
			value: &anypb.Any{TypeUrl: WorkloadAuthorizationType},
			facts: ResourceFacts{Authorization: &AuthorizationResourceFacts{Scope: AuthorizationScopeNamespace}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewResource(tc.key, "", Prebuilt(tc.value), nil, tc.facts); err == nil {
				t.Fatal("NewResource accepted invalid facts")
			}
		})
	}
}

func TestNewResourceValidatesDiscoveryPrincipalShape(t *testing.T) {
	tests := []struct {
		name      string
		principal Principal
		wantErr   bool
	}{
		{name: "absent principal"},
		{name: "invalid SPIFFE URI", principal: Principal{uri: "not-a-spiffe-uri"}, wantErr: true},
		{name: "empty path segment", principal: Principal{uri: "spiffe://cluster.local//id"}, wantErr: true},
		{name: "query in URI", principal: Principal{uri: "spiffe://cluster.local/workload/id?"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewResource(
				ResourceKey{TypeURL: AddressType, Name: "workload-a"},
				"",
				Prebuilt(&anypb.Any{TypeUrl: AddressType}),
				nil,
				ResourceFacts{Workload: &WorkloadResourceFacts{
					WorkloadUID: "sandbox-a",
					Principal:   tc.principal,
				}},
			)
			if (err != nil) != tc.wantErr {
				t.Fatalf("NewResource() error = %v, wantErr %t", err, tc.wantErr)
			}
		})
	}
}

// Production snapshots enter the set pre-hashed; that path validates without
// re-normalizing and must reject invalid facts just like NewResource.
func TestPreHashedResourceFactValidation(t *testing.T) {
	base := testResource(t, "one", "value")
	normalized, err := NewResource(base.Key, "", Prebuilt(base.Value), nil, ResourceFacts{})
	if err != nil {
		t.Fatal(err)
	}
	invalid := normalized
	invalid.Facts.Workload = &WorkloadResourceFacts{WorkloadUID: "sandbox-a", Principal: testPrincipal()}

	if _, err := NewResourceSet([]Resource{invalid}); err == nil {
		t.Fatal("NewResourceSet accepted invalid pre-hashed facts")
	}
	set, err := NewResourceSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := set.Apply([]ResourceChange{{Key: invalid.Key, New: &invalid}}); err == nil {
		t.Fatal("Apply accepted invalid pre-hashed facts")
	}
}

func TestIsWorkloadAddress(t *testing.T) {
	workload := testWorkloadResource(t, "uid-a", "value", "uid-a", "", nil, nil)
	placed := testWorkloadResource(t, "uid-b", "value", "uid-b", "node-a", nil, nil)
	service := Resource{Facts: ResourceFacts{Service: &ServiceResourceFacts{ServiceKey: "demo/svc"}}}
	if !workload.IsWorkloadAddress() || !placed.IsWorkloadAddress() {
		t.Fatal("Workload-fact resources must be workload addresses")
	}
	if service.IsWorkloadAddress() {
		t.Fatal("service variant must not be a workload address")
	}
}

func TestResourceFactsNamespaceAffectsEquality(t *testing.T) {
	a := ResourceFacts{Workload: &WorkloadResourceFacts{Namespace: "a", Principal: testPrincipal()}}
	b := ResourceFacts{Workload: &WorkloadResourceFacts{Namespace: "b", Principal: testPrincipal()}}
	if a.Equal(b) {
		t.Fatal("namespace policy scope change treated as a no-op")
	}
}
