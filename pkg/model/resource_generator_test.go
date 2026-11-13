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
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
)

func TestResourceGeneratePrebuilt(t *testing.T) {
	resource, err := NewResource(
		ResourceKey{TypeURL: ClusterType, Name: "cluster"},
		"",
		Prebuilt(&anypb.Any{TypeUrl: ClusterType}),
		nil,
		ResourceFacts{},
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := resource.Encode(ClientScope{}, ClusterType)
	if err != nil || got.Value != resource.Value || got.Hash != resource.Hash {
		t.Fatal("prebuilt contents changed", err)
	}
	encoded, err := json.Marshal(resource)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if _, found := fields["ResourceGenerator"]; found {
		t.Fatal("debug JSON exposes generator")
	}
	if _, err := resource.Generate(ClientScope{}, WorkloadType); err == nil {
		t.Fatal("accepted unsupported output")
	}
}

func TestNewResourceStructuredService(t *testing.T) {
	address := &workloadv1.Address{Type: &workloadv1.Address_Service{Service: &workloadv1.Service{Name: "service"}}}
	encoded := new(anypb.Any)
	if err := anypb.MarshalFrom(encoded, address, proto.MarshalOptions{Deterministic: true}); err != nil {
		t.Fatal(err)
	}
	key := ResourceKey{TypeURL: AddressType, Name: "demo/service"}
	facts := ResourceFacts{Service: &ServiceResourceFacts{ServiceKey: key.Name}}
	resource, err := NewResource(key, "", Prebuilt(address), nil, facts)
	if err != nil {
		t.Fatal(err)
	}
	prebuilt, err := NewResource(key, "", Prebuilt(encoded), nil, facts)
	if err != nil || resource.Hash != prebuilt.Hash || !proto.Equal(resource.Value, encoded) {
		t.Fatal("structured Service changed canonical contents or hash", err)
	}
	address.GetService().Name = "changed"
	generated, err := resource.Encode(ClientScope{}, AddressType)
	if err != nil || !proto.Equal(generated.Value, encoded) {
		t.Fatal("Service generator retained mutable input", err)
	}
	if _, err := resource.Generate(ClientScope{}, WorkloadType); err == nil {
		t.Fatal("Service Address received a Workload generator")
	}
}

func TestNewResourceRejectsInvalidMessages(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value proto.Message
	}{
		{name: "nil"},
		{name: "nil Any", value: (*anypb.Any)(nil)},
		{name: "nil Address", value: (*workloadv1.Address)(nil)},
		{name: "wrong type", value: &workloadv1.Workload{Uid: "uid"}},
		{name: "invalid UTF-8",
			value: &workloadv1.Address{Type: &workloadv1.Address_Workload{
				Workload: &workloadv1.Workload{Uid: string([]byte{0xff})},
			}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewResource(ResourceKey{TypeURL: AddressType, Name: "uid"}, "", Prebuilt(tc.value), nil,
				ResourceFacts{Workload: &WorkloadResourceFacts{WorkloadUID: "uid"}})
			if err == nil {
				t.Fatal("invalid message accepted")
			}
		})
	}
}

func TestWorkloadResourceGenerate(t *testing.T) {
	workload := &workloadv1.Workload{Uid: "uid",
		Node: "node-a",
		Services: map[string]*workloadv1.PortList{
			"demo/b": {Ports: []*workloadv1.Port{{ServicePort: 443, TargetPort: 8443}}},
			"demo/a": {Ports: []*workloadv1.Port{{ServicePort: 80, TargetPort: 8080}}},
		}}
	workload.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 0x01})
	extensions := []*workloadv1.Extension{
		{Name: "other", Config: &anypb.Any{TypeUrl: "test/Other", Value: []byte("keep")}},
		{Name: "security-profile-reference", Config: &anypb.Any{TypeUrl: "test/Reference", Value: []byte("profile")}},
		{Name: "sni-traffic-policy", Config: &anypb.Any{TypeUrl: SniTrafficPolicyType, Value: []byte("policy")}},
	}
	original := proto.Clone(workload)
	resource, err := NewResource(
		ResourceKey{TypeURL: AddressType, Name: "uid"},
		"",
		WorkloadContents(workload, extensions),
		[]string{"/10.0.0.1"},
		ResourceFacts{Workload: &WorkloadResourceFacts{WorkloadUID: "uid"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if resource.Value != nil || !proto.Equal(workload, original) {
		t.Fatal("construction materialized or modified Workload")
	}
	classes := []ClientClass{
		ClientAgentioEgress,
		ClientEgressGateway,
		ClientEPE,
		ClientSharedZTunnel,
		ClientDedicatedZTunnel,
	}
	types := []string{AddressType, WorkloadType}
	const clients = 30
	var wg sync.WaitGroup
	got := make([]Resource, clients)
	errs := make([]error, clients)
	for client := range clients {
		wg.Go(func() {
			got[client], errs[client] = resource.Encode(
				ClientScope{Class: classes[client%5], WorkloadUID: fmt.Sprint(client)},
				types[client/5%2],
			)
		})
	}
	wg.Wait()
	for client := range clients {
		if errs[client] != nil {
			t.Fatal(errs[client])
		}
		class, typeURL := classes[client%5], types[client/5%2]
		want := proto.Clone(workload).(*workloadv1.Workload)
		for _, extension := range extensions {
			if extension.Name == "sni-traffic-policy" && class != ClientEgressGateway ||
				extension.Name == "security-profile-reference" &&
					(class == ClientSharedZTunnel || class == ClientDedicatedZTunnel) {
				continue
			}
			want.Extensions = append(want.Extensions, extension)
		}
		var message proto.Message = want
		var decoded proto.Message = new(workloadv1.Workload)
		if typeURL == AddressType {
			message = &workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: want}}
			decoded = new(workloadv1.Address)
		}
		if err := got[client].Value.UnmarshalTo(decoded); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(decoded, message) || got[client].Value != got[client%10].Value {
			t.Fatalf("client %d: wrong contents or cache", client)
		}
	}
	if got[0].Value != got[2].Value || got[3].Value != got[4].Value {
		t.Fatal("identical outputs not shared")
	}
	if !proto.Equal(workload, original) {
		t.Fatal("generation mutated base Workload")
	}
}

func TestWorkloadResourceCacheFollowsPublication(t *testing.T) {
	build := func(node string) Resource {
		workload := &workloadv1.Workload{Uid: "uid", Node: node}
		resource, err := NewResource(
			ResourceKey{TypeURL: AddressType, Name: "uid"},
			"",
			WorkloadContents(workload, nil),
			nil,
			ResourceFacts{Workload: &WorkloadResourceFacts{WorkloadUID: "uid"}},
		)
		if err != nil {
			t.Fatal(err)
		}
		return resource
	}
	original := build("node-a")
	before, err := NewResourceSet([]Resource{original})
	if err != nil {
		t.Fatal(err)
	}
	scope := ClientScope{Class: ClientAgentioEgress}
	previous, err := original.Generate(scope, WorkloadType)
	if err != nil {
		t.Fatal(err)
	}
	same := build("node-a")
	unchanged, _, err := before.Apply([]ResourceChange{{Key: same.Key, New: &same}})
	if err != nil {
		t.Fatal(err)
	}
	shared, _ := unchanged.Get(original.Key)
	current, err := shared.Generate(scope, WorkloadType)
	if err != nil || current.Value != previous.Value {
		t.Fatal("unchanged publication lost its shared cache")
	}
	replacement := build("node-b")
	after, _, err := before.Apply([]ResourceChange{{Key: replacement.Key, New: &replacement}})
	if err != nil {
		t.Fatal(err)
	}
	latest, _ := after.Get(original.Key)
	next, err := latest.Generate(scope, WorkloadType)
	if err != nil || next.Hash == previous.Hash {
		t.Fatal("updated publication reused stale contents")
	}
	old, _ := before.Get(original.Key)
	stillOld, err := old.Generate(scope, WorkloadType)
	if err != nil || stillOld.Value != previous.Value {
		t.Fatal("new publication changed previous snapshot")
	}
}

func TestWorkloadContentsRejectsInvalidBase(t *testing.T) {
	for _, base := range []*workloadv1.Workload{nil, {Uid: "uid", Extensions: []*workloadv1.Extension{{Name: "unexpected"}}}} {
		if _, err := NewResource(
			ResourceKey{TypeURL: AddressType, Name: "uid"},
			"",
			WorkloadContents(base, nil),
			nil,
			ResourceFacts{Workload: &WorkloadResourceFacts{WorkloadUID: "uid"}},
		); err == nil {
			t.Fatal("invalid base accepted")
		}
	}
}

func TestResourceSetInitializesGenerators(t *testing.T) {
	value, err := anypb.New(
		&workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: &workloadv1.Workload{Uid: "uid"}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	raw := Resource{
		Key:   ResourceKey{TypeURL: AddressType, Name: "uid"},
		Value: value,
		Facts: ResourceFacts{Workload: &WorkloadResourceFacts{WorkloadUID: "uid"}},
	}
	initial, err := NewResourceSet([]Resource{raw})
	if err != nil {
		t.Fatal(err)
	}
	raw.Aliases = []string{"/10.0.0.1"}
	updated, _, err := initial.Apply([]ResourceChange{{Key: raw.Key, New: &raw}})
	if err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []ResourceSet{initial, updated} {
		resource, _ := snapshot.Get(raw.Key)
		generated, err := resource.Encode(ClientScope{}, AddressType)
		if err != nil || generated.Hash != resource.Hash {
			t.Fatal("raw resource missing prebuilt implementation", err)
		}

	}
}

func TestEncodedVersionsIncludeMetadata(t *testing.T) {
	source := WorkloadContents(&workloadv1.Workload{Uid: "uid"}, nil)
	key := ResourceKey{TypeURL: AddressType, Name: "uid"}
	facts := ResourceFacts{Workload: &WorkloadResourceFacts{WorkloadUID: "uid"}}
	first, err := NewResource(key, "", source, []string{"old-alias"}, facts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewResource(key, "", source, []string{"new-alias"}, facts)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make([]Resource, 32)
	for index := range results {
		wg.Go(func() {
			resource := first
			if index%2 == 1 {
				resource = second
			}
			encoded, err := resource.Encode(ClientScope{Class: ClientAgentioEgress}, WorkloadType)
			if err != nil {
				t.Error(err)
				return
			}
			results[index] = encoded
		})
	}
	wg.Wait()
	if first.Hash == second.Hash || results[0].Hash == results[1].Hash {
		t.Fatal("alias change lost from version")
	}
	for index, output := range results {
		if output.Hash != results[index%2].Hash || output.Value != results[0].Value {
			t.Fatal("incorrect version or unshared payload")
		}
	}
}

func TestSelectionFactsChangeSourceButNotWireVersion(t *testing.T) {
	source := WorkloadContents(&workloadv1.Workload{Uid: "uid"}, nil)
	facts := ResourceFacts{Workload: &WorkloadResourceFacts{WorkloadUID: "uid"}}
	key := ResourceKey{TypeURL: AddressType, Name: "uid"}
	before, err := NewResource(key, "", source, nil, facts)
	if err != nil {
		t.Fatal(err)
	}
	facts.References = &ResourceReferences{Keys: []ResourceKey{{TypeURL: SecurityProfileType, Name: "profile"}}}
	after, err := NewResource(key, "", source, nil, facts)
	if err != nil {
		t.Fatal(err)
	}
	oldWire, err := before.Encode(ClientScope{Class: ClientSharedZTunnel}, AddressType)
	if err != nil {
		t.Fatal(err)
	}
	newWire, err := after.Encode(ClientScope{Class: ClientSharedZTunnel}, AddressType)
	if err != nil {
		t.Fatal(err)
	}
	if before.Hash == after.Hash || oldWire.Hash != newWire.Hash {
		t.Fatal("source and wire revisions were conflated")
	}
}
