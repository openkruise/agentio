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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
)

// EncodedResource is immutable client-specific content. Hash covers Value.
type EncodedResource struct {
	Value *anypb.Any
	Hash  string
}

// ResourceGenerator owns complete source contents and materializes client formats.
// NewResource calls Hash before publishing the generator to concurrent readers.
type ResourceGenerator interface {
	Hash() (string, error)
	Generate(ClientScope, string) (EncodedResource, error)
}

type prebuiltResource struct {
	input   proto.Message
	encoded EncodedResource
}

// Prebuilt adapts a protobuf or existing Any to the resource generation contract.
// NewResource copies and encodes it before publication.
func Prebuilt(value proto.Message) ResourceGenerator {
	return &prebuiltResource{input: value}
}

func (r *prebuiltResource) Hash() (string, error) {
	if r.encoded.Value != nil {
		return r.encoded.Hash, nil
	}
	if r.input == nil || !r.input.ProtoReflect().IsValid() {
		return "", fmt.Errorf("resource has no value")
	}
	value, ok := r.input.(*anypb.Any)
	if ok {
		value = proto.Clone(value).(*anypb.Any)
	} else {
		value = new(anypb.Any)
		if err := anypb.MarshalFrom(value, r.input, proto.MarshalOptions{Deterministic: true}); err != nil {
			return "", err
		}
	}
	encoded, err := encodeResource(value)
	if err != nil {
		return "", err
	}
	r.encoded = encoded
	r.input = nil
	return encoded.Hash, nil
}

func (r *prebuiltResource) Generate(_ ClientScope, typeURL string) (EncodedResource, error) {
	if r.encoded.Value.GetTypeUrl() != typeURL {
		return EncodedResource{}, fmt.Errorf("resource %s cannot generate %s", r.encoded.Value.GetTypeUrl(), typeURL)
	}
	return r.encoded, nil
}

// workloadResource owns a Workload without extensions and the complete extension list.
// Only requested wire formats are assembled and retained.
type workloadResource struct {
	workload   *workloadv1.Workload
	extensions []*workloadv1.Extension
	mu         sync.Mutex
	hash       string
	cached     [3][2]*EncodedResource
}

// WorkloadContents transfers ownership of the base Workload and extensions.
// The base must not contain extensions; callers must not mutate either input afterwards.
func WorkloadContents(workload *workloadv1.Workload, extensions []*workloadv1.Extension) ResourceGenerator {
	return &workloadResource{workload: workload, extensions: extensions}
}

func (r *workloadResource) Hash() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hash != "" {
		return r.hash, nil
	}
	if r.workload == nil {
		return "", fmt.Errorf("Workload contents have no base")
	}
	if len(r.workload.Extensions) != 0 {
		return "", fmt.Errorf("base Workload must not contain extensions")
	}
	hasher := sha256.New()
	hasher.Write([]byte("workload-contents"))
	var buffer []byte
	var length [8]byte
	// Length framing preserves field boundaries and extension order.
	for index := -1; index < len(r.extensions); index++ {
		var message proto.Message = r.workload
		if index >= 0 {
			message = r.extensions[index]
		}
		var err error
		buffer, err = proto.MarshalOptions{Deterministic: true}.MarshalAppend(buffer[:0], message)
		if err != nil {
			return "", err
		}
		binary.LittleEndian.PutUint64(length[:], uint64(len(buffer)))
		hasher.Write(length[:])
		hasher.Write(buffer)
	}
	r.hash = hex.EncodeToString(hasher.Sum(nil))
	return r.hash, nil
}

func (r *workloadResource) Generate(scope ClientScope, typeURL string) (EncodedResource, error) {
	if typeURL != AddressType && typeURL != WorkloadType {
		return EncodedResource{}, fmt.Errorf("Workload cannot generate %s", typeURL)
	}
	const (
		legacy = iota
		ztunnel
		native
	)
	format := legacy
	switch scope.Class {
	case ClientSharedZTunnel, ClientDedicatedZTunnel:
		format = ztunnel
	case ClientAgentioEgress, ClientEPE:
		format = native
	}
	output := 0
	if typeURL == WorkloadType {
		output = 1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cached := &r.cached[format][output]
	if *cached != nil {
		return **cached, nil
	}
	workload := proto.Clone(r.workload).(*workloadv1.Workload)
	for _, extension := range r.extensions {
		switch extension.GetName() {
		case "sni-traffic-policy":
			if format != legacy {
				continue
			}
		case "security-profile-reference":
			if format == ztunnel {
				continue
			}
		}
		workload.Extensions = append(workload.Extensions, extension)
	}
	var message proto.Message = workload
	if typeURL == AddressType {
		message = &workloadv1.Address{Type: &workloadv1.Address_Workload{Workload: workload}}
	}
	value := new(anypb.Any)
	if err := anypb.MarshalFrom(value, message, proto.MarshalOptions{Deterministic: true}); err != nil {
		return EncodedResource{}, err
	}
	encoded, err := encodeResource(value)
	if err != nil {
		return EncodedResource{}, err
	}
	*cached = &encoded
	return encoded, nil
}

func encodeResource(value *anypb.Any) (EncodedResource, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(value)
	if err != nil {
		return EncodedResource{}, err
	}
	sum := sha256.Sum256(encoded)
	return EncodedResource{Value: value, Hash: hex.EncodeToString(sum[:])}, nil
}
