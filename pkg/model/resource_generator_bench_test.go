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

	"google.golang.org/protobuf/types/known/anypb"
)

func BenchmarkPrebuiltResource(b *testing.B) {
	key := ResourceKey{TypeURL: ClusterType, Name: "cluster"}
	value := &anypb.Any{TypeUrl: ClusterType, Value: []byte("payload")}
	b.Run("construct", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := NewResource(key, "", Prebuilt(value), nil, ResourceFacts{}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("generate", func(b *testing.B) {
		resource, err := NewResource(key, "", Prebuilt(value), nil, ResourceFacts{})
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			got, err := resource.Encode(ClientScope{}, ClusterType)
			if err != nil || got.Hash != resource.Hash {
				b.Fatal("incorrect prebuilt generation", err)
			}
		}
	})
}
