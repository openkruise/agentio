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
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func testResource(t *testing.T, name, value string) Resource {
	t.Helper()
	message := wrapperspb.String(value)
	encoded, err := anypb.New(message)
	if err != nil {
		t.Fatal(err)
	}
	return Resource{
		Key: ResourceKey{
			TypeURL: encoded.TypeUrl,
			Name:    name,
		},
		Value: encoded,
	}
}

func testWorkloadResource(
	t *testing.T,
	name, value, sandboxUID, nodeName string,
	serviceKeys, gatewayReferences []string,
) Resource {
	t.Helper()
	return Resource{
		Key:   ResourceKey{TypeURL: AddressType, Name: name},
		Value: &anypb.Any{TypeUrl: AddressType, Value: []byte(value)},
		Facts: ResourceFacts{Workload: &WorkloadResourceFacts{Namespace: "demo",
			WorkloadUID:       sandboxUID,
			NodeName:          nodeName,
			Principal:         testPrincipal(),
			ServiceKeys:       serviceKeys,
			GatewayReferences: gatewayReferences,
		}},
	}
}

func testPrincipal() Principal {
	return MustServiceAccountPrincipal("demo", "default")
}
