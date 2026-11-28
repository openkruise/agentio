//go:build ignore

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

// Generate the cross-language GetSandboxResponse wire corpus using the real Go
// compiler. Rust (src/discovery/query_corpus.rs) and Go (EPE adapter tests)
// consume the same file and must reach identical outcomes.
//
// Regenerate: go run ./extensions/porter/tests/query_fixtures.go extensions/porter/tests/query_fixtures.json
package main

import (
	"encoding/json"
	"os"
	"time"

	agents "github.com/openkruise/agents-api/agents/v1alpha1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/pkg/compiler"
	"github.com/openkruise/agentio/pkg/model"
)

type expect struct {
	Outcome string `json:"outcome"`
	Code    string `json:"code,omitempty"`
	UID     string `json:"uid,omitempty"`
	Version string `json:"version,omitempty"`
	Profile bool   `json:"profile"`
	// Deferred marks rejections that happen after transport validation: the Go
	// adapter delivers the body and the profile decode fails downstream, while
	// Rust compiles the view inside the query path and rejects immediately.
	Deferred bool `json:"deferred,omitempty"`
}

type fixture struct {
	Name     string `json:"name"`
	Response []byte `json:"response"`
	Expect   expect `json:"expect"`
}

func mustMarshal(response *sandboxv1.GetSandboxResponse) []byte {
	body, err := proto.Marshal(response)
	if err != nil {
		panic(err)
	}
	return body
}

func compiled(uid string) *sandboxv1.Sandbox {
	spec := agents.SecurityProfileSpec{
		Rules: []agents.SecurityRule{{
			Name: "http-0",
			Match: []agents.RuleMatch{{
				Domains: []string{"api.example.com"},
				Ports:   []int32{443},
				Schemes: []string{"https"},
			}},
			Actions: agents.SecurityRuleActions{
				HeaderManipulation: &agents.HeaderManipulationAction{
					Set: []agents.HeaderValue{{Name: "x-bench", Value: "1"}},
				},
			},
		}},
	}
	payload, err := compiler.CompileSandboxPayload(model.Sandbox{
		UID:            uid,
		Name:           uid,
		Namespace:      "bench",
		SourceIdentity: model.SourceIdentity{UID: "src-" + uid},
		Attester:       &model.Attester{WorkloadUID: "host-uid"},
		Policies:       &model.SandboxPolicies{SecurityProfile: &spec},
	})
	if err != nil {
		panic(err)
	}
	return payload
}

func main() {
	present := &sandboxv1.Sandbox{
		Uid:      "kruise:bench-1",
		Attester: &sandboxv1.Sandbox_Attester{WorkloadUid: "host-uid"},
	}
	withProfile := compiled("kruise:bench-2")
	corrupt := compiled("kruise:bench-3")
	for _, extension := range corrupt.Extensions {
		if extension.TypeUrl == "type.googleapis.com/agentio.security.SecurityProfile" {
			extension.Value = []byte{0xff, 0xff, 0xff, 0xff}
		}
	}

	fixtures := []fixture{
		{"present", mustMarshal(&sandboxv1.GetSandboxResponse{
			Sandbox: present, CacheTtl: durationpb.New(10 * time.Second), Version: "src-uid-1",
		}), expect{Outcome: "value", UID: "kruise:bench-1", Version: "src-uid-1"}},
		{"present-with-profile", mustMarshal(&sandboxv1.GetSandboxResponse{
			Sandbox: withProfile, CacheTtl: durationpb.New(10 * time.Second), Version: "src-kruise:bench-2",
		}), expect{Outcome: "value", UID: "kruise:bench-2", Version: "src-kruise:bench-2", Profile: true}},
		{"absent", mustMarshal(&sandboxv1.GetSandboxResponse{
			CacheTtl: durationpb.New(5 * time.Second),
		}), expect{Outcome: "not_found"}},
		{"zero-ttl", mustMarshal(&sandboxv1.GetSandboxResponse{
			Sandbox: present, CacheTtl: durationpb.New(0),
		}), expect{Outcome: "value", UID: "kruise:bench-1"}},
		{"negative-ttl", mustMarshal(&sandboxv1.GetSandboxResponse{
			Sandbox: present, CacheTtl: durationpb.New(-time.Second),
		}), expect{Outcome: "error", Code: "DataLoss"}},
		{"overflow-ttl", mustMarshal(&sandboxv1.GetSandboxResponse{
			Sandbox: present, CacheTtl: &durationpb.Duration{Seconds: 315_576_000_001},
		}), expect{Outcome: "error", Code: "DataLoss"}},
		{"empty-uid", mustMarshal(&sandboxv1.GetSandboxResponse{
			Sandbox: &sandboxv1.Sandbox{}, CacheTtl: durationpb.New(10 * time.Second),
		}), expect{Outcome: "error", Code: "DataLoss"}},
		{"corrupt-profile", mustMarshal(&sandboxv1.GetSandboxResponse{
			Sandbox: corrupt, CacheTtl: durationpb.New(10 * time.Second),
		}), expect{Outcome: "error", Code: "DataLoss", Deferred: true}},
	}
	output, err := json.Marshal(fixtures)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[1], output, 0644); err != nil {
		panic(err)
	}
}