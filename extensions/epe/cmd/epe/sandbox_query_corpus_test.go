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

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	securityv1 "github.com/openkruise/agentio/api/security/v1"
)

const corpusProfileType = "type.googleapis.com/agentio.security.SecurityProfile"

type corpusClient struct{ response *sandboxv1.GetSandboxResponse }

func (c corpusClient) GetSandbox(
	context.Context,
	*sandboxv1.GetSandboxRequest,
	...grpc.CallOption,
) (*sandboxv1.GetSandboxResponse, error) {
	return c.response, nil
}

type corpusExpect struct {
	Outcome  string `json:"outcome"`
	UID      string `json:"uid"`
	Version  string `json:"version"`
	Profile  bool   `json:"profile"`
	Deferred bool   `json:"deferred"`
}

type corpusCase struct {
	Name     string       `json:"name"`
	Response string       `json:"response"`
	Expect   corpusExpect `json:"expect"`
}

// The same corpus Rust consumes in src/discovery/query_corpus.rs. The adapter
// validates transport semantics; profile decode failures surface downstream,
// so deferred cases assert the body is delivered and the profile wire fails.
func TestSandboxQueryWireCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../../../extensions/porter/tests/query_fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []corpusCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("empty corpus")
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			body, err := base64.StdEncoding.DecodeString(c.Response)
			if err != nil {
				t.Fatal(err)
			}
			response := &sandboxv1.GetSandboxResponse{}
			if err := proto.Unmarshal(body, response); err != nil {
				t.Fatal(err)
			}
			if response.Version != c.Expect.Version {
				t.Fatalf("version = %q, want %q", response.Version, c.Expect.Version)
			}
			query := sandboxQuery(corpusClient{response}, &core.Node{Id: "epe-corpus"})
			uid, payload, _, err := query(t.Context(), "ignored")
			switch c.Expect.Outcome {
			case "value":
				if err != nil || payload == nil {
					t.Fatalf("value case: %v %v", payload, err)
				}
				sandbox := &sandboxv1.Sandbox{}
				if err := payload.UnmarshalTo(sandbox); err != nil {
					t.Fatal(err)
				}
				if sandbox.Uid != c.Expect.UID || uid != c.Expect.UID {
					t.Fatalf("uid = %q/%q, want %q", sandbox.Uid, uid, c.Expect.UID)
				}
				profiles := 0
				for _, extension := range sandbox.Extensions {
					if extension.TypeUrl != corpusProfileType {
						continue
					}
					profiles++
					if err := proto.Unmarshal(extension.Value, &securityv1.SecurityProfile{}); err != nil {
						t.Fatalf("profile decode: %v", err)
					}
				}
				if (profiles > 0) != c.Expect.Profile {
					t.Fatalf("profile presence = %v, want %v", profiles > 0, c.Expect.Profile)
				}
			case "not_found":
				if err != nil || payload != nil {
					t.Fatalf("absent case: %v %v", payload, err)
				}
			case "error":
				if !c.Expect.Deferred {
					if err == nil {
						t.Fatal("expected transport rejection")
					}
					return
				}
				if err != nil || payload == nil {
					t.Fatalf("deferred case must deliver body: %v", err)
				}
				sandbox := &sandboxv1.Sandbox{}
				if err := payload.UnmarshalTo(sandbox); err != nil {
					t.Fatal(err)
				}
				for _, extension := range sandbox.Extensions {
					if extension.TypeUrl == corpusProfileType {
						if err := proto.Unmarshal(extension.Value, &securityv1.SecurityProfile{}); err == nil {
							t.Fatal("corrupt profile decoded successfully")
						}
						return
					}
				}
				t.Fatal("corrupt case missing profile extension")
			default:
				t.Fatalf("unknown outcome %q", c.Expect.Outcome)
			}
		})
	}
}