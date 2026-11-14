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
	"testing"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/types/known/anypb"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestPreparationDeadlineRetryAndBinding(t *testing.T) {
	p := newPrepareController()
	s := &prepareClient{workload: "own", sandbox: "sandbox", workloadReady: true}
	p.clients[0] = s
	now := time.Now()
	if err := p.start(prepareCommand{Name: "no-retry"}, now); err != nil {
		t.Fatal(err)
	}
	wrong, err := anypb.New(
		&sandboxv1.Sandbox{Uid: "sandbox", Attester: &sandboxv1.Sandbox_Attester{WorkloadUid: "other"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	response := &discovery.DeltaDiscoveryResponse{
		TypeUrl:   model.SandboxType,
		Resources: []*discovery.Resource{{Name: "sandbox", Resource: wrong}},
	}
	if err := p.accept(0, response); err != nil {
		t.Fatal(err)
	}
	if s.prepared {
		t.Fatal("wrong binding prepared")
	}
	p.tick(now.Add(30 * time.Second))
	if s.timeouts != 1 || s.active || s.prepared {
		t.Fatal(s)
	}
	correct, err := anypb.New(
		&sandboxv1.Sandbox{Uid: "sandbox", Attester: &sandboxv1.Sandbox_Attester{WorkloadUid: "own"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	response.Resources[0].Resource = correct
	if err := p.accept(0, response); err != nil {
		t.Fatal(err)
	}
	if s.prepared {
		t.Fatal("timed out initial RPC registered itself")
	}
	s.bound = false
	if err := p.start(prepareCommand{Name: "retry", Retry: true}, now); err != nil {
		t.Fatal(err)
	}
	p.tick(now.Add(30 * time.Second))
	if err := p.accept(0, response); err != nil {
		t.Fatal(err)
	}
	if s.prepared {
		t.Fatal("retry sleep skipped")
	}
	p.tick(now.Add(35 * time.Second))
	if !s.prepared || s.attempts != 2 || s.timeouts != 1 {
		t.Fatal(s)
	}
	if err := p.accept(
		0,
		&discovery.DeltaDiscoveryResponse{TypeUrl: model.SandboxType, RemovedResources: []string{"sandbox"}},
	); err != nil {
		t.Fatal(err)
	}
	if s.bound {
		t.Fatal("deleted binding retained")
	}
}
