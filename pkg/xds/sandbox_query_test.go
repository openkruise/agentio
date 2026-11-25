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

package xds

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/pkg/model"
)

func TestSandboxQueryPublishedSnapshot(t *testing.T) {
	sb := sandboxResourceWithAttester(t, "uid", "host")
	withAlias := func(r model.Resource) model.Resource {
		r, err := model.NewResource(
			r.Key,
			r.XDSName,
			testResourceContents(testResourceValue(r)),
			[]string{"ns/host"},
			r.Facts,
		)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	server := newTestServer(t, gatewayScope(), []model.Resource{withAlias(sb)}, nil)
	q := server.server.SandboxQuery(nil, nil, 10*time.Second)
	for _, name := range []string{"uid", "ns/host", "missing"} {
		r, err := q.GetSandbox(t.Context(), &sandboxv1.GetSandboxRequest{Name: name})
		if err != nil || r.GetCacheTtl().AsDuration() != 10*time.Second {
			t.Fatal(name, r, err)
		}
		if name == "missing" {
			if r.Sandbox != nil {
				t.Fatal(r)
			}
		} else if r.GetSandbox().GetUid() != "uid" || r.Sandbox.GetAttester().GetWorkloadUid() != "host" {
			t.Fatal(r)
		}
	}
	server.resources.publish(
		selectionSnapshot(t, []model.Resource{withAlias(sb), withAlias(sandboxResource(t, "other"))}),
	)
	if _, err := q.GetSandbox(t.Context(), &sandboxv1.GetSandboxRequest{Name: "ns/host"}); status.Code(
		err,
	) != codes.FailedPrecondition {
		t.Fatal(err)
	}
	server.resources.publish(selectionSnapshot(t, nil))
	r, err := q.GetSandbox(t.Context(), &sandboxv1.GetSandboxRequest{Name: "uid"})
	if err != nil || r.Sandbox != nil {
		t.Fatal(r, err)
	}
	pending := sourceReaderFunc(func(key model.ResourceKey) (model.SourceIdentity, bool) {
		return model.SourceIdentity{UID: "next"}, key.Name == "uid"
	})
	q = server.server.SandboxQuery(nil, pending, 0)
	server.resources.publish(selectionSnapshot(t, []model.Resource{withAlias(sb)}))
	if _, err := q.GetSandbox(t.Context(), &sandboxv1.GetSandboxRequest{Name: "ns/host"}); status.Code(
		err,
	) != codes.Unavailable {
		t.Fatal(err)
	}
	if _, err := q.GetSandbox(t.Context(), &sandboxv1.GetSandboxRequest{Name: "uid"}); status.Code(
		err,
	) != codes.Unavailable {
		t.Fatal(err)
	}
}

func TestSandboxQueryReadsOneKeyAfterAuthentication(t *testing.T) {
	scope := gatewayScope()
	scope.Class = model.ClientEPE
	server := newTestServer(t, scope, nil, nil).server
	node := nodeRequest(model.SandboxType).Node
	req := &sandboxv1.GetSandboxRequest{Name: "one", NodeId: node.Id, NodeMetadata: node.Metadata}
	value := &sandboxv1.Sandbox{Uid: "one"}
	calls := 0
	var sourceErr error
	lookup := func(ctx context.Context, got model.ClientScope, name string) (*sandboxv1.Sandbox, error) {
		calls++
		if got.Class != scope.Class || got.WorkloadUID != scope.WorkloadUID || name != "one" {
			t.Fatal(got, name)
		}
		return value, sourceErr
	}
	q := server.SandboxQuery(lookup, nil, 0)
	for range 2 {
		r, err := q.GetSandbox(t.Context(), req)
		if err != nil || !proto.Equal(r.GetSandbox(), value) || r.CacheTtl.AsDuration() != 0 {
			t.Fatal(r, err)
		}
	}
	sourceErr = errors.New("database connection lost")
	if _, err := q.GetSandbox(t.Context(), req); status.Code(err) != codes.Unavailable {
		t.Fatal(err)
	}
	req.Name = "*"
	if _, err := q.GetSandbox(t.Context(), req); status.Code(err) != codes.InvalidArgument {
		t.Fatal(err)
	}
	req.Name = "one"
	server.scopeFuncs = fakeResolver{scope: ztunnelScope()}.scopeFuncs()
	if _, err := q.GetSandbox(t.Context(), req); status.Code(err) != codes.PermissionDenied {
		t.Fatal(err)
	}
	server.authenticator = fakeAuthenticator{err: errors.New("expired token")}
	if _, err := q.GetSandbox(t.Context(), req); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("backend reads = %d, want 3", calls)
	}
}
