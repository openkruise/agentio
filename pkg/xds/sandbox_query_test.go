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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
)

type sandboxLookupFunc func(context.Context, model.ClientScope, string) (*sandboxv1.Sandbox, string, error)

func (f sandboxLookupFunc) LookupSandbox(ctx context.Context, scope model.ClientScope, name string) (*sandboxv1.Sandbox, string, error) {
	return f(ctx, scope, name)
}

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
		} else if r.GetSandbox().GetUid() != "uid" || r.Sandbox.GetAttester().GetWorkloadUid() != "host" || r.GetVersion() != "" {
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
	lookup := func(ctx context.Context, got model.ClientScope, name string) (*sandboxv1.Sandbox, string, error) {
		calls++
		if got.Class != scope.Class || got.WorkloadUID != scope.WorkloadUID || name != "one" {
			t.Fatal(got, name)
		}
		return value, "source-v1", sourceErr
	}
	q := server.SandboxQuery(sandboxLookupFunc(lookup), nil, 0)
	for range 2 {
		r, err := q.GetSandbox(t.Context(), req)
		if err != nil || !proto.Equal(r.GetSandbox(), value) || r.GetVersion() != "source-v1" || r.CacheTtl.AsDuration() != 0 {
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

func TestSandboxQueryPublishedSourceVersion(t *testing.T) {
	base := sandboxResourceWithAttester(t, "uid", "host")
	facts := base.Facts
	facts.SourceIdentity = model.SourceIdentity{UID: "source-uid"}
	resource, err := model.NewResource(base.Key, base.XDSName, testResourceContents(testResourceValue(base)), nil, facts)
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServer(t, gatewayScope(), []model.Resource{resource}, nil)
	source := sourceReaderFunc(func(key model.ResourceKey) (model.SourceIdentity, bool) {
		return model.SourceIdentity{UID: "source-uid"}, key == resource.Key
	})
	q := server.server.SandboxQuery(nil, source, 0)
	r, err := q.GetSandbox(t.Context(), &sandboxv1.GetSandboxRequest{Name: "uid"})
	if err != nil || r.GetSandbox().GetUid() != "uid" || r.GetVersion() != "source-uid" {
		t.Fatal(r, err)
	}
	// Without a source reader the published payload carries no known version.
	q = server.server.SandboxQuery(nil, nil, 0)
	r, err = q.GetSandbox(t.Context(), &sandboxv1.GetSandboxRequest{Name: "uid"})
	if err != nil || r.GetSandbox().GetUid() != "uid" || r.GetVersion() != "" {
		t.Fatal(r, err)
	}
}

func TestSandboxQueryUnaryAdmission(t *testing.T) {
	previousMetrics := metrics.Default
	registry := metrics.NewRegistry()
	metrics.Default = registry
	t.Cleanup(func() { metrics.Default = previousMetrics })

	server := newTestServer(t, gatewayScope(), nil, nil)
	config := defaultFlowControlConfig(1, 0)
	config.unaryConcurrency = 1
	config.admissionWait = 10 * time.Millisecond
	server.server.flow = newFlowController(config)
	authenticator := &countingAuthenticator{caller: model.PeerIdentity{AttestedBy: model.AttestationKubernetes}}
	server.server.authenticator = authenticator
	q := server.server.SandboxQuery(sandboxLookupFunc(
		func(context.Context, model.ClientScope, string) (*sandboxv1.Sandbox, string, error) {
			return &sandboxv1.Sandbox{Uid: "one"}, "v1", nil
		}), nil, 0)
	req := &sandboxv1.GetSandboxRequest{Name: "one"}

	server.server.flow.unarySlots <- struct{}{}
	_, err := q.GetSandbox(t.Context(), req)
	if status.Code(err) != codes.ResourceExhausted || !strings.Contains(err.Error(), "unary admission") {
		t.Fatalf("saturated unary admission = %v, want ResourceExhausted", err)
	}
	if authenticator.calls != 0 {
		t.Fatal("unary overload reached authentication")
	}
	requireSandboxCounter(t, registry, "agentio_xds_request_rejections_total", 1)
	requireSandboxCounter(t, registry, "agentio_sandbox_queries_total", 1)

	// A canceled caller surfaces its own context error, not the pool limit.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := q.GetSandbox(ctx, req); status.Code(err) != codes.Canceled {
		t.Fatalf("canceled unary admission = %v, want Canceled", err)
	}

	<-server.server.flow.unarySlots
	r, err := q.GetSandbox(t.Context(), req)
	if err != nil || r.GetSandbox().GetUid() != "one" || r.GetVersion() != "v1" {
		t.Fatal(r, err)
	}
	if len(server.server.flow.unarySlots) != 0 {
		t.Fatal("unary admission leaked its slot")
	}
	requireSandboxCounter(t, registry, "agentio_xds_request_rejections_total", 2)
	requireSandboxCounter(t, registry, "agentio_sandbox_queries_total", 3)
}

func requireSandboxCounter(t *testing.T, registry *metrics.Registry, name string, want uint64) {
	t.Helper()
	recorder := httptest.NewRecorder()
	registry.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	line := fmt.Sprintf("%s %d", name, want)
	for candidate := range strings.SplitSeq(recorder.Body.String(), "\n") {
		if strings.TrimSpace(candidate) == line {
			return
		}
	}
	t.Fatalf("missing metric line %q", line)
}
