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
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	sandboxv1 "github.com/openkruise/agentio/api/sandbox/v1"
	"github.com/openkruise/agentio/pkg/model"
)

// SandboxLookup reads one UID or workload alias in the authenticated scope.
// A nil Sandbox and nil error means authoritative absence.
type SandboxLookup func(context.Context, model.ClientScope, string) (*sandboxv1.Sandbox, error)

type sandboxQuery struct {
	sandboxv1.UnimplementedSandboxQueryServiceServer
	server *Server
	lookup SandboxLookup
	ttl    time.Duration
}

// SandboxQuery shares ADS authentication and scope resolution, without opening a subscription.
func (s *Server) SandboxQuery(
	lookup SandboxLookup,
	source model.SourceReader,
	ttl time.Duration,
) sandboxv1.SandboxQueryServiceServer {
	if lookup == nil {
		lookup = func(_ context.Context, scope model.ClientScope, name string) (*sandboxv1.Sandbox, error) {
			var found *sandboxv1.Sandbox
			pending := false
			for _, resource := range s.resources.Snapshot().Lookup(model.SandboxType, name) {
				if !matchesSource(resource, source) {
					// The alias may still point at a previous incarnation of a live source.
					_, live := source.Lookup(resource.Key)
					pending = pending || live
					continue
				}
				if found != nil {
					return nil, status.Error(codes.FailedPrecondition, "ambiguous Sandbox name")
				}
				encoded, err := resource.Encode(scope, model.SandboxType)
				if err != nil {
					return nil, status.Error(codes.Internal, err.Error())
				}
				found = new(sandboxv1.Sandbox)
				if err := encoded.Value.UnmarshalTo(found); err != nil {
					return nil, status.Error(codes.Internal, err.Error())
				}
			}
			if found == nil && source != nil {
				if _, live := source.Lookup(model.ResourceKey{TypeURL: model.SandboxType, Name: name}); live ||
					pending {
					return nil, status.Error(codes.Unavailable, "Sandbox is awaiting publication")
				}
			}
			return found, nil
		}
	}
	return &sandboxQuery{server: s, lookup: lookup, ttl: ttl}
}

func (q *sandboxQuery) GetSandbox(
	ctx context.Context,
	req *sandboxv1.GetSandboxRequest,
) (*sandboxv1.GetSandboxResponse, error) {
	if !q.server.ready() {
		return nil, status.Error(codes.Unavailable, "server is not ready")
	}
	peer, err := q.server.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetName() == "" || req.GetName() == "*" {
		return nil, status.Error(codes.InvalidArgument, "an exact Sandbox name is required")
	}
	scope, err := q.server.resolveScope(ctx, &core.Node{Id: req.NodeId, Metadata: req.NodeMetadata}, peer)
	if err != nil {
		return nil, err
	}
	switch scope.Class {
	case model.ClientEgressGateway, model.ClientAgentioEgress, model.ClientEPE:
	default:
		return nil, status.Error(codes.PermissionDenied, "Sandbox queries require a gateway or EPE identity")
	}
	value, err := q.lookup(ctx, scope, req.Name)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, status.FromContextError(err).Err()
		}
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		return nil, status.Errorf(codes.Unavailable, "read Sandbox: %v", err)
	}
	return &sandboxv1.GetSandboxResponse{Sandbox: value, CacheTtl: durationpb.New(q.ttl)}, nil
}
