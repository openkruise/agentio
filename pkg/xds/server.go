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
	"io"
	"strings"
	"sync/atomic"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/attestation"
	"github.com/openkruise/agentio/pkg/util/nilutil"
	xdsstore "github.com/openkruise/agentio/pkg/xds/store"
)

// DeltaStream is the protocol surface needed by the local Delta ADS loop.
type DeltaStream interface {
	Context() context.Context
	Recv() (*discoveryv3.DeltaDiscoveryRequest, error)
	Send(*discoveryv3.DeltaDiscoveryResponse) error
}

// ResourceStore supplies immutable xDS snapshots and context-bound subscriptions.
type ResourceStore interface {
	Snapshot() model.ResourceSet
	Subscribe(context.Context, model.ClientScope) xdsstore.Subscription
}

type Server struct {
	discoveryv3.UnimplementedAggregatedDiscoveryServiceServer
	authenticator attestation.Authenticator
	scopeFuncs    ScopeFuncs
	resources     ResourceStore
	ready         func() bool
	queueSize     int
	generators    map[string]ResourceGenerator
	defaultGen    ResourceGenerator
	nonce         atomic.Uint64
	connections   atomic.Uint64
	pushScheduler *PushScheduler
	pushesDone    chan struct{}
	flow          *flowController
}

type streamRequest struct {
	request *discoveryv3.DeltaDiscoveryRequest
	err     error
}

var clientClasses = [...]model.ClientClass{
	model.ClientSharedZTunnel,
	model.ClientDedicatedZTunnel,
	model.ClientEgressGateway,
	model.ClientAgentioEgress,
}

// NewServer builds the Delta ADS server. Admission and the independent push and
// request-response concurrency limits are shared by its streams and fixed at construction.
func NewServer(
	authenticator attestation.Authenticator,
	scopeFuncs ScopeFuncs,
	resources ResourceStore,
	ready func() bool,
	queueSize int,
	generators map[string]ResourceGenerator,
	pushConcurrency int,
	requestRateLimit float64,
) (*Server, error) {
	if authenticator == nil || scopeFuncs == nil || nilutil.IsNilInterface(resources) || ready == nil {
		return nil, fmt.Errorf("authenticator, scope functions, resource source, and readiness callback are required")
	}
	if queueSize <= 0 {
		return nil, fmt.Errorf("client queue size must be positive")
	}
	if pushConcurrency <= 0 {
		return nil, fmt.Errorf("push concurrency must be positive")
	}
	if invalidRequestRateLimit(requestRateLimit) {
		return nil, fmt.Errorf("request rate limit must be finite and non-negative")
	}
	return newServerWithScheduler(
		authenticator,
		scopeFuncs,
		resources,
		ready,
		queueSize,
		generators,
		NewPushScheduler(pushConcurrency),
		defaultFlowControlConfig(pushConcurrency, requestRateLimit),
	)
}

func newServerWithScheduler(
	authenticator attestation.Authenticator,
	scopeFuncs ScopeFuncs,
	resources ResourceStore,
	ready func() bool,
	queueSize int,
	generators map[string]ResourceGenerator,
	pushScheduler *PushScheduler,
	flowConfig flowControlConfig,
) (*Server, error) {
	if authenticator == nil || scopeFuncs == nil || nilutil.IsNilInterface(resources) || ready == nil ||
		pushScheduler == nil {
		return nil, fmt.Errorf(
			"authenticator, scope functions, resource source, readiness callback, and push scheduler are required",
		)
	}
	if queueSize <= 0 {
		return nil, fmt.Errorf("client queue size must be positive")
	}
	if invalidRequestRateLimit(flowConfig.requestRateLimit) {
		return nil, fmt.Errorf("request rate limit must be finite and non-negative")
	}
	ownedGenerators := make(map[string]ResourceGenerator, len(generators))
	for typeURL, generator := range generators {
		if typeURL == "" || nilutil.IsNilInterface(generator) {
			return nil, fmt.Errorf("generator type URL and implementation are required")
		}
		ownedGenerators[typeURL] = generator
	}
	for _, class := range clientClasses {
		metrics.Default.EnsureXDSConnectionClass(string(class))
	}
	server := &Server{
		authenticator: authenticator,
		scopeFuncs:    scopeFuncs,
		resources:     resources,
		ready:         ready,
		queueSize:     queueSize,
		generators:    ownedGenerators,
		defaultGen:    SnapshotGenerator{},
		pushScheduler: pushScheduler,
		pushesDone:    make(chan struct{}),
		flow:          newFlowController(flowConfig),
	}
	go server.dispatchPushes()
	return server, nil
}

func (s *Server) generator(typeURL string) ResourceGenerator {
	if generator := s.generators[typeURL]; generator != nil {
		return generator
	}
	return s.defaultGen
}

// StreamAggregatedResources rejects state-of-the-world ADS requests.
func (s *Server) StreamAggregatedResources(
	discoveryv3.AggregatedDiscoveryService_StreamAggregatedResourcesServer,
) error {
	return status.Error(codes.Unimplemented, "state-of-the-world ADS is not supported")
}

// DeltaAggregatedResources serves a Delta ADS stream.
func (s *Server) DeltaAggregatedResources(
	stream discoveryv3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer,
) error {
	return s.serveDelta(&boundedSendStream{DeltaStream: stream, timeout: s.flow.config.sendTimeout})
}

func (s *Server) serveDelta(stream DeltaStream) (err error) {
	if !s.ready() {
		return status.Error(codes.Unavailable, "server is not ready")
	}
	if err := s.flow.acceptRequest(stream.Context()); err != nil {
		metrics.Default.RecordXDSRequestRejection()
		return status.Error(codes.ResourceExhausted, err.Error())
	}
	caller, err := s.authenticator.Authenticate(stream.Context())
	if err != nil {
		if stream.Context().Err() != nil {
			return status.FromContextError(stream.Context().Err()).Err()
		}
		if errors.Is(err, attestation.ErrTokenReviewUnavailable) {
			return status.Error(codes.Unavailable, err.Error())
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return status.FromContextError(err).Err()
		}
		return status.Error(codes.Unauthenticated, err.Error())
	}

	requests := make(chan streamRequest, s.queueSize)
	go receive(stream, requests)
	var first streamRequest
	select {
	case <-stream.Context().Done():
		return stream.Context().Err()
	case first = <-requests:
	}
	if first.err != nil {
		if first.err == io.EOF {
			return nil
		}
		return first.err
	}
	if first.request == nil || first.request.GetNode() == nil {
		return status.Error(codes.InvalidArgument, "first DeltaDiscoveryRequest must include node metadata")
	}
	scope, err := s.scopeFuncs.ResolveScope(stream.Context(), first.request.GetNode(), caller)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return status.FromContextError(err).Err()
		}
		return status.Error(codes.PermissionDenied, err.Error())
	}
	if err := scope.Validate(); err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	version := clientVersion(first.request.GetNode())

	metrics.Default.AddXDSConnection(1)
	metrics.Default.AddXDSConnectionForClass(string(scope.Class), 1)
	versionLabel := metrics.Default.AddXDSConnectionForVersion(version, 1)
	defer metrics.Default.AddXDSConnection(-1)
	defer metrics.Default.AddXDSConnectionForClass(string(scope.Class), -1)
	defer metrics.Default.AddXDSConnectionForVersion(versionLabel, -1)
	nodeID := first.request.GetNode().GetId()
	connLog := log.With("connection_id", s.connections.Add(1), "node_id", nodeID, "client_class", scope.Class)
	connLog.Info("authenticated Delta ADS client", "data_plane_version", version)
	connected := time.Now()
	defer func() {
		attrs := []any{"duration", time.Since(connected)}
		if err != nil {
			attrs = append(attrs, "error", err)
		}
		if expectedStreamError(err) {
			connLog.Info("Delta ADS client disconnected", attrs...)
			return
		}
		connLog.Error("Delta ADS client disconnected", attrs...)
	}()

	return newDeltaSession(s, stream, scope, connLog, requests).run(first.request)
}

func expectedStreamError(err error) bool {
	// The stream loop also returns Context.Err directly, not just gRPC status
	// errors. status.Code(context.Canceled) is Unknown.
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return true
	}
	switch status.Code(err) {
	case codes.Canceled, codes.DeadlineExceeded:
		return true
	case codes.Unavailable:
		message := err.Error()
		for _, expected := range []string{"client disconnected", "error reading from server: EOF", "transport is closing"} {
			if strings.Contains(message, expected) {
				return true
			}
		}
	}
	message := err.Error()
	return strings.Contains(message, "stream terminated by RST_STREAM with error code: NO_ERROR") ||
		strings.Contains(message, "received prior goaway: code: NO_ERROR")
}

func (s *Server) dispatchPushes() {
	defer close(s.pushesDone)
	for {
		push := s.pushScheduler.Next(context.Background())
		if push == nil {
			return
		}
		metrics.Default.RecordXDSQueue(time.Since(push.Started))
		select {
		case push.Connection.pushes <- push:
		case <-push.Connection.context.Done():
			s.pushScheduler.Done(push)
		case <-s.pushScheduler.closed:
			s.pushScheduler.Done(push)
		}
	}
}

// Close stops push scheduling. Active streams are owned by the gRPC server and
// continue to use their contexts for transport shutdown.
func (s *Server) Close() {
	s.pushScheduler.Close()
	<-s.pushesDone
}

func receive(stream DeltaStream, target chan<- streamRequest) {
	for {
		request, err := stream.Recv()
		select {
		case target <- streamRequest{request: request, err: err}:
		case <-stream.Context().Done():
			return
		}
		if err != nil {
			return
		}
	}
}
