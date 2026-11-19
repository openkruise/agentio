// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package extproc

import (
	"context"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
)

// HandleResponseBody dispatches a chunk or resumes the buffered response walk.
// BUFFERED may flush at trailers without EndOfStream; that message is complete.
func (s *Server) HandleResponseBody(
	ctx context.Context,
	body *extProcPb.HttpBody,
	state *streamState,
) ([]*extProcPb.ProcessingResponse, error) {
	if state == nil || state.lifecycle == lifecycleIdle || state.responseBodyContinuation == nil {
		return nil, status.Error(codes.FailedPrecondition,
			"received response body without an outstanding response-body obligation")
	}
	if body == nil {
		return nil, status.Error(codes.InvalidArgument, "response body is missing")
	}

	loggerD := log.FromContext(ctx).V(logging.DEBUG)
	loggerD.Info("running deferred response-body filters", "bodyLen", len(body.Body))

	prior := state.responseBodyContinuation
	if prior.BodyMode() == filter.BodyStreamed {
		return s.handleBodyChunk(ctx, body, state, true, false)
	}
	state.responseBodyContinuation = nil
	result, err := s.eng.EvalResponseBody(ctx, state.stream, prior, filter.Body{
		Bytes:    body.Body,
		Complete: true,
	})
	if err != nil {
		return nil, err
	}
	state.lifecycle = lifecycleFinalizePending
	state.armFinalization(result.Disposition)
	return translateResponseBodyResult(result), nil
}
