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

// defaultPassThroughBody is the empty-mutation body response.
var defaultPassThroughBody = []*extProcPb.ProcessingResponse{
	{Response: &extProcPb.ProcessingResponse_RequestBody{
		RequestBody: &extProcPb.BodyResponse{},
	}},
}

// HandleRequestBody dispatches a chunk or complete body to the callbacks
// registered during headers, without reauthorizing the fixed target.
func (s *Server) HandleRequestBody(
	ctx context.Context,
	body *extProcPb.HttpBody,
	state *streamState,
) ([]*extProcPb.ProcessingResponse, error) {
	ctx, cancel := s.requestContext(ctx)
	defer cancel()
	if state == nil || state.lifecycle == lifecycleIdle ||
		state.requestBodyContinuation == nil || !state.requestBodyContinuation.NeedsBody() {
		return nil, status.Error(codes.FailedPrecondition,
			"received request body without an outstanding request-body obligation")
	}
	if body == nil {
		return nil, status.Error(codes.InvalidArgument, "request body is missing")
	}

	loggerD := log.FromContext(ctx).V(logging.DEBUG)
	loggerD.Info("running deferred body-phase filters", "bodyLen", len(body.Body))

	prior := state.requestBodyContinuation
	if prior.BodyMode() == filter.BodyStreamed {
		return s.handleBodyChunk(ctx, body, state, false, false)
	}
	state.requestBodyContinuation = nil
	reqBodyRes, err := s.eng.EvalRequestBody(ctx, state.stream, prior, filter.Body{
		Bytes: body.Body,
		// Deliberately not body.EndOfStream. BUFFERED delivers the whole body
		// in one message, including trailer flushes with EndOfStream clear. Copying
		// the flag would tell filters that a complete body was partial.
		Complete: true,
	})
	if err != nil {
		return nil, err
	}
	// Response-header demand is fixed before request evaluation; body callbacks
	// can only narrow dispatch through ResponseScope.
	state.responseScope = reqBodyRes.ResponseScope

	state.armFinalization(reqBodyRes.Disposition)
	return translateRequestBodyResult(reqBodyRes), nil
}
