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
	"bytes"
	"context"
	"slices"
	"strings"

	corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// Incremental filters can change output length after headers are committed.
func removeStreamingContentLength(headers *extProcPb.HeadersResponse) {
	if headers.Response == nil {
		headers.Response = &extProcPb.CommonResponse{}
	}
	if headers.Response.HeaderMutation == nil {
		headers.Response.HeaderMutation = &extProcPb.HeaderMutation{}
	}
	headers.Response.HeaderMutation.SetHeaders = slices.DeleteFunc(
		headers.Response.HeaderMutation.SetHeaders,
		func(h *corepb.HeaderValueOption) bool {
			return strings.EqualFold(h.GetHeader().GetKey(), "content-length")
		},
	)
	headers.Response.HeaderMutation.RemoveHeaders = append(
		headers.Response.HeaderMutation.RemoveHeaders,
		"content-length",
	)
}

// handleBodyChunk returns exactly one response per STREAMED body message.
// Trailers complete the consumer without creating an unsolicited body response.
func (s *Server) handleBodyChunk(
	ctx context.Context,
	body *extProcPb.HttpBody,
	state *streamState,
	response, trailers bool,
) ([]*extProcPb.ProcessingResponse, error) {
	input := filter.Body{Bytes: body.GetBody(), Complete: body.GetEndOfStream() || trailers}
	var result *engine.BodyChunkResult
	var err error
	if response {
		result, err = s.eng.EvalResponseBodyChunk(ctx, state.stream, state.responseBodyContinuation, input)
	} else {
		result, err = s.eng.EvalRequestBodyChunk(ctx, state.stream, state.requestBodyContinuation, input)
	}
	if err != nil {
		return nil, err
	}
	if result.Disposition == engine.DispositionBlocked {
		state.armFinalization(result.Disposition)
		// Envoy sends a local reply before response headers, or resets the HTTP
		// stream if response headers have already been committed.
		return []*extProcPb.ProcessingResponse{immediateFromReply(result.Reply)}, nil
	}
	if result.Complete {
		if response {
			state.responseBodyContinuation = nil
			state.lifecycle = lifecycleFinalizePending
		} else {
			state.requestBodyContinuation = nil
			state.responseScope = result.ResponseScope
		}
	}
	if trailers {
		// STREAMED has already acknowledged every DATA chunk. A trailers reply
		// cannot carry body bytes, so do not silently discard a filter's output.
		if len(result.Body) != 0 {
			return nil, status.Error(codes.FailedPrecondition, "streamed filter emitted body bytes at trailers")
		}
		return nil, nil
	}
	return []*extProcPb.ProcessingResponse{streamedResponse(input.Bytes, result.Body, response)}, nil
}

// Envoy retains the original chunk until its matching response arrives.
// Only changed bytes need a mutation; an empty replacement explicitly drops it.
func streamedResponse(input, output []byte, response bool) *extProcPb.ProcessingResponse {
	common := &extProcPb.CommonResponse{}
	if !bytes.Equal(input, output) {
		common.BodyMutation = &extProcPb.BodyMutation{
			Mutation: &extProcPb.BodyMutation_Body{Body: output},
		}
	}
	body := &extProcPb.BodyResponse{Response: common}
	if response {
		return &extProcPb.ProcessingResponse{Response: &extProcPb.ProcessingResponse_ResponseBody{ResponseBody: body}}
	}
	return &extProcPb.ProcessingResponse{Response: &extProcPb.ProcessingResponse_RequestBody{RequestBody: body}}
}

func (s *Server) handleTrailers(
	ctx context.Context,
	trailers *extProcPb.HttpTrailers,
	state *streamState,
	response bool,
) ([]*extProcPb.ProcessingResponse, error) {
	streaming := state.requestBodyContinuation != nil && state.requestBodyContinuation.BodyMode() == filter.BodyStreamed
	if response {
		streaming = state.responseBodyContinuation != nil &&
			state.responseBodyContinuation.BodyMode() == filter.BodyStreamed
	}
	if streaming {
		responses, err := s.handleBodyChunk(ctx, &extProcPb.HttpBody{}, state, response, true)
		if err != nil {
			return responses, err
		}
		if len(responses) != 0 && responses[0].GetImmediateResponse() != nil {
			return responses, nil
		}
	}
	if response {
		return s.HandleResponseTrailers(ctx, trailers)
	}
	return s.HandleRequestTrailers(ctx, trailers)
}
