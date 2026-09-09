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

// Translation between the engine's plain results and ext_proc protos.
// This is the single place mutations become wire format — the reason
// filters can stay proto-free.
package extproc

import (
	"strconv"

	"github.com/go-logr/logr"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoyTypeV3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// routeAffectingHeaders force clear_route_cache: a rewrite of any of these
// silently misses routing when an earlier filter cached the route.
// Path rewrites are excluded: their cache behavior is explicitly selected
// through Route.ClearCache, including when SetPath is used.
var routeAffectingHeaders = map[string]bool{
	":authority": true,
	":method":    true,
	":scheme":    true,
	"host":       true,
}

// translateRequestHeadersResult maps an RequestHeadersResult to the headers-phase response
// list.
func translateRequestHeadersResult(reqHeadersRes *engine.RequestHeadersResult, loggerD logr.Logger, peer filter.Peer) []*extProcPb.ProcessingResponse {
	if reqHeadersRes.Disposition == engine.DispositionBlocked {
		return []*extProcPb.ProcessingResponse{immediateFromReply(reqHeadersRes.Reply)}
	}
	clearCache := reqHeadersRes.Route != nil && reqHeadersRes.Route.ClearCache
	if len(reqHeadersRes.HeaderOps) == 0 && reqHeadersRes.Body == nil && !clearCache {
		if reqHeadersRes.Disposition == engine.DispositionPassthrough {
			loggerD.Info("no filter produced mutations; passthrough", "pod", peer.Pod.String())
		}
		return []*extProcPb.ProcessingResponse{applyRouteMutation(defaultPassThrough[0], reqHeadersRes.Route)}
	}
	common := commonResponse(reqHeadersRes.HeaderOps, reqHeadersRes.Body, nil,
		clearCache, true, true)
	return []*extProcPb.ProcessingResponse{applyRouteMutation(&extProcPb.ProcessingResponse{
		Response: &extProcPb.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extProcPb.HeadersResponse{
				Response: common,
			},
		},
	}, reqHeadersRes.Route)}
}

// translateRequestBodyResult maps a RequestBodyResult to the body-phase response list.
func translateRequestBodyResult(reqBodyRes *engine.RequestBodyResult) []*extProcPb.ProcessingResponse {
	if reqBodyRes.Disposition == engine.DispositionBlocked {
		return []*extProcPb.ProcessingResponse{immediateFromReply(reqBodyRes.Reply)}
	}
	clearCache := reqBodyRes.Route != nil && reqBodyRes.Route.ClearCache
	if len(reqBodyRes.HeaderOps) == 0 && reqBodyRes.Body == nil && !clearCache {
		return []*extProcPb.ProcessingResponse{applyRouteMutation(defaultPassThroughBody[0], reqBodyRes.Route)}
	}
	common := commonResponse(reqBodyRes.HeaderOps, reqBodyRes.Body, nil,
		clearCache, false, true)
	return []*extProcPb.ProcessingResponse{applyRouteMutation(&extProcPb.ProcessingResponse{
		Response: &extProcPb.ProcessingResponse_RequestBody{
			RequestBody: &extProcPb.BodyResponse{
				Response: common,
			},
		},
	}, reqBodyRes.Route)}
}

// translateResponseHeadersResult emits a blocking reply, response mutations,
// or a bare acknowledgement. It never clears the request-side route cache.
func translateResponseHeadersResult(respHeadersRes *engine.ResponseHeadersResult) []*extProcPb.ProcessingResponse {
	if respHeadersRes.Disposition == engine.DispositionBlocked {
		// Envoy holds the upstream response headers while awaiting our reply, so
		// this local reply genuinely replaces them. HeaderOps are ignored: the
		// response being mutated no longer goes downstream.
		return []*extProcPb.ProcessingResponse{immediateFromReply(respHeadersRes.Reply)}
	}
	if len(respHeadersRes.HeaderOps) == 0 && respHeadersRes.Body == nil && respHeadersRes.StatusCode == nil {
		return emptyResponseHeadersAck
	}
	common := commonResponse(respHeadersRes.HeaderOps, respHeadersRes.Body,
		respHeadersRes.StatusCode, false, true, false)
	return []*extProcPb.ProcessingResponse{{
		Response: &extProcPb.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extProcPb.HeadersResponse{
				Response: common,
			},
		},
	}}
}

// translateResponseBodyResult maps the completed response-direction walk to a
// response-body acknowledgement, or to a terminal local reply.
func translateResponseBodyResult(respBodyRes *engine.ResponseBodyResult) []*extProcPb.ProcessingResponse {
	if respBodyRes.Disposition == engine.DispositionBlocked {
		return []*extProcPb.ProcessingResponse{immediateFromReply(respBodyRes.Reply)}
	}
	if len(respBodyRes.HeaderOps) == 0 && respBodyRes.Body == nil && respBodyRes.StatusCode == nil {
		return defaultPassThroughResponseBody
	}
	common := commonResponse(respBodyRes.HeaderOps, respBodyRes.Body,
		respBodyRes.StatusCode, false, false, false)
	return []*extProcPb.ProcessingResponse{{
		Response: &extProcPb.ProcessingResponse_ResponseBody{
			ResponseBody: &extProcPb.BodyResponse{Response: common},
		},
	}}
}

// defaultPassThroughResponseBody is the immutable empty-mutation response-body
// acknowledgement.
var defaultPassThroughResponseBody = []*extProcPb.ProcessingResponse{{
	Response: &extProcPb.ProcessingResponse_ResponseBody{
		ResponseBody: &extProcPb.BodyResponse{},
	},
}}

// emptyResponseHeadersAck is the immutable bare acknowledgement for response headers.
var emptyResponseHeadersAck = []*extProcPb.ProcessingResponse{{
	Response: &extProcPb.ProcessingResponse_ResponseHeaders{
		ResponseHeaders: &extProcPb.HeadersResponse{},
	},
}}

// commonResponse renders one direction's folded neutral mutations. Status is
// response-only by engine validation. Body replacement always overwrites
// content-length; header-phase replacement additionally requires
// CONTINUE_AND_REPLACE or Envoy silently drops the body mutation.
func commonResponse(
	ops []filter.HeaderOp,
	body []byte,
	statusCode *int,
	clearRouteCache bool,
	headersPhase bool,
	requestDirection bool,
) *extProcPb.CommonResponse {
	mut, routeAffecting := headerMutationFromOps(ops)
	common := &extProcPb.CommonResponse{HeaderMutation: mut}
	if requestDirection {
		common.ClearRouteCache = clearRouteCache || routeAffecting
	}
	if statusCode != nil {
		mut.SetHeaders = append(mut.SetHeaders, overwriteHeader(":status", strconv.Itoa(*statusCode)))
	}
	if body != nil {
		common.BodyMutation = &extProcPb.BodyMutation{
			Mutation: &extProcPb.BodyMutation_Body{Body: body},
		}
		mut.SetHeaders = append(mut.SetHeaders, overwriteHeader("content-length", strconv.Itoa(len(body))))
		if headersPhase {
			common.Status = extProcPb.CommonResponse_CONTINUE_AND_REPLACE
		}
	}
	return common
}

func overwriteHeader(name, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:      name,
			RawValue: []byte(value),
		},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}

// headerMutationFromOps renders folded ops as one proto HeaderMutation and
// reports whether a route-affecting header was touched.
func headerMutationFromOps(ops []filter.HeaderOp) (*extProcPb.HeaderMutation, bool) {
	mut := &extProcPb.HeaderMutation{}
	clear := false
	for _, op := range ops {
		if routeAffectingHeaders[op.Name] {
			clear = true
		}
		switch op.Kind {
		case filter.HeaderSet:
			mut.SetHeaders = append(mut.SetHeaders, &corev3.HeaderValueOption{
				Header:       &corev3.HeaderValue{Key: op.Name, RawValue: []byte(op.Value)},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			})
		case filter.HeaderAdd:
			mut.SetHeaders = append(mut.SetHeaders, &corev3.HeaderValueOption{
				Header:       &corev3.HeaderValue{Key: op.Name, RawValue: []byte(op.Value)},
				AppendAction: corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
			})
		case filter.HeaderRemove:
			mut.RemoveHeaders = append(mut.RemoveHeaders, op.Name)
		}
	}
	return mut, clear
}

// immediateFromReply renders a terminal Reply as an ImmediateResponse.
func immediateFromReply(r filter.Reply) *extProcPb.ProcessingResponse {
	immediate := &extProcPb.ImmediateResponse{
		Status:  &envoyTypeV3.HttpStatus{Code: envoyTypeV3.StatusCode(r.Status)},
		Body:    r.Body,
		Details: r.Details,
	}
	if len(r.HeaderOps) > 0 {
		// The route-affecting flag is discarded: an immediate response has no
		// route left to invalidate.
		immediate.Headers, _ = headerMutationFromOps(r.HeaderOps)
	}
	return &extProcPb.ProcessingResponse{
		Response: &extProcPb.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: immediate,
		},
	}
}
