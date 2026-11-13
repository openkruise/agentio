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
package filter

import "github.com/openkruise/agentio/extensions/epe/pkg/httpreq"

// Body is the complete buffered view of one direction's body; both
// OnRequestBody and OnResponseBody receive it.
type Body struct {
	Bytes []byte
	// Complete reports that Bytes is the whole body. The adapter only ever
	// dispatches whole bodies — it requests Envoy's BUFFERED mode, which
	// delivers the body in one message — so this is always true in practice.
	// The field lets a filter that must not decide on a fragment reject one
	// explicitly rather than assuming.
	Complete bool
}

// RequestContext is prepared before filters run and remains fixed for the stream.
// Effective request views copy this value; maps and compiled policies stay shared and read-only.
type RequestContext struct {
	Caller    CallerContext
	Request   httpreq.HTTPRequest
	RequestID string
	Policies  PolicySnapshot `json:"-"`
}

// PolicySnapshot keeps destination authorization and rule execution on one request snapshot.
// Each unit owns its Profile/Rule scope and references that profile's immutable inputs.
type PolicySnapshot struct {
	// Global static restrictions run before this request-bound authorizer.
	DestinationAuthorizer DestinationAuthorizer
	FilterRules           []Unit
	StreamLogger          StreamLogger
}

// Stream is the request context and the current phase's runtime view.
// Filters must treat both as read-only; the engine owns runtime updates.
type Stream struct {
	RequestContext
	StreamRuntime
}

// StreamRuntime contains observations and data populated or changed during execution.
type StreamRuntime struct {
	// Upstream changes while routing, then authorization pins the final destination.
	Upstream *UpstreamTarget
	Response httpreq.HTTPResponse
	Info     *StreamInfo
}
