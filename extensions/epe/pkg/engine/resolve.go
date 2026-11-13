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
package engine

import (
	"context"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
)

// Resolution is what a Resolver hands back: the neutral units the engine
// evaluates, plus an optional stream logger the adapter appends to this
// stream's loggers.
//
// The adapter never looks inside the logger. That is deliberate: audit
// attribution (which profile, which rule, which match fired) is policy
// vocabulary, so the policy layer supplies a logger closed over its own typed
// units rather than publishing them through a channel the adapter would have
// to carry — attribution never has to survive a round trip through an untyped
// map to reach the one component that reads it.
type Resolution struct {
	DestinationAuthorizer filter.DestinationAuthorizer
	Units                 []Unit
	// StreamLogger, when non-nil, is invoked once at stream end under the
	// same contract as the statically registered loggers: exactly once, at
	// true stream end including abnormal termination, and it must not block.
	// See filter.StreamLogger.
	StreamLogger filter.StreamLogger
}

// Resolver maps one request's identity to the units that apply to it. It is a
// function field rather than an interface, and rather than a concrete policy
// store plus binder, so the adapter stays free of the policy layer and a
// second policy API needs no change here.
//
// Returning zero units skips rule processing; independent request authorization
// still applies when configured.
type Resolver func(ctx context.Context, subject subject.Subject, req *httpreq.HTTPRequest) (Resolution, error)

// RequestAuthorizer runs once after all request headers, including bypass
// and empty resolutions, before any body callback. The stream contains
// the effective request target. A reply
// denies the request; otherwise the returned target is pinned for forwarding.
// Errors become local failures, never an allow decision.
type RequestAuthorizer func(context.Context, *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error)

// RequestAuthorizationError distinguishes a failed checkpoint from an engine
// contract error, so adapters can reject locally even with transport fail-open.
type RequestAuthorizationError struct{ Err error }

func (e *RequestAuthorizationError) Error() string { return e.Err.Error() }
func (e *RequestAuthorizationError) Unwrap() error { return e.Err }
