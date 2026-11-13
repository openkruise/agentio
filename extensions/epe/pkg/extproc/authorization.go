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
	"encoding/json"

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/extproc/attributes"
)

// requestContext shares one budget across rule evaluation and authorization.
func (s *Server) requestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.pluginBudget <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, s.pluginBudget)
}

// authorize checks and pins the final target after all request headers run,
// before any request-body callback. It leaves the matching request and
// bypass response scope intact. Denials are local replies,
// so an authorization error cannot turn into an ext_proc transport fail-open.
func (s *Server) authorize(
	ctx context.Context,
	stream *filter.Stream,
	ops []filter.HeaderOp,
	route *filter.RouteMutation,
) (*filter.RouteMutation, *filter.Reply) {
	if s.authorizeRequest == nil {
		return route, nil
	}
	effective := *stream
	effective.Request = attributes.RequestAfterMutations(ctx, stream.Request, ops)
	if route != nil && route.Upstream != nil {
		effective.Upstream = route.Upstream
	}
	target, reply, err := s.authorizeRequest(ctx, &effective)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return nil, authorizationFailure(ctx, stream, err)
	}
	if reply != nil {
		if reply.Details == "epe_egress_denied" {
			return nil, authorizationReply(
				reply.Status,
				reply.Details,
				"Outbound destination is denied by policy.",
				stream.RequestID,
			)
		}
		return nil, reply
	}
	if target == nil {
		return route, nil
	}
	result := filter.RouteMutation{Upstream: target}
	if route != nil {
		result.ClearCache = route.ClearCache
	}
	return &result, nil
}

func authorizationReply(status int, code, message, requestID string) *filter.Reply {
	body, _ := json.Marshal(struct { //nolint:errcheck // String-only fields cannot fail JSON encoding.
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"requestID"`
	}{code, message, requestID})
	return &filter.Reply{
		Status:    status,
		Details:   code,
		Body:      body,
		HeaderOps: []filter.HeaderOp{{Kind: filter.HeaderSet, Name: "content-type", Value: "application/json"}},
	}
}

// Both checkpoints and final authorization report failures as local replies.
func authorizationFailure(ctx context.Context, stream *filter.Stream, err error) *filter.Reply {
	log.FromContext(ctx).Error(err, "request authorization failed")
	stream.Info.Error = err.Error()
	if stream.Info.Authorization == nil || stream.Info.Authorization.Action != "error" {
		stream.Info.RecordAuthorization(
			filter.AuthorizationDecision{
				Action: "error",
				Reason: filter.AuthorizationReasonFailed,
			},
		)
	}
	return authorizationReply(
		500,
		"epe_request_authorization_failed",
		"Unable to authorize outbound destination.",
		stream.RequestID,
	)
}
