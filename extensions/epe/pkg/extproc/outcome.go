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

// Derivation of the audit outcome from what EPE actually told Envoy.
//
// The audit Outcome is derived here rather than accumulated by the engine as it
// decides, so the accesslog states what Envoy was told instead of what the
// engine intended. The polarity matters for a security audit: a translation bug
// that drops a mutation now under-reports enforcement, where an intent-based
// outcome would keep claiming the policy applied.

package extproc

import (
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// messageEffect is what one ProcessingResponse told Envoy to do about the
// message it answers. Ordered: a later, stronger effect wins.
type messageEffect uint8

const (
	// effectNone is an acknowledgement that changes nothing — the passthrough
	// singletons, a bare ack, a trailers ack, or a response whose only content
	// is a ModeOverride.
	effectNone messageEffect = iota
	// effectMutated carries a header, body, status, or upstream target change.
	effectMutated
	// effectBlocked is an ImmediateResponse: the message never goes anywhere.
	effectBlocked
)

// observe keeps the strongest effect seen so far.
func (e *messageEffect) observe(other messageEffect) {
	if other > *e {
		*e = other
	}
}

// classifyResponse reports what resp tells Envoy to do.
//
// ModeOverride is deliberately not consulted: asking for a body changes no
// message. ClearRouteCache alone is also not a message modification. An
// explicit upstream in request metadata counts as a target change sent to Envoy.
func classifyResponse(resp *extProcPb.ProcessingResponse) messageEffect {
	switch r := resp.GetResponse().(type) {
	case *extProcPb.ProcessingResponse_ImmediateResponse:
		return effectBlocked
	case *extProcPb.ProcessingResponse_RequestHeaders:
		if responseUpstream(resp) != nil {
			return effectMutated
		}
		return commonEffect(r.RequestHeaders.GetResponse())
	case *extProcPb.ProcessingResponse_RequestBody:
		if responseUpstream(resp) != nil {
			return effectMutated
		}
		return commonEffect(r.RequestBody.GetResponse())
	case *extProcPb.ProcessingResponse_ResponseHeaders:
		return commonEffect(r.ResponseHeaders.GetResponse())
	case *extProcPb.ProcessingResponse_ResponseBody:
		return commonEffect(r.ResponseBody.GetResponse())
	default:
		// Trailers acks, a nil response, and any arm added after this was
		// written. effectNone is a safety decision, not laziness: an
		// unrecognised arm read as a modification would over-report
		// enforcement, which is the one error an audit log must not make.
		return effectNone
	}
}

// commonEffect judges one direction's CommonResponse by its contents.
//
// Emptiness rather than nil-ness is the test: commonResponse always allocates a
// HeaderMutation (translate.go:154), so a nil check would call every mutation
// response mutated and, worse, would keep doing so if that allocation ever
// became conditional. The BodyMutation arm follows the same rule for the same
// reason — a BodyMutation whose oneof is unset changes no byte of the body, and
// calling it mutated is the one direction this file must not err in.
func commonEffect(common *extProcPb.CommonResponse) messageEffect {
	if common == nil {
		return effectNone
	}
	mut := common.GetHeaderMutation()
	if len(mut.GetSetHeaders()) > 0 || len(mut.GetRemoveHeaders()) > 0 {
		return effectMutated
	}
	if common.GetBodyMutation().GetMutation() != nil {
		return effectMutated
	}
	return effectNone
}

// deriveOutcome renders the audit vocabulary from the three things that decide
// it: the strongest effect actually sent, whether the stream ended in an error,
// and how many policy units matched.
//
// Precedence is error > blocked > mutated > bypassed > passthrough. The last two
// are what separates "no policy selected this request" from "policy selected it
// and changed nothing"; both leave the message untouched, so nothing on the wire
// tells them apart and the unit count has to.
func deriveOutcome(effect messageEffect, streamFailed bool, matchedUnits int) filter.Disposition {
	switch {
	case streamFailed:
		return filter.DispositionError
	case effect == effectBlocked:
		return filter.DispositionBlocked
	case effect == effectMutated:
		return filter.DispositionMutated
	case matchedUnits > 0:
		return filter.DispositionBypassed
	default:
		return filter.DispositionPassthrough
	}
}
