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

package enginetest

import (
	"reflect"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	auditlog "github.com/openkruise/agentio/extensions/epe/pkg/audit/log"
)

func setOpt(key, value string, action corev3.HeaderValueOption_HeaderAppendAction) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: key, RawValue: []byte(value)},
		AppendAction: action,
	}
}

// Request and response mutations are recorded separately.
func TestParseVerdict_ResponseHeaderOpsArePhaseDistinct(t *testing.T) {
	responses := []*extProcPb.ProcessingResponse{
		{Response: &extProcPb.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extProcPb.HeadersResponse{Response: &extProcPb.CommonResponse{
				HeaderMutation: &extProcPb.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{
						setOpt("x-req", "1", corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD),
					},
					RemoveHeaders: []string{"x-drop-req"},
				},
			}},
		}},
		{Response: &extProcPb.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extProcPb.HeadersResponse{Response: &extProcPb.CommonResponse{
				HeaderMutation: &extProcPb.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{
						setOpt("X-Epe", "policy", corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD),
					},
					RemoveHeaders: []string{"Server"},
				},
			}},
		}},
	}
	v := ParseVerdict(responses, nil)

	// Each direction records only its own ops, in proto order, lowercased.
	wantRequest := []HeaderOp{
		{Kind: HeaderSet, Name: "x-req", Value: "1"},
		{Kind: HeaderRemove, Name: "x-drop-req"},
	}
	if !reflect.DeepEqual(v.RequestHeaderOps, wantRequest) {
		t.Errorf("RequestHeaderOps = %+v, want %+v", v.RequestHeaderOps, wantRequest)
	}
	wantResponse := []HeaderOp{
		{Kind: HeaderSet, Name: "x-epe", Value: "policy"},
		{Kind: HeaderRemove, Name: "server"},
	}
	if !reflect.DeepEqual(v.ResponseHeaderOps, wantResponse) {
		t.Errorf("ResponseHeaderOps = %+v, want %+v", v.ResponseHeaderOps, wantResponse)
	}
	v.RequireHeader(t, "X-Req", "1")
	v.RequireHeaderRemoved(t, "x-drop-req")
	v.RequireResponseHeader(t, "X-Epe", "policy")
	v.RequireResponseHeaderRemoved(t, "server")
}

func TestParseVerdict_BodyMutationsAndResponseStatusKeepDirectionAndPresence(t *testing.T) {
	responses := []*extProcPb.ProcessingResponse{
		{Response: &extProcPb.ProcessingResponse_RequestBody{
			RequestBody: &extProcPb.BodyResponse{Response: &extProcPb.CommonResponse{
				BodyMutation: &extProcPb.BodyMutation{
					Mutation: &extProcPb.BodyMutation_Body{Body: []byte("request rewritten")},
				},
			}},
		}},
		{Response: &extProcPb.ProcessingResponse_ResponseBody{
			ResponseBody: &extProcPb.BodyResponse{Response: &extProcPb.CommonResponse{
				HeaderMutation: &extProcPb.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{
					setOpt(":status", "202", corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD),
					setOpt("x-response", "body-phase", corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD),
				}},
				BodyMutation: &extProcPb.BodyMutation{Mutation: &extProcPb.BodyMutation_Body{Body: []byte{}}},
			}},
		}},
	}
	v := ParseVerdict(responses, nil)
	if !v.RequestBodyChanged || string(v.RequestBody) != "request rewritten" {
		t.Fatalf("request body changed=%v body=%q", v.RequestBodyChanged, v.RequestBody)
	}
	if !v.ResponseBodyChanged || v.ResponseBody == nil || len(v.ResponseBody) != 0 {
		t.Fatalf(
			"response body changed=%v body=%#v, want explicit empty replacement",
			v.ResponseBodyChanged,
			v.ResponseBody,
		)
	}
	if v.ResponseStatus == nil || *v.ResponseStatus != 202 {
		t.Fatalf("ResponseStatus = %v, want 202", v.ResponseStatus)
	}
	v.RequireResponseHeader(t, "x-response", "body-phase")
}

// Direction-specific lookups do not return operations from the other direction.
func TestVerdictLookups_DoNotCrossDirections(t *testing.T) {
	v := &Verdict{
		RequestHeaderOps: []HeaderOp{
			{Kind: HeaderSet, Name: "x-req", Value: "1"},
			{Kind: HeaderRemove, Name: "x-gone-req"},
		},
		ResponseHeaderOps: []HeaderOp{
			{Kind: HeaderSet, Name: "x-resp", Value: "2"},
			{Kind: HeaderRemove, Name: "x-gone-resp"},
		},
	}
	if got := v.RequestHeaderValues("x-req"); !reflect.DeepEqual(got, []string{"1"}) {
		t.Errorf("RequestHeaderValues(x-req) = %v, want [1]", got)
	}
	if got := v.RequestHeaderValues("x-resp"); got != nil {
		t.Errorf("RequestHeaderValues(x-resp) = %v, want nil: that is a response op", got)
	}
	if got := v.ResponseHeaderValues("x-resp"); !reflect.DeepEqual(got, []string{"2"}) {
		t.Errorf("ResponseHeaderValues(x-resp) = %v, want [2]", got)
	}
	if got := v.ResponseHeaderValues("x-req"); got != nil {
		t.Errorf("ResponseHeaderValues(x-req) = %v, want nil: that is a request op", got)
	}
	if !headerRemoved(v.RequestHeaderOps, "x-gone-req") || headerRemoved(v.RequestHeaderOps, "x-gone-resp") {
		t.Error("request removal lookup saw the response direction")
	}
	if !headerRemoved(v.ResponseHeaderOps, "x-gone-resp") || headerRemoved(v.ResponseHeaderOps, "x-gone-req") {
		t.Error("response removal lookup saw the request direction")
	}
}

// Response set-cookie mutations preserve values, order, and add semantics.
func TestParseVerdict_ResponseSetCookieKeepsEveryLineInOrder(t *testing.T) {
	responses := []*extProcPb.ProcessingResponse{
		{Response: &extProcPb.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extProcPb.HeadersResponse{Response: &extProcPb.CommonResponse{
				HeaderMutation: &extProcPb.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{
					setOpt("set-cookie", "a=1", corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD),
					setOpt("set-cookie", "b=2", corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD),
				}},
			}},
		}},
	}
	v := ParseVerdict(responses, nil)
	want := []HeaderOp{
		{Kind: HeaderAdd, Name: "set-cookie", Value: "a=1"},
		{Kind: HeaderAdd, Name: "set-cookie", Value: "b=2"},
	}
	if !reflect.DeepEqual(v.ResponseHeaderOps, want) {
		t.Fatalf("ResponseHeaderOps = %+v, want both cookie lines in order", v.ResponseHeaderOps)
	}
	if got := v.ResponseHeaderValues("set-cookie"); !reflect.DeepEqual(got, []string{"a=1", "b=2"}) {
		t.Errorf("ResponseHeaderValues = %v, want both lines", got)
	}
}

// A response-only mutation must not be classified as a request mutation: Kind
// describes the request verdict, which is still a passthrough here.
func TestParseVerdict_ResponseOnlyMutationDoesNotChangeRequestKind(t *testing.T) {
	responses := []*extProcPb.ProcessingResponse{
		{Response: &extProcPb.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extProcPb.HeadersResponse{},
		}},
		{Response: &extProcPb.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extProcPb.HeadersResponse{Response: &extProcPb.CommonResponse{
				HeaderMutation: &extProcPb.HeaderMutation{
					RemoveHeaders: []string{"server"},
				},
			}},
		}},
	}
	v := ParseVerdict(responses, nil)
	if v.Kind != VerdictPassthrough {
		t.Errorf("Kind = %s, want passthrough: the request itself was not mutated", v.Kind)
	}
	if len(v.ResponseHeaderOps) != 1 {
		t.Errorf("ResponseHeaderOps = %+v, want the response removal recorded", v.ResponseHeaderOps)
	}
}

// The harness must assert the outcome the product actually logs, not the
// internal field the probe scraped. They agree after derivation; asserting the
// log is what catches them disagreeing.
func TestRequireOutcome_ReadsTheAccessLogEntry(t *testing.T) {
	v := &Verdict{
		Kind: VerdictPassthrough,
		AccessLog: []auditlog.Entry{{
			Outcome: "bypassed",
			Units:   1,
		}},
	}
	// Passes without failing the test.
	v.RequireOutcome(t, "bypassed")
}
