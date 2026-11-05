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
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoyTypeV3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

func setHeader(name, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{Key: name, RawValue: []byte(value)},
	}
}

// requestHeadersResp wraps a CommonResponse in the request-headers arm.
func requestHeadersResp(common *extProcPb.CommonResponse) *extProcPb.ProcessingResponse {
	return &extProcPb.ProcessingResponse{
		Response: &extProcPb.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extProcPb.HeadersResponse{Response: common},
		},
	}
}

func TestClassifyResponse(t *testing.T) {
	// emptyMutation reproduces what commonResponse always allocates
	// (translate.go:154): a non-nil but empty HeaderMutation. Judging
	// nil-ness instead of contents would call every response mutated.
	emptyMutation := &extProcPb.CommonResponse{HeaderMutation: &extProcPb.HeaderMutation{}}

	tests := []struct {
		name string
		resp *extProcPb.ProcessingResponse
		want messageEffect
	}{
		{"nil response", nil, effectNone},
		{"nil oneof", &extProcPb.ProcessingResponse{}, effectNone},
		{
			"request headers passthrough singleton shape",
			requestHeadersResp(nil),
			effectNone,
		},
		{
			"request headers with allocated but empty mutation",
			requestHeadersResp(emptyMutation),
			effectNone,
		},
		{
			"request headers set header",
			requestHeadersResp(&extProcPb.CommonResponse{
				HeaderMutation: &extProcPb.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{setHeader("x-a", "1")},
				},
			}),
			effectMutated,
		},
		{
			"request headers remove header",
			requestHeadersResp(&extProcPb.CommonResponse{
				HeaderMutation: &extProcPb.HeaderMutation{RemoveHeaders: []string{"x-a"}},
			}),
			effectMutated,
		},
		{
			"request headers clear route cache only is not a modification",
			requestHeadersResp(&extProcPb.CommonResponse{
				HeaderMutation:  &extProcPb.HeaderMutation{},
				ClearRouteCache: true,
			}),
			effectNone,
		},
		{
			"request body mutation",
			&extProcPb.ProcessingResponse{
				Response: &extProcPb.ProcessingResponse_RequestBody{
					RequestBody: &extProcPb.BodyResponse{Response: &extProcPb.CommonResponse{
						HeaderMutation: &extProcPb.HeaderMutation{},
						BodyMutation: &extProcPb.BodyMutation{
							Mutation: &extProcPb.BodyMutation_Body{Body: []byte("replaced")},
						},
					}},
				},
			},
			effectMutated,
		},
		{
			// A BodyMutation whose oneof is unset replaces no byte of the body,
			// so it is not a mutation. Judging the BodyMutation's nil-ness
			// instead of its contents would over-report enforcement here, which
			// is the one direction this derivation must not err in.
			"request body mutation with unset oneof is not a modification",
			&extProcPb.ProcessingResponse{
				Response: &extProcPb.ProcessingResponse_RequestBody{
					RequestBody: &extProcPb.BodyResponse{Response: &extProcPb.CommonResponse{
						HeaderMutation: &extProcPb.HeaderMutation{},
						BodyMutation:   &extProcPb.BodyMutation{},
					}},
				},
			},
			effectNone,
		},
		{
			"response headers status rewrite counts, unlike ParseVerdict.Kind",
			&extProcPb.ProcessingResponse{
				Response: &extProcPb.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &extProcPb.HeadersResponse{Response: &extProcPb.CommonResponse{
						HeaderMutation: &extProcPb.HeaderMutation{
							SetHeaders: []*corev3.HeaderValueOption{setHeader(":status", "418")},
						},
					}},
				},
			},
			effectMutated,
		},
		{
			"response headers bare ack",
			&extProcPb.ProcessingResponse{
				Response: &extProcPb.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &extProcPb.HeadersResponse{},
				},
			},
			effectNone,
		},
		{
			"response body mutation",
			&extProcPb.ProcessingResponse{
				Response: &extProcPb.ProcessingResponse_ResponseBody{
					ResponseBody: &extProcPb.BodyResponse{Response: &extProcPb.CommonResponse{
						HeaderMutation: &extProcPb.HeaderMutation{},
						BodyMutation: &extProcPb.BodyMutation{
							Mutation: &extProcPb.BodyMutation_Body{Body: []byte("x")},
						},
					}},
				},
			},
			effectMutated,
		},
		{
			"immediate response",
			&extProcPb.ProcessingResponse{
				Response: &extProcPb.ProcessingResponse_ImmediateResponse{
					ImmediateResponse: &extProcPb.ImmediateResponse{
						Status: &envoyTypeV3.HttpStatus{Code: envoyTypeV3.StatusCode(403)},
					},
				},
			},
			effectBlocked,
		},
		{
			"request trailers ack",
			&extProcPb.ProcessingResponse{
				Response: &extProcPb.ProcessingResponse_RequestTrailers{
					RequestTrailers: &extProcPb.TrailersResponse{},
				},
			},
			effectNone,
		},
		{
			"response trailers ack",
			&extProcPb.ProcessingResponse{
				Response: &extProcPb.ProcessingResponse_ResponseTrailers{
					ResponseTrailers: &extProcPb.TrailersResponse{},
				},
			},
			effectNone,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, upstreamMutation := range []bool{false, true} {
				if got := classifyResponse(tc.resp, upstreamMutation); got != tc.want {
					t.Errorf("classifyResponse(upstreamMutation=%v) = %v, want %v", upstreamMutation, got, tc.want)
				}
			}
		})
	}
}

// A NeedBody response is the passthrough singleton cloned with a ModeOverride
// attached (request.go:165-167). Asking Envoy for the body changes no message,
// so it must not read as a mutation.
func TestClassifyResponse_ModeOverrideOnlyIsNotAMutation(t *testing.T) {
	resp := cloneResponse(defaultPassThrough[0])
	resp.ModeOverride = &extProcV3.ProcessingMode{
		RequestBodyMode: extProcV3.ProcessingMode_BUFFERED,
	}

	if got := classifyResponse(resp, true); got != effectNone {
		t.Errorf("classifyResponse(ModeOverride only) = %v, want effectNone", got)
	}
}

func TestMessageEffect_ObserveKeepsStrongest(t *testing.T) {
	tests := []struct {
		name  string
		start messageEffect
		next  messageEffect
		want  messageEffect
	}{
		{"none then mutated", effectNone, effectMutated, effectMutated},
		{"mutated then none holds", effectMutated, effectNone, effectMutated},
		{"mutated then blocked", effectMutated, effectBlocked, effectBlocked},
		{"blocked then mutated holds", effectBlocked, effectMutated, effectBlocked},
		{"none then none", effectNone, effectNone, effectNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.start
			got.observe(tc.next)
			if got != tc.want {
				t.Errorf("observe() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDeriveOutcome(t *testing.T) {
	tests := []struct {
		name         string
		effect       messageEffect
		streamFailed bool
		matched      int
		want         filter.Disposition
	}{
		{"no units, nothing sent", effectNone, false, 0, filter.DispositionPassthrough},
		{"units matched, nothing modified", effectNone, false, 2, filter.DispositionBypassed},
		{"mutation wins over bypass", effectMutated, false, 2, filter.DispositionMutated},
		{"block wins over mutation", effectBlocked, false, 1, filter.DispositionBlocked},
		{"error wins over block", effectBlocked, true, 1, filter.DispositionError},
		{"error with nothing sent", effectNone, true, 0, filter.DispositionError},
		// Unreachable in practice (a block requires a matched unit) but the
		// function must be total, and blocked outranks the unit count.
		{"block without matched units", effectBlocked, false, 0, filter.DispositionBlocked},
		// A mutation with no matched unit would mean EPE modified a message no
		// policy selected. Report the modification rather than hiding it.
		{"mutation without matched units", effectMutated, false, 0, filter.DispositionMutated},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveOutcome(tc.effect, tc.streamFailed, tc.matched)
			if got != tc.want {
				t.Errorf("deriveOutcome() = %q, want %q", got, tc.want)
			}
		})
	}
}
