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
	"testing"

	corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

type earlyResponseDeny struct {
	filter.PassThrough
	body bool
}

func (*earlyResponseDeny) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(filter.IncrementalBody), nil
}

func (f *earlyResponseDeny) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	if f.body {
		return filter.NeedBody(filter.CompleteBody), nil
	}
	return filter.Stop(filter.Reply{Status: 403}), nil
}

func (*earlyResponseDeny) OnResponseBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	return filter.Stop(filter.Reply{Status: 403}), nil
}

func TestStreamedUploadEarlyResponseDeny(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(map[bool]string{false: "headers", true: "buffered-body"}[body], func(t *testing.T) {
			reg := fixedReg("deny", &earlyResponseDeny{body: body})
			reg.Phases = filter.DispatchedPhases
			reg.Subscribes = func(any) filter.Phase { return filter.PhaseResponseHeaders }
			logger := &recordingStreamLogger{}
			s := NewServer(ServerDeps{
				Registrations: []filter.Registration{reg},
				Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
					return engine.Resolution{
						Units:        []engine.Unit{{Cfgs: []any{struct{}{}}}},
						StreamLogger: logger,
					}, nil
				},
			})
			stream := &collectingStream{
				ctx: t.Context(),
				msgs: []*extProcPb.ProcessingRequest{
					{Request: &extProcPb.ProcessingRequest_RequestHeaders{
						RequestHeaders: makeRequestHeaders("example.com", "/", "POST"),
					},
						Attributes: makeAttrsWithLabels("test", "fixture", ""),
					},
					{
						Request: &extProcPb.ProcessingRequest_RequestBody{
							RequestBody: &extProcPb.HttpBody{Body: []byte("partial")},
						},
					},
					{Request: &extProcPb.ProcessingRequest_ResponseHeaders{ResponseHeaders: responseHeaderMsg("200")}},
				}}
			if body {
				stream.msgs = append(stream.msgs, &extProcPb.ProcessingRequest{
					Request: &extProcPb.ProcessingRequest_ResponseBody{
						ResponseBody: &extProcPb.HttpBody{Body: []byte("denied"), EndOfStream: true},
					},
				})
			}
			if err := s.Process(stream); err != nil {
				t.Fatal(err)
			}
			if stream.sent[0].GetModeOverride().GetRequestBodyMode() != extProcV3.ProcessingMode_STREAMED ||
				stream.sent[len(stream.sent)-1].GetImmediateResponse().GetStatus().GetCode() != 403 ||
				logger.calls != 1 || logger.result != "blocked" {
				t.Fatalf("sent=%v audit=%q calls=%d", stream.sent, logger.result, logger.calls)
			}
		})
	}
}

func TestStreamedTrailersCompleteOnce(t *testing.T) {
	for _, response := range []bool{false, true} {
		for _, tc := range []struct {
			name     string
			act      filter.Action
			wantCode codes.Code
			blocked  bool
		}{
			{"allow", filter.Continue(), codes.OK, false},
			{"deny", filter.Stop(filter.Reply{Status: 403}), codes.OK, true},
			{"body-output", filter.Continue(filter.Mutation{Body: []byte("tail")}), codes.FailedPrecondition, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				requestProbe := &bodyProbe{requirement: filter.IncrementalBody}
				responseProbe := &responseBodyProbe{requirement: filter.IncrementalBody}
				var reg filter.Registration
				if response {
					reg = responseBodyReg("probe", responseProbe, filter.FailClosed)
				} else {
					reg = fixedReg("probe", requestProbe)
				}

				s, _ := wantsServer(t, []filter.Registration{reg}, []string{"r"})
				state := newStreamState()
				runRequestHeaders(t, s, state, false)
				var err error
				if response {
					_, err = s.HandleResponseHeaders(t.Context(), responseHeaderMsg("200"), state)
					if err != nil {
						t.Fatal(err)
					}
					_, err = s.HandleResponseBody(t.Context(), &extProcPb.HttpBody{Body: []byte("data")}, state)
					responseProbe.bodyAct = tc.act
				} else {
					_, err = s.HandleRequestBody(t.Context(), &extProcPb.HttpBody{Body: []byte("data")}, state)
					requestProbe.bodyAct = tc.act
				}
				if err != nil {
					t.Fatal(err)
				}
				out, err := s.handleTrailers(t.Context(), &extProcPb.HttpTrailers{}, state, response)
				if status.Code(err) != tc.wantCode {
					t.Fatalf("out=%v err=%v", out, err)
				}
				if tc.wantCode != codes.OK {
					if len(out) != 0 {
						t.Fatal("invalid trailers output was sent")
					}
					return
				}
				if len(out) != 1 {
					t.Fatalf("trailers must receive one response: %v", out)
				}
				if tc.blocked {
					if out[0].GetImmediateResponse() == nil || state.awaitingInput() {
						t.Fatal("block did not retire stream")
					}
				} else if (response && out[0].GetResponseTrailers() == nil) || (!response && out[0].GetRequestTrailers() == nil) {
					t.Fatalf("not a trailers acknowledgement: %v", out)
				}
				if response {
					if responseProbe.bodyCalls != 2 || !responseProbe.receivedComplete ||
						len(responseProbe.receivedBody) != 0 {
						t.Fatal("missing empty final body callback")
					}
				} else if requestProbe.bodyCalls != 2 || len(requestProbe.receivedBody) != 0 {
					t.Fatal("missing empty final body callback")
				}
			})
		}
	}
}

func TestStreamedResponse(t *testing.T) {
	for _, response := range []bool{false, true} {
		for _, tc := range []struct {
			name    string
			input   []byte
			output  []byte
			mutated bool
		}{
			{"unchanged", []byte("original"), []byte("original"), false},
			{"empty-eos", nil, nil, false},
			{"replace", []byte("original"), []byte("new"), true},
			{"drop", []byte("original"), nil, true},
			{"large-replacement", []byte("original"), bytes.Repeat([]byte("x"), 70<<10), true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				r := streamedResponse(tc.input, tc.output, response)
				body := r.GetRequestBody()
				if response {
					body = r.GetResponseBody()
				}
				if body == nil {
					t.Fatal("wrong response direction")
				}
				common := body.GetResponse()
				mutation := common.GetBodyMutation()
				if mutation.GetStreamedResponse() != nil || common.GetHeaderMutation() != nil {
					t.Fatal("STREAMED response included duplex output or committed header mutation")
				}
				if tc.mutated {
					if _, ok := mutation.GetMutation().(*extProcPb.BodyMutation_Body); !ok ||
						!bytes.Equal(mutation.GetBody(), tc.output) || classifyResponse(r) != effectMutated {
						t.Fatalf("replacement lost: %v", r)
					}
				} else if mutation != nil || classifyResponse(r) != effectNone {
					t.Fatalf("unchanged input should only be acknowledged: %v", r)
				}
			})
		}
	}
}

func TestStreamingContentLength(t *testing.T) {
	headers := &extProcPb.HeadersResponse{
		Response: &extProcPb.CommonResponse{
			HeaderMutation: &extProcPb.HeaderMutation{SetHeaders: []*corepb.HeaderValueOption{
				{Header: &corepb.HeaderValue{Key: "Content-Length", Value: "100"}},
				{Header: &corepb.HeaderValue{Key: "x-keep", Value: "yes"}},
			}},
		},
	}
	removeStreamingContentLength(headers)
	m := headers.Response.HeaderMutation
	if len(m.SetHeaders) != 1 || m.SetHeaders[0].Header.Key != "x-keep" || len(m.RemoveHeaders) != 1 ||
		m.RemoveHeaders[0] != "content-length" {
		t.Fatalf("mutation: %v", m)
	}
}

func TestStreamedModeAndEarlyResponse(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		t.Run(map[bool]string{false: "streamed", true: "buffered-consumer"}[buffered], func(t *testing.T) {
			reg := fixedReg("probe", &streamingFixtureFilter{})
			reg.Phases = filter.DispatchedPhases
			reg.Subscribes = func(any) filter.Phase { return filter.PhaseResponseHeaders }

			regs := []filter.Registration{reg}
			cfgs := []any{struct{}{}}
			if buffered {
				regs = append(regs, fixedReg("complete", &bodyProbe{}))
				cfgs = append(cfgs, struct{}{})
			}
			s := NewServer(
				ServerDeps{
					Registrations: regs,
					Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
						return engine.Resolution{
							Units: []engine.Unit{{ID: filter.UnitID{Name: "rule"}, Cfgs: cfgs}},
						}, nil
					},
				},
			)
			ctx := context.Background()
			state := newStreamState()
			out, err := s.HandleRequestHeaders(
				ctx,
				makeRequestHeaders("example.com", "/response", "POST"),
				makeAttrsWithLabels("test", "fixture", ""),
				state,
			)
			if err != nil {
				t.Fatal(err)
			}
			wantMode := extProcV3.ProcessingMode_STREAMED
			if buffered {
				wantMode = extProcV3.ProcessingMode_BUFFERED
			}
			if out[0].GetModeOverride().GetRequestBodyMode() != wantMode {
				t.Fatalf("mode: %v", out)
			}
			if buffered {
				return
			}
			// A response may finish while the upload is still in progress.
			out, err = s.HandleResponseHeaders(
				ctx,
				&extProcPb.HttpHeaders{
					Headers: &corepb.HeaderMap{Headers: []*corepb.HeaderValue{{Key: ":status", Value: "200"}}},
				},
				state,
			)
			if err != nil {
				t.Fatal(err)
			}
			if out[0].ModeOverride.RequestBodyMode != wantMode ||
				out[0].ModeOverride.RequestTrailerMode != extProcV3.ProcessingMode_SEND {
				t.Fatal("response disabled upload")
			}
			if _, err = s.HandleResponseBody(
				ctx,
				&extProcPb.HttpBody{Body: []byte("ok"), EndOfStream: true},
				state,
			); err != nil {
				t.Fatal(err)
			}
			s.finishAfterSend(ctx, state)
			if state.lifecycle == lifecycleFinalized {
				t.Fatal("audit finalized before upload")
			}
			out, err = s.HandleRequestBody(ctx, &extProcPb.HttpBody{Body: []byte("upload")}, state)
			if err != nil || len(out) != 1 || out[0].GetRequestBody() == nil ||
				out[0].GetRequestBody().GetResponse().GetBodyMutation() != nil {
				t.Fatalf("upload: %v %v", out, err)
			}
			out, err = s.handleTrailers(ctx, &extProcPb.HttpTrailers{}, state, false)
			if err != nil {
				t.Fatal(err)
			}
			if len(out) != 1 || out[0].GetRequestTrailers() == nil {
				t.Fatalf("trailer completion: %v", out)
			}
			s.finishAfterSend(ctx, state)
			if state.lifecycle != lifecycleFinalized {
				t.Fatal("audit never finalized")
			}
		})
	}
}

// Request body consumers must see the target authorized after all headers ran.
type authorizedChunkProbe struct {
	filter.PassThrough
	target *filter.UpstreamTarget
	calls  int
	t      *testing.T
}

func (p *authorizedChunkProbe) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(filter.IncrementalBody), nil
}

func (p *authorizedChunkProbe) OnRequestBody(
	_ context.Context,
	st *filter.Stream,
	_ filter.Body,
) (filter.Action, error) {
	p.calls++
	if st.Upstream == nil || *st.Upstream.Address != *p.target.Address {
		p.t.Fatalf("body missed authorized target: %v", st.Upstream)
	}
	if st.Request.Host != "original.example" {
		p.t.Fatal("body lost original request view")
	}
	return filter.Continue(), nil
}

func TestStreamingAuthorizesBeforeBodyAndCommitsHeaders(t *testing.T) {
	for _, deny := range []bool{false, true} {
		for _, endStream := range []bool{false, true} {
			target := upstreamRoute("192.0.2.9:8443", true)
			probe := &authorizedChunkProbe{target: target.Upstream, t: t}
			reg := fixedReg("capture", probe)

			regs := []filter.Registration{
				reg,
				fixedRegHeaders("rewrite", filter.Continue(filter.SetHeader(":authority", "rewritten.example"))),
			}
			authorized := 0
			s := NewServer(ServerDeps{
				Registrations: regs,
				Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
					return engine.Resolution{Units: []engine.Unit{{Cfgs: []any{struct{}{}, struct{}{}}}}}, nil
				},
				AuthorizeRequest: func(_ context.Context, st *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
					authorized++
					if probe.calls != 0 || st.Request.Host != "rewritten.example" {
						t.Fatal("authorization did not precede body or missed later header mutation")
					}
					if deny {
						return nil, &filter.Reply{Status: 403}, nil
					}
					return target.Upstream, nil, nil
				},
			})
			state := newStreamState()
			headers := makeRequestHeaders("original.example", "/", "POST")
			headers.EndOfStream = endStream
			out, err := s.HandleRequestHeaders(t.Context(), headers, makeAttrsWithLabels("test", "pod", ""), state)
			if err != nil {
				t.Fatal(err)
			}
			if authorized != 1 {
				t.Fatalf("authorization calls: %d", authorized)
			}
			if deny {
				if out[0].GetImmediateResponse().GetStatus().GetCode() != 403 || probe.calls != 0 ||
					state.awaitingInput() {
					t.Fatal("denied request reached body processing")
				}
				continue
			}
			if responseUpstream(out[0]).GetFields()[upstreamAddressField].GetStringValue() != "192.0.2.9:8443" {
				t.Fatal("authorized target not committed")
			}
			found := false
			for _, h := range out[0].GetRequestHeaders().GetResponse().GetHeaderMutation().GetSetHeaders() {
				if h.GetHeader().GetKey() == ":authority" &&
					string(h.GetHeader().GetRawValue()) == "rewritten.example" {
					found = true
				}
			}
			if !found {
				t.Fatal("streaming lost pending header mutation")
			}
			if endStream {
				if probe.calls != 1 || state.awaitingInput() {
					t.Fatal("bodyless request did not complete after authorization")
				}
				continue
			}
			if out[0].GetModeOverride().GetRequestBodyMode() != extProcV3.ProcessingMode_STREAMED {
				t.Fatal("incremental request did not select STREAMED")
			}
			for _, last := range []bool{false, true} {
				out, err = s.HandleRequestBody(
					t.Context(),
					&extProcPb.HttpBody{Body: []byte("chunk"), EndOfStream: last},
					state,
				)
				if err != nil || len(out) != 1 || out[0].GetRequestBody() == nil ||
					out[0].GetRequestBody().GetResponse().GetBodyMutation() != nil {
					t.Fatalf("stream output: %v %v", out, err)
				}
			}
			if probe.calls != 2 || authorized != 1 {
				t.Fatal("unexpected body or authorization count")
			}
		}
	}
}

type streamingFixtureFilter struct {
	filter.PassThrough
	path string
}

func (f *streamingFixtureFilter) OnRequestHeaders(_ context.Context, st *filter.Stream) (filter.Action, error) {
	f.path = st.Request.Path
	return filter.NeedBody(filter.IncrementalBody), nil
}

func (f *streamingFixtureFilter) OnRequestBody(
	_ context.Context,
	_ *filter.Stream,
	body filter.Body,
) (filter.Action, error) {
	if f.path == "/deny-request" && bytes.Contains(body.Bytes, []byte("BLOCK")) {
		return filter.Stop(filter.Reply{Status: 403, Details: "fixture_deny"}), nil
	}
	return filter.Continue(), nil
}
func (f *streamingFixtureFilter) OnResponseHeaders(_ context.Context, st *filter.Stream) (filter.Action, error) {
	f.path = st.Request.Path
	return filter.NeedBody(filter.IncrementalBody), nil
}

func (f *streamingFixtureFilter) OnResponseBody(
	_ context.Context,
	_ *filter.Stream,
	body filter.Body,
) (filter.Action, error) {
	if f.path == "/deny-response" && bytes.Contains(body.Bytes, []byte("BLOCK")) {
		return filter.Stop(filter.Reply{Status: 403, Details: "fixture_deny"}), nil
	}
	if f.path == "/mutate-response" {
		return filter.Continue(filter.Mutation{Body: append(bytes.Clone(body.Bytes), '!')}), nil
	}
	return filter.Continue(), nil
}
