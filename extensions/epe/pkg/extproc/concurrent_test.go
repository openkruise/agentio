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
	"fmt"
	"sync"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// One Server serves every stream, so everything it holds — registrations,
// pre-resolved metrics children, the package-level pass-through singletons — is
// shared. Until this test existed the suite drove one stream at a time, which
// means a green `-race` said nothing whatever about cross-stream safety.
//
// The registrations below build a FRESH filter per invocation on purpose. The
// other tests in this package share one instance and let it count calls, which is
// fine serially but would itself race here — and a fixture race would drown out
// the production race this test exists to find.

// concurrentReqFilter mutates a request header and asks for the response phase.
// It holds no state, so nothing it does can race.
type concurrentReqFilter struct {
	filter.PassThrough
	value string
}

func (f *concurrentReqFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.Continue(filter.SetHeader("x-req", f.value)), nil
}

func (f *concurrentReqFilter) OnResponseHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.Continue(filter.SetHeader("x-resp", f.value)), nil
}

// concurrentPauseFilter forces the body phase, so each stream also exercises the
// continuation and the resumed walk.
type concurrentPauseFilter struct {
	filter.PassThrough
}

func (f *concurrentPauseFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(filter.CompleteBody), nil
}

func (f *concurrentPauseFilter) OnRequestBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	return filter.Continue(), nil
}

// concurrentServer builds a Server whose resolver yields one unit per stream,
// each carrying a per-stream value so a leaked mutation between streams shows up
// as a wrong value rather than merely as a race.
func concurrentServer(t *testing.T) *Server {
	t.Helper()
	pause := filter.Registration{
		Name:    "pause",
		Phases:  filter.PhaseRequestHeaders | filter.PhaseRequestBody,
		OnError: func(any) filter.FailurePolicy { return filter.FailClosed },
		Parse:   func(json.RawMessage) (any, error) { return struct{}{}, nil },
		New:     func(filter.ErasedRuleConfig) filter.Filter { return &concurrentPauseFilter{} },
	}
	resp := filter.Registration{
		Name:       "resp",
		Phases:     filter.PhaseRequestHeaders | filter.PhaseResponseHeaders,
		OnError:    func(any) filter.FailurePolicy { return filter.FailClosed },
		Parse:      func(json.RawMessage) (any, error) { return struct{}{}, nil },
		Subscribes: func(any) filter.Phase { return filter.PhaseResponseHeaders },
		New: func(cfg filter.ErasedRuleConfig) filter.Filter {
			// The config carries this stream's value, so the filter instance is
			// per-invocation and immutable.
			v, _ := cfg.Cfg.(string)
			return &concurrentReqFilter{value: v}
		},
	}
	regs := []filter.Registration{pause, resp}
	return NewServer(ServerDeps{
		Resolve: func(_ context.Context, pod inputs.Pod, _ *httpreq.HTTPRequest) (engine.Resolution, error) {
			// pod.Name identifies the stream; the unit's config carries it
			// through to the filter.
			return engine.Resolution{Units: []engine.Unit{{
				ID:    filter.UnitID{Scope: "default/p1", Name: pod.Name},
				Scope: inputs.NewScope(inputs.Request{}, inputs.Pod{}, inputs.Profile{}, inputs.Rule{}, nil),
				Cfgs:  []any{struct{}{}, pod.Name},
			}}}, nil
		},
		Registrations: regs,
	})
}

func concurrentMessages(pod string) []*extProcPb.ProcessingRequest {
	headers := makeRequestHeaders("api.example.com", "/x", "POST")
	return []*extProcPb.ProcessingRequest{
		{
			Request:    &extProcPb.ProcessingRequest_RequestHeaders{RequestHeaders: headers},
			Attributes: makeAttrsWithLabels("default", pod, testLabelsB64),
		},
		{Request: &extProcPb.ProcessingRequest_RequestBody{
			RequestBody: &extProcPb.HttpBody{Body: []byte("payload"), EndOfStream: true},
		}},
		{Request: &extProcPb.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extProcPb.HttpHeaders{Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
				{Key: ":status", RawValue: []byte("200")},
			}}},
		}},
	}
}

// setHeaderValue returns the value a response HeaderMutation sets for name.
func setHeaderValue(resp *extProcPb.ProcessingResponse, name string) (string, bool) {
	mut := resp.GetResponseHeaders().GetResponse().GetHeaderMutation()
	for _, h := range mut.GetSetHeaders() {
		if h.GetHeader().GetKey() == name {
			return string(h.GetHeader().GetRawValue()), true
		}
	}
	return "", false
}

func TestProcess_ConcurrentStreamsDoNotShareState(t *testing.T) {
	const streams = 24
	s := concurrentServer(t)

	var wg sync.WaitGroup
	results := make([]*collectingStream, streams)
	errs := make([]error, streams)
	for i := 0; i < streams; i++ {
		i := i
		pod := fmt.Sprintf("pod-%02d", i)
		stream := &collectingStream{ctx: context.Background(), msgs: concurrentMessages(pod)}
		results[i] = stream
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.Process(stream)
		}()
	}
	wg.Wait()

	for i, stream := range results {
		pod := fmt.Sprintf("pod-%02d", i)
		if errs[i] != nil {
			t.Errorf("stream %s: Process = %v, want nil", pod, errs[i])
			continue
		}
		// headers ack, body ack, response headers.
		if len(stream.sent) != 3 {
			t.Errorf("stream %s: sent %d responses, want 3", pod, len(stream.sent))
			continue
		}
		// The ModeOverride must open the response phase for every stream: one
		// stream's override must not satisfy or suppress another's.
		mode := stream.sent[0].GetModeOverride()
		if mode == nil || mode.GetResponseHeaderMode() != extProcV3.ProcessingMode_SEND {
			t.Errorf("stream %s: ModeOverride = %v, want ResponseHeaderMode SEND", pod, mode)
		}
		// The response mutation must carry THIS stream's value. A shared demand
		// map or a shared response proto would show up here as another pod's
		// value, or as a missing mutation.
		got, ok := setHeaderValue(stream.sent[2], "x-resp")
		if !ok {
			t.Errorf("stream %s: response headers carried no x-resp mutation", pod)
			continue
		}
		if got != pod {
			t.Errorf("stream %s: x-resp = %q, want %q — a mutation leaked between streams", pod, got, pod)
		}
	}
}

// The pass-through singletons are shared across streams by design, so a handler
// that ever attached a per-stream ModeOverride to one would corrupt every other
// stream. cloneResponse exists for exactly that reason; this pins that the
// response-phase ack is never mutated in place either.
func TestProcess_SharedAcksAreNeverMutated(t *testing.T) {
	beforePassThrough := defaultPassThrough[0].GetModeOverride()
	beforeBody := defaultPassThroughBody[0].GetModeOverride()
	beforeRespAck := emptyResponseHeadersAck[0].GetResponseHeaders().GetResponse()

	s := concurrentServer(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		pod := fmt.Sprintf("pod-%02d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Process(&collectingStream{ctx: context.Background(), msgs: concurrentMessages(pod)})
		}()
	}
	wg.Wait()

	if got := defaultPassThrough[0].GetModeOverride(); got != beforePassThrough {
		t.Errorf("defaultPassThrough gained a ModeOverride %v: the shared proto was mutated", got)
	}
	if got := defaultPassThroughBody[0].GetModeOverride(); got != beforeBody {
		t.Errorf("defaultPassThroughBody gained a ModeOverride %v: the shared proto was mutated", got)
	}
	if got := emptyResponseHeadersAck[0].GetResponseHeaders().GetResponse(); got != beforeRespAck {
		t.Errorf("emptyResponseHeadersAck gained a CommonResponse %v: the shared proto was mutated", got)
	}
}
