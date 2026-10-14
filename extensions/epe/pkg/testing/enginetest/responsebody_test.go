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
package enginetest

import (
	"context"
	"slices"
	"testing"

	extProcV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

type responseBodyObservation struct {
	statuses []int
	headers  []string
	bodies   [][]byte
}

type scenarioResponseBodyFilter struct {
	filter.PassThrough
	observation *responseBodyObservation
	headerName  string
	body        string
	status      int
}

func (f *scenarioResponseBodyFilter) OnResponseHeaders(_ context.Context, st *filter.Stream) (filter.Action, error) {
	f.observation.statuses = append(f.observation.statuses, st.Response.Status)
	f.observation.headers = append(f.observation.headers, st.Response.Headers["x-original"])
	return filter.NeedBody(filter.CompleteBody, filter.SetHeader(f.headerName, "seen")), nil
}

func (f *scenarioResponseBodyFilter) OnResponseBody(_ context.Context, _ *filter.Stream, body filter.Body) (filter.Action, error) {
	f.observation.bodies = append(f.observation.bodies, append([]byte(nil), body.Bytes...))
	statusCode := f.status
	return filter.Continue(filter.Mutation{
		Body:       []byte(f.body),
		StatusCode: &statusCode,
	}), nil
}

func scenarioResponseBodyRegistration(name, headerName, body string, statusCode int, observation *responseBodyObservation) filter.Registration {
	return filter.Registration{
		Name:    name,
		Phases:  filter.PhaseResponseHeaders | filter.PhaseResponseBody,
		OnError: func(any) filter.FailurePolicy { return filter.FailClosed },
		Subscribes: func(any) filter.Phase {
			return filter.PhaseResponseHeaders
		},
		New: func(filter.ErasedRuleConfig) filter.Filter {
			return &scenarioResponseBodyFilter{
				observation: observation,
				headerName:  headerName,
				body:        body,
				status:      statusCode,
			}
		},
	}
}

func TestHarness_ResponseBodyFiltersSeeOriginalInputAndFoldFinalWireResult(t *testing.T) {
	first := &responseBodyObservation{}
	second := &responseBodyObservation{}
	regs := []filter.Registration{
		scenarioResponseBodyRegistration("first", "x-first", "first replacement", 201, first),
		scenarioResponseBodyRegistration("second", "x-second", "final replacement", 202, second),
	}
	resolve := func(_ context.Context, _ inputs.Pod, _ *httpreq.HTTPRequest) (engine.Resolution, error) {
		return engine.Resolution{Units: []engine.Unit{{
			ID:   filter.UnitID{Scope: "test/profile", Name: "response"},
			Cfgs: []any{struct{}{}, struct{}{}},
		}}}, nil
	}
	h := New(t, Options{Resolve: resolve, Registrations: regs})
	verdict := h.Run(t, NewRequest("GET", "server.example.com", "/response").
		Peer("test", "pod", map[string]string{"app": "test"}).
		RequestID("request-1").
		ResponseHeaders(200).
		ResponseHeader("x-original", "yes").
		ResponseBody([]byte("original response")))

	if verdict.Err != nil {
		t.Fatalf("Process: %v", verdict.Err)
	}
	if !verdict.ResponseBodyChanged || string(verdict.ResponseBody) != "final replacement" {
		t.Fatalf("response body changed=%v body=%q", verdict.ResponseBodyChanged, verdict.ResponseBody)
	}
	if verdict.ResponseStatus == nil || *verdict.ResponseStatus != 202 {
		t.Fatalf("ResponseStatus = %v, want 202", verdict.ResponseStatus)
	}
	verdict.RequireResponseHeader(t, "x-first", "seen")
	verdict.RequireResponseHeader(t, "x-second", "seen")
	if verdict.ResponseModeOverride == nil ||
		verdict.ResponseModeOverride.GetResponseBodyMode() != extProcV3.ProcessingMode_BUFFERED {
		t.Fatalf("response ModeOverride = %v, want BUFFERED body", verdict.ResponseModeOverride)
	}
	for name, observation := range map[string]*responseBodyObservation{"first": first, "second": second} {
		if !slices.Equal(observation.statuses, []int{200}) || !slices.Equal(observation.headers, []string{"yes"}) ||
			len(observation.bodies) != 1 || !slices.Equal(observation.bodies[0], []byte("original response")) {
			t.Errorf("%s observation = %+v, want original response", name, observation)
		}
	}
	if verdict.Info == nil || verdict.Info.Outcome != filter.DispositionMutated {
		t.Fatalf("StreamInfo = %+v, want mutated", verdict.Info)
	}
	if len(verdict.AccessLog) != 1 || verdict.AccessLog[0].Outcome != "mutated" {
		t.Fatalf("AccessLog = %+v, want one mutated entry", verdict.AccessLog)
	}
}
