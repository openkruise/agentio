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
	"testing"

	"github.com/go-logr/logr"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// A headers-phase body mutation under plain CONTINUE is silently dropped
// by Envoy; the adapter must use CONTINUE_AND_REPLACE.
func TestTranslate_HeadersBodyMutationUsesContinueAndReplace(t *testing.T) {
	er := &engine.RequestHeadersResult{
		Disposition: engine.DispositionMutated,
		Body:        []byte("replaced"),
	}
	resp := translateRequestHeadersResult(er, logr.Discard(), filter.Peer{})
	if len(resp) != 1 {
		t.Fatalf("responses = %d, want 1", len(resp))
	}
	common := resp[0].GetRequestHeaders().GetResponse()
	if common.GetStatus() != extProcPb.CommonResponse_CONTINUE_AND_REPLACE {
		t.Errorf("Status = %v, want CONTINUE_AND_REPLACE — plain CONTINUE drops body mutations", common.GetStatus())
	}
	if string(common.GetBodyMutation().GetBody()) != "replaced" {
		t.Errorf("BodyMutation = %q", common.GetBodyMutation().GetBody())
	}
	if got, ok := mutationSetValue(common.GetHeaderMutation(), "content-length"); !ok || got != "8" {
		t.Errorf("content-length = %q present=%v, want 8", got, ok)
	}
}

func TestTranslate_ResponseHeadersBodyMutationUsesContinueAndReplace(t *testing.T) {
	er := &engine.ResponseHeadersResult{
		Disposition: engine.DispositionMutated,
		HeaderOps: []filter.HeaderOp{
			{Kind: filter.HeaderSet, Name: "x-response", Value: "mutated"},
		},
		Body: []byte("replaced"),
	}
	resp := translateResponseHeadersResult(er)
	if len(resp) != 1 {
		t.Fatalf("responses = %d, want 1", len(resp))
	}
	common := resp[0].GetResponseHeaders().GetResponse()
	if common.GetStatus() != extProcPb.CommonResponse_CONTINUE_AND_REPLACE {
		t.Errorf("Status = %v, want CONTINUE_AND_REPLACE", common.GetStatus())
	}
	if string(common.GetBodyMutation().GetBody()) != "replaced" {
		t.Errorf("BodyMutation = %q", common.GetBodyMutation().GetBody())
	}
	if got, ok := mutationSetValue(common.GetHeaderMutation(), "x-response"); !ok || got != "mutated" {
		t.Errorf("x-response = %q present=%v, want mutated", got, ok)
	}
	if got, ok := mutationSetValue(common.GetHeaderMutation(), "content-length"); !ok || got != "8" {
		t.Errorf("content-length = %q present=%v, want 8", got, ok)
	}
}

func TestTranslate_ResponseBodyCarriesHeadersBodyStatusAndLength(t *testing.T) {
	status := 202
	result := &engine.ResponseBodyResult{
		Disposition: engine.DispositionMutated,
		HeaderOps: []filter.HeaderOp{
			{Kind: filter.HeaderSet, Name: "x-result", Value: "ok"},
		},
		Body:       []byte("rewritten"),
		StatusCode: &status,
	}
	responses := translateResponseBodyResult(result)
	if len(responses) != 1 {
		t.Fatalf("responses = %d, want 1", len(responses))
	}
	common := responses[0].GetResponseBody().GetResponse()
	if common == nil {
		t.Fatal("missing ResponseBody CommonResponse")
	}
	if string(common.GetBodyMutation().GetBody()) != "rewritten" {
		t.Fatalf("BodyMutation = %q", common.GetBodyMutation().GetBody())
	}
	for name, want := range map[string]string{
		"x-result":       "ok",
		"content-length": "9",
		":status":        "202",
	} {
		if got, ok := mutationSetValue(common.GetHeaderMutation(), name); !ok || got != want {
			t.Errorf("%s = %q present=%v, want %q", name, got, ok, want)
		}
	}
}

func TestTranslate_ResponseHeadersStatusWithoutBody(t *testing.T) {
	status := 204
	responses := translateResponseHeadersResult(&engine.ResponseHeadersResult{
		Disposition: engine.DispositionMutated,
		StatusCode:  &status,
	})
	common := responses[0].GetResponseHeaders().GetResponse()
	if got, ok := mutationSetValue(common.GetHeaderMutation(), ":status"); !ok || got != "204" {
		t.Fatalf(":status = %q present=%v, want 204", got, ok)
	}
}

func TestTranslate_ExplicitEmptyResponseBodySetsZeroLength(t *testing.T) {
	responses := translateResponseBodyResult(&engine.ResponseBodyResult{
		Disposition: engine.DispositionMutated,
		Body:        []byte{},
	})
	common := responses[0].GetResponseBody().GetResponse()
	if common.GetBodyMutation() == nil {
		t.Fatal("explicit empty body was treated as unchanged")
	}
	if got, ok := mutationSetValue(common.GetHeaderMutation(), "content-length"); !ok || got != "0" {
		t.Fatalf("content-length = %q present=%v, want 0", got, ok)
	}
}

func TestTranslate_BlockedResponseBodyUsesReplyAndDiscardsMutations(t *testing.T) {
	status := 202
	responses := translateResponseBodyResult(&engine.ResponseBodyResult{
		Disposition: engine.DispositionBlocked,
		Reply:       filter.Reply{Status: 500, Details: "failed-closed"},
		HeaderOps:   []filter.HeaderOp{{Kind: filter.HeaderSet, Name: "x-leak", Value: "bad"}},
		Body:        []byte("leak"),
		StatusCode:  &status,
	})
	immediate := responses[0].GetImmediateResponse()
	if immediate.GetStatus().GetCode() != 500 || immediate.GetDetails() != "failed-closed" {
		t.Fatalf("ImmediateResponse = %+v", immediate)
	}
	if immediate.GetHeaders() != nil || len(immediate.GetBody()) != 0 {
		t.Fatalf("blocked result leaked pending mutations: %+v", immediate)
	}
}

// Envoy applies ImmediateResponse.Headers as a HeaderMutation to the response
// it synthesizes, so each op kind must survive the crossing intact — an
// unset AppendAction would silently append where the filter asked to overwrite.
func TestTranslate_ImmediateReplyRendersHeaderOpsInOrder(t *testing.T) {
	response := immediateFromReply(filter.Reply{
		Status: 403,
		HeaderOps: []filter.HeaderOp{
			{Kind: filter.HeaderSet, Name: "content-type", Value: "application/json"},
			{Kind: filter.HeaderAdd, Name: "set-cookie", Value: "a=1"},
			{Kind: filter.HeaderAdd, Name: "set-cookie", Value: "b=2"},
			{Kind: filter.HeaderRemove, Name: "x-upstream"},
		},
	})
	headers := response.GetImmediateResponse().GetHeaders()
	set := headers.GetSetHeaders()
	if len(set) != 3 {
		t.Fatalf("SetHeaders = %d, want 3", len(set))
	}
	wantSet := []struct {
		name   string
		value  string
		action corev3.HeaderValueOption_HeaderAppendAction
	}{
		{"content-type", "application/json", corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD},
		{"set-cookie", "a=1", corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD},
		{"set-cookie", "b=2", corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD},
	}
	for i, want := range wantSet {
		got := set[i]
		if got.GetHeader().GetKey() != want.name || string(got.GetHeader().GetRawValue()) != want.value {
			t.Errorf("SetHeaders[%d] = %s: %q, want %s: %q", i,
				got.GetHeader().GetKey(), got.GetHeader().GetRawValue(), want.name, want.value)
		}
		if got.GetAppendAction() != want.action {
			t.Errorf("SetHeaders[%d] AppendAction = %v, want %v", i, got.GetAppendAction(), want.action)
		}
	}
	if remove := headers.GetRemoveHeaders(); len(remove) != 1 || remove[0] != "x-upstream" {
		t.Errorf("RemoveHeaders = %v, want [x-upstream]", remove)
	}
}

func TestTranslate_ImmediateReplyWithoutHeaderOpsOmitsHeaders(t *testing.T) {
	response := immediateFromReply(filter.Reply{Status: 403, Details: "denied"})
	if got := response.GetImmediateResponse().GetHeaders(); got != nil {
		t.Fatalf("Headers = %+v, want nil for an op-free reply", got)
	}
	response = immediateFromReply(filter.Reply{Status: 403, HeaderOps: []filter.HeaderOp{}})
	if got := response.GetImmediateResponse().GetHeaders(); got != nil {
		t.Fatalf("Headers = %+v, want nil for an empty op list", got)
	}
}

// A BUFFERED body rewrite with a stale content-length is a hard 500; the
// adapter must set a matching content-length with the mutation.
func TestTranslate_BodyPhaseRewriteSetsContentLength(t *testing.T) {
	br := &engine.RequestBodyResult{
		Disposition: engine.DispositionMutated,
		Body:        []byte("new-body!"),
	}
	resp := translateRequestBodyResult(br)
	if len(resp) != 1 {
		t.Fatalf("responses = %d, want 1", len(resp))
	}
	common := resp[0].GetRequestBody().GetResponse()
	if string(common.GetBodyMutation().GetBody()) != "new-body!" {
		t.Fatalf("BodyMutation = %q", common.GetBodyMutation().GetBody())
	}
	found := false
	for _, h := range common.GetHeaderMutation().GetSetHeaders() {
		if h.GetHeader().GetKey() == "content-length" {
			found = true
			if got := string(h.GetHeader().GetRawValue()); got != "9" {
				t.Errorf("content-length = %q, want 9", got)
			}
		}
	}
	if !found {
		t.Error("no content-length header set alongside the body rewrite")
	}
}

// Path rewriting must preserve the caller's explicit cache decision.
func TestTranslate_PathOpHonorsClearRouteCache(t *testing.T) {
	for _, clear := range []bool{false, true} {
		er := &engine.RequestHeadersResult{
			Disposition: engine.DispositionMutated,
			HeaderOps:   []filter.HeaderOp{{Kind: filter.HeaderSet, Name: ":path", Value: "/new"}},
			Route:       &filter.RouteMutation{ClearCache: clear},
		}
		resp := translateRequestHeadersResult(er, logr.Discard(), filter.Peer{})
		common := resp[0].GetRequestHeaders().GetResponse()
		if common.GetClearRouteCache() != clear {
			t.Errorf("path rewrite did not preserve clearRouteCache=%v", clear)
		}
	}
}

// Engine-side: a filter's Mutation.Body flows into the result, last writer
// in execution order wins.
func TestEval_BodyMutationLastWriterWins(t *testing.T) {
	regA := fixedRegHeaders("a", filter.Continue(filter.Mutation{Body: []byte("one")}))
	regB := fixedRegHeaders("b", filter.Continue(filter.Mutation{Body: []byte("two")}))
	e := engine.NewEngine([]filter.Registration{regA, regB}, 0)
	units := []engine.Unit{{ID: filter.UnitID{Scope: "ns/p", Name: "r"}, Cfgs: []any{struct{}{}, struct{}{}}}}
	er, err := e.EvalRequestHeaders(t.Context(), &filter.Stream{}, units)
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if er.Body == nil || string(er.Body) != "two" {
		t.Fatalf("Body = %q, want last writer 'two'", er.Body)
	}
	if er.Disposition != engine.DispositionMutated {
		t.Errorf("Disposition = %v, want Mutated", er.Disposition)
	}
}

func fixedRegHeaders(name string, act filter.Action) filter.Registration {
	return filter.Registration{
		Name:   name,
		Phases: filter.PhaseRequestHeaders,
		Parse:  func(json.RawMessage) (any, error) { return struct{}{}, nil },
		New: func(filter.ErasedRuleConfig) filter.Filter {
			return &actionFilter{act: act}
		},
	}
}

func mutationSetValue(mutation *extProcPb.HeaderMutation, name string) (string, bool) {
	for _, h := range mutation.GetSetHeaders() {
		if h.GetHeader().GetKey() == name {
			return string(h.GetHeader().GetRawValue()), true
		}
	}
	return "", false
}

type actionFilter struct {
	filter.PassThrough
	act filter.Action
}

func (f *actionFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return f.act, nil
}
