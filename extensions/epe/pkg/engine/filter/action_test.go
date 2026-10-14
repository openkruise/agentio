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

import (
	"context"
	"testing"
)

func TestActionConstructorsAndKinds(t *testing.T) {
	m := SetHeader("x-a", "1")

	c := Continue(m)
	if c.Kind() != KindContinue {
		t.Errorf("Continue Kind = %v, want KindContinue", c.Kind())
	}
	if len(c.Mutations()) != 1 {
		t.Errorf("Continue Mutations = %d, want 1", len(c.Mutations()))
	}
	if _, ok := c.Reply(); ok {
		t.Error("Continue must not carry a reply")
	}
	s := Stop(Reply{Status: 403, Body: []byte("no")})
	if s.Kind() != KindStop {
		t.Errorf("Stop Kind = %v, want KindStop", s.Kind())
	}
	r, ok := s.Reply()
	if !ok || r.Status != 403 {
		t.Errorf("Stop Reply = %+v ok=%v, want status 403", r, ok)
	}

	bypass := Bypass()
	if bypass.Kind() != KindBypass {
		t.Errorf("Bypass Kind = %v", bypass.Kind())
	}
	if _, ok := bypass.Reply(); ok {
		t.Error("Bypass must not carry a reply")
	}

	n := NeedBody(CompleteBody, m)
	if n.Kind() != KindNeedBody {
		t.Errorf("NeedBody Kind = %v, want KindNeedBody", n.Kind())
	}
	if len(n.Mutations()) != 1 {
		t.Errorf("NeedBody must carry its mutations, got %d", len(n.Mutations()))
	}
}

// Stop takes a Reply only — a block discards mutations by construction, so
// there is no way to hand it any.
func TestStopDiscardsMutationsByConstruction(t *testing.T) {
	if got := Stop(Reply{Status: 451}).Mutations(); got != nil {
		t.Errorf("Stop carries mutations %v, want none", got)
	}
}

func TestActionEqual(t *testing.T) {
	m := SetHeader("k", "v")
	statusAccepted := 202
	statusAcceptedAgain := 202
	statusCreated := 201
	tests := []struct {
		name string
		a, b Action
		want bool
	}{
		{"same continue", Continue(m), Continue(SetHeader("k", "v")), true},
		{"different mutation", Continue(m), Continue(SetHeader("k", "w")), false},
		{"kind mismatch", Continue(), Stop(Reply{}), false},
		{"same stop", Stop(Reply{Status: 403}), Stop(Reply{Status: 403}), true},
		{"different status", Stop(Reply{Status: 403}), Stop(Reply{Status: 451}), false},
		{"same need", NeedBody(CompleteBody), NeedBody(CompleteBody), true},
		{"same mutation status", Continue(Mutation{StatusCode: &statusAccepted}), Continue(Mutation{StatusCode: &statusAcceptedAgain}), true},
		{"different mutation status", Continue(Mutation{StatusCode: &statusAccepted}), Continue(Mutation{StatusCode: &statusCreated}), false},
		{"missing mutation status", Continue(Mutation{StatusCode: &statusAccepted}), Continue(Mutation{}), false},
	}
	for _, tt := range tests {
		if got := tt.a.Equal(tt.b); got != tt.want {
			t.Errorf("%s: Equal = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// PassThrough must continue on every supported phase; capability is
// "which methods a filter overrides", so the default must be inert.
func TestPassThroughSupportedPhasesContinue(t *testing.T) {
	var pt PassThrough
	st := &Stream{}
	ctx := context.Background()

	calls := []struct {
		name string
		call func() (Action, error)
	}{
		{"OnRequestHeaders", func() (Action, error) { return pt.OnRequestHeaders(ctx, st) }},
		{"OnRequestBody", func() (Action, error) { return pt.OnRequestBody(ctx, st, Body{}) }},
		{"OnResponseHeaders", func() (Action, error) { return pt.OnResponseHeaders(ctx, st) }},
		{"OnResponseBody", func() (Action, error) { return pt.OnResponseBody(ctx, st, Body{}) }},
	}
	for _, c := range calls {
		a, err := c.call()
		if err != nil {
			t.Errorf("%s: err = %v", c.name, err)
		}
		if !a.Equal(Continue()) {
			t.Errorf("%s: action = %+v, want Continue()", c.name, a)
		}
	}
}
