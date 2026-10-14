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
package auditlog

import (
	"context"
	"slices"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

type captureLogger struct{ fn func(Entry) }

func (c *captureLogger) Submit(r Record) {
	if e, ok := r.(Entry); ok {
		c.fn(e)
	}
}

// logOne runs record against a fresh StreamInfo and returns the logged entry.
func logOne(t *testing.T, record func(*filter.StreamInfo)) Entry {
	t.Helper()
	var got Entry
	s := NewStreamLog(&captureLogger{fn: func(e Entry) { got = e }})
	info := filter.NewStreamInfo()
	record(info)
	s.Log(context.Background(), &filter.Stream{}, info)
	return got
}

// Actions must name what the filter did, not merely that it acted. Under the
// derived outcome an explicit bypass is no longer visible in Outcome — a
// bypass after a mutation reports "mutated", and a matched-but-inert stream
// reports "bypassed" without any bypass having fired — so the kind here is the
// only place an exemption is recorded.
func TestStreamLog_ActionsCarryTheKind(t *testing.T) {
	var got Entry
	l := &captureLogger{fn: func(e Entry) { got = e }}
	s := NewStreamLog(l)

	// UnitID is {Scope, Name, Ordinal} where Scope is "<ns>/<profile>"
	// (engine/filter/rule.go:25-32); String() renders "<scope>/<name>#<ordinal>".
	unit := filter.UnitID{Scope: "ns/p", Name: "r", Ordinal: 0}
	info := filter.NewStreamInfo()
	info.RecordUnitAction(unit, "block", filter.ActionBlock)
	info.RecordUnitAction(unit, "authz", filter.ActionBypass)
	info.RecordUnitAction(unit, "tokentransform", filter.ActionMutate)

	s.Log(context.Background(), &filter.Stream{}, info)

	want := []string{
		"block:block:" + unit.String(),
		"authz:bypass:" + unit.String(),
		"tokentransform:mutate:" + unit.String(),
	}
	if len(got.Actions) != len(want) {
		t.Fatalf("Actions = %v, want %v", got.Actions, want)
	}
	for i := range want {
		if got.Actions[i] != want[i] {
			t.Errorf("Actions[%d] = %q, want %q", i, got.Actions[i], want[i])
		}
	}
}

var testUnit = filter.UnitID{Scope: "ns/p", Name: "r", Ordinal: 0}

// A fail-closed filter did not choose to deny — its failure policy denied for
// it. Recording that as plain "block" made a broken enforcement path
// indistinguishable from a working one in the only field an operator reads.
func TestStreamLog_FailClosedIsNotAPlainBlock(t *testing.T) {
	got := logOne(t, func(info *filter.StreamInfo) {
		info.RecordUnitAction(testUnit, "authz", filter.ActionErrorClosed)
	})

	want := "authz:error-closed:" + testUnit.String()
	if !slices.Equal(got.Actions, []string{want}) {
		t.Errorf("Actions = %v, want [%s]", got.Actions, want)
	}
	if len(got.Skipped) != 0 {
		t.Errorf("Skipped = %v, want empty — the request was denied, so the filter acted", got.Skipped)
	}
}

// Both reasons a rule can go unenforced must name the rule, not just the
// filter: "which rule stopped being enforced" is the question, and a count
// keyed by filter name could not answer it.
func TestStreamLog_SkippedNamesTheReasonAndTheRule(t *testing.T) {
	tests := []struct {
		name string
		kind filter.UnitActionKind
	}{
		{"filter errored and the policy admitted the request", filter.ActionErrorOpen},
		{"filter asked for a body that never arrived", filter.ActionNeedBody},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := logOne(t, func(info *filter.StreamInfo) {
				info.RecordUnitAction(testUnit, "mcpacl", tt.kind)
			})

			want := "mcpacl:" + string(tt.kind) + ":" + testUnit.String()
			if !slices.Equal(got.Skipped, []string{want}) {
				t.Errorf("Skipped = %v, want [%s]", got.Skipped, want)
			}
			if len(got.Actions) != 0 {
				t.Errorf("Actions = %v, want empty — the rule went unenforced", got.Actions)
			}
		})
	}
}

// The need-body promise is cancelled by whatever answers it. A filter that got
// its body and then errored open ran exactly once and was skipped exactly once;
// reporting both the unkept promise and the error double-counted it.
func TestStreamLog_ResolvedNeedBodyIsNotAlsoReported(t *testing.T) {
	tests := []struct {
		name     string
		resolve  filter.UnitActionKind
		wantKind filter.UnitActionKind
		acted    bool
	}{
		{"resolved by a verdict", filter.ActionBlock, filter.ActionBlock, true},
		{"resolved by failing open", filter.ActionErrorOpen, filter.ActionErrorOpen, false},
		{"resolved by failing closed", filter.ActionErrorClosed, filter.ActionErrorClosed, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := logOne(t, func(info *filter.StreamInfo) {
				info.RecordUnitAction(testUnit, "mcpacl", filter.ActionNeedBody)
				info.RecordUnitAction(testUnit, "mcpacl", tt.resolve)
			})

			want := "mcpacl:" + string(tt.wantKind) + ":" + testUnit.String()
			field, other := got.Actions, got.Skipped
			if !tt.acted {
				field, other = got.Skipped, got.Actions
			}
			if !slices.Equal(field, []string{want}) {
				t.Errorf("recorded = %v, want exactly [%s]", field, want)
			}
			if len(other) != 0 {
				t.Errorf("the other field = %v, want empty — one run, one record", other)
			}
		})
	}
}

// A promise the same filter made against a different rule is a different
// promise: cancelling one must not cancel the other.
func TestStreamLog_NeedBodyIsTrackedPerRule(t *testing.T) {
	other := filter.UnitID{Scope: "ns/p", Name: "r2", Ordinal: 1}
	got := logOne(t, func(info *filter.StreamInfo) {
		info.RecordUnitAction(testUnit, "mcpacl", filter.ActionNeedBody)
		info.RecordUnitAction(testUnit, "mcpacl", filter.ActionBlock)
		info.RecordUnitAction(other, "mcpacl", filter.ActionNeedBody)
	})

	want := "mcpacl:need-body:" + other.String()
	if !slices.Equal(got.Skipped, []string{want}) {
		t.Errorf("Skipped = %v, want [%s] — only the unanswered rule", got.Skipped, want)
	}
}

func TestStreamLogExcludesCapturedContent(t *testing.T) {
	entry := logOne(t, func(info *filter.StreamInfo) {
		info.Matched = []filter.UnitRecord{{ID: testUnit}}
		info.RecordContent(testUnit, filter.ContentRecord{Status: "complete", Content: "request-only"})
		info.RecordResponseContent(testUnit, filter.ContentRecord{Status: "complete", Content: "response-only"})
	})
	logger, sink := newRecorderLogger()
	entry.emit(logger)
	fields := kvMap(sink.snapshot()[0].kvs)
	for _, key := range []string{"content", "requestContent", "responseContent"} {
		if _, present := fields[key]; present {
			t.Fatalf("access log contains %s: %v", key, fields)
		}
	}
}
