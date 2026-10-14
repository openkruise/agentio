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
	"time"
)

// Disposition is both the engine's per-walk control-flow verdict and the
// vocabulary the audit outcome is rendered in. Filters never name it: the
// engine derives the walk's own value from which Action constructor won, and
// extproc derives the stream's audit value from what it actually sent Envoy.
type Disposition uint8

const (
	DispositionPassthrough Disposition = iota
	DispositionMutated
	DispositionBlocked
	DispositionBypassed
	DispositionError
)

// String returns the audit-visible outcome string.
func (d Disposition) String() string {
	switch d {
	case DispositionMutated:
		return "mutated"
	case DispositionBlocked:
		return "blocked"
	case DispositionBypassed:
		return "bypassed"
	case DispositionError:
		return "error"
	default:
		return "passthrough"
	}
}

// UnitAction is one filter's action on one policy unit.
type UnitAction struct {
	Filter string
	Kind   UnitActionKind
}

// UnitRecord is one matched policy unit and what each filter did to it.
type UnitRecord struct {
	ID            UnitID
	FilterActions []UnitAction
}

// FilterRecord is one filter invocation as the framework observed it.
// Incremental body callbacks aggregate duration and outcome per consumer.
type FilterRecord struct {
	Filter   string
	Phase    string
	Outcome  string
	Duration time.Duration
	// Err carries the filter's error even when a fail-open policy
	// swallowed it.
	Err error
}

// StreamInfo accumulates execution records and bounded content observations.
// Peer/Request/Response live on Stream.
type StreamInfo struct {
	// content holds bounded, owned observations written by content filters.
	// Entries are replaced, never mutated, so a sink can retain a completed record.
	content         map[UnitID]ContentRecord
	responseContent map[UnitID]ContentRecord
	Matched         []UnitRecord
	Filters         []FilterRecord
	// Outcome is written exactly once, at stream end, by the ext_proc layer —
	// derived from the responses it actually sent, the stream's error, and
	// len(Matched). The engine deliberately does not accumulate it: an outcome
	// tracked as filters decide would keep claiming enforcement that the
	// translation layer dropped.
	Outcome Disposition
	// Error records the failure that resolved the stream, when one did.
	Error string
}

// ContentRecord describes content capture, independently of enforcement.
// Content is an owned JSON-native value; complete or truncated observations may carry it.
type ContentRecord struct {
	Status        string `json:"status"`
	BytesSeen     int64  `json:"bytesSeen"`
	CapturedBytes int    `json:"capturedBytes"`
	Content       any    `json:"content"`
}

// RecordContent replaces this unit's observation. The caller transfers ownership
// of Content and must not modify it afterwards. Calls are serialized with the stream.
func (i *StreamInfo) RecordContent(id UnitID, record ContentRecord) {
	if i == nil {
		return
	}
	if i.content == nil {
		i.content = make(map[UnitID]ContentRecord)
	}
	i.content[id] = record
}

// Content returns a read-only observation for one matched unit.
func (i *StreamInfo) Content(id UnitID) (ContentRecord, bool) {
	if i == nil {
		return ContentRecord{}, false
	}
	r, ok := i.content[id]
	return r, ok
}

// RecordResponseContent replaces the response observation without overwriting
// request content. It has the same ownership contract as RecordContent.
func (i *StreamInfo) RecordResponseContent(id UnitID, record ContentRecord) {
	if i == nil {
		return
	}
	if i.responseContent == nil {
		i.responseContent = make(map[UnitID]ContentRecord)
	}
	i.responseContent[id] = record
}

// ResponseContent returns a read-only response observation for one matched unit.
func (i *StreamInfo) ResponseContent(id UnitID) (ContentRecord, bool) {
	if i == nil {
		return ContentRecord{}, false
	}
	r, ok := i.responseContent[id]
	return r, ok
}

// NewStreamInfo builds an empty info for one stream.
func NewStreamInfo() *StreamInfo {
	return &StreamInfo{}
}

// UnitActionKind names what a filter did to one policy unit, for audit. It is
// deliberately not ActionKind, which names what a filter *decided*
// (action.go:20): this vocabulary is a projection of that one onto what an
// operator can see, and the two differ — error-open has no Action counterpart,
// and mutate is inferred from pending mutations rather than from any kind.
//
// It is a distinct type so a kind outside the vocabulary below cannot be
// recorded by accident: an unconverted string literal does not compile.
type UnitActionKind string

// The unit action kinds. They live here rather than in the engine because both
// ends need them — the engine records them, and the accesslog reader matches on
// them to decide which are audit-visible actions and which only mark a filter
// as skipped.
const (
	ActionBlock  UnitActionKind = "block"
	ActionBypass UnitActionKind = "bypass"
	ActionMutate UnitActionKind = "mutate"
	// ActionErrorClosed is a block the filter did not choose: it errored and the
	// rule's FailClosed policy answered for it. Distinct from ActionBlock
	// because "the policy denied this" and "the enforcement path broke and we
	// denied to be safe" call for different responses from an operator.
	ActionErrorClosed UnitActionKind = "error-closed"
	// ActionNeedBody is a promise, not an act: the filter asked for a body and
	// deferred its verdict. It only reaches the audit when the promise went
	// unkept, because a filter that got its body records what it then decided.
	ActionNeedBody UnitActionKind = "need-body"
	// ActionErrorOpen is a filter that errored where the rule's FailOpen policy
	// admitted the request anyway — so the rule was not enforced.
	ActionErrorOpen UnitActionKind = "error-open"
)

// RecordUnitAction appends one action to the unit's record, creating it on first
// touch. A nil *StreamInfo is a no-op: a Stream may carry no info (filters and
// tests build one without), and every call site would otherwise restate that
// guard.
func (i *StreamInfo) RecordUnitAction(id UnitID, filterName string, kind UnitActionKind) {
	if i == nil {
		return
	}
	action := UnitAction{Filter: filterName, Kind: kind}
	for idx := range i.Matched {
		if i.Matched[idx].ID == id {
			i.Matched[idx].FilterActions = append(i.Matched[idx].FilterActions, action)
			return
		}
	}
	i.Matched = append(i.Matched, UnitRecord{ID: id, FilterActions: []UnitAction{action}})
}

// RecordFilter appends one filter invocation record. A nil *StreamInfo is a
// no-op, as for RecordUnitAction.
func (i *StreamInfo) RecordFilter(rec FilterRecord) {
	if i == nil {
		return
	}
	i.Filters = append(i.Filters, rec)
}

// StreamLogger observes the completed stream. It is invoked exactly once
// per stream, at true stream end — including abnormal termination (ctx
// cancellation, Envoy reset, budget exhaustion). Implementations must not
// block.
type StreamLogger interface {
	Log(ctx context.Context, st *Stream, info *StreamInfo)
}
