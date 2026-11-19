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

	"k8s.io/apimachinery/pkg/types"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// StreamLog adapts a Logger to the StreamLogger contract: it reduces the
// finished stream to one access entry and separate entries for captured content.
type StreamLog struct {
	l Logger
}

// NewStreamLog wraps l; nil falls back to the no-op logger.
func NewStreamLog(l Logger) *StreamLog {
	if l == nil {
		l = Nop()
	}
	return &StreamLog{l: l}
}

var _ filter.StreamLogger = (*StreamLog)(nil)

// committedKinds are the unit actions that count as "the filter acted", and so
// belong in Actions rather than Skipped. error-closed is one of them: the filter
// broke, but the request was still denied on its behalf.
var committedKinds = map[filter.UnitActionKind]bool{
	filter.ActionBlock:       true,
	filter.ActionBypass:      true,
	filter.ActionMutate:      true,
	filter.ActionErrorClosed: true,
}

// Log implements filter.StreamLogger.
func (s *StreamLog) Log(_ context.Context, st *filter.Stream, info *filter.StreamInfo) {
	workload := st.Caller.Subject.Workload
	entry := Entry{
		Workload:      types.NamespacedName{Namespace: workload.Namespace, Name: workload.Name},
		RequestID:     st.RequestID,
		Method:        st.Request.Method,
		Host:          st.Request.Host,
		Path:          st.Request.Path,
		Units:         len(info.Matched),
		Outcome:       info.Outcome.String(),
		Error:         info.Error,
		Authorization: info.Authorization,
	}

	for _, u := range info.Matched {
		for _, a := range u.FilterActions {
			switch {
			case committedKinds[a.Kind]:
				entry.Actions = append(entry.Actions, unitAction(a, u.ID))
			case a.Kind == filter.ActionErrorOpen || a.Kind == filter.ActionNeedBody:
				entry.Skipped = append(entry.Skipped, unitAction(a, u.ID))
			}
		}
	}

	s.l.Submit(entry)
	content := ContentEntry{
		RequestID: st.RequestID,
		Method:    st.Request.Method,
		Host:      st.Request.Host,
		Path:      st.Request.Path,
	}
	for _, unit := range info.Matched {
		content.Unit = unit.ID.String()
		if record, ok := info.Content(unit.ID); ok {
			content.Direction, content.Record = "request", record
			s.l.Submit(content)
		}
		if record, ok := info.ResponseContent(unit.ID); ok {
			content.Direction, content.Record = "response", record
			s.l.Submit(content)
		}
	}
}

// unitAction renders one recorded action as "<filter>:<kind>:<unit>". Actions
// and Skipped share this format deliberately: a consumer parses one shape, and
// the kind alone says whether the filter acted or failed to.
func unitAction(a filter.UnitAction, id filter.UnitID) string {
	return a.Filter + ":" + string(a.Kind) + ":" + id.String()
}
