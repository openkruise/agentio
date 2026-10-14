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

// auditlog.go is the policy adapter's per-stream StreamLogger: it turns the
// units resolved for one stream into audit.Events once the stream's outcome is
// final. The resolver hands it to the ext_proc adapter, which invokes it
// without knowing what it holds — so the core logger list stays
// policy-ignorant while the attribution stays typed.

package securityprofile

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
)

// streamLogger evaluates one stream's matched units against their audit
// entries at stream end and enqueues the events that fire. One instance is
// built per resolution, closing over that resolution's units.
type streamLogger struct {
	sink  audit.Sink
	units []unit
}

var _ filter.StreamLogger = (*streamLogger)(nil)

// newStreamLogger builds the per-stream logger for one resolution.
func newStreamLogger(sink audit.Sink, units []unit) *streamLogger {
	return &streamLogger{sink: sink, units: units}
}

// Log implements filter.StreamLogger.
func (l *streamLogger) Log(ctx context.Context, st *filter.Stream, info *filter.StreamInfo) {
	result := info.Outcome.String()
	for i := range l.units {
		u := &l.units[i]
		if !u.HasAudits {
			continue
		}
		entries := resolveEntries(u)
		if len(entries) == 0 {
			continue
		}
		scope := buildScope(u, st, result)
		for _, ca := range entries {
			fire, err := audit.EvalWhen(ca.When, &scope)
			if err != nil {
				audit.EvalDroppedTotal.WithLabelValues("when_eval").Inc()
				// Debug rather than error: this fires per request (for
				// example while a profile's inputs are unavailable), so the
				// counter is the alerting signal and this line supplies the
				// attribution an investigation needs.
				log.FromContext(ctx).V(logging.DEBUG).Info("audit event dropped: when expression failed",
					"profile", u.Profile.Meta.Namespace+"/"+u.Profile.Meta.Name,
					"rule", u.Rule.Name, "audit", ca.Name, "error", err)
				continue
			}
			if !fire {
				continue
			}
			l.sink.Enqueue(audit.Event{
				ProfileNN:  profileNN(u.Profile),
				RuleName:   u.Rule.Name,
				ActionName: ca.Name,
				Audit:      ca,
				Scope:      &scope,
			})
		}
	}
}

// resolveEntries applies the override semantics: rule-level audits replace
// the profile-level list when present.
func resolveEntries(u *unit) []*audit.Audit {
	if len(u.Rule.Audits) > 0 {
		return u.Rule.Audits
	}
	return u.Profile.Audits
}

func profileNN(p *Profile) types.NamespacedName {
	if p == nil {
		return types.NamespacedName{}
	}
	return types.NamespacedName{Namespace: p.Meta.Namespace, Name: p.Meta.Name}
}

// buildScope assembles the CEL/template evaluation scope for one unit from
// its immutable per-unit Scope, the stream, and the final result.
// The embedded Scope is copied unconditionally: a nil u.Scope is not a case to
// paper over. A unit that reaches audit without one is a programming error, and
// guarding it here would substitute a zero-value inputs.Scope whose memoisation
// cache is nil — inputs.Scope.Activation panics on exactly that (inputs/scope.go:90),
// so the nil check would create the crash it looks like it prevents. The only
// caller already guards on u.HasAudits, which implies a resolved unit.
func buildScope(u *unit, st *filter.Stream, result string) audit.Scope {
	var content map[string]any
	if r, ok := st.Info.Content(u.ID); ok {
		content = contentFields(r)
	}
	if r, ok := st.Info.ResponseContent(u.ID); ok {
		if content == nil {
			content = make(map[string]any)
		}
		content["response"] = contentFields(r)
	}
	return audit.Scope{
		Scope:   *u.Scope,
		Content: content,
		Result:  result,
		Matched: buildMatch(u, &st.Request),
	}
}

func contentFields(r filter.ContentRecord) map[string]any {
	return map[string]any{
		"status":        r.Status,
		"bytesSeen":     r.BytesSeen,
		"capturedBytes": r.CapturedBytes,
		"content":       r.Content,
	}
}

// buildMatch reports the RuleMatch clause that fired, populated only with
// the dimensions that clause actually constrained — reconstructed from the
// MatchIndex precomputed at unit resolution.
func buildMatch(u *unit, req *httpreq.HTTPRequest) audit.Match {
	m := audit.Match{Host: req.Host}
	if u.MatchIndex < 0 || u.MatchIndex >= len(u.Rule.Matches) {
		return m
	}
	rm := &u.Rule.Matches[u.MatchIndex]
	if len(rm.Methods) > 0 {
		m.Method = req.Method
	}
	if len(rm.Paths) > 0 {
		m.Path = req.Path
	}
	if len(rm.Ports) > 0 {
		m.Port = req.Port
	}
	if len(rm.Headers) > 0 {
		m.Headers = make(map[string]string, len(rm.Headers))
		for _, h := range rm.Headers {
			m.Headers[h.Name] = req.Headers[h.Name]
		}
	}
	if len(rm.QueryParams) > 0 {
		m.QueryParams = make(map[string]string, len(rm.QueryParams))
		for _, q := range rm.QueryParams {
			if vals, ok := req.Query[q.Name]; ok && len(vals) > 0 {
				m.QueryParams[q.Name] = vals[0]
			}
		}
	}
	return m
}
