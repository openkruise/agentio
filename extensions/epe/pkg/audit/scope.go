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
// Package audit hosts the audit domain entities of the SecurityProfile
// Audit action: an asynchronous, fire-and-forget callback fired after a
// matched request resolves. Audit never alters the upstream response.
//
// The stream logger that observes matched rules and emits events lives in
// pkg/policy/securityprofile, beside the binder that resolves them; sink
// implementations (e.g. the webhook dispatcher) consume the Event/Scope types
// defined here.
package audit

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/interpreter"

	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// Scope is the template root passed to URL / header / body renderers and
// the CEL `when` evaluator. It embeds the shared inputs.Scope, so the
// promoted Request/Pod/Profile/Rule accessor methods resolve the documented
// template paths ({{ .Request.* }}, {{ .Pod.* }}, ...) — text/template treats
// an exported method exactly as it treats an exported field. Those accessors
// take value receivers, so they promote through the embedded value whether the
// render root is a *Scope or a Scope value; TestAuditScopeRendersTemplatePaths
// pins both. Request inputs are fixed at resolution; outcome and content are
// attached at stream end. All fields are read-only once handed to a sink.
type Scope struct {
	inputs.Scope
	// Content holds this rule's request observation and optional "response"
	// observation, or nil when neither ran. Nested values are read-only.
	Content map[string]any
	// Result is the stream's derived audit outcome, surfaced to SecurityProfile
	// authors as the CEL `result` variable (bound in Activation below, declared
	// in pkg/eval/cel.go). It is one of "error", "blocked", "mutated",
	// "bypassed", or "passthrough" — a partition, in that precedence — derived
	// from what EPE actually told Envoy rather than from what the engine
	// intended; see pkg/extproc/outcome.go for the derivation. Note "bypassed"
	// means a policy unit matched and the message was not modified, not that an
	// exemption fired.
	Result  string
	Matched Match
}

// Activation shadows the embedded inputs.Scope.Activation: the audit projection
// additionally exposes audit-only `result` and `content`. It is layered as a
// hierarchical child rather than written into the base, so the
// base stays immutable and shared with the unit's Scope — which is what makes
// audit see the request exactly as it was evaluated at request time.
//
// This is where every phase-varying variable belongs; the rule is stated on
// inputs.Scope.buildBag, the site it constrains.
func (s *Scope) Activation() cel.Activation {
	top, err := cel.NewActivation(map[string]any{
		"result":  s.Result,
		"content": s.Content,
	})
	if err != nil {
		// Unreachable: NewActivation rejects only nil and non-map bindings.
		panic("audit: activation: " + err.Error())
	}
	// (parent, child): NewHierarchicalActivation resolves the child first and
	// falls back to the parent, so the base goes first and the audit-only
	// bindings second. Swapping them is currently unobservable — the two key
	// sets are disjoint, so nothing shadows anything and no test can tell the
	// difference. Whoever adds the first child that deliberately overrides a
	// base variable has to check this line by hand: the base's keys come from
	// inputs.buildBag, and a test in this package cannot make one collide.
	return interpreter.NewHierarchicalActivation(s.Scope.Activation(), top)
}

// MatchedCriteria is a template-compatibility accessor: documented webhook
// templates reference {{ .MatchedCriteria.* }}, so it must keep returning
// Matched.
func (s *Scope) MatchedCriteria() Match {
	return s.Matched
}

// Match reports the matched RuleMatch entry as a flat view.
// A field is left zero when the RuleMatch did not constrain that
// dimension.
type Match struct {
	Host        string
	Method      string
	Path        string
	Port        int32
	Headers     map[string]string
	QueryParams map[string]string
}
