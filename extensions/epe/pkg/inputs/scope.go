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
// Package inputs provides the evaluation-scope views and activations that
// feed CEL and template expressions. It contains only expression-visible
// data; extraction and identity types live in extproc/attributes.
package inputs

import (
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
)

// Scope is the unified, read-only evaluation scope shared by the CEL and
// template engines. Every field is fixed at construction and must never be
// written afterwards: the CEL activation is memoised on first use, so a later
// write would leave CEL reading a frozen bag while text/template reads the live
// field, and the two would silently disagree.
//
// It deliberately carries only non-sensitive request context: identity payloads
// such as SandboxToken must never be added here.
type Scope struct {
	request  Request
	workload Workload
	profile  Profile
	rule     Rule
	inputs   map[string]any
	// inputsErr marks the declared inputs as unavailable (for example a
	// ConfigMap-backed input whose ConfigMap does not exist). It poisons only
	// the inputs slot: CEL binds `inputs` to an error value and the template
	// accessor returns an error, so evaluations that never touch inputs are
	// unaffected while every read of inputs fails closed instead of silently
	// seeing an absent key.
	inputsErr string

	cache *activationCache
}

// The accessors below are what text/template resolves: it treats an exported
// method exactly as it treats an exported field, so documented paths such as
// {{ .Request.Header "X-Id" }} and {{ .Pod.Label "app" }} keep working while
// the fields themselves stay unwritable from outside this package. Value
// receivers, so they promote through audit.Scope's embedded value on both
// pointer and value roots.
func (s Scope) Request() Request { return s.request }

// Pod preserves the workload accessor used by existing templates.
func (s Scope) Pod() Workload { return s.workload }

func (s Scope) Profile() Profile { return s.profile }
func (s Scope) Rule() Rule       { return s.rule }

// Inputs returns the resolved inputs map, or an error when the profile's
// declared inputs are unavailable. The two-value form is deliberate:
// text/template aborts execution on a non-nil second return, which is what
// keeps a template that reads {{ .Inputs.x }} from rendering a zero value
// (missingkey=zero) while the backing ConfigMap is missing.
func (s Scope) Inputs() (map[string]any, error) {
	if s.inputsErr != "" {
		return nil, fmt.Errorf("profile inputs unavailable: %s", s.inputsErr)
	}
	return s.inputs, nil
}

// activationCache memoises the projected variable bag for one Scope. It is
// reached through a pointer because audit's buildScope copies inputs.Scope by
// value (policy/securityprofile/auditlog.go:107): a sync.Once stored inline
// would make that copy a go vet copylocks failure, and a copied cache would
// diverge from the original.
//
// The Once protects the memoisation and nothing else. It does not make the
// Scope's fields safe to write, and it does not protect the maps the built
// activation references — those are safe only because they are immutable for
// the stream's life.
type activationCache struct {
	once sync.Once
	act  cel.Activation
}

// ScopeOption adjusts a Scope during NewScope construction, before the
// memoised activation freezes it.
type ScopeOption func(*Scope)

// WithInputsError marks the scope's declared inputs as unavailable. Every
// CEL or template read of inputs then fails with msg instead of observing an
// absent key; evaluations that never touch inputs are unaffected.
func WithInputsError(msg string) ScopeOption {
	return func(s *Scope) { s.inputsErr = msg }
}

// NewScope is the only way to obtain a usable Scope. There is deliberately no
// fallback for a Scope built as a literal: a memoisation that can be silently
// absent is a second construction path whose failure mode is invisible.
func NewScope(
	req Request,
	workload Workload,
	profile Profile,
	rule Rule,
	in map[string]any,
	opts ...ScopeOption,
) *Scope {
	s := &Scope{
		request:  req,
		workload: workload,
		profile:  profile,
		rule:     rule,
		inputs:   in,
		cache:    &activationCache{},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Activation projects the Scope into the CEL variable bag (variables `request`,
// `pod`, `profile`, `rule`, `inputs`), memoised for the Scope's lifetime. The
// audit-only `result` and `response` variables are deliberately absent: audit
// layers them over this base rather than writing into it, so their invisibility
// here is structural rather than a deletion someone has to remember.
//
// Evaluations are cheap and the bag is immutable, so there is nothing to
// release.
func (s *Scope) Activation() cel.Activation {
	if s.cache == nil {
		panic("inputs: Scope was not built with NewScope")
	}
	s.cache.once.Do(func() { s.cache.act = s.build() })
	return s.cache.act
}

// build wraps the projected bag in a cel.Activation. The projection itself is
// buildBag, kept separate so the shape tests can be driven by the bag's real
// contents rather than by a hand-maintained list of slots.
func (s *Scope) build() cel.Activation {
	act, err := cel.NewActivation(s.buildBag())
	if err != nil {
		// Unreachable: NewActivation rejects only nil and non-map bindings.
		panic("inputs: activation: " + err.Error())
	}
	return act
}

// buildBag projects the views into the CEL variable bag. It reads only its
// receiver's fields and never pointer identity: the first call can legitimately
// come from audit's by-value copy of the Scope, whose fields are identical and
// whose maps are shared.
//
// This bag holds only variables that are fixed when the unit is bound, and its
// key set is exactly {request, pod, profile, rule, inputs} —
// TestBuildBagKeySetIsExact pins that. Anything whose value can change within
// the unit's lifetime — `result`, `response`, a response header, a buffered
// body — must never be added here, where the memoisation would freeze it at the
// first evaluation; it is layered as a hierarchical child instead, in
// audit.Scope.Activation (audit/scope.go).
//
// The header and label maps are shared, not copied. Their sources are allocated
// fresh per request (extproc/attributes/extract.go:246 and :89) and nothing
// mutates them in place, so a copy would buy nothing and cost O(headers) on
// every request.
func (s *Scope) buildBag() map[string]any {
	queryParams := make(map[string]string, len(s.request.Query))
	for k, vals := range s.request.Query {
		if len(vals) > 0 {
			queryParams[k] = vals[0]
		}
	}

	// Written unconditionally, nil included: with the key absent,
	// has(inputs.x) errors instead of returning false, which silently drops
	// an audit event and fails a credential fetch into a 403.
	//
	// When the profile's declared inputs failed to resolve, the slot holds a
	// CEL error value instead: every expression that touches inputs —
	// including has(inputs.x) — evaluates to this error and resolves through
	// the consumer's failure policy, never through a silently absent key.
	var inputsSlot any = s.inputs
	if s.inputsErr != "" {
		inputsSlot = types.NewErr("profile inputs unavailable: %s", s.inputsErr)
	}

	return map[string]any{
		"request": map[string]any{
			"dnsCandidates": s.request.DNSCandidates,
			"host":          s.request.Host,
			"port":          int64(s.request.Port),
			"path":          s.request.Path,
			"method":        s.request.Method,
			"scheme":        s.request.Scheme,
			"headers":       orEmpty(s.request.headers),
			"queryParams":   queryParams,
		},
		"pod": map[string]any{
			"name":      s.workload.Name,
			"namespace": s.workload.Namespace,
			"ip":        s.workload.IP,
			"labels":    orEmpty(s.workload.Labels),
		},
		"profile": map[string]string{
			"name":      s.profile.Name,
			"namespace": s.profile.Namespace,
		},
		"rule":   map[string]string{"name": s.rule.Name},
		"inputs": inputsSlot,
	}
}

// orEmpty keeps the projected maps non-nil so the bag's shape does not depend
// on whether the source request carried headers at all. The source map itself
// is returned when it is non-nil; it is never copied.
func orEmpty(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
