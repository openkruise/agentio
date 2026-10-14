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

import "slices"

// ActionKind names what a filter decided. It is only readable through
// Action accessors; filters never construct an Action from a kind.
type ActionKind uint8

const (
	// KindContinue lets the chain proceed, optionally with mutations.
	KindContinue ActionKind = iota
	// KindStop terminates the HTTP exchange and discards pending mutations.
	KindStop
	// KindBypass skips following actions and rules in every phase while
	// preserving earlier work and the bypassing pair itself.
	KindBypass
	// KindNeedBody registers a body callback while header evaluation continues.
	// It is valid only from request or response headers.
	KindNeedBody
)

// Action is opaque: fields are private and only the constructors below can
// produce one, so the invariants each kind documents hold by construction.
type Action struct {
	kind            ActionKind
	bodyRequirement BodyRequirement
	mutations       []Mutation
	reply           Reply
}

// Continue proceeds, accumulating the given mutations in execution order.
func Continue(m ...Mutation) Action {
	return Action{kind: KindContinue, mutations: m}
}

// Stop terminates with the given reply and discards pending mutations.
// It deliberately accepts no mutations: a block never mutates.
func Stop(r Reply) Action {
	return Action{kind: KindStop, reply: r}
}

// Bypass skips all following actions and rules. Earlier mutations and side
// effects are preserved.
func Bypass() Action { return Action{kind: KindBypass} }

// NeedBody asks for the request or response body, optionally carrying
// mutations accumulated so far.
func NeedBody(requirement BodyRequirement, m ...Mutation) Action {
	return Action{kind: KindNeedBody, bodyRequirement: requirement, mutations: m}
}

// BodyRequirement reports the input contract carried by a NeedBody action.
func (a Action) BodyRequirement() BodyRequirement { return a.bodyRequirement }

// Kind reports what the filter decided.
func (a Action) Kind() ActionKind { return a.kind }

// Mutations returns the mutations carried by a Continue or NeedBody action.
func (a Action) Mutations() []Mutation { return a.mutations }

// Reply returns the blocking reply and whether one is present.
func (a Action) Reply() (Reply, bool) { return a.reply, a.kind == KindStop }

// Equal reports semantic equality, for test assertions.
func (a Action) Equal(b Action) bool {
	if a.kind != b.kind || a.bodyRequirement != b.bodyRequirement {
		return false
	}
	if a.kind == KindStop && !a.reply.equal(b.reply) {
		return false
	}
	return slices.EqualFunc(a.mutations, b.mutations, Mutation.equal)
}
