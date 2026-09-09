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
package engine

import (
	"fmt"
	"strings"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// foldRoute preserves one upstream target and ORs cache-clear requests.
// Conflicting targets are a contract error, not a last-writer override.
// Copy all nested values so callers cannot mutate filter-owned data.
func foldRoute(muts []filter.Mutation) (*filter.RouteMutation, error) {
	var result *filter.RouteMutation
	for _, m := range muts {
		if m.Route == nil {
			continue
		}
		if err := m.Route.Validate(); err != nil {
			return nil, err
		}
		if result == nil {
			result = &filter.RouteMutation{}
		}
		result.ClearCache = result.ClearCache || m.Route.ClearCache
		if m.Route.Upstream == nil {
			continue
		}
		address := *m.Route.Upstream.Address
		if result.Upstream != nil && *result.Upstream.Address != address {
			return nil, fmt.Errorf("conflicting upstream targets: %s and %s", result.Upstream.Address, address)
		}
		result.Upstream = &filter.UpstreamTarget{Address: &address}
	}
	return result, nil
}

// fold computes the net effect of mutations applied in execution order.
//
// Envoy executes all remove_headers before all set_headers within a single
// HeaderMutation, so "a later action removes a header an earlier action set"
// is inexpressible by list concatenation — the set would win. Folding in the
// abstract model resolves that ordering.
//
// The "each key ends up as removes or set/adds, never both" shape is only
// required in the Set->Remove direction. Remove-then-Add is the one case
// that genuinely needs BOTH ops: because Envoy's removes run first,
// [Remove, Add] correctly means "drop the inbound value, then add this one",
// whereas the add alone would append to the inbound value.
//
// Keys fold case-insensitively: HTTP header names are case-insensitive and
// Envoy lower-cases them, so X-Foo and x-foo are one header. The first-seen
// spelling is preserved in the output.
func fold(muts []filter.Mutation) []filter.HeaderOp {
	type keyState struct {
		name    string            // first-seen spelling, used for output
		ops     []filter.HeaderOp // pending Set/Add ops, in order
		removed bool
		// removeFirst records that a Remove preceded the pending adds and
		// must be emitted ahead of them.
		removeFirst bool
	}
	states := map[string]*keyState{}
	var order []string // first-touch order for deterministic output

	stateFor := func(name string) *keyState {
		key := strings.ToLower(name)
		s, ok := states[key]
		if !ok {
			s = &keyState{name: name}
			states[key] = s
			order = append(order, key)
		}
		return s
	}

	for _, m := range muts {
		for _, op := range m.HeaderOps {
			s := stateFor(op.Name)
			switch op.Kind {
			case filter.HeaderSet:
				// A set overwrites, so it subsumes any pending remove.
				s.ops = []filter.HeaderOp{op}
				s.removed = false
				s.removeFirst = false
			case filter.HeaderAdd:
				// An add preserves whatever is there, so a preceding remove
				// still has to happen.
				if s.removed {
					s.removeFirst = true
				}
				s.ops = append(s.ops, op)
				s.removed = false
			case filter.HeaderRemove:
				s.ops = nil
				s.removed = true
				s.removeFirst = false
			}
		}
	}

	var out []filter.HeaderOp
	for _, key := range order {
		s := states[key]
		if s.removed {
			out = append(out, filter.HeaderOp{Kind: filter.HeaderRemove, Name: s.name})
			continue
		}
		if s.removeFirst {
			out = append(out, filter.HeaderOp{Kind: filter.HeaderRemove, Name: s.name})
		}
		out = append(out, s.ops...)
	}
	return out
}
