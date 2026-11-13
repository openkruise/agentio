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
	"strconv"

	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// UnitID is the complete identity the engine needs for one policy unit:
// rule order uses slice position, metrics use the filter name, and
// accesslog/audit attribution use these two strings plus the ordinal.
type UnitID struct {
	// Scope is "<ns>/<profile>".
	Scope string
	// Name is the rule name.
	Name string
	// Ordinal disambiguates duplicates and gives loggers a stable index.
	Ordinal int
}

func (u UnitID) String() string {
	return u.Scope + "/" + u.Name + "#" + strconv.Itoa(u.Ordinal)
}

// RuleConfig pairs a projected filter config with its unit identity. It
// holds no policy-API types: that is the point.
type RuleConfig[C any] struct {
	ID  UnitID
	Cfg C
	// Scope is the immutable CEL/template evaluation scope for this unit.
	Scope *inputs.Scope
}

// Unit is one bound policy rule, with its immutable evaluation scope and configs.
type Unit struct {
	// CheckRequest is an ordered request-only authorization checkpoint between rule groups.
	// The engine supplies the effective routing headers and upstream target.
	CheckRequest func(context.Context, *Stream) (Action, error)

	ID    UnitID
	Scope *inputs.Scope
	// Cfgs[i] belongs to filter registration i; nil means no config for that filter.
	Cfgs []any
}
