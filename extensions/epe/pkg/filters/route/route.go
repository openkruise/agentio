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

// Package route applies policy-defined request routing changes.
package route

import (
	"context"
	"fmt"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

const FilterName = "route"

type Filter struct {
	filter.PassThrough
	cfg Config
}

// New snapshots the rule config.
func New(rule filter.RuleConfig[Config]) filter.Filter {
	cfg := rule.Cfg
	if cfg.Upstream != nil {
		upstream := *cfg.Upstream
		cfg.Upstream = &upstream
		if upstream.Address != nil {
			address := *upstream.Address
			upstream.Address = &address
		}
	}
	return &Filter{cfg: cfg}
}

func (f *Filter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	if err := f.cfg.Validate(); err != nil {
		return filter.Action{}, fmt.Errorf("route config: %w", err)
	}
	mutation := &filter.RouteMutation{}
	if upstream := f.cfg.Upstream; upstream != nil {
		value := *upstream.Address
		mutation.Upstream = &filter.UpstreamTarget{Address: &value}
	}
	return filter.Continue(filter.Mutation{Route: mutation}), nil
}

// Descriptor declares a fail-closed filter for request routing changes.
func Descriptor() filter.Descriptor[Config] {
	return filter.Descriptor[Config]{
		Name:    FilterName,
		Phases:  filter.PhaseRequestHeaders,
		OnError: filter.Always[Config](filter.FailClosed),
		New:     New,
	}
}
