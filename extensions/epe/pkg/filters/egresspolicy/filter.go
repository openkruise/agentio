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

// Package egresspolicy authorizes caller-supplied forwarding destinations.
package egresspolicy

import (
	"context"
	"net/netip"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

const FilterName = "egresspolicy"

// Config is an immutable compiled policy. Build it with Parse or Definition.
// Its zero value denies every destination.
type Config struct {
	allowDefault bool
	reply        filter.Reply
	rules        []rule
}

type rule struct {
	cidrs []netip.Prefix
	ports []portRange
	allow bool
}

type portRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

type Filter struct {
	filter.PassThrough
	cfg Config
}

func New(cfg filter.RuleConfig[Config]) filter.Filter { return &Filter{cfg: cfg.Cfg} }

func (f *Filter) OnRequestHeaders(_ context.Context, s *filter.Stream) (filter.Action, error) {
	if s == nil || !s.Destination.IP.IsValid() || s.Destination.IP.Zone() != "" || s.Destination.Port == 0 {
		return f.deny(), nil
	}
	ip, port := s.Destination.IP.Unmap(), s.Destination.Port
	for _, r := range f.cfg.rules {
		ipMatch := len(r.cidrs) == 0
		for _, cidr := range r.cidrs {
			if cidr.Contains(ip) {
				ipMatch = true
				break
			}
		}
		if !ipMatch {
			continue
		}
		portMatch := len(r.ports) == 0
		for _, ports := range r.ports {
			if port >= ports.Start && port <= ports.End {
				portMatch = true
				break
			}
		}
		if !portMatch {
			continue
		}
		if r.allow {
			return filter.Continue(), nil
		}
		return f.deny(), nil
	}
	if f.cfg.allowDefault {
		return filter.Continue(), nil
	}
	return f.deny(), nil
}

func (f *Filter) deny() filter.Action {
	reply := f.cfg.reply
	if reply.Status == 0 {
		reply.Status = 403
	}
	return filter.Stop(reply)
}

func Descriptor() filter.Descriptor[Config] {
	return filter.Descriptor[Config]{Name: FilterName, Phases: filter.PhaseRequestHeaders,
		OnError: filter.Always[Config](filter.FailClosed), New: New}
}

func Definition() filter.Definition { return filter.Define(Descriptor(), Parse) }
