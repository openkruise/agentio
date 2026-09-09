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

// Package egressauthz authorizes resolved destinations and pins the selected
// upstream address so the proxy can connect to the address that was authorized.
package egressauthz

import (
	"context"
	"fmt"
	"net/netip"

	log "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
	"github.com/openkruise/agentio/pkg/dns"
)

const FilterName = "egressauthz"

type Filter struct {
	filter.PassThrough
	cfg    Config
	client *dns.Client
}

// New captures the immutable Config selected by the caller for this request.
// DNS cache/custom records remain shared through the injected client.
func New(rule filter.RuleConfig[Config], client *dns.Client) filter.Filter {
	return &Filter{cfg: rule.Cfg, client: client}
}

func (f *Filter) OnRequestHeaders(ctx context.Context, stream *filter.Stream) (filter.Action, error) {
	if err := f.cfg.Validate(); err != nil {
		return filter.Action{}, fmt.Errorf("egressauthz config: %w", err)
	}
	addresses, err := resolveDNS(ctx, f.client, stream, f.cfg.Family)
	if err != nil {
		return filter.Action{}, fmt.Errorf("egressauthz: %w", err)
	}
	// The same request snapshot governs DNS completion and every candidate.
	// Publishing a new Config cannot change this invocation's policy decisions.
	logger := log.FromContext(ctx).V(logging.DEBUG)
	for _, ip := range addresses {
		address := netip.AddrPortFrom(ip, uint16(stream.Request.Port))
		decision := f.cfg.Evaluate(address)
		if logger.Enabled() {
			logger.Info("egress destination evaluated",
				"address", address.String(), "action", string(decision.Action),
				"policy", decision.PolicyName, "ruleIndex", decision.RuleIndex)
		}
		if decision.Action != Allow {
			continue
		}
		return filter.Continue(filter.Mutation{Route: &filter.RouteMutation{
			Upstream: &filter.UpstreamTarget{Address: &address},
		}}), nil
	}
	return filter.Stop(filter.Reply{
		Status:  403,
		Details: "epe_egress_denied",
	}), nil
}

// Descriptor binds the shared client and fails closed on resolution errors.
// Ensuring this filter runs for every required request belongs to chain assembly.
func Descriptor(client *dns.Client) filter.Descriptor[Config] {
	return filter.Descriptor[Config]{
		Name:    FilterName,
		Phases:  filter.PhaseRequestHeaders,
		OnError: filter.Always[Config](filter.FailClosed),
		New: func(rule filter.RuleConfig[Config]) filter.Filter {
			return New(rule, client)
		},
	}
}
