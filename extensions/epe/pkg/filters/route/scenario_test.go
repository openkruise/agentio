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

package route_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/route"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
)

// The policy schema is not wired yet. Scenarios inject typed configs and run
// the real descriptor, engine and extproc.Server through a scripted stream.
func routeHarness(t *testing.T, configs []route.Config, buffered bool, denyBody bool) *enginetest.Harness {
	t.Helper()
	definitions := []filter.Definition{filter.Define(route.Descriptor(),
		func(json.RawMessage) (route.Config, error) { return route.Config{}, nil })}
	if buffered {
		definitions = append(definitions, filter.Define(filter.Descriptor[bool]{
			Name:   "bodycheck",
			Phases: filter.PhaseRequestHeaders | filter.PhaseRequestBody,
			New:    func(cfg filter.RuleConfig[bool]) filter.Filter { return &bodyCheck{deny: cfg.Cfg} },
		}, func(json.RawMessage) (bool, error) { return false, nil }))
	}
	regs, err := filter.Build(definitions...)
	if err != nil {
		t.Fatal(err)
	}
	units := make([]engine.Unit, len(configs))
	for i, cfg := range configs {
		row := make([]any, len(regs))
		row[0] = cfg
		units[i] = engine.Unit{ID: filter.UnitID{Scope: "default/routes", Name: "target", Ordinal: i}, Cfgs: row}
	}
	if buffered {
		units[len(units)-1].Cfgs[1] = denyBody
	}
	return enginetest.New(t, enginetest.Options{
		Registrations: regs,
		Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{Units: units}, nil
		},
	})
}

func target(address string) route.Config {
	value := netip.MustParseAddrPort(address)
	return route.Config{Upstream: &filter.UpstreamTarget{Address: &value}}
}

func routeRequest() *enginetest.RequestBuilder {
	return enginetest.NewRequest("GET", "api.example.com:443", "/v1").
		Peer("default", "sandbox", nil)
}

func TestScenario_RouteTargetReachesWire(t *testing.T) {
	for _, address := range []string{"192.0.2.10:8443", "[2001:db8::10]:8443"} {
		t.Run(address, func(t *testing.T) {
			h := routeHarness(t, []route.Config{target(address)}, false, false)
			v := h.Run(t, routeRequest())
			response := v.RequireUpstream(t, address)
			v.RequireOutcome(t, "mutated")
			if response.GetRequestHeaders() == nil || response.GetRequestHeaders().GetResponse().GetClearRouteCache() ||
				len(v.RequestHeaderOps) != 0 {
				t.Fatalf("route changed headers/cache or wrong phase: %v", v.Raw)
			}
		})
	}
}

func TestScenario_RouteMergesMatchingTargetsAndRejectsConflicts(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		name, second := "same", "192.0.2.10:443"
		if conflict {
			name, second = "conflict", "192.0.2.20:443"
		}
		t.Run(name, func(t *testing.T) {
			h := routeHarness(t, []route.Config{target("192.0.2.10:443"), target(second)}, false, false)
			v := h.Run(t, routeRequest())
			if conflict {
				if v.Err == nil {
					t.Fatal("conflicting routes must fail processing")
				}
				v.RequireNoUpstream(t)
			} else {
				v.RequireUpstream(t, "192.0.2.10:443")
			}
		})
	}
}

func TestScenario_RouteWaitsForBufferedDecision(t *testing.T) {
	for _, deny := range []bool{false, true} {
		name := "allow"
		if deny {
			name = "deny"
		}
		t.Run(name, func(t *testing.T) {
			h := routeHarness(t, []route.Config{target("192.0.2.10:443")}, true, deny)
			v := h.Run(t, routeRequest().Body([]byte("payload")))
			if v.ModeOverride == nil || len(v.Raw) != 2 {
				t.Fatalf("expected buffered header/body exchange: %v", v.Raw)
			}
			if deny {
				v.RequireBlocked(t, 403)
				v.RequireNoUpstream(t)
			} else {
				response := v.RequireUpstream(t, "192.0.2.10:443")
				if response.GetRequestBody() == nil || response.GetRequestBody().GetResponse().GetClearRouteCache() {
					t.Fatalf("target must be emitted only after body decision: %v", v.Raw)
				}
			}
		})
	}
}

type bodyCheck struct {
	filter.PassThrough
	deny bool
}

func (*bodyCheck) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(), nil
}

func (f *bodyCheck) OnRequestBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	if f.deny {
		return filter.Stop(filter.Reply{Status: 403}), nil
	}
	return filter.Continue(), nil
}
