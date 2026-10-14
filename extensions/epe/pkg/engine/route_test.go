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
	"context"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

type routeTestFilter struct {
	filter.PassThrough
	headers filter.Action
	body    filter.Action
}

func (f *routeTestFilter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return f.headers, nil
}

func (f *routeTestFilter) OnRequestBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	return f.body, nil
}

func routeTestEngine(t *testing.T, filters ...*routeTestFilter) (*Engine, []Unit) {
	t.Helper()
	var specs []regSpec
	var row []string
	for i, f := range filters {
		specs = append(
			specs,
			regSpec{name: "route" + strconv.Itoa(i), make: func(filter.RuleConfig[string]) filter.Filter { return f }},
		)
		row = append(row, "enabled")
	}
	return NewEngine(buildRegs(t, specs), 0), unitsFor([][]string{row})
}

func routeMutation(address string, clear bool) filter.Mutation {
	a := netip.MustParseAddrPort(address)
	return filter.Mutation{Route: &filter.RouteMutation{
		Upstream:   &filter.UpstreamTarget{Address: &a},
		ClearCache: clear,
	}}
}

func TestRouteMutationHeaders(t *testing.T) {
	first := routeMutation("192.0.2.1:443", true)
	for _, tc := range []struct {
		name     string
		last     filter.Action
		want     Disposition
		conflict bool
	}{
		{"same target", filter.Continue(routeMutation("192.0.2.1:443", false)), DispositionMutated, false},
		{"bypass", filter.Bypass(), DispositionBypassed, false},
		{"block", filter.Stop(filter.Reply{Status: 403}), DispositionBlocked, false},
		{"conflict", filter.Continue(routeMutation("192.0.2.2:443", false)), DispositionError, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, units := routeTestEngine(
				t,
				&routeTestFilter{headers: filter.Continue(first)},
				&routeTestFilter{headers: tc.last},
			)
			result, err := e.EvalRequestHeaders(context.Background(), &filter.Stream{}, units)
			if tc.conflict {
				if err == nil || !strings.Contains(err.Error(), "conflicting upstream") {
					t.Fatalf("err=%v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			requireDisposition(t, result.Disposition, tc.want)
			if tc.conflict || tc.want == DispositionBlocked {
				if result.Route != nil {
					t.Fatal("failed/blocked result retained a route")
				}
				return
			}
			if result.Route == nil || !result.Route.ClearCache || result.Route.Upstream == nil ||
				*result.Route.Upstream.Address != *first.Route.Upstream.Address {
				t.Fatalf("route=%+v", result.Route)
			}
			// Returned results must not alias filter-owned pointers.
			*result.Route.Upstream.Address = netip.MustParseAddrPort("192.0.2.99:80")
			result.Route.ClearCache = false
			if first.Route.Upstream.Address.String() != "192.0.2.1:443" || !first.Route.ClearCache {
				t.Fatal("result aliased filter data")
			}
		})
	}
}

func TestRouteMutationContinuation(t *testing.T) {
	for _, inline := range []bool{false, true} {
		for _, conflicting := range []bool{false, true} {
			target := routeMutation("192.0.2.1:443", false)
			next := filter.Continue(filter.Mutation{Route: &filter.RouteMutation{ClearCache: true}})
			if conflicting {
				next = filter.Continue(routeMutation("192.0.2.2:443", false))
			}
			e, units := routeTestEngine(
				t,
				&routeTestFilter{headers: filter.NeedBody(filter.CompleteBody, target), body: filter.Continue()},
				&routeTestFilter{headers: next},
			)
			st := &filter.Stream{}
			body := filter.Body{Complete: true}
			var options []RequestOption
			if inline {
				options = append(options, WithAvailableRequestBody(body))
			}
			headers, err := e.EvalRequestHeaders(context.Background(), st, units, options...)
			route := headers.Route
			if !inline && !conflicting {
				if err != nil || !headers.NeedsBody() || headers.Route == nil {
					t.Fatalf("paused result=%+v, err=%v", headers, err)
				}
				resumed, bodyErr := e.EvalRequestBody(context.Background(), st, headers, body)
				route, err = resumed.Route, bodyErr
			}
			if conflicting {
				if err == nil || !strings.Contains(err.Error(), "conflicting upstream") || route != nil {
					t.Fatalf("inline=%v route=%+v err=%v", inline, route, err)
				}
			} else if err != nil || route == nil || route.Upstream == nil || route.Upstream.Address.String() != "192.0.2.1:443" || !route.ClearCache {
				t.Fatalf("inline=%v route=%+v err=%v", inline, route, err)
			}
		}
	}
}

func TestRouteMutationPhaseValidation(t *testing.T) {
	reg := filter.Registration{Name: "route"}
	action := filter.Continue(routeMutation("192.0.2.1:443", false))
	if err := validateAction(reg, filter.PhaseRequestHeaders, action); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []filter.Phase{filter.PhaseRequestBody, filter.PhaseResponseHeaders, filter.PhaseResponseBody} {
		if err := validateAction(reg, phase, action); err == nil {
			t.Fatalf("phase %v accepted target", phase)
		}
	}
	empty := filter.Continue(filter.Mutation{Route: &filter.RouteMutation{Upstream: &filter.UpstreamTarget{}}})
	if err := validateAction(reg, filter.PhaseRequestHeaders, empty); err == nil {
		t.Fatal("empty target accepted")
	}
}

func TestRequestBodyCannotChangeDestination(t *testing.T) {
	reg := filter.Registration{Name: "body"}
	for _, mutation := range []filter.Mutation{
		filter.SetHeader("Host", "other.example"),
		filter.SetHeader(":authority", "other.example:8443"),
		filter.SetHeader(":scheme", "http"),
		filter.SetHeader(":method", "CONNECT"),
		filter.SetPath("/other", true),
		routeMutation("192.0.2.99:8443", false),
	} {
		if err := validateAction(reg, filter.PhaseRequestBody, filter.Continue(mutation)); err == nil {
			t.Fatalf("body accepted destination mutation: %+v", mutation)
		}
	}
	if err := validateAction(
		reg,
		filter.PhaseRequestBody,
		filter.Continue(filter.SetPath("/signed?Signature=value", false)),
	); err != nil {
		t.Fatal("body signing must remain supported", err)
	}
}

func TestRequestStreamViewReuse(t *testing.T) {
	for _, routed := range []bool{false, true} {
		t.Run(strconv.FormatBool(routed), func(t *testing.T) {
			walk := phaseWalk{actionWalk: newActionWalk(&filter.Stream{})}
			if routed {
				walk.pending = []filter.Mutation{routeMutation("192.0.2.1:443", false)}
			}
			if _, err := walk.streamView(); err != nil {
				t.Fatal(err)
			}
			allocations := testing.AllocsPerRun(100, func() {
				view, err := walk.streamView()
				if err != nil {
					t.Fatal(err)
				}
				benchSink = view
			})
			if allocations != 0 {
				t.Fatalf("unchanged request view allocated %v times", allocations)
			}
		})
	}
}

func TestRequestStreamViewSnapshots(t *testing.T) {
	st := &filter.Stream{}
	st.Request.Host = "original.example"
	walk := phaseWalk{actionWalk: newActionWalk(st)}
	first, err := walk.streamView()
	if err != nil {
		t.Fatal(err)
	}
	mutation := routeMutation("192.0.2.1:443", false)
	walk.pending = append(walk.pending, mutation)
	routed, err := walk.streamView()
	if err != nil {
		t.Fatal(err)
	}
	walk.pending = append(walk.pending, filter.SetHeader("x-test", "value"))
	next, err := walk.streamView()
	if err != nil {
		t.Fatal(err)
	}
	if first.Upstream != nil || st.Upstream != nil || next.Request.Host != st.Request.Host {
		t.Fatal("later routing changed the original request view")
	}
	if next.Upstream.Address.String() != "192.0.2.1:443" || routed.Upstream.Address.String() != "192.0.2.1:443" {
		t.Fatal("request view lost the selected target")
	}
	if routed.Upstream == mutation.Route.Upstream || routed.Upstream.Address == mutation.Route.Upstream.Address {
		t.Fatal("request view aliases filter-owned target")
	}
	walk.pending = append(walk.pending, routeMutation("192.0.2.2:443", false))
	if _, err := walk.streamView(); err == nil || !strings.Contains(err.Error(), "conflicting upstream") {
		t.Fatalf("incremental route conflict was not rejected: %v", err)
	}
	if routed.Upstream.Address.String() != "192.0.2.1:443" {
		t.Fatal("failed routing changed a prior request view")
	}
}

func TestIncrementalRoutePreservesPrior(t *testing.T) {
	prior, err := foldRoute([]filter.Mutation{routeMutation("192.0.2.1:443", false)})
	if err != nil {
		t.Fatal(err)
	}
	next, err := foldRouteFrom(prior, []filter.Mutation{{Route: &filter.RouteMutation{ClearCache: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if prior.ClearCache || !next.ClearCache || next.Upstream.Address.String() != "192.0.2.1:443" {
		t.Fatal("incremental route merge changed a published route or lost its target")
	}
}
