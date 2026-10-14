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

package egressauthz_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/route"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
	"github.com/openkruise/agentio/pkg/dns"
)

// Run real route rules and authorization, with an optional body suspension
// between the headers and final authorization. DNS is deliberately configured to prefer a different endpoint.
func preferenceHarness(
	t *testing.T,
	client *dns.Client,
	target string,
	cfg egressauthz.Config,
	buffered bool,
) *enginetest.Harness {
	t.Helper()
	definitions := []filter.Definition{
		filter.Define(route.Descriptor(), func(json.RawMessage) (route.Config, error) { return route.Config{}, nil }),
	}
	address := netip.MustParseAddrPort(target)
	units := []engine.Unit{{Cfgs: []any{route.Config{Upstream: &filter.UpstreamTarget{Address: &address}}, nil}}}
	definitions = append(
		definitions,
		filter.Define(filter.Descriptor[bool]{Name: "bodycheck",
			Phases: filter.PhaseRequestHeaders | filter.PhaseRequestBody,
			New:    func(filter.RuleConfig[bool]) filter.Filter { return &preferenceBodyCheck{} }},
			func(json.RawMessage) (bool, error) { return false, nil }),
	)
	next := engine.Unit{Cfgs: []any{nil, nil}}
	if buffered {
		next.Cfgs[1] = true
	}
	units = append(units, next)
	regs, err := filter.Build(definitions...)
	if err != nil {
		t.Fatal(err)
	}
	return enginetest.New(t, enginetest.Options{
		Registrations: regs,
		AuthorizeRequest: func(ctx context.Context, stream *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
			return egressauthz.Authorize(ctx, cfg, client, stream)
		},
		Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{Units: units}, nil
		},
	})
}

type preferenceBodyCheck struct{ filter.PassThrough }

func (*preferenceBodyCheck) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.NeedBody(filter.CompleteBody), nil
}

func TestScenario_EgressAuthzKeepsAllowedRoute(t *testing.T) {
	client := dns.NewClient(nil, time.Second)
	if err := client.SetRecord(
		"api.example.com",
		[]netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")},
	); err != nil {
		t.Fatal(err)
	}
	cfg := egressauthz.Config{
		Policies: []egressauthz.Policy{
			{
				Name: "allow",
				Rules: []egressauthz.Rule{
					authRule(egressauthz.Allow, "192.0.2.0/24", 8443),
					authRule(egressauthz.Allow, "192.0.2.0/24", 443),
				},
			},
		},
	}
	for _, buffered := range []bool{false, true} {
		t.Run(map[bool]string{false: "headers", true: "buffered"}[buffered], func(t *testing.T) {
			h := preferenceHarness(t, client, "192.0.2.2:8443", cfg, buffered)
			request := authRequest("api.example.com:443").DestinationAddress("192.0.2.1:443").DestinationPort(443)
			if buffered {
				request.Body([]byte("payload"))
			}
			v := h.Run(t, request)
			if buffered {
				if len(v.Raw) != 2 {
					t.Fatalf("expected headers and body responses, got %v", v.Raw)
				}
				for i := range v.Raw {
					enginetest.ParseVerdict(v.Raw[i:i+1], v.Err).RequireUpstream(t, "192.0.2.2:8443")
				}
			} else {
				v.RequireUpstream(t, "192.0.2.2:8443")
			}
		})
	}
}

func TestScenario_EgressAuthzRouteDoesNotRequireDNS(t *testing.T) {
	cfg := egressauthz.Config{
		Policies: []egressauthz.Policy{
			{Name: "allow", Rules: []egressauthz.Rule{authRule(egressauthz.Allow, "192.0.2.2/32", 8443)}},
		},
	}
	h := preferenceHarness(t, nil, "192.0.2.2:8443", cfg, false)
	h.Run(t, authRequest("unresolved.invalid:443")).RequireUpstream(t, "192.0.2.2:8443")
}

func TestScenario_EgressAuthzDeniedRouteDoesNotFallBack(t *testing.T) {
	client := dns.NewClient(nil, time.Second)
	if err := client.SetRecord("api.example.com", []netip.Addr{netip.MustParseAddr("192.0.2.1")}); err != nil {
		t.Fatal(err)
	}
	cfg := egressauthz.Config{
		Policies: []egressauthz.Policy{
			{Name: "allow", Rules: []egressauthz.Rule{authRule(egressauthz.Allow, "192.0.2.1/32", 443)}},
		},
	}
	h := preferenceHarness(t, client, "192.0.2.99:443", cfg, false)
	requireDenied(
		t,
		h.Run(t, authRequest("api.example.com:443").DestinationAddress("192.0.2.1:443").DestinationPort(443)),
	)
}

func TestScenario_EgressAuthzPrefersAllowedOriginalDestination(t *testing.T) {
	client := dns.NewClient(nil, time.Second)
	if err := client.SetRecord("api.example.com", []netip.Addr{netip.MustParseAddr("192.0.2.1")}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		original string
		want     string
		port     int32
	}{
		{"allowed original is kept", "192.0.2.2:443", "192.0.2.2:443", 443},
		{"denied original falls back to DNS", "192.0.2.99:443", "192.0.2.1:443", 443},
		{"original port is authorized", "192.0.2.2:8443", "192.0.2.2:8443", 8443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &atomic.Pointer[egressauthz.Config]{}
			publishPolicies(t, cfg, egressauthz.Policy{Name: "allow",
				Rules: []egressauthz.Rule{
					authRule(
						egressauthz.Allow,
						"192.0.2.1/32",
						443,
					),
					authRule(egressauthz.Allow, "192.0.2.2/32", uint16(tc.port)),
				}})
			h := authHarness(t, client, cfg)
			h.Run(t, authRequest("api.example.com:443").DestinationAddress(tc.original).DestinationPort(tc.port)).
				RequireUpstream(t, tc.want)
		})
	}
}

func TestEgressAuthzAllowedOriginalDoesNotRequireDNS(t *testing.T) {
	cfg := egressauthz.Config{
		Family: dns.IPv4Only,
		Policies: []egressauthz.Policy{
			{Name: "allow", Rules: []egressauthz.Rule{authRule(egressauthz.Allow, "2001:db8::2/128", 8443)}},
		},
	}
	target, reply, err := egressauthz.Authorize(t.Context(), cfg, nil, &filter.Stream{Request: httpreq.HTTPRequest{
		Host:                "unresolved.invalid",
		Port:                443,
		OriginalDestination: netip.MustParseAddrPort("[2001:db8::2]:8443"),
	}})
	if err != nil || reply != nil || target == nil || target.Address.String() != "[2001:db8::2]:8443" {
		t.Fatalf("target=%v reply=%v err=%v", target, reply, err)
	}
}

// The restored IP belonged to the original authority. A rule's authority or
// port rewrite must be authorized on its own, including after body inspection.
func TestScenario_EgressAuthzChecksRewrittenAuthority(t *testing.T) {
	for _, header := range []string{":authority", "Host"} {
		for _, buffered := range []bool{false, true} {
			for _, allow := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/body=%v/allow=%v", header, buffered, allow), func(t *testing.T) {
					rules := []egressauthz.Rule{authRule(egressauthz.Allow, "192.0.2.1/32", 443)}
					if allow {
						rules = append(rules, authRule(egressauthz.Allow, "192.0.2.2/32", 8443))
					}
					cfg := egressauthz.Config{Policies: []egressauthz.Policy{{Name: "allow", Rules: rules}}}
					client := dns.NewClient(nil, time.Second)
					calls := 0
					h := enginetest.New(t, enginetest.Options{
						Registrations: []filter.Registration{{
							Name:   "rewrite",
							Phases: filter.PhaseRequestHeaders | filter.PhaseRequestBody,
							New: func(filter.ErasedRuleConfig) filter.Filter {
								return &authorityRewrite{
									buffered: buffered,
									mutation: filter.SetHeader(header, "192.0.2.2:8443"),
								}
							},
						}},
						Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
							return engine.Resolution{Units: []engine.Unit{{Cfgs: []any{true}}}}, nil
						},
						AuthorizeRequest: func(ctx context.Context, stream *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
							calls++
							return egressauthz.Authorize(ctx, cfg, client, stream)
						},
					})
					request := authRequest(
						"original.example:443",
					).DestinationAddress("192.0.2.1:443").
						DestinationPort(443)
					if buffered {
						request.Body([]byte("payload"))
					}
					verdict := h.Run(t, request)
					wantCalls := 1
					if buffered && allow {
						if len(verdict.Raw) != 2 {
							t.Fatalf("expected headers and body responses, got %v", verdict.Raw)
						}
						enginetest.ParseVerdict(verdict.Raw[:1], verdict.Err).RequireUpstream(t, "192.0.2.2:8443")
						verdict = enginetest.ParseVerdict(verdict.Raw[1:], verdict.Err)
					}
					if allow {
						verdict.RequireUpstream(t, "192.0.2.2:8443")
					} else {
						requireDenied(t, verdict)
					}
					if calls != wantCalls {
						t.Fatalf("authorization calls=%d, want %d", calls, wantCalls)
					}
				})
			}
		}
	}
}

type authorityRewrite struct {
	filter.PassThrough
	buffered bool
	mutation filter.Mutation
}

func (f *authorityRewrite) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	if f.buffered {
		return filter.NeedBody(filter.CompleteBody, f.mutation), nil
	}
	return filter.Continue(f.mutation), nil
}

func (f *authorityRewrite) OnRequestBody(context.Context, *filter.Stream, filter.Body) (filter.Action, error) {
	return filter.Continue(), nil
}
